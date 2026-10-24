use anyhow::Context;
use aquatic_common::{
    access_list::update_access_list,
    ip_ban::update_ip_ban_list,
    client_ban::update_client_ban_list,
    client_whitelist::update_client_whitelist,
    trusted_proxies::update_trusted_proxies,
    privileges::PrivilegeDropper,
    rustls_config::create_rustls_config,
    auto_ban::{validate_auto_ban_config, AutoBanTracker},
    validate_interval, validate_worker_counts,
    WorkerType,
    ServerStartInstant,
};
#[cfg(feature = "cpu-pinning")]
use aquatic_common::cpu_pinning::{pin_current_if_configured_to, WorkerIndex};
use arc_swap::ArcSwap;
use common::State;
use glommio::{channels::channel_mesh::MeshBuilder, prelude::*};
use signal_hook::{consts::{SIGUSR1, SIGUSR2}, iterator::Signals};
use std::{
    sync::Arc,
    thread::{sleep, Builder, JoinHandle},
    time::Duration,
};

use crate::config::Config;

mod common;
pub mod config;
mod workers;

pub const APP_NAME: &str = "aquatic_http: HTTP BitTorrent tracker";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

const SHARED_CHANNEL_SIZE: usize = 4096;

pub fn run(mut config: Config) -> ::anyhow::Result<()> {
    let mut signals = Signals::new([SIGUSR1, SIGUSR2])?;

    if !(config.network.use_ipv4 || config.network.use_ipv6) {
        return Result::Err(anyhow::anyhow!(
            "Both use_ipv4 and use_ipv6 can not be set to false"
        ));
    }

    validate_worker_counts(&mut config.socket_workers, Some(config.swarm_workers))?;

    validate_interval(
        "cleaning.torrent_cleaning_interval",
        config.cleaning.torrent_cleaning_interval,
    )?;
    validate_interval(
        "cleaning.connection_cleaning_interval",
        config.cleaning.connection_cleaning_interval,
    )?;

    #[cfg(feature = "metrics")]
    validate_interval(
        "metrics.torrent_count_update_interval",
        config.metrics.torrent_count_update_interval,
    )?;

    if config.network.tcp_keepalive {
        validate_interval(
            "network.tcp_keepalive_idle_secs",
            config.network.tcp_keepalive_idle_secs,
        )?;
        validate_interval(
            "network.tcp_keepalive_interval_secs",
            config.network.tcp_keepalive_interval_secs,
        )?;

        if config.network.tcp_keepalive_probes == 0 {
            return Err(anyhow::anyhow!(
                "network.tcp_keepalive_probes must be at least 1 (got 0)"
            ));
        }
    }

    // The response buffer is allocated per connection and sized from the
    // configured peer/scrape limits. Reject absurd values before the first
    // connection allocates gigabytes (the buffer would otherwise only fail at
    // request time, or abort the process on allocation failure).
    const MAX_RESPONSE_BUFFER_SIZE: usize = 1024 * 1024;

    let response_buffer_size = crate::workers::socket::response_buffer_size(&config);

    if response_buffer_size > MAX_RESPONSE_BUFFER_SIZE {
        return Err(anyhow::anyhow!(
            "protocol.max_peers = {} and protocol.max_scrape_torrents = {} require a \
             {}-byte response buffer per connection, above the {} byte limit; reduce them \
             (for example max_peers <= 40000 or max_scrape_torrents <= 9000)",
            config.protocol.max_peers,
            config.protocol.max_scrape_torrents,
            response_buffer_size,
            MAX_RESPONSE_BUFFER_SIZE,
        ));
    }

    // Trusting X-Forwarded-For without a trusted proxy list lets any client
    // choose the address it is tracked and banned under.
    if config.network.runs_behind_reverse_proxy && !config.trusted_proxies.enabled {
        return Err(anyhow::anyhow!(
            "network.runs_behind_reverse_proxy = true requires trusted_proxies.enabled = true \
             and a non-empty trusted proxy list: otherwise any client can forge the '{}' header",
            config.network.reverse_proxy_ip_header_name,
        ));
    }

    validate_auto_ban_config(&config.auto_ban, &config.ip_ban)?;

    let state = State::default();

    // Initialize auto-ban tracker if enabled
    let state = if config.auto_ban.enabled {
        let ban_list_path = if config.auto_ban.ban_list_path.as_os_str().is_empty() {
            None
        } else {
            Some(config.auto_ban.ban_list_path.clone())
        };
        let tracker = Arc::new(AutoBanTracker::new(
            config.auto_ban.threshold,
            config.auto_ban.window_secs,
            config.auto_ban.ban_duration_secs,
            ban_list_path,
        ));
        State {
            auto_ban_tracker: Some(tracker),
            ..state
        }
    } else {
        state
    };

    update_access_list(&config.access_list, &state.access_list)?;
    update_ip_ban_list(&config.ip_ban, &state.ip_ban_list)?;
    update_client_ban_list(&config.client_ban, &state.client_ban_list)?;
    update_client_whitelist(&config.client_whitelist, &state.client_whitelist)?;
    update_trusted_proxies(&config.trusted_proxies, &state.trusted_proxies)?;

    let request_mesh_builder = MeshBuilder::partial(
        config.socket_workers + config.swarm_workers,
        SHARED_CHANNEL_SIZE,
    );

    let num_sockets_per_worker =
        if config.network.use_ipv4 { 1 } else { 0 } + if config.network.use_ipv6 { 1 } else { 0 };

    let priv_dropper = PrivilegeDropper::new(
        config.privileges.clone(),
        config.socket_workers * num_sockets_per_worker,
    );

    let opt_tls_config = if config.network.enable_tls {
        Some(Arc::new(ArcSwap::from_pointee(create_rustls_config(
            &config.network.tls_certificate_path,
            &config.network.tls_private_key_path,
        )?)))
    } else {
        None
    };

    let server_start_instant = ServerStartInstant::new();

    let mut join_handles = Vec::new();

    for i in 0..(config.socket_workers) {
        let config = config.clone();
        let state = state.clone();
        let opt_tls_config = opt_tls_config.clone();
        let request_mesh_builder = request_mesh_builder.clone();

        let mut priv_droppers = Vec::new();

        for _ in 0..num_sockets_per_worker {
            priv_droppers.push(priv_dropper.clone());
        }

        let handle = Builder::new()
            .name(format!("socket-{:02}", i + 1))
            .spawn(move || {
                #[cfg(feature = "cpu-pinning")]
                pin_current_if_configured_to(
                    &config.cpu_pinning,
                    config.socket_workers,
                    config.swarm_workers,
                    WorkerIndex::SocketWorker(i),
                );

                LocalExecutorBuilder::default()
                    .make()
                    .map_err(|err| anyhow::anyhow!("Spawning executor failed: {:#}", err))?
                    .run(workers::socket::run_socket_worker(
                        config,
                        state,
                        opt_tls_config,
                        request_mesh_builder,
                        priv_droppers,
                        server_start_instant,
                        i,
                    ))
            })
            .context("spawn socket worker")?;

        join_handles.push((WorkerType::Socket(i), handle));
    }

    for i in 0..(config.swarm_workers) {
        let config = config.clone();
        let state = state.clone();
        let request_mesh_builder = request_mesh_builder.clone();

        let handle = Builder::new()
            .name(format!("swarm-{:02}", i + 1))
            .spawn(move || {
                #[cfg(feature = "cpu-pinning")]
                pin_current_if_configured_to(
                    &config.cpu_pinning,
                    config.socket_workers,
                    config.swarm_workers,
                    WorkerIndex::SwarmWorker(i),
                );

                LocalExecutorBuilder::default()
                    .make()
                    .map_err(|err| anyhow::anyhow!("Spawning executor failed: {:#}", err))?
                    .run(workers::swarm::run_swarm_worker(
                        config,
                        state,
                        request_mesh_builder,
                        server_start_instant,
                        i,
                    ))
            })
            .context("spawn swarm worker")?;

        join_handles.push((WorkerType::Swarm(i), handle));
    }

    #[cfg(feature = "prometheus")]
    if config.metrics.run_prometheus_endpoint {
        let idle_timeout = config
            .cleaning
            .connection_cleaning_interval
            .max(config.cleaning.torrent_cleaning_interval)
            .max(config.metrics.torrent_count_update_interval)
            * 2;

        let handle = aquatic_common::spawn_prometheus_endpoint(
            config.metrics.prometheus_endpoint_address,
            Some(Duration::from_secs(idle_timeout)),
            Some(metrics_util::MetricKindMask::GAUGE),
        )?;

        join_handles.push((WorkerType::Prometheus, handle));
    }

    // Spawn auto-ban flush thread
    if config.auto_ban.enabled {
        let flush_interval_secs = config.auto_ban.flush_interval_secs.max(1);
        let flush_interval = Duration::from_secs(flush_interval_secs);
        let auto_ban_tracker = state.auto_ban_tracker.clone();
        let ip_ban_config = config.ip_ban.clone();
        let ip_ban_list = state.ip_ban_list.clone();

        let handle: JoinHandle<anyhow::Result<()>> = Builder::new()
            .name("auto-ban-flush".into())
            .spawn(move || {
                loop {
                    sleep(flush_interval);

                    if let Some(tracker) = &auto_ban_tracker {
                        // Only flush to file if ip_ban mode is On, otherwise
                        // the file will grow indefinitely with duplicate entries
                        // since remove_ips() won't be called
                        if ip_ban_config.mode.is_on() {
                            let flushed = tracker.flush_to_file();

                            if !flushed.is_empty() {
                                // Reload ip_ban_list FIRST so it picks up the newly written IPs
                                if let Err(err) = update_ip_ban_list(&ip_ban_config, &ip_ban_list) {
                                    ::log::error!("auto-ban flush: failed to reload ip_ban_list: {:#}", err);
                                    // Don't remove from memory if reload failed - keep dual protection
                                } else {
                                    ::log::info!(
                                        "auto-ban flush: reloaded ip_ban_list after writing {} IPs",
                                        flushed.len(),
                                    );
                                    tracker.remove_ips(&flushed);
                                }
                            }
                        }

                        // Always cleanup expired entries, even if nothing was flushed
                        tracker.cleanup();

                        ::log::debug!(
                            "auto-ban: {} IPs tracked, {} currently banned",
                            tracker.tracked_count(),
                            tracker.banned_count(),
                        );
                    }
                }

                #[allow(unreachable_code)]
                Ok(())
            })
            .context("spawn auto-ban flush worker")?;

        join_handles.push((WorkerType::AutoBanFlush, handle));
    }

    // Spawn signal handler thread
    {
        let handle: JoinHandle<anyhow::Result<()>> = Builder::new()
            .name("signals".into())
            .spawn(move || {
                for signal in &mut signals {
                    match signal {
                        SIGUSR1 => {
                            let _ = update_access_list(&config.access_list, &state.access_list);

                            if let Some(tls_config) = opt_tls_config.as_ref() {
                                match create_rustls_config(
                                    &config.network.tls_certificate_path,
                                    &config.network.tls_private_key_path,
                                ) {
                                    Ok(config) => {
                                        tls_config.store(Arc::new(config));

                                        ::log::info!("successfully updated tls config");
                                    }
                                    Err(err) => {
                                        ::log::error!("could not update tls config: {:#}", err)
                                    }
                                }
                            }
                        }
                        SIGUSR2 => {
                            let _ = update_ip_ban_list(&config.ip_ban, &state.ip_ban_list);
                            let _ = update_client_ban_list(&config.client_ban, &state.client_ban_list);
                            let _ = update_client_whitelist(&config.client_whitelist, &state.client_whitelist);
                            let _ = update_trusted_proxies(&config.trusted_proxies, &state.trusted_proxies);
                        }
                        _ => unreachable!(),
                    }
                }

                Ok(())
            })
            .context("spawn signal worker")?;

        join_handles.push((WorkerType::Signals, handle));
    }

    loop {
        for (i, (_, handle)) in join_handles.iter().enumerate() {
            if handle.is_finished() {
                let (worker_type, handle) = join_handles.remove(i);

                match handle.join() {
                    Ok(Ok(())) => {
                        return Err(anyhow::anyhow!("{} stopped", worker_type));
                    }
                    Ok(Err(err)) => {
                        return Err(err.context(format!("{} stopped", worker_type)));
                    }
                    Err(_) => {
                        return Err(anyhow::anyhow!("{} panicked", worker_type));
                    }
                }
            }
        }

        sleep(Duration::from_secs(5));
    }
}
