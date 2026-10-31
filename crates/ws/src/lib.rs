pub mod common;
pub mod config;
pub mod workers;

use std::sync::Arc;
use std::thread::{sleep, Builder, JoinHandle};
use std::time::Duration;

use anyhow::Context;
use aquatic_common::rustls_config::create_rustls_config;
use aquatic_common::{
    validate_interval, validate_worker_counts, ServerStartInstant, WorkerType,
};
use arc_swap::ArcSwap;
use glommio::{channels::channel_mesh::MeshBuilder, prelude::*};
use signal_hook::{consts::SIGUSR1, consts::SIGUSR2, iterator::Signals};

use aquatic_common::access_list::update_access_list;
use aquatic_common::ip_ban::update_ip_ban_list;
use aquatic_common::client_ban::{
    update_client_ban_list, warn_about_identity_enforce_with_auto_ban,
};
use aquatic_common::trusted_proxies::update_trusted_proxies;
use aquatic_common::auto_ban::{validate_auto_ban_config, AutoBanTracker};
use aquatic_common::privileges::PrivilegeDropper;

use common::*;
use config::Config;

pub const APP_NAME: &str = "aquatic_ws: WebTorrent tracker";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const SHARED_IN_CHANNEL_SIZE: usize = 1024;

pub fn run(mut config: Config) -> ::anyhow::Result<()> {
    if config.network.enable_tls && config.network.enable_http_health_checks {
        return Err(anyhow::anyhow!(
            "configuration: network.enable_tls and network.enable_http_health_check can't both be set to true"
        ));
    }

    let mut signals = Signals::new([SIGUSR1, SIGUSR2])?;

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

    validate_auto_ban_config(&config.auto_ban, &config.ip_ban)?;

    let mut state = State::default();

    update_access_list(&config.access_list, &state.access_list)?;
    update_ip_ban_list(&config.ip_ban, &state.ip_ban_list)?;
    update_client_ban_list(&config.client_ban, &state.client_ban_list)?;
    warn_about_identity_enforce_with_auto_ban(&config.client_ban, &config.auto_ban);
    update_trusted_proxies(&config.trusted_proxies, &state.trusted_proxies)?;

    // Initialize auto-ban tracker
    let auto_ban_tracker = if config.auto_ban.enabled {
        let tracker = AutoBanTracker::from_config(&config.auto_ban);

        let restored = tracker.load_client_bans();

        if restored > 0 {
            ::log::info!(
                "auto-ban: restored {} client bans from {}",
                restored,
                config.auto_ban.client_ban_list_path.display(),
            );
        }

        Some(Arc::new(tracker))
    } else {
        None
    };
    state.auto_ban_tracker = auto_ban_tracker.clone();

    let num_mesh_peers = config.socket_workers + config.swarm_workers;

    let request_mesh_builder = MeshBuilder::partial(num_mesh_peers, SHARED_IN_CHANNEL_SIZE);
    let response_mesh_builder = MeshBuilder::partial(num_mesh_peers, SHARED_IN_CHANNEL_SIZE * 16);
    let control_mesh_builder = MeshBuilder::partial(num_mesh_peers, SHARED_IN_CHANNEL_SIZE * 16);

    let priv_dropper = PrivilegeDropper::new(config.privileges.clone(), config.socket_workers);

    let opt_tls_config = if config.network.enable_tls {
        Some(Arc::new(ArcSwap::from_pointee(
            create_rustls_config(
                &config.network.tls_certificate_path,
                &config.network.tls_private_key_path,
            )
            .with_context(|| "create rustls config")?,
        )))
    } else {
        None
    };
    let (mut opt_tls_cert_data, mut opt_tls_key_data) = if config.network.enable_tls {
        (
            Some(
                ::std::fs::read(&config.network.tls_certificate_path)
                    .with_context(|| "open tls certificate file")?,
            ),
            Some(
                ::std::fs::read(&config.network.tls_private_key_path)
                    .with_context(|| "open tls private key file")?,
            ),
        )
    } else {
        (None, None)
    };

    let server_start_instant = ServerStartInstant::new();

    let mut join_handles = Vec::new();

    // Spawn auto-ban flush thread
    if let Some(tracker) = &auto_ban_tracker {
        let tracker = tracker.clone();
        let ip_ban_config = config.ip_ban.clone();
        let ip_ban_list = state.ip_ban_list.clone();

        let flush_interval_secs = config.auto_ban.flush_interval_secs.max(1);
        let flush_interval = Duration::from_secs(flush_interval_secs);

        let handle: JoinHandle<anyhow::Result<()>> = Builder::new()
            .name("auto-ban-flush".into())
            .spawn(move || {
                loop {
                    sleep(flush_interval);

                    // Expired client bans are pruned at most once a day; the
                    // file is independent of the ip_ban list.
                    let pruned = tracker.maybe_cleanup_client_bans();

                    if pruned > 0 {
                        ::log::info!("auto-ban: pruned {} expired client bans", pruned);
                    }

                    // Only flush to file if ip_ban mode is On
                    if ip_ban_config.mode.is_on() {
                        let flushed = tracker.flush_to_file();

                        if !flushed.is_empty() {
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

                    // Always cleanup expired entries
                    tracker.cleanup();

                    ::log::debug!(
                        "auto-ban: {} IPs tracked, {} currently banned",
                        tracker.tracked_count(),
                        tracker.banned_count(),
                    );
                }

                #[allow(unreachable_code)]
                Ok(())
            })
            .with_context(|| "spawn auto-ban flush thread")?;

        join_handles.push((WorkerType::AutoBanFlush, handle));
    }

    for i in 0..(config.socket_workers) {
        let config = config.clone();
        let state = state.clone();
        let opt_tls_config = opt_tls_config.clone();
        let control_mesh_builder = control_mesh_builder.clone();
        let request_mesh_builder = request_mesh_builder.clone();
        let response_mesh_builder = response_mesh_builder.clone();
        let priv_dropper = priv_dropper.clone();

        let handle = Builder::new()
            .name(format!("socket-{:02}", i + 1))
            .spawn(move || {
                LocalExecutorBuilder::default()
                    .make()
                    .map_err(|err| anyhow::anyhow!("Spawning executor failed: {:#}", err))?
                    .run(workers::socket::run_socket_worker(
                        config,
                        state,
                        opt_tls_config,
                        control_mesh_builder,
                        request_mesh_builder,
                        response_mesh_builder,
                        priv_dropper,
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
        let control_mesh_builder = control_mesh_builder.clone();
        let request_mesh_builder = request_mesh_builder.clone();
        let response_mesh_builder = response_mesh_builder.clone();

        let handle = Builder::new()
            .name(format!("swarm-{:02}", i + 1))
            .spawn(move || {
                LocalExecutorBuilder::default()
                    .make()
                    .map_err(|err| anyhow::anyhow!("Spawning executor failed: {:#}", err))?
                    .run(workers::swarm::run_swarm_worker(
                        config,
                        state,
                        control_mesh_builder,
                        request_mesh_builder,
                        response_mesh_builder,
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

    // Spawn signal handler thread
    {
        let config = config.clone();
        let state = state.clone();

        let handle: JoinHandle<anyhow::Result<()>> = Builder::new()
            .name("signals".into())
            .spawn(move || {
                for signal in &mut signals {
                    match signal {
                        SIGUSR1 => {
                            let _ = update_access_list(&config.access_list, &state.access_list);

                            if let Some(tls_config) = opt_tls_config.as_ref() {
                                match (
                                    ::std::fs::read(&config.network.tls_certificate_path),
                                    ::std::fs::read(&config.network.tls_private_key_path),
                                ) {
                                    (Ok(cert_data), Ok(key_data)) => {
                                        // Compare both files: a renewed certificate
                                        // often reuses the private key, and a rotated
                                        // key with an unchanged certificate must also
                                        // be picked up.
                                        let unchanged =
                                            opt_tls_cert_data.as_ref() == Some(&cert_data)
                                                && opt_tls_key_data.as_ref() == Some(&key_data);

                                        if unchanged {
                                            ::log::info!("skipping tls config update: files identical to currently loaded");
                                        } else {
                                            match create_rustls_config(
                                                &config.network.tls_certificate_path,
                                                &config.network.tls_private_key_path,
                                            ) {
                                                Ok(config) => {
                                                    tls_config.store(Arc::new(config));
                                                    opt_tls_cert_data = Some(cert_data);
                                                    opt_tls_key_data = Some(key_data);

                                                    ::log::info!("successfully updated tls config");
                                                }
                                                Err(err) => ::log::error!("could not update tls config: {:#}", err),
                                            }
                                        }
                                    }
                                    (Err(err), _) => ::log::error!("couldn't read tls certificate file: {:#}", err),
                                    (_, Err(err)) => ::log::error!("couldn't read tls private key file: {:#}", err),
                                }
                            }
                        }
                        SIGUSR2 => {
                            let _ = update_ip_ban_list(&config.ip_ban, &state.ip_ban_list);
                            let _ = update_client_ban_list(&config.client_ban, &state.client_ban_list);
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
