pub mod common;
pub mod config;
pub mod swarm;
pub mod workers;

use std::thread::{available_parallelism, sleep, Builder, JoinHandle};
use std::time::Duration;
use std::sync::Arc;

use anyhow::Context;
use aquatic_common::WorkerType;
use crossbeam_channel::unbounded;
#[cfg(unix)]
use signal_hook::consts::SIGUSR1;
#[cfg(unix)]
use signal_hook::consts::SIGUSR2;
#[cfg(unix)]
use signal_hook::iterator::Signals;

use aquatic_common::access_list::update_access_list;
use aquatic_common::ip_ban::update_ip_ban_list;
use aquatic_common::client_ban::update_client_ban_list;
use aquatic_common::client_whitelist::update_client_whitelist;
use aquatic_common::auto_ban::AutoBanTracker;
use aquatic_common::privileges::PrivilegeDropper;

use common::{State, Statistics};
use config::Config;
use workers::socket::ConnectionValidator;

pub const APP_NAME: &str = "aquatic_udp: UDP BitTorrent tracker";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn run(mut config: Config) -> ::anyhow::Result<()> {
    #[cfg(unix)]
    let mut signals = Signals::new([SIGUSR1, SIGUSR2])?;

    if !(config.network.use_ipv4 || config.network.use_ipv6) {
        return Result::Err(anyhow::anyhow!(
            "Both use_ipv4 and use_ipv6 can not be set to false"
        ));
    }

    if config.socket_workers == 0 {
        config.socket_workers = available_parallelism().map(Into::into).unwrap_or(1);
    };

    let num_sockets_per_worker =
        if config.network.use_ipv4 { 1 } else { 0 } + if config.network.use_ipv6 { 1 } else { 0 };

    let mut state = State::default();
    let statistics = Statistics::new(&config);
    let connection_validator = ConnectionValidator::new(&config)?;
    let priv_dropper = PrivilegeDropper::new(
        config.privileges.clone(),
        config.socket_workers * num_sockets_per_worker,
    );
    let (statistics_sender, statistics_receiver) = unbounded();

    update_access_list(&config.access_list, &state.access_list)?;
    update_ip_ban_list(&config.ip_ban, &state.ip_ban_list)?;
    update_client_ban_list(&config.client_ban, &state.client_ban_list)?;
    update_client_whitelist(&config.client_whitelist, &state.client_whitelist)?;

    // Initialize auto-ban tracker
    let auto_ban_tracker = if config.auto_ban.enabled {
        let ban_list_path = if config.auto_ban.ban_list_path.as_os_str().is_empty() {
            None
        } else {
            Some(config.auto_ban.ban_list_path.clone())
        };
        let tracker = AutoBanTracker::new(
            config.auto_ban.threshold,
            config.auto_ban.window_secs,
            config.auto_ban.ban_duration_secs,
            ban_list_path,
        );
        Some(Arc::new(tracker))
    } else {
        None
    };
    state.auto_ban_tracker = auto_ban_tracker.clone();

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
                }

                #[allow(unreachable_code)]
                Ok(())
            })
            .with_context(|| "spawn auto-ban flush thread")?;

        join_handles.push((WorkerType::AutoBanFlush, handle));
    }

    // Spawn socket worker threads
    for i in 0..config.socket_workers {
        let state = state.clone();
        let config = config.clone();
        let connection_validator = connection_validator.clone();
        let statistics = statistics.socket[i].clone();
        let statistics_sender = statistics_sender.clone();

        let mut priv_droppers = Vec::new();

        for _ in 0..num_sockets_per_worker {
            priv_droppers.push(priv_dropper.clone());
        }

        let handle = Builder::new()
            .name(format!("socket-{:02}", i + 1))
            .spawn(move || {
                workers::socket::run_socket_worker(
                    config,
                    state,
                    statistics,
                    statistics_sender,
                    connection_validator,
                    priv_droppers,
                )
            })
            .with_context(|| "spawn socket worker")?;

        join_handles.push((WorkerType::Socket(i), handle));
    }

    // Spawn cleaning thread
    {
        let state = state.clone();
        let config = config.clone();
        let statistics = statistics.swarm.clone();
        let statistics_sender = statistics_sender.clone();

        let handle = Builder::new().name("cleaning".into()).spawn(move || loop {
            sleep(Duration::from_secs(
                config.cleaning.torrent_cleaning_interval,
            ));

            state.torrent_maps.clean_and_update_statistics(
                &config,
                &statistics,
                &statistics_sender,
                &state.access_list,
                state.server_start_instant,
            );
        })?;

        join_handles.push((WorkerType::Cleaning, handle));
    }

    // Spawn statistics thread
    if config.statistics.active() {
        let state = state.clone();
        let config = config.clone();

        let handle = Builder::new()
            .name("statistics".into())
            .spawn(move || {
                workers::statistics::run_statistics_worker(
                    config,
                    state,
                    statistics,
                    statistics_receiver,
                )
            })
            .with_context(|| "spawn statistics worker")?;

        join_handles.push((WorkerType::Statistics, handle));
    }

    // Spawn prometheus endpoint thread
    #[cfg(feature = "prometheus")]
    if config.statistics.active() && config.statistics.run_prometheus_endpoint {
        let handle = aquatic_common::spawn_prometheus_endpoint(
            config.statistics.prometheus_endpoint_address,
            Some(Duration::from_secs(
                config.cleaning.torrent_cleaning_interval * 2,
            )),
            None,
        )?;

        join_handles.push((WorkerType::Prometheus, handle));
    }

    // Spawn signal handler thread
    #[cfg(unix)]
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
                        }
                        SIGUSR2 => {
                            let _ = update_ip_ban_list(&config.ip_ban, &state.ip_ban_list);
                            let _ = update_client_ban_list(&config.client_ban, &state.client_ban_list);
                            let _ = update_client_whitelist(&config.client_whitelist, &state.client_whitelist);
                        }
                        _ => unreachable!(),
                    }
                }

                Ok(())
            })
            .context("spawn signal worker")?;

        join_handles.push((WorkerType::Signals, handle));
    }

    // Quit application if any worker returns or panics
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
