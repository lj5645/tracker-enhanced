mod connection;
mod request;

use std::cell::RefCell;
use std::net::SocketAddr;
use std::os::unix::prelude::{FromRawFd, IntoRawFd};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use aquatic_common::privileges::PrivilegeDropper;
use aquatic_common::rustls_config::RustlsConfig;
use aquatic_common::{CanonicalSocketAddr, ServerStartInstant};
use arc_swap::ArcSwap;
use futures_lite::future::race;
use futures_lite::StreamExt;
use glommio::channels::channel_mesh::{MeshBuilder, Partial, Role, Senders};
use glommio::channels::local_channel::{new_bounded, LocalReceiver, LocalSender};
use glommio::net::{TcpListener, TcpStream};
use glommio::timer::{sleep, TimerActionRepeat};
use glommio::{enclose, prelude::*};
use slotmap::HopSlotMap;

use crate::common::*;
use crate::config::Config;
use crate::workers::socket::connection::{run_connection, ConnectionError};

struct ConnectionHandle {
    close_conn_sender: LocalSender<()>,
    valid_until: Rc<RefCell<ValidUntil>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_socket_worker(
    config: Config,
    state: State,
    opt_tls_config: Option<Arc<ArcSwap<RustlsConfig>>>,
    request_mesh_builder: MeshBuilder<ChannelRequest, Partial>,
    mut priv_droppers: Vec<PrivilegeDropper>,
    server_start_instant: ServerStartInstant,
    worker_index: usize,
) -> anyhow::Result<()> {
    let config = Rc::new(config);

    let tcp_listeners = {
        let opt_listener_ipv4 = if config.network.use_ipv4 {
            let priv_dropper = priv_droppers
                .pop()
                .ok_or(anyhow::anyhow!("no enough priv droppers"))?;
            let socket =
                create_tcp_listener(&config, priv_dropper, config.network.address_ipv4.into())
                    .context("create tcp listener")?;

            Some(socket)
        } else {
            None
        };
        let opt_listener_ipv6 = if config.network.use_ipv6 {
            let priv_dropper = priv_droppers
                .pop()
                .ok_or(anyhow::anyhow!("no enough priv droppers"))?;
            let socket =
                create_tcp_listener(&config, priv_dropper, config.network.address_ipv6.into())
                    .context("create tcp listener")?;

            Some(socket)
        } else {
            None
        };

        [opt_listener_ipv4, opt_listener_ipv6]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
    };

    let (request_senders, _) = request_mesh_builder
        .join(Role::Producer)
        .await
        .map_err(|err| anyhow::anyhow!("join request mesh: {:#}", err))?;
    let request_senders = Rc::new(request_senders);

    let connection_handles = Rc::new(RefCell::new(HopSlotMap::with_key()));

    TimerActionRepeat::repeat(enclose!((config, connection_handles) move || {
        clean_connections(
            config.clone(),
            connection_handles.clone(),
            server_start_instant,
        )
    }));

    let tasks = tcp_listeners
        .into_iter()
        .map(|tcp_listener| {
            let listener_state = ListenerState {
                config: config.clone(),
                state: state.clone(),
                opt_tls_config: opt_tls_config.clone(),
                server_start_instant,
                connection_handles: connection_handles.clone(),
                request_senders: request_senders.clone(),
                worker_index,
            };

            spawn_local(listener_state.accept_connections(tcp_listener))
        })
        .collect::<Vec<_>>();

    for task in tasks {
        task.await;
    }

    Ok(())
}

#[derive(Clone)]
struct ListenerState {
    config: Rc<Config>,
    state: State,
    opt_tls_config: Option<Arc<ArcSwap<RustlsConfig>>>,
    server_start_instant: ServerStartInstant,
    connection_handles: Rc<RefCell<HopSlotMap<ConnectionId, ConnectionHandle>>>,
    request_senders: Rc<Senders<ChannelRequest>>,
    worker_index: usize,
}

impl ListenerState {
    async fn accept_connections(self, listener: TcpListener) {
        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            match stream {
                Ok(stream) => {
                    // Check connection limit
                    let current_connections = self.connection_handles.borrow().len();
                    if self.config.network.max_connections_per_worker > 0
                        && current_connections >= self.config.network.max_connections_per_worker
                    {
                        // Debug level: under a connection storm this would
                        // otherwise flood the log once per rejected connection.
                        ::log::debug!(
                            "Connection limit reached ({}/{}), rejecting new connection",
                            current_connections,
                            self.config.network.max_connections_per_worker
                        );
                        // Connection will be dropped when stream goes out of scope
                        continue;
                    }

                    // Set TCP keepalive on the accepted stream
                    if self.config.network.tcp_keepalive {
                        if let Err(err) = set_tcp_keepalive(&stream, &self.config) {
                            ::log::debug!("Failed to set TCP keepalive: {}", err);
                        }
                    }

                    let (close_conn_sender, close_conn_receiver) = new_bounded(1);

                    let valid_until = Rc::new(RefCell::new(ValidUntil::new(
                        self.server_start_instant,
                        self.config.cleaning.max_connection_idle,
                    )));

                    let connection_id =
                        self.connection_handles
                            .borrow_mut()
                            .insert(ConnectionHandle {
                                close_conn_sender,
                                valid_until: valid_until.clone(),
                            });

                    spawn_local(self.clone().handle_connection(
                        close_conn_receiver,
                        valid_until,
                        connection_id,
                        stream,
                    ))
                    .detach();
                }
                Err(err) => {
                    ::log::error!("accept connection: {:?}", err);

                    // Back off briefly: persistent accept errors (for example
                    // EMFILE under a file-descriptor exhaustion attack) would
                    // otherwise spin this loop at full speed.
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle_connection(
        self,
        close_conn_receiver: LocalReceiver<()>,
        valid_until: Rc<RefCell<ValidUntil>>,
        connection_id: ConnectionId,
        stream: TcpStream,
    ) {
        #[cfg(feature = "metrics")]
        let active_connections_gauge = ::metrics::gauge!(
            "aquatic_active_connections",
            "worker_index" => self.worker_index.to_string(),
        );

        #[cfg(feature = "metrics")]
        active_connections_gauge.increment(1.0);

        let auto_ban_tracker = self.state.auto_ban_tracker.clone();

        let f1 = async {
            run_connection(
                self.config,
                self.state,
                self.request_senders,
                self.server_start_instant,
                self.opt_tls_config,
                valid_until.clone(),
                stream,
                self.worker_index,
                auto_ban_tracker,
            )
            .await
        };
        let f2 = async {
            close_conn_receiver.recv().await;

            Err(ConnectionError::Inactive)
        };

        let result = race(f1, f2).await;

        #[cfg(feature = "metrics")]
        active_connections_gauge.decrement(1.0);

        match result {
            Ok(()) => (),
            Err(
                err @ (ConnectionError::ResponseBufferWrite(_)
                | ConnectionError::ResponseBufferFull
                | ConnectionError::ScrapeChannelError(_)
                | ConnectionError::ResponseSenderClosed),
            ) => {
                ::log::error!("connection closed: {:#}", err);
            }
            Err(err @ ConnectionError::RequestBufferFull) => {
                ::log::info!("connection closed: {:#}", err);
            }
            Err(err) => {
                ::log::debug!("connection closed: {:#}", err);
            }
        }

        self.connection_handles.borrow_mut().remove(connection_id);
    }
}

async fn clean_connections(
    config: Rc<Config>,
    connection_slab: Rc<RefCell<HopSlotMap<ConnectionId, ConnectionHandle>>>,
    server_start_instant: ServerStartInstant,
) -> Option<Duration> {
    let now = server_start_instant.seconds_elapsed();

    connection_slab.borrow_mut().retain(|_, handle| {
        if handle.valid_until.borrow().valid(now) {
            true
        } else {
            let _ = handle.close_conn_sender.try_send(());

            false
        }
    });

    Some(Duration::from_secs(
        config.cleaning.connection_cleaning_interval,
    ))
}

fn create_tcp_listener(
    config: &Config,
    priv_dropper: PrivilegeDropper,
    address: SocketAddr,
) -> anyhow::Result<TcpListener> {
    let socket = if address.is_ipv4() {
        socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?
    } else {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;

        if config.network.set_only_ipv6 {
            socket
                .set_only_v6(true)
                .with_context(|| "socket: set only ipv6")?;
        }

        socket
    };

    socket
        .set_reuse_port(true)
        .with_context(|| "socket: set reuse port")?;

    // Allow restarting quickly after a crash without waiting for sockets in
    // TIME_WAIT to disappear.
    socket
        .set_reuse_address(true)
        .with_context(|| "socket: set reuse address")?;

    // Buffer sizes are a performance tuning knob, not a correctness
    // requirement: report a failure and keep going rather than refusing to
    // start (the OS default still works).
    if config.network.socket_recv_buffer_size > 0 {
        let size = config.network.socket_recv_buffer_size;

        if let Err(err) = socket.set_recv_buffer_size(size.min(i32::MAX as usize)) {
            ::log::warn!("socket: set recv buffer size to {}: {}", size, err);
        }
    }

    if config.network.socket_send_buffer_size > 0 {
        let size = config.network.socket_send_buffer_size;

        if let Err(err) = socket.set_send_buffer_size(size.min(i32::MAX as usize)) {
            ::log::warn!("socket: set send buffer size to {}: {}", size, err);
        }
    }

    socket
        .bind(&address.into())
        .with_context(|| format!("socket: bind to {}", address))?;

    socket
        .listen(config.network.tcp_backlog)
        .with_context(|| format!("socket: listen on {}", address))?;

    priv_dropper.after_socket_creation()?;

    Ok(unsafe { TcpListener::from_raw_fd(socket.into_raw_fd()) })
}

#[cfg(feature = "metrics")]
fn peer_addr_to_ip_version_str(addr: &CanonicalSocketAddr) -> &'static str {
    if addr.is_ipv4() {
        "4"
    } else {
        "6"
    }
}

fn set_tcp_keepalive(stream: &TcpStream, config: &Config) -> anyhow::Result<()> {
    use std::os::unix::prelude::AsRawFd;

    let fd = stream.as_raw_fd();

    set_keepalive_option(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)
        .context("set SO_KEEPALIVE")?;

    // The tuning knobs are best-effort: some kernels do not support all of
    // them, and keepalive still works with the system defaults. Values are
    // clamped to c_int because the configuration accepts any u64/u32.
    for (name, value, label) in [
        (
            libc::TCP_KEEPIDLE,
            clamp_c_int(config.network.tcp_keepalive_idle_secs),
            "TCP_KEEPIDLE",
        ),
        (
            libc::TCP_KEEPINTVL,
            clamp_c_int(config.network.tcp_keepalive_interval_secs),
            "TCP_KEEPINTVL",
        ),
        (
            libc::TCP_KEEPCNT,
            clamp_c_int(config.network.tcp_keepalive_probes as u64),
            "TCP_KEEPCNT",
        ),
    ] {
        if let Err(err) = set_keepalive_option(fd, libc::IPPROTO_TCP, name, value) {
            ::log::debug!("set {} failed: {}", label, err);
        }
    }

    Ok(())
}

fn clamp_c_int(value: u64) -> libc::c_int {
    value.min(libc::c_int::MAX as u64) as libc::c_int
}

fn set_keepalive_option(
    fd: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> ::std::io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const _,
            ::std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result != 0 {
        Err(::std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
