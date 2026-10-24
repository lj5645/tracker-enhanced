use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Instant;

use ahash::RandomState;

pub mod access_list;
pub mod auto_ban;
pub mod cli;
pub mod cpu_pinning;
pub mod ip_ban;
pub mod client_ban;
pub mod client_whitelist;
pub mod request_filter;
pub mod privileges;
pub mod trusted_proxies;
#[cfg(feature = "rustls")]
pub mod rustls_config;

/// IndexMap using AHash hasher
pub type IndexMap<K, V> = indexmap::IndexMap<K, V, RandomState>;

/// Peer, connection or similar valid until this instant
#[derive(Debug, Clone, Copy)]
pub struct ValidUntil(SecondsSinceServerStart);

impl ValidUntil {
    #[inline]
    pub fn new(start_instant: ServerStartInstant, offset_seconds: u32) -> Self {
        Self(SecondsSinceServerStart(
            start_instant.seconds_elapsed().0 + offset_seconds,
        ))
    }
    pub fn new_with_now(now: SecondsSinceServerStart, offset_seconds: u32) -> Self {
        Self(SecondsSinceServerStart(now.0 + offset_seconds))
    }
    pub fn valid(&self, now: SecondsSinceServerStart) -> bool {
        self.0 .0 > now.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ServerStartInstant(Instant);

impl ServerStartInstant {
    #[allow(clippy::new_without_default)] // I prefer ::new here
    pub fn new() -> Self {
        Self(Instant::now())
    }
    pub fn seconds_elapsed(&self) -> SecondsSinceServerStart {
        SecondsSinceServerStart(
            self.0
                .elapsed()
                .as_secs()
                .try_into()
                .expect("server ran for more seconds than what fits in a u32"),
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SecondsSinceServerStart(u32);

/// Convert an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to plain IPv4.
///
/// Dual-stack sockets (for example a WebSocket listener bound to `[::]` with
/// `only_ipv6 = false`) report IPv4 peers in mapped form. Security checks such
/// as IP ban lists, trusted-proxy matching and private IP filters are written
/// with plain IPv4 addresses, so peer addresses must be canonicalized before
/// they are compared — otherwise every check silently misses IPv4 clients.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(addr) => match addr.octets() {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => {
                IpAddr::V4(Ipv4Addr::new(a, b, c, d))
            }
            _ => ip,
        },
    }
}

/// SocketAddr that is not an IPv6-mapped IPv4 address
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct CanonicalSocketAddr(SocketAddr);

impl CanonicalSocketAddr {
    pub fn new(addr: SocketAddr) -> Self {
        match addr {
            addr @ SocketAddr::V4(_) => Self(addr),
            SocketAddr::V6(addr) => match canonical_ip(IpAddr::V6(*addr.ip())) {
                IpAddr::V4(ip) => Self(SocketAddr::V4(SocketAddrV4::new(ip, addr.port()))),
                IpAddr::V6(_) => Self(addr.into()),
            },
        }
    }

    pub fn get_ipv6_mapped(self) -> SocketAddr {
        match self.0 {
            SocketAddr::V4(addr) => {
                let ip = addr.ip().to_ipv6_mapped();

                SocketAddr::V6(SocketAddrV6::new(ip, addr.port(), 0, 0))
            }
            addr => addr,
        }
    }

    pub fn get(self) -> SocketAddr {
        self.0
    }

    pub fn get_ipv4(self) -> Option<SocketAddr> {
        match self.0 {
            addr @ SocketAddr::V4(_) => Some(addr),
            _ => None,
        }
    }

    pub fn is_ipv4(&self) -> bool {
        self.0.is_ipv4()
    }
}

#[cfg(feature = "prometheus")]
pub fn spawn_prometheus_endpoint(
    addr: SocketAddr,
    timeout: Option<::std::time::Duration>,
    timeout_mask: Option<metrics_util::MetricKindMask>,
) -> anyhow::Result<::std::thread::JoinHandle<anyhow::Result<()>>> {
    use std::thread::Builder;
    use std::time::Duration;

    use anyhow::Context;

    let handle = Builder::new()
        .name("prometheus".into())
        .spawn(move || {
            use metrics_exporter_prometheus::PrometheusBuilder;
            use metrics_util::MetricKindMask;

            let rt = ::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build prometheus tokio runtime")?;

            rt.block_on(async {
                let mask = timeout_mask.unwrap_or(MetricKindMask::ALL);

                let (recorder, exporter) = PrometheusBuilder::new()
                    .idle_timeout(mask, timeout)
                    .with_http_listener(addr)
                    .build()
                    .context("build prometheus recorder and exporter")?;

                let recorder_handle = recorder.handle();

                ::metrics::set_global_recorder(recorder).context("set global metrics recorder")?;

                ::tokio::spawn(async move {
                    let mut interval = ::tokio::time::interval(Duration::from_secs(5));

                    loop {
                        interval.tick().await;

                        // Periodically render metrics to make sure
                        // idles are cleaned up
                        recorder_handle.render();
                    }
                });

                exporter
                    .await
                    .map_err(|err| anyhow::anyhow!("run prometheus exporter: :{:#?}", err))
            })
        })
        .context("spawn prometheus endpoint")?;

    Ok(handle)
}

pub enum WorkerType {
    Swarm(usize),
    Socket(usize),
    Statistics,
    Signals,
    Cleaning,
    AutoBanFlush,
    #[cfg(feature = "prometheus")]
    Prometheus,
}

impl Display for WorkerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Swarm(index) => f.write_fmt(format_args!("Swarm worker {}", index + 1)),
            Self::Socket(index) => f.write_fmt(format_args!("Socket worker {}", index + 1)),
            Self::Statistics => f.write_str("Statistics worker"),
            Self::Signals => f.write_str("Signals worker"),
            Self::Cleaning => f.write_str("Cleaning worker"),
            Self::AutoBanFlush => f.write_str("Auto-ban flush worker"),
            #[cfg(feature = "prometheus")]
            Self::Prometheus => f.write_str("Prometheus worker"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn test_canonical_ip() {
        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(canonical_ip(v4), v4);

        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        assert_eq!(canonical_ip(mapped), v4);

        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonical_ip(v6), v6);

        // IPv6 loopback is not an IPv4-mapped address.
        let loopback = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(canonical_ip(loopback), loopback);
    }

    #[test]
    fn test_canonical_socket_addr_mapped() {
        let mapped: SocketAddr = "[::ffff:203.0.113.7]:8080".parse().unwrap();
        let canonical = CanonicalSocketAddr::new(mapped).get();

        assert_eq!(canonical, "203.0.113.7:8080".parse::<SocketAddr>().unwrap());

        let v6: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        assert_eq!(CanonicalSocketAddr::new(v6).get(), v6);
    }
}
