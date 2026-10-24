use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use aquatic_toml_config::TomlConfig;
use arc_swap::ArcSwap;
use serde::Deserialize;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

#[derive(Clone, Debug, PartialEq, TomlConfig, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustedProxiesConfig {
    /// Enable trusted proxies validation
    ///
    /// When enabled, X-Forwarded-For header will only be trusted
    /// when the request comes from a trusted proxy IP.
    /// This prevents IP spoofing attacks where attackers inject
    /// fake X-Forwarded-For headers.
    pub enabled: bool,
    /// Path to trusted proxies list file
    ///
    /// File format: one IP or CIDR per line
    /// Examples:
    /// - 192.168.1.1
    /// - 10.0.0.0/8
    /// - ::1
    /// - 2001:db8::/32
    pub path: PathBuf,
}

impl Default for TrustedProxiesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "".into(),
        }
    }
}

pub struct TrustedProxies {
    table: IpNetworkTable<()>,
}

impl std::fmt::Debug for TrustedProxies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedProxies")
            .field("entry_count", &self.table.len())
            .finish()
    }
}

impl Clone for TrustedProxies {
    fn clone(&self) -> Self {
        let mut new_table = IpNetworkTable::new();
        for (network, value) in self.table.iter() {
            new_table.insert(network, value.clone());
        }
        Self { table: new_table }
    }
}

impl Default for TrustedProxies {
    fn default() -> Self {
        Self {
            table: IpNetworkTable::new(),
        }
    }
}

impl TrustedProxies {
    pub fn from_iter<I: IntoIterator<Item = IpNetwork>>(iter: I) -> Self {
        let mut table = IpNetworkTable::new();
        for network in iter {
            table.insert(network, ());
        }
        Self { table }
    }

    pub fn is_trusted(&self, addr: IpAddr) -> bool {
        if self.table.is_empty() {
            return false;
        }
        self.table.longest_match(addr).is_some()
    }

    pub fn len(&self) -> usize {
        self.table.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

/// Return the rightmost valid IP in an `X-Forwarded-For` header.
///
/// The rightmost entry was appended by the trusted reverse proxy that accepted
/// the connection; entries to its left are client-supplied. Using the leftmost
/// value lets a client spoof its address with
/// `X-Forwarded-For: <fake>, $proxy_add_x_forwarded_for`.
pub fn last_forwarded_for_ip(header: &str) -> Option<IpAddr> {
    header
        .split(',')
        .rev()
        .filter_map(|value| value.trim().parse::<IpAddr>().ok())
        .next()
}

pub type TrustedProxiesArcSwap = ArcSwap<TrustedProxies>;

/// Parse a trusted proxy entry as either a CIDR network or a bare IP address.
///
/// A bare address is treated as a single-host network (`/32` or `/128`), since
/// the configuration documents plain IPs as valid entries.
fn parse_trusted_proxy_entry(line: &str) -> Option<IpNetwork> {
    if let Ok(network) = line.parse::<IpNetwork>() {
        return Some(network);
    }

    let ip = line.parse::<IpAddr>().ok()?;
    let prefix = if ip.is_ipv4() { 32 } else { 128 };

    format!("{}/{}", ip, prefix).parse().ok()
}

pub fn update_trusted_proxies(
    config: &TrustedProxiesConfig,
    trusted_proxies: &Arc<TrustedProxiesArcSwap>,
) -> anyhow::Result<()> {
    if config.enabled && !config.path.as_os_str().is_empty() {
        let content = std::fs::read_to_string(&config.path)
            .with_context(|| format!("Failed to read trusted proxies file: {:?}", config.path))?;
        
        let mut networks = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match parse_trusted_proxy_entry(line) {
                Some(network) => networks.push(network),
                None => {
                    ::log::warn!("Failed to parse trusted proxy entry '{}'", line);
                }
            }
        }
        
        let proxies = TrustedProxies::from_iter(networks);
        trusted_proxies.store(Arc::new(proxies));
        ::log::info!("Trusted proxies updated ({} entries)", trusted_proxies.load().len());
    } else {
        trusted_proxies.store(Arc::new(TrustedProxies::default()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_proxies() {
        let proxies = TrustedProxies::from_iter(vec![
            "192.168.1.0/24".parse().unwrap(),
            "10.0.0.1/32".parse().unwrap(),
        ]);

        assert!(proxies.is_trusted("192.168.1.100".parse().unwrap()));
        assert!(proxies.is_trusted("10.0.0.1".parse().unwrap()));
        assert!(!proxies.is_trusted("10.0.0.2".parse().unwrap()));
        assert!(!proxies.is_trusted("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_parse_trusted_proxy_entry() {
        assert_eq!(
            parse_trusted_proxy_entry("10.0.0.1").unwrap(),
            "10.0.0.1/32".parse::<IpNetwork>().unwrap()
        );
        assert_eq!(
            parse_trusted_proxy_entry("::1").unwrap(),
            "::1/128".parse::<IpNetwork>().unwrap()
        );
        assert_eq!(
            parse_trusted_proxy_entry("192.168.0.0/16").unwrap(),
            "192.168.0.0/16".parse::<IpNetwork>().unwrap()
        );
        assert!(parse_trusted_proxy_entry("not-an-ip").is_none());
    }

    #[test]
    fn test_last_forwarded_for_ip() {
        assert_eq!(
            last_forwarded_for_ip("1.2.3.4, 10.0.0.1, 203.0.113.1"),
            Some("203.0.113.1".parse().unwrap())
        );
        // Whitespace around entries is common.
        assert_eq!(
            last_forwarded_for_ip("2001:db8::1, 198.51.100.7"),
            Some("198.51.100.7".parse().unwrap())
        );
        // A malformed rightmost entry falls back to the next valid one.
        assert_eq!(
            last_forwarded_for_ip("1.2.3.4, not-an-ip"),
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(last_forwarded_for_ip(""), None);
        assert_eq!(last_forwarded_for_ip("not-an-ip"), None);
    }

    #[test]
    fn test_empty_trusted_proxies() {
        let proxies = TrustedProxies::default();

        // Empty table should NOT trust any IP (security: no proxies = no trust)
        assert!(!proxies.is_trusted("192.168.1.1".parse().unwrap()));
        assert!(!proxies.is_trusted("8.8.8.8".parse().unwrap()));
    }
}
