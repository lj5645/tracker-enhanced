use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use aquatic_toml_config::TomlConfig;
use arc_swap::ArcSwap;
use serde::Deserialize;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

use crate::list_file::read_list_file;

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

        if self.table.longest_match(addr).is_some() {
            return true;
        }

        // Dual-stack listeners report IPv4 peers as IPv4-mapped IPv6
        // addresses, while proxy lists normally contain plain IPv4 entries
        // (and vice versa). Match the canonical form as well.
        let canonical = crate::canonical_ip(addr);

        canonical != addr && self.table.longest_match(canonical).is_some()
    }

    pub fn len(&self) -> usize {
        self.table.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

/// Return the client IP from an `X-Forwarded-For` header.
///
/// Entries are appended from left to right as the request traverses proxies.
/// The rightmost entry was added by the proxy that accepted the connection and
/// everything left of it can have been supplied by the client. With chained
/// proxies (for example a CDN in front of nginx), the rightmost entries are
/// themselves trusted proxies, so the rightmost entry that is *not* a trusted
/// proxy is the client address.
///
/// Falls back to the leftmost valid entry when every entry is a trusted proxy,
/// which happens when the client itself is a proxy on the trusted list.
///
/// Using the leftmost value unconditionally would let a client spoof its
/// address with `X-Forwarded-For: <fake>, $proxy_add_x_forwarded_for`.
pub fn last_forwarded_for_ip(header: &str, trusted_proxies: &TrustedProxies) -> Option<IpAddr> {
    let mut leftmost_valid = None;
    let mut rightmost_untrusted = None;

    for value in header.split(',') {
        let ip = match value.trim().parse::<IpAddr>() {
            Ok(ip) => crate::canonical_ip(ip),
            Err(_) => continue,
        };

        leftmost_valid.get_or_insert(ip);

        if !trusted_proxies.is_trusted(ip) {
            rightmost_untrusted = Some(ip);
        }
    }

    rightmost_untrusted.or(leftmost_valid)
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
    if !config.enabled {
        trusted_proxies.store(Arc::new(TrustedProxies::default()));

        return Ok(());
    }

    if config.path.as_os_str().is_empty() {
        return Err(anyhow::anyhow!(
            "trusted_proxies.enabled = true but trusted_proxies.path is empty; \
             configure a path or disable trusted_proxies"
        ));
    }

    let mut networks = Vec::new();

    for (line_number, line) in read_list_file(&config.path)? {
        match parse_trusted_proxy_entry(&line) {
            Some(network) => networks.push(network),
            None => {
                ::log::warn!(
                    "Invalid trusted proxy entry on line {} ('{}')",
                    line_number,
                    line,
                );
            }
        }
    }

    if networks.is_empty() {
        return Err(anyhow::anyhow!(
            "trusted_proxies.enabled = true but '{}' contains no usable entries; \
             refusing to start with an empty trusted proxy list because every \
             X-Forwarded-For header would be ignored",
            config.path.display(),
        ));
    }

    let proxies = TrustedProxies::from_iter(networks);
    trusted_proxies.store(Arc::new(proxies));
    ::log::info!(
        "Trusted proxies updated ({} entries)",
        trusted_proxies.load().len()
    );

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
    fn test_trusted_proxies_ipv4_mapped() {
        let proxies = TrustedProxies::from_iter(vec![
            "127.0.0.1/32".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ]);

        // Dual-stack listeners report IPv4 peers in mapped form.
        assert!(proxies.is_trusted("::ffff:127.0.0.1".parse().unwrap()));
        assert!(proxies.is_trusted("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!proxies.is_trusted("::ffff:8.8.8.8".parse().unwrap()));
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
        let none = TrustedProxies::default();

        assert_eq!(
            last_forwarded_for_ip("1.2.3.4, 10.0.0.1, 203.0.113.1", &none),
            Some("203.0.113.1".parse().unwrap())
        );
        // Whitespace around entries is common.
        assert_eq!(
            last_forwarded_for_ip("2001:db8::1, 198.51.100.7", &none),
            Some("198.51.100.7".parse().unwrap())
        );
        // A malformed rightmost entry falls back to the next valid one.
        assert_eq!(
            last_forwarded_for_ip("1.2.3.4, not-an-ip", &none),
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(last_forwarded_for_ip("", &none), None);
        assert_eq!(last_forwarded_for_ip("not-an-ip", &none), None);
    }

    #[test]
    fn test_last_forwarded_for_ip_skips_trusted_proxy_hops() {
        // Client -> CDN (trusted) -> nginx (trusted, the socket peer).
        // Both rightmost entries are proxies, so the client is 4.3.2.1.
        let proxies = TrustedProxies::from_iter(vec![
            "10.0.0.0/8".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ]);

        assert_eq!(
            last_forwarded_for_ip("4.3.2.1, 10.1.1.1, 2001:db8::5", &proxies),
            Some("4.3.2.1".parse().unwrap())
        );

        // A client that is itself a trusted proxy: every entry is trusted, so
        // fall back to the leftmost (the client) instead of returning a hop.
        assert_eq!(
            last_forwarded_for_ip("10.9.9.9, 10.1.1.1", &proxies),
            Some("10.9.9.9".parse().unwrap())
        );
    }

    #[test]
    fn test_enabled_requires_a_non_empty_list() {
        let swap = Arc::new(TrustedProxiesArcSwap::from_pointee(
            TrustedProxies::default(),
        ));

        // Empty path: misconfiguration, refuse instead of silently trusting
        // nothing (which would ignore every X-Forwarded-For header).
        let empty_path = TrustedProxiesConfig {
            enabled: true,
            path: "".into(),
        };
        assert!(update_trusted_proxies(&empty_path, &swap).is_err());

        let path = std::env::temp_dir().join("aquatic_trusted_proxies_empty_test.txt");
        std::fs::write(&path, "# only comments\n\n").unwrap();

        let empty_file = TrustedProxiesConfig {
            enabled: true,
            path: path.clone(),
        };
        assert!(update_trusted_proxies(&empty_file, &swap).is_err());

        // A disabled configuration is allowed to point anywhere.
        let disabled = TrustedProxiesConfig {
            enabled: false,
            path: path.clone(),
        };
        assert!(update_trusted_proxies(&disabled, &swap).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_tolerates_bom_and_inline_comments() {
        let path = std::env::temp_dir().join("aquatic_trusted_proxies_formats_test.txt");
        std::fs::write(
            &path,
            "\u{feff}203.0.113.7\r\n10.0.0.0/8 # internal\r\n",
        )
        .unwrap();

        let swap = Arc::new(TrustedProxiesArcSwap::from_pointee(
            TrustedProxies::default(),
        ));
        let config = TrustedProxiesConfig {
            enabled: true,
            path: path.clone(),
        };

        update_trusted_proxies(&config, &swap).unwrap();

        assert!(swap.load().is_trusted("203.0.113.7".parse().unwrap()));
        assert!(swap.load().is_trusted("10.2.3.4".parse().unwrap()));
        assert!(!swap.load().is_trusted("8.8.8.8".parse().unwrap()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_empty_trusted_proxies() {
        let proxies = TrustedProxies::default();

        // Empty table should NOT trust any IP (security: no proxies = no trust)
        assert!(!proxies.is_trusted("192.168.1.1".parse().unwrap()));
        assert!(!proxies.is_trusted("8.8.8.8".parse().unwrap()));
    }
}
