use std::net::IpAddr;
use std::path::PathBuf;

use aquatic_toml_config::TomlConfig;
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
            return true;
        }
        self.table.longest_match(addr).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trusted_proxies() {
        let proxies = TrustedProxies::from_iter(vec![
            "192.168.1.0/24".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ]);

        assert!(proxies.is_trusted("192.168.1.100".parse().unwrap()));
        assert!(proxies.is_trusted("10.0.0.1".parse().unwrap()));
        assert!(!proxies.is_trusted("10.0.0.2".parse().unwrap()));
        assert!(!proxies.is_trusted("8.8.8.8".parse().unwrap()));
    }
}
