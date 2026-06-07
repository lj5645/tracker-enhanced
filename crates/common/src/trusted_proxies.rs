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

pub type TrustedProxiesArcSwap = ArcSwap<TrustedProxies>;

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
            match line.parse::<IpNetwork>() {
                Ok(network) => networks.push(network),
                Err(err) => {
                    ::log::warn!("Failed to parse trusted proxy entry '{}': {}", line, err);
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
            "10.0.0.1".parse().unwrap(),
        ]);

        assert!(proxies.is_trusted("192.168.1.100".parse().unwrap()));
        assert!(proxies.is_trusted("10.0.0.1".parse().unwrap()));
        assert!(!proxies.is_trusted("10.0.0.2".parse().unwrap()));
        assert!(!proxies.is_trusted("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_empty_trusted_proxies() {
        let proxies = TrustedProxies::default();

        // Empty table should NOT trust any IP (security: no proxies = no trust)
        assert!(!proxies.is_trusted("192.168.1.1".parse().unwrap()));
        assert!(!proxies.is_trusted("8.8.8.8".parse().unwrap()));
    }
}
