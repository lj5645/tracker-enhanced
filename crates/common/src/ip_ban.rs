use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use aquatic_toml_config::TomlConfig;
use arc_swap::{ArcSwap, Cache};
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, TomlConfig, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpBanMode {
    On,
    Off,
}

impl IpBanMode {
    pub fn is_on(&self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Clone, Debug, PartialEq, TomlConfig, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IpBanConfig {
    pub mode: IpBanMode,
    pub path: PathBuf,
}

impl Default for IpBanConfig {
    fn default() -> Self {
        Self {
            mode: IpBanMode::Off,
            path: "./ip-ban-list.txt".into(),
        }
    }
}

#[derive(Debug, Clone)]
struct IpRange {
    base: IpAddr,
    prefix_len: u8,
}

impl IpRange {
    fn contains(&self, ip: &IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => {
                let mask = if self.prefix_len == 0 {
                    0u32
                } else {
                    !0u32 << (32 - self.prefix_len)
                };
                let base_bits = u32::from(base) & mask;
                let ip_bits = u32::from(*ip) & mask;
                base_bits == ip_bits
            }
            (IpAddr::V6(base), IpAddr::V6(ip)) => {
                let mask = if self.prefix_len == 0 {
                    0u128
                } else {
                    !0u128 << (128 - self.prefix_len)
                };
                let base_bits = u128::from(base) & mask;
                let ip_bits = u128::from(*ip) & mask;
                base_bits == ip_bits
            }
            _ => false,
        }
    }
}

#[derive(Default, Clone)]
pub struct IpBanList {
    banned_ips: HashSet<IpAddr>,
    banned_ranges: Vec<IpRange>,
}

impl IpBanList {
    pub fn create_from_path(path: &PathBuf) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut list = Self::default();

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Err(err) = list.add_entry(line) {
                ::log::warn!("Invalid IP ban entry '{}': {:#}", line, err);
            }
        }

        Ok(list)
    }

    fn add_entry(&mut self, line: &str) -> anyhow::Result<()> {
        if line.contains('/') {
            let parts: Vec<&str> = line.split('/').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid CIDR format"));
            }

            let ip: IpAddr = parts[0].parse()?;
            let prefix_len: u8 = parts[1].parse()?;

            let max_prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };

            if prefix_len > max_prefix {
                return Err(anyhow::anyhow!("Prefix length {} is too large for IP type", prefix_len));
            }

            self.banned_ranges.push(IpRange {
                base: ip,
                prefix_len,
            });
        } else {
            let ip: IpAddr = line.parse()?;
            self.banned_ips.insert(ip);
        }

        Ok(())
    }

    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        if self.banned_ips.contains(ip) {
            return true;
        }

        for range in &self.banned_ranges {
            if range.contains(ip) {
                return true;
            }
        }

        false
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.banned_ips.len() + self.banned_ranges.len()
    }
}

pub trait IpBanListQuery {
    fn update(&self, config: &IpBanConfig) -> anyhow::Result<()>;
    fn is_banned(&self, ip: &IpAddr) -> bool;
}

pub type IpBanListArcSwap = ArcSwap<IpBanList>;
pub type IpBanListCache = Cache<Arc<IpBanListArcSwap>, Arc<IpBanList>>;

impl IpBanListQuery for IpBanListArcSwap {
    fn update(&self, config: &IpBanConfig) -> anyhow::Result<()> {
        self.store(Arc::new(IpBanList::create_from_path(&config.path)?));
        Ok(())
    }

    fn is_banned(&self, ip: &IpAddr) -> bool {
        self.load().is_banned(ip)
    }
}

pub fn create_ip_ban_list_cache(arc_swap: &Arc<IpBanListArcSwap>) -> IpBanListCache {
    Cache::from(Arc::clone(arc_swap))
}

pub fn update_ip_ban_list(
    config: &IpBanConfig,
    ip_ban_list: &Arc<IpBanListArcSwap>,
) -> anyhow::Result<()> {
    if config.mode.is_on() {
        match ip_ban_list.update(config) {
            Ok(()) => {
                ::log::info!("IP ban list updated ({} entries)", ip_ban_list.load().len());
            }
            Err(err) => {
                ::log::error!("Updating IP ban list failed: {:#}", err);
                return Err(err);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_ban() {
        let mut list = IpBanList::default();
        list.add_entry("192.168.1.100").unwrap();
        list.add_entry("10.0.0.0/8").unwrap();

        assert!(list.is_banned(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!list.is_banned(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
        assert!(list.is_banned(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(list.is_banned(&IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(!list.is_banned(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    }

    #[test]
    fn test_ipv6_ban() {
        let mut list = IpBanList::default();
        list.add_entry("::1").unwrap();
        list.add_entry("2001:db8::/32").unwrap();

        assert!(list.is_banned(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));
        assert!(list.is_banned(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        assert!(!list.is_banned(&IpAddr::V6(Ipv6Addr::new(0x2002, 0xdb8, 0, 0, 0, 0, 0, 1))));
    }
}
