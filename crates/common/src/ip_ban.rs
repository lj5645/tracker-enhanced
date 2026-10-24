use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use aquatic_toml_config::TomlConfig;
use arc_swap::{ArcSwap, Cache};
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};

use crate::canonical_ip;

#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};

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
        // Read the file as bytes and decode lossily: a single non-UTF-8 byte
        // (for example a comment written by a Windows editor in a local code
        // page) would otherwise make the whole file fail to load, silently
        // disabling every ban in it.
        let bytes = std::fs::read(path)?;
        let content = String::from_utf8_lossy(&bytes);

        let mut list = Self::default();

        for (index, line) in content.lines().enumerate() {
            // Files written by Windows editors commonly start with a UTF-8 BOM,
            // and operators often add trailing comments. Both would otherwise
            // make the first (or every annotated) entry silently unbanned.
            let line = line.trim_start_matches('\u{feff}');
            let line = match line.split_once('#') {
                Some((entry, _)) => entry,
                None => line,
            };
            let line = line.trim();

            if line.is_empty() {
                continue;
            }

            if let Err(err) = list.add_entry(line) {
                ::log::warn!(
                    "Invalid IP ban entry on line {} ('{}'): {:#}",
                    index + 1,
                    line,
                    err,
                );
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
        // Dual-stack listeners report IPv4 peers as `::ffff:a.b.c.d`. Match
        // both the address as received and its canonical IPv4 form so entries
        // written in either notation (and IPv4 CIDR ranges) keep working.
        if self.matches(ip) {
            return true;
        }

        let canonical = canonical_ip(*ip);

        canonical != *ip && self.matches(&canonical)
    }

    fn matches(&self, ip: &IpAddr) -> bool {
        self.banned_ips.contains(ip) || self.banned_ranges.iter().any(|range| range.contains(ip))
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

    #[test]
    fn test_ipv4_mapped_ipv6_matches_ipv4_entries() {
        // A dual-stack listener reports IPv4 clients as ::ffff:a.b.c.d.
        let mut list = IpBanList::default();
        list.add_entry("192.168.1.100").unwrap();
        list.add_entry("10.0.0.0/8").unwrap();

        let mapped_exact: IpAddr = "::ffff:192.168.1.100".parse().unwrap();
        let mapped_range: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        let mapped_other: IpAddr = "::ffff:192.168.1.101".parse().unwrap();

        assert!(list.is_banned(&mapped_exact));
        assert!(list.is_banned(&mapped_range));
        assert!(!list.is_banned(&mapped_other));

        // Plain IPv4 still matches.
        assert!(list.is_banned(&"192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_peer_matches_mapped_entry() {
        // An operator may also write the mapped form into the list.
        let mut list = IpBanList::default();
        list.add_entry("::ffff:203.0.113.9").unwrap();

        assert!(list.is_banned(&"203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn test_ban_list_file_formats() {
        let path = std::env::temp_dir().join("aquatic_ip_ban_formats_test.txt");
        std::fs::write(
            &path,
            "\u{feff}127.0.0.1\r\n\
             \r\n\
             # full line comment\r\n\
             10.0.0.0/8 # inline comment\r\n\
             192.0.2.5\r\n",
        )
        .unwrap();

        let list = IpBanList::create_from_path(&path).unwrap();

        assert!(list.is_banned(&"127.0.0.1".parse().unwrap()));
        assert!(list.is_banned(&"10.9.8.7".parse().unwrap()));
        assert!(list.is_banned(&"192.0.2.5".parse().unwrap()));
        assert!(!list.is_banned(&"192.0.2.6".parse().unwrap()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_ban_list_non_utf8_line_does_not_break_list() {
        let path = std::env::temp_dir().join("aquatic_ip_ban_non_utf8_test.txt");
        // A comment written in a non-UTF-8 code page (GBK for "扫描器")
        // followed by a valid entry: only the undecodable line is skipped.
        std::fs::write(&path, b"\xc9\xa8\xc3\xe8\xc6\xf7\n203.0.113.1\n").unwrap();

        let list = IpBanList::create_from_path(&path).unwrap();

        assert!(list.is_banned(&"203.0.113.1".parse().unwrap()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_invalid_entries_are_skipped() {
        let path = std::env::temp_dir().join("aquatic_ip_ban_invalid_test.txt");
        std::fs::write(&path, "not-an-ip\n10.0.0.0/33\n1.2.3.4/nope\n203.0.113.1\n").unwrap();

        let list = IpBanList::create_from_path(&path).unwrap();

        // Valid entries still load; invalid ones are ignored rather than
        // aborting the whole list.
        assert!(list.is_banned(&"203.0.113.1".parse().unwrap()));
        assert!(!list.is_banned(&"10.1.1.1".parse().unwrap()));

        let _ = std::fs::remove_file(&path);
    }
}
