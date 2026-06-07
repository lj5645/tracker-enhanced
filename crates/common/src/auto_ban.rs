use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Instant;

use aquatic_toml_config::TomlConfig;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
/// Auto-ban configuration
#[derive(Clone, Debug, PartialEq, TomlConfig, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AutoBanConfig {
    /// Enable auto-ban feature
    ///
    /// When enabled, IPs that exceed the violation threshold within the
    /// time window will be automatically banned.
    pub enabled: bool,
    /// Number of violations before an IP is auto-banned
    pub threshold: u32,
    /// Time window in seconds for counting violations
    pub window_secs: u64,
    /// Ban duration in seconds. Use 0 for permanent ban.
    ///
    /// Note: When ban_duration_secs > 0 (temporary ban), auto-banned IPs are
    /// NOT written to the ban_list_path file because the file format doesn't
    /// support expiration times. Temporary bans are only kept in memory and
    /// will be lost on restart. Use 0 for permanent bans that persist across restarts.
    pub ban_duration_secs: u64,
    /// Path to write auto-banned IPs. When set, auto-banned IPs are batch-written
    /// to this file periodically (one IP per line), making bans persistent across restarts.
    /// Set to empty string to disable file persistence.
    pub ban_list_path: PathBuf,
    /// Interval in seconds for batch-writing banned IPs to file and reloading ip_ban_list.
    /// Banned IPs are kept in memory until flushed. After flushing, ip_ban_list takes over.
    /// Minimum value is 1.
    pub flush_interval_secs: u64,
}

impl Default for AutoBanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 10,
            window_secs: 60,
            ban_duration_secs: 3600,
            ban_list_path: PathBuf::from("./ip-ban-list.txt"),
            flush_interval_secs: 60,
        }
    }
}

/// Reason why an IP was flagged for auto-ban
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoBanReason {
    IpBanned,
    SqlInjection,
    PathTraversal,
    Crawler,
    MissingUserAgent,
    ClientBanned,
    NotWhitelisted,
    PrivateIp,
}

impl AutoBanReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IpBanned => "ip_banned",
            Self::SqlInjection => "sql_injection",
            Self::PathTraversal => "path_traversal",
            Self::Crawler => "crawler",
            Self::MissingUserAgent => "missing_user_agent",
            Self::ClientBanned => "client_banned",
            Self::NotWhitelisted => "not_whitelisted",
            Self::PrivateIp => "private_ip",
        }
    }
}

/// Record for a single IP's violation count
struct IpRecord {
    count: u32,
    first_violation: Instant,
    /// Some(instant) if currently banned, None if just counting
    banned_until: Option<Instant>,
}

/// Thread-safe auto-ban tracker using RwLock for correct concurrent access
pub struct AutoBanTracker {
    inner: RwLock<AutoBanInner>,
    ban_list_path: Option<PathBuf>,
}

struct AutoBanInner {
    records: HashMap<IpAddr, IpRecord>,
    threshold: u32,
    window_secs: u64,
    ban_duration_secs: u64,
    max_records: usize,
}

impl AutoBanTracker {
    pub fn new(threshold: u32, window_secs: u64, ban_duration_secs: u64, ban_list_path: Option<PathBuf>) -> Self {
        Self {
            inner: RwLock::new(AutoBanInner {
                records: HashMap::new(),
                threshold,
                window_secs,
                ban_duration_secs,
                max_records: 100_000,
            }),
            ban_list_path,
        }
    }

    /// Record a violation for an IP. Returns true if the IP should be auto-banned.
    /// This is called on the hot path - NO file I/O here.
    pub fn record_violation(&self, ip: &IpAddr, reason: AutoBanReason) -> bool {
        let mut inner = self.inner.write().unwrap();
        let now = Instant::now();

        // Check if already banned
        if let Some(record) = inner.records.get(ip) {
            if let Some(banned_until) = record.banned_until {
                if now < banned_until {
                    return false; // Already banned
                }
            }
        }

        let threshold = inner.threshold;
        let window_secs = inner.window_secs;
        let ban_duration_secs = inner.ban_duration_secs;
        let max_records = inner.max_records;

        // Cleanup if too many records
        if inner.records.len() >= max_records {
            inner.records.retain(|_, record| {
                if let Some(banned_until) = record.banned_until {
                    now < banned_until
                } else {
                    now.duration_since(record.first_violation).as_secs() < window_secs
                }
            });
        }

        let should_ban = match inner.records.get_mut(ip) {
            Some(record) => {
                // Reset if outside window
                if now.duration_since(record.first_violation).as_secs() >= window_secs {
                    record.count = 0;
                    record.first_violation = now;
                }

                // Clear expired ban
                if let Some(banned_until) = record.banned_until {
                    if now >= banned_until {
                        record.banned_until = None;
                    }
                }

                record.count += 1;

                if record.count >= threshold && record.banned_until.is_none() {
                    record.banned_until = if ban_duration_secs > 0 {
                        Some(now + std::time::Duration::from_secs(ban_duration_secs))
                    } else {
                        Some(now + std::time::Duration::from_secs(365 * 24 * 3600))
                    };
                    true
                } else {
                    false
                }
            }
            None => {
                let should = threshold <= 1;
                inner.records.insert(
                    *ip,
                    IpRecord {
                        count: 1,
                        first_violation: now,
                        banned_until: if should {
                            if ban_duration_secs > 0 {
                                Some(now + std::time::Duration::from_secs(ban_duration_secs))
                            } else {
                                Some(now + std::time::Duration::from_secs(365 * 24 * 3600))
                            }
                        } else {
                            None
                        },
                    },
                );
                should
            }
        };

        if should_ban {
            ::log::warn!(
                "Auto-ban IP {} (reason: {}, count: {}/{})",
                ip,
                reason.as_str(),
                inner.records.get(ip).map(|r| r.count).unwrap_or(0),
                threshold,
            );
        }

        should_ban
    }

    /// Check if an IP is currently auto-banned (in-memory check only)
    pub fn is_auto_banned(&self, ip: &IpAddr) -> bool {
        let inner = self.inner.read().unwrap();
        let now = Instant::now();

        if let Some(record) = inner.records.get(ip) {
            if let Some(banned_until) = record.banned_until {
                return now < banned_until;
            }
        }

        false
    }

    /// Flush permanently banned IPs to file and return the list of flushed IPs.
    /// Only IPs with ban_duration_secs == 0 (permanent bans) are written to file,
    /// because the file format doesn't support expiration times.
    /// Temporary bans are kept in memory only and cleaned up by cleanup().
    /// Records are NOT removed from memory yet - call remove_ips() after
    /// ip_ban_list has been successfully reloaded.
    pub fn flush_to_file(&self) -> Vec<IpAddr> {
        let inner = self.inner.read().unwrap();
        let now = Instant::now();
        let is_permanent = inner.ban_duration_secs == 0;

        // Collect IPs that are banned
        // Only flush permanent bans to file (temporary bans can't be persisted
        // because the file format doesn't support expiration times)
        let to_flush: Vec<IpAddr> = if is_permanent {
            inner
                .records
                .iter()
                .filter(|(_, record)| {
                    record.banned_until.map_or(false, |until| now < until)
                })
                .map(|(ip, _)| *ip)
                .collect()
        } else {
            // For temporary bans, don't write to file - just return empty
            // The IPs are still tracked in memory and will be cleaned up by cleanup()
            return Vec::new();
        };

        drop(inner); // Release read lock before I/O

        if to_flush.is_empty() {
            return Vec::new();
        }

        // Batch write to file
        if let Some(path) = &self.ban_list_path {
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(mut file) => {
                    let mut lines = String::with_capacity(to_flush.len() * 40);
                    for ip in &to_flush {
                        lines.push_str(&ip.to_string());
                        lines.push('\n');
                    }
                    if let Err(err) = file.write_all(lines.as_bytes()) {
                        ::log::error!("Failed to flush auto-banned IPs to file: {}", err);
                        return Vec::new(); // Don't report as flushed if write failed
                    }
                    ::log::info!(
                        "Auto-ban flush: wrote {} IPs to {}",
                        to_flush.len(),
                        path.display(),
                    );
                }
                Err(err) => {
                    ::log::error!("Failed to open ban list file {}: {}", path.display(), err);
                    return Vec::new(); // Don't report as flushed if open failed
                }
            }
        } else {
            // No file path configured — don't report as flushed, otherwise
            // the flush thread will call remove_ips() and the IPs will
            // escape both auto_ban memory and ip_ban_list
            return Vec::new();
        }

        to_flush
    }

    /// Remove IPs from memory after ip_ban_list has been reloaded.
    /// This ensures no gap between auto_ban memory and ip_ban_list.
    pub fn remove_ips(&self, ips: &[IpAddr]) {
        let mut inner = self.inner.write().unwrap();
        let before = inner.records.len();

        for ip in ips {
            inner.records.remove(ip);
        }

        let removed = before - inner.records.len();
        if removed > 0 {
            ::log::info!("Auto-ban flush: freed {} memory records (ip_ban_list takes over)", removed);
        }
    }

    /// Get the number of tracked IPs
    pub fn tracked_count(&self) -> usize {
        self.inner.read().unwrap().records.len()
    }

    /// Get the number of currently banned IPs (in memory)
    pub fn banned_count(&self) -> usize {
        let inner = self.inner.read().unwrap();
        let now = Instant::now();

        inner
            .records
            .values()
            .filter(|record| {
                record.banned_until.map_or(false, |until| now < until)
            })
            .count()
    }

    /// Remove expired entries
    pub fn cleanup(&self) {
        let mut inner = self.inner.write().unwrap();
        let now = Instant::now();
        let window_secs = inner.window_secs;

        let before = inner.records.len();

        inner.records.retain(|_, record| {
            if let Some(banned_until) = record.banned_until {
                now < banned_until
            } else {
                now.duration_since(record.first_violation).as_secs() < window_secs
            }
        });

        let removed = before - inner.records.len();
        if removed > 0 {
            ::log::info!("Auto-ban cleanup: removed {} expired entries", removed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_auto_ban_threshold() {
        let tracker = AutoBanTracker::new(3, 60, 3600, None);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        assert!(!tracker.is_auto_banned(&ip));

        assert!(!tracker.record_violation(&ip, AutoBanReason::SqlInjection));
        assert!(!tracker.record_violation(&ip, AutoBanReason::SqlInjection));
        assert!(tracker.record_violation(&ip, AutoBanReason::SqlInjection));

        assert!(tracker.is_auto_banned(&ip));
        assert!(!tracker.record_violation(&ip, AutoBanReason::SqlInjection));
    }

    #[test]
    fn test_auto_ban_ipv6() {
        let tracker = AutoBanTracker::new(2, 60, 3600, None);
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        assert!(!tracker.record_violation(&ip, AutoBanReason::Crawler));
        assert!(tracker.record_violation(&ip, AutoBanReason::Crawler));
        assert!(tracker.is_auto_banned(&ip));
    }

    #[test]
    fn test_different_ips_independent() {
        let tracker = AutoBanTracker::new(2, 60, 3600, None);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        assert!(!tracker.record_violation(&ip1, AutoBanReason::SqlInjection));
        assert!(!tracker.record_violation(&ip2, AutoBanReason::SqlInjection));

        assert!(tracker.record_violation(&ip1, AutoBanReason::SqlInjection));
        assert!(tracker.is_auto_banned(&ip1));
        assert!(!tracker.is_auto_banned(&ip2));
    }

    #[test]
    fn test_threshold_one() {
        let tracker = AutoBanTracker::new(1, 60, 3600, None);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert!(tracker.record_violation(&ip, AutoBanReason::MissingUserAgent));
        assert!(tracker.is_auto_banned(&ip));
    }

    #[test]
    fn test_flush_to_file_permanent_ban() {
        // Use ban_duration_secs=0 for permanent bans (written to file)
        let tmp = std::env::temp_dir().join("test_auto_ban_flush.txt");
        let _ = std::fs::remove_file(&tmp); // Clean up from previous runs
        let path = tmp.clone();

        let tracker = AutoBanTracker::new(2, 60, 0, Some(path.clone()));
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        // Ban two IPs
        assert!(!tracker.record_violation(&ip1, AutoBanReason::SqlInjection));
        assert!(tracker.record_violation(&ip1, AutoBanReason::SqlInjection));
        assert!(tracker.record_violation(&ip2, AutoBanReason::Crawler));

        assert_eq!(tracker.banned_count(), 2);

        // Flush to file (records still in memory until remove_ips called)
        let flushed = tracker.flush_to_file();
        assert_eq!(flushed.len(), 2);

        // Still in memory until remove_ips is called
        assert_eq!(tracker.banned_count(), 2);

        // Remove from memory (simulates successful ip_ban_list reload)
        tracker.remove_ips(&flushed);
        assert_eq!(tracker.banned_count(), 0);

        // File should contain both IPs
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("1.2.3.4"));
        assert!(contents.contains("5.6.7.8"));

        let _ = std::fs::remove_file(&tmp); // Clean up
    }

    #[test]
    fn test_flush_temporary_ban_no_file() {
        // Use ban_duration_secs=3600 for temporary bans (NOT written to file)
        let tracker = AutoBanTracker::new(1, 60, 3600, None);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert!(tracker.record_violation(&ip, AutoBanReason::SqlInjection));
        assert_eq!(tracker.tracked_count(), 1);

        // Flush returns empty for temporary bans
        let flushed = tracker.flush_to_file();
        assert_eq!(flushed.len(), 0);

        // Still in memory
        assert_eq!(tracker.tracked_count(), 1);
        assert!(tracker.is_auto_banned(&ip));
    }

    #[test]
    fn test_flush_no_file_path() {
        // Permanent ban but no file path configured — should return empty
        let tracker = AutoBanTracker::new(1, 60, 0, None);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert!(tracker.record_violation(&ip, AutoBanReason::SqlInjection));
        assert_eq!(tracker.banned_count(), 1);

        // No file path — flush returns empty to prevent IP escape
        let flushed = tracker.flush_to_file();
        assert_eq!(flushed.len(), 0);

        // Still in memory and still banned
        assert!(tracker.is_auto_banned(&ip));
    }
}
