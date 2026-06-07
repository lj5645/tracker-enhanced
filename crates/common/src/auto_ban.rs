use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use hashbrown::HashMap;
use aquatic_toml_config::TomlConfig;
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
    pub ban_duration_secs: u64,
}

impl Default for AutoBanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 10,
            window_secs: 60,
            ban_duration_secs: 3600,
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
        }
    }
}

/// Record for a single IP's violation count
struct IpRecord {
    count: u32,
    first_violation: Instant,
    banned_until: Option<Instant>,
}

/// Thread-safe auto-ban tracker
pub struct AutoBanTracker {
    inner: Arc<ArcSwap<AutoBanInner>>,
}

struct AutoBanInner {
    records: HashMap<IpAddr, IpRecord>,
    threshold: u32,
    window_secs: u64,
    ban_duration_secs: u64,
    max_records: usize,
}

impl AutoBanTracker {
    pub fn new(threshold: u32, window_secs: u64, ban_duration_secs: u64) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(AutoBanInner {
                records: HashMap::new(),
                threshold,
                window_secs,
                ban_duration_secs,
                max_records: 100_000,
            })),
        }
    }

    /// Record a violation for an IP. Returns true if the IP should be auto-banned.
    pub fn record_violation(&self, ip: &IpAddr, reason: AutoBanReason) -> bool {
        let inner = self.inner.load();
        let now = Instant::now();

        // Check if already banned
        if let Some(record) = inner.records.get(ip) {
            if let Some(banned_until) = record.banned_until {
                if now < banned_until {
                    return false; // Already banned, no need to re-ban
                }
            }
        }

        let threshold = inner.threshold;
        let window_secs = inner.window_secs;
        let ban_duration_secs = inner.ban_duration_secs;
        let max_records = inner.max_records;

        // Clone, update, and swap back (simple copy-on-write)
        let mut new_inner = AutoBanInner {
            records: inner.records.clone(),
            threshold,
            window_secs,
            ban_duration_secs,
            max_records,
        };

        // Cleanup expired entries if too many records
        if new_inner.records.len() >= max_records {
            new_inner.records.retain(|_, record| {
                if let Some(banned_until) = record.banned_until {
                    now < banned_until
                } else {
                    now.duration_since(record.first_violation).as_secs() < window_secs
                }
            });
        }

        let should_ban = match new_inner.records.get_mut(ip) {
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

                if record.count >= threshold {
                    record.banned_until = if ban_duration_secs > 0 {
                        Some(now + std::time::Duration::from_secs(ban_duration_secs))
                    } else {
                        // Permanent ban - set far future
                        Some(now + std::time::Duration::from_secs(365 * 24 * 3600))
                    };
                    true
                } else {
                    false
                }
            }
            None => {
                new_inner.records.insert(
                    *ip,
                    IpRecord {
                        count: 1,
                        first_violation: now,
                        banned_until: None,
                    },
                );
                threshold <= 1
            }
        };

        if should_ban {
            ::log::warn!(
                "Auto-ban IP {} (reason: {}, count: {}/{})",
                ip,
                reason.as_str(),
                new_inner.records.get(ip).map(|r| r.count).unwrap_or(0),
                threshold,
            );
        }

        self.inner.store(Arc::new(new_inner));
        should_ban
    }

    /// Check if an IP is currently auto-banned
    pub fn is_auto_banned(&self, ip: &IpAddr) -> bool {
        let inner = self.inner.load();
        let now = Instant::now();

        if let Some(record) = inner.records.get(ip) {
            if let Some(banned_until) = record.banned_until {
                return now < banned_until;
            }
        }

        false
    }

    /// Get the number of tracked IPs
    pub fn tracked_count(&self) -> usize {
        self.inner.load().records.len()
    }

    /// Get the number of currently banned IPs
    pub fn banned_count(&self) -> usize {
        let inner = self.inner.load();
        let now = Instant::now();

        inner
            .records
            .values()
            .filter(|record| {
                record
                    .banned_until
                    .map(|until| now < until)
                    .unwrap_or(false)
            })
            .count()
    }

    /// Remove expired entries
    pub fn cleanup(&self) {
        let inner = self.inner.load();
        let now = Instant::now();
        let window_secs = inner.window_secs;

        let mut new_inner = (*inner).clone();
        let before = new_inner.records.len();

        new_inner.records.retain(|_, record| {
            if let Some(banned_until) = record.banned_until {
                now < banned_until
            } else {
                now.duration_since(record.first_violation).as_secs() < window_secs
            }
        });

        let removed = before - new_inner.records.len();
        if removed > 0 {
            ::log::info!("Auto-ban cleanup: removed {} expired entries", removed);
            self.inner.store(Arc::new(new_inner));
        }
    }
}

impl Clone for AutoBanInner {
    fn clone(&self) -> Self {
        Self {
            records: self.records.clone(),
            threshold: self.threshold,
            window_secs: self.window_secs,
            ban_duration_secs: self.ban_duration_secs,
            max_records: self.max_records,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_auto_ban_threshold() {
        let tracker = AutoBanTracker::new(3, 60, 3600);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        assert!(!tracker.is_auto_banned(&ip));

        // First two violations should not trigger ban
        assert!(!tracker.record_violation(&ip, AutoBanReason::SqlInjection));
        assert!(!tracker.record_violation(&ip, AutoBanReason::SqlInjection));

        // Third violation should trigger ban
        assert!(tracker.record_violation(&ip, AutoBanReason::SqlInjection));

        // Should now be banned
        assert!(tracker.is_auto_banned(&ip));

        // Further violations should not re-trigger
        assert!(!tracker.record_violation(&ip, AutoBanReason::SqlInjection));
    }

    #[test]
    fn test_auto_ban_ipv6() {
        let tracker = AutoBanTracker::new(2, 60, 3600);
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        assert!(!tracker.record_violation(&ip, AutoBanReason::Crawler));
        assert!(tracker.record_violation(&ip, AutoBanReason::Crawler));
        assert!(tracker.is_auto_banned(&ip));
    }

    #[test]
    fn test_different_ips_independent() {
        let tracker = AutoBanTracker::new(2, 60, 3600);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        assert!(!tracker.record_violation(&ip1, AutoBanReason::SqlInjection));
        assert!(!tracker.record_violation(&ip2, AutoBanReason::SqlInjection));

        assert!(!tracker.is_auto_banned(&ip1));
        assert!(!tracker.is_auto_banned(&ip2));

        assert!(tracker.record_violation(&ip1, AutoBanReason::SqlInjection));
        assert!(tracker.is_auto_banned(&ip1));
        assert!(!tracker.is_auto_banned(&ip2));
    }

    #[test]
    fn test_threshold_one() {
        let tracker = AutoBanTracker::new(1, 60, 3600);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert!(tracker.record_violation(&ip, AutoBanReason::MissingUserAgent));
        assert!(tracker.is_auto_banned(&ip));
    }
}
