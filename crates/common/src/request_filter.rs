use std::net::IpAddr;

use aquatic_toml_config::TomlConfig;
use serde::{Deserialize, Serialize};

use crate::{canonical_ip, contains_ascii_case_insensitive};

pub struct RequestFilter {
    sql_injection_patterns: Vec<&'static str>,
    path_traversal_patterns: Vec<&'static str>,
    crawler_user_agents: Vec<&'static str>,
    private_ip_ranges: Vec<(IpAddr, u8)>,
}

impl Default for RequestFilter {
    fn default() -> Self {
        Self {
            // SQL keywords are matched on word boundaries (see
            // `matches_pattern`) to avoid flagging them inside random
            // hex-encoded query values. Single characters such as `'`, `"` and
            // `0x` are deliberately not listed: they occur in too many
            // harmless URLs to be useful and made false positives easy.
            sql_injection_patterns: vec![
                "--",
                "/*",
                "*/",
                "union",
                "select",
                "insert",
                "delete",
                "update",
                "drop",
                "exec",
                "execute",
                "xp_",
                "sp_",
            ],
            path_traversal_patterns: vec![
                "../",
                "..\\",
                "%2e%2e",
                "%252e",
                "..%2f",
                "..%5c",
            ],
            // Unambiguous crawler/scanning signatures only. Generic HTTP
            // libraries (Java, OkHttp, Apache HttpClient, Go, node-fetch,
            // axios, Postman, Insomnia) are used by legitimate clients and
            // monitoring tools as well, so they are not treated as crawlers.
            crawler_user_agents: vec![
                "bot",
                "crawler",
                "spider",
                "scraper",
                "python-requests",
                "python-urllib",
                "curl",
                "wget",
                "httpie",
                "go-http-client",
            ],
            // Non-public address space: RFC 1918, CGNAT, link-local, loopback,
            // "this network", multicast and reserved ranges, plus ULA,
            // loopback, link-local and multicast for IPv6.
            private_ip_ranges: vec![
                (IpAddr::V4("0.0.0.0".parse().unwrap()), 8),
                (IpAddr::V4("10.0.0.0".parse().unwrap()), 8),
                (IpAddr::V4("100.64.0.0".parse().unwrap()), 10),
                (IpAddr::V4("127.0.0.0".parse().unwrap()), 8),
                (IpAddr::V4("169.254.0.0".parse().unwrap()), 16),
                (IpAddr::V4("172.16.0.0".parse().unwrap()), 12),
                (IpAddr::V4("192.168.0.0".parse().unwrap()), 16),
                (IpAddr::V4("198.18.0.0".parse().unwrap()), 15),
                (IpAddr::V4("224.0.0.0".parse().unwrap()), 4),
                (IpAddr::V4("240.0.0.0".parse().unwrap()), 4),
                (IpAddr::V6("::".parse().unwrap()), 128),
                (IpAddr::V6("::1".parse().unwrap()), 128),
                (IpAddr::V6("fc00::".parse().unwrap()), 7),
                (IpAddr::V6("fe80::".parse().unwrap()), 10),
                (IpAddr::V6("ff00::".parse().unwrap()), 8),
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum FilterResult {
    Allowed,
    BlockedSqlInjection,
    BlockedPathTraversal,
    BlockedCrawler,
    BlockedPrivateIp,
    BlockedMissingUserAgent,
}

impl RequestFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Legacy entry point: applies SQL injection, path traversal and crawler
    /// filtering, with the missing-User-Agent check controlled by the
    /// argument. New code should use [`Self::check_request_with_config`] so
    /// the configured flags are honoured.
    pub fn check_request(
        &self,
        uri: &str,
        user_agent: Option<&str>,
        filter_missing_ua: bool,
    ) -> FilterResult {
        let config = RequestFilterConfig {
            filter_sql_injection: true,
            filter_path_traversal: true,
            filter_crawlers: true,
            filter_private_ips: false,
            filter_missing_user_agent: filter_missing_ua,
        };

        self.check_request_with_config(uri, user_agent, &config)
    }

    pub fn check_request_with_config(
        &self,
        uri: &str,
        user_agent: Option<&str>,
        config: &RequestFilterConfig,
    ) -> FilterResult {
        if config.filter_sql_injection && self.is_sql_injection(uri) {
            return FilterResult::BlockedSqlInjection;
        }

        if config.filter_path_traversal && self.is_path_traversal(uri) {
            return FilterResult::BlockedPathTraversal;
        }

        if config.filter_crawlers && self.is_crawler(user_agent) {
            return FilterResult::BlockedCrawler;
        }

        if user_agent.is_none() && config.filter_missing_user_agent {
            return FilterResult::BlockedMissingUserAgent;
        }

        FilterResult::Allowed
    }

    pub fn check_ip(&self, ip: &IpAddr) -> FilterResult {
        // Dual-stack listeners report IPv4 peers as IPv4-mapped IPv6
        // addresses; canonicalize so the IPv4 private ranges still match.
        let ip = canonical_ip(*ip);

        for (range_base, prefix_len) in &self.private_ip_ranges {
            if self.ip_in_range(&ip, range_base, *prefix_len) {
                return FilterResult::BlockedPrivateIp;
            }
        }
        FilterResult::Allowed
    }

    fn ip_in_range(&self, ip: &IpAddr, base: &IpAddr, prefix_len: u8) -> bool {
        match (ip, base) {
            (IpAddr::V4(ip), IpAddr::V4(base)) => {
                if prefix_len == 0 {
                    return true;
                }
                let mask = !0u32 << (32 - prefix_len);
                let ip_bits = u32::from(*ip) & mask;
                let base_bits = u32::from(*base) & mask;
                ip_bits == base_bits
            }
            (IpAddr::V6(ip), IpAddr::V6(base)) => {
                if prefix_len == 0 {
                    return true;
                }
                let mask = !0u128 << (128 - prefix_len);
                let ip_bits = u128::from(*ip) & mask;
                let base_bits = u128::from(*base) & mask;
                ip_bits == base_bits
            }
            _ => false,
        }
    }

    pub fn is_allowed(&self, uri: &str, user_agent: Option<&str>, filter_missing_ua: bool) -> bool {
        matches!(self.check_request(uri, user_agent, filter_missing_ua), FilterResult::Allowed)
    }

    pub fn is_allowed_with_config(
        &self,
        uri: &str,
        user_agent: Option<&str>,
        config: &RequestFilterConfig,
    ) -> bool {
        matches!(
            self.check_request_with_config(uri, user_agent, config),
            FilterResult::Allowed
        )
    }

    pub fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        matches!(self.check_ip(ip), FilterResult::Allowed)
    }

    /// Check if the URI contains SQL injection patterns
    pub fn is_sql_injection(&self, uri: &str) -> bool {
        self.sql_injection_patterns
            .iter()
            .any(|pattern| matches_pattern(uri, pattern))
    }

    /// Check if the URI contains path traversal patterns
    pub fn is_path_traversal(&self, uri: &str) -> bool {
        self.path_traversal_patterns
            .iter()
            .any(|pattern| contains_ascii_case_insensitive(uri, pattern))
    }

    /// Check if the User-Agent matches crawler patterns
    pub fn is_crawler(&self, user_agent: Option<&str>) -> bool {
        user_agent.map_or(false, |ua| {
            self.crawler_user_agents
                .iter()
                .any(|pattern| contains_ascii_case_insensitive(ua, pattern))
        })
    }
}

/// Match one SQL-injection pattern without allocating.
///
/// Whole-word patterns such as `select` are only matched on word boundaries,
/// so a percent-encoded peer id or key cannot accidentally contain them. For
/// example, `%73%65%6c%65%63%74` contains no literal `select`, while a plain
/// `info_hash=select` still matches. Symbol and prefix patterns (`--`, `xp_`)
/// are matched as plain substrings.
fn matches_pattern(haystack: &str, pattern: &str) -> bool {
    if pattern.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        contains_word_ascii_case_insensitive(haystack, pattern)
    } else {
        contains_ascii_case_insensitive(haystack, pattern)
    }
}

fn contains_word_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();

    if haystack.len() < needle.len() {
        return false;
    }

    // The hex digit ending a percent escape (`%20`) is alphanumeric but is a
    // separator in the decoded value, not part of a word next to the keyword.
    // Without this, `1%20union%20select` would not be recognized while the
    // same query with literal spaces would be.
    let is_word_byte_at = |index: usize| {
        let byte = haystack[index];

        if !(byte.is_ascii_alphanumeric() || byte == b'_') {
            return false;
        }

        !(index >= 2 && haystack[index - 2] == b'%' && haystack[index - 1].is_ascii_hexdigit())
    };

    haystack
        .windows(needle.len())
        .enumerate()
        .any(|(start, window)| {
            window.eq_ignore_ascii_case(needle)
                && (start == 0 || !is_word_byte_at(start - 1))
                && (start + needle.len() == haystack.len()
                    || !is_word_byte_at(start + needle.len()))
        })
}

#[derive(Clone, Debug, PartialEq, TomlConfig, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RequestFilterConfig {
    pub filter_sql_injection: bool,
    pub filter_path_traversal: bool,
    pub filter_crawlers: bool,
    pub filter_private_ips: bool,
    /// Filter requests without User-Agent header
    ///
    /// Most legitimate BitTorrent clients send User-Agent headers.
    /// Requests without User-Agent are likely from crawlers, scanners,
    /// or malicious tools.
    pub filter_missing_user_agent: bool,
}

impl Default for RequestFilterConfig {
    fn default() -> Self {
        // Filters are opt-in. A tracker must not reject legitimate clients
        // because a config file predates a new filter or omits a flag.
        Self {
            filter_sql_injection: false,
            filter_path_traversal: false,
            filter_crawlers: false,
            filter_private_ips: false,
            filter_missing_user_agent: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_detection() {
        let filter = RequestFilter::new();

        assert_eq!(
            filter.check_request("/announce?info_hash=1%20union%20select", None, false),
            FilterResult::BlockedSqlInjection
        );
        assert_eq!(
            filter.check_request("/announce?info_hash=union select", None, false),
            FilterResult::BlockedSqlInjection
        );
        assert_eq!(
            filter.check_request("/announce?info_hash=valid", None, false),
            FilterResult::Allowed
        );
    }

    #[test]
    fn test_sql_filter_does_not_flag_benign_values() {
        let filter = RequestFilter::new();

        // Quotes are used by some clients in unrelated parameters; they are
        // no longer treated as injection on their own.
        assert_eq!(
            filter.check_request("/announce?comment=it's-fine", None, false),
            FilterResult::Allowed
        );

        // Keywords are only matched on word boundaries.
        assert_eq!(
            filter.check_request("/announce?info_hash=selectvalue", None, false),
            FilterResult::Allowed
        );
        assert_eq!(
            filter.check_request("/announce?info_hash=unionall", None, false),
            FilterResult::Allowed
        );

        // Percent-encoded letters are not keywords either.
        assert_eq!(
            filter.check_request("/announce?info_hash=%73%65%6c%65%63%74", None, false),
            FilterResult::Allowed
        );
    }

    #[test]
    fn test_path_traversal_detection() {
        let filter = RequestFilter::new();

        assert_eq!(
            filter.check_request("/../../../etc/passwd", None, false),
            FilterResult::BlockedPathTraversal
        );
        assert_eq!(
            filter.check_request("/announce?info_hash=valid", None, false),
            FilterResult::Allowed
        );
    }

    #[test]
    fn test_crawler_detection() {
        let filter = RequestFilter::new();

        assert_eq!(
            filter.check_request("/announce", Some("python-requests/2.28.0"), false),
            FilterResult::BlockedCrawler
        );
        assert_eq!(
            filter.check_request("/announce", Some("curl/7.68.0"), false),
            FilterResult::BlockedCrawler
        );
        assert_eq!(
            filter.check_request("/announce", Some("uTorrent/3.5.5"), false),
            FilterResult::Allowed
        );
    }

    #[test]
    fn test_missing_user_agent_detection() {
        let filter = RequestFilter::new();

        // 不过滤缺少 UA 的请求
        assert_eq!(
            filter.check_request("/announce", None, false),
            FilterResult::Allowed
        );

        // 过滤缺少 UA 的请求
        assert_eq!(
            filter.check_request("/announce", None, true),
            FilterResult::BlockedMissingUserAgent
        );

        // 有 UA 的请求不受影响
        assert_eq!(
            filter.check_request("/announce", Some("uTorrent/3.5.5"), true),
            FilterResult::Allowed
        );
    }

    #[test]
    fn test_config_flags_are_honoured() {
        let filter = RequestFilter::new();

        let disabled = RequestFilterConfig::default();

        // Defaults must allow legitimate clients and opt out of every filter.
        assert_eq!(
            filter.check_request_with_config(
                "/announce?info_hash=union select",
                Some("python-requests/2.28.0"),
                &disabled
            ),
            FilterResult::Allowed
        );
        assert_eq!(
            filter.check_request_with_config("/../../../etc/passwd", None, &disabled),
            FilterResult::Allowed
        );

        let sql_only = RequestFilterConfig {
            filter_sql_injection: true,
            ..disabled.clone()
        };
        assert_eq!(
            filter.check_request_with_config(
                "/announce?info_hash=1%20union%20select",
                None,
                &sql_only
            ),
            FilterResult::BlockedSqlInjection
        );
        assert_eq!(
            filter.check_request_with_config("/../etc/passwd", None, &sql_only),
            FilterResult::Allowed
        );

        let path_only = RequestFilterConfig {
            filter_path_traversal: true,
            ..disabled.clone()
        };
        assert_eq!(
            filter.check_request_with_config("/../etc/passwd", None, &path_only),
            FilterResult::BlockedPathTraversal
        );

        let crawler_only = RequestFilterConfig {
            filter_crawlers: true,
            ..disabled.clone()
        };
        assert_eq!(
            filter
                .check_request_with_config("/announce", Some("curl/7.68.0"), &crawler_only),
            FilterResult::BlockedCrawler
        );
        assert_eq!(
            filter.check_request_with_config("/announce", Some("uTorrent/3.5.5"), &crawler_only),
            FilterResult::Allowed
        );
    }

    #[test]
    fn test_private_ip_detection() {
        let filter = RequestFilter::new();

        assert_eq!(
            filter.check_ip(&IpAddr::V4("10.0.0.1".parse().unwrap())),
            FilterResult::BlockedPrivateIp
        );
        assert_eq!(
            filter.check_ip(&IpAddr::V4("192.168.1.1".parse().unwrap())),
            FilterResult::BlockedPrivateIp
        );
        assert_eq!(
            filter.check_ip(&IpAddr::V4("8.8.8.8".parse().unwrap())),
            FilterResult::Allowed
        );

        // CGNAT, link-local and "this network" are not public client
        // addresses either.
        assert_eq!(
            filter.check_ip(&IpAddr::V4("100.64.1.2".parse().unwrap())),
            FilterResult::BlockedPrivateIp
        );
        assert_eq!(
            filter.check_ip(&IpAddr::V4("169.254.1.2".parse().unwrap())),
            FilterResult::BlockedPrivateIp
        );
        assert_eq!(
            filter.check_ip(&IpAddr::V4("0.0.0.0".parse().unwrap())),
            FilterResult::BlockedPrivateIp
        );
        assert_eq!(
            filter.check_ip(&IpAddr::V4("224.0.0.1".parse().unwrap())),
            FilterResult::BlockedPrivateIp
        );
    }

    #[test]
    fn test_generic_http_libraries_are_not_crawlers() {
        let filter = RequestFilter::new();

        for ua in [
            "Apache-HttpClient/4.5.13 (Java/17)",
            "okhttp/4.9.0",
            "node-fetch/1.0",
            "axios/1.6.0",
            "PostmanRuntime/7.36.0",
        ] {
            assert!(!filter.is_crawler(Some(ua)), "unexpectedly blocked: {ua}");
        }
    }

    #[test]
    fn test_private_ip_detection_ipv4_mapped() {
        let filter = RequestFilter::new();

        // Dual-stack listeners report IPv4 peers as ::ffff:a.b.c.d.
        assert_eq!(
            filter.check_ip(&"::ffff:10.0.0.1".parse().unwrap()),
            FilterResult::BlockedPrivateIp
        );
        assert_eq!(
            filter.check_ip(&"::ffff:192.168.1.1".parse().unwrap()),
            FilterResult::BlockedPrivateIp
        );
        assert_eq!(
            filter.check_ip(&"::ffff:8.8.8.8".parse().unwrap()),
            FilterResult::Allowed
        );
    }
}
