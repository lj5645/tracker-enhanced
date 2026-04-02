use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub struct RequestFilter {
    sql_injection_patterns: Vec<&'static str>,
    path_traversal_patterns: Vec<&'static str>,
    crawler_user_agents: Vec<&'static str>,
    private_ip_ranges: Vec<(IpAddr, u8)>,
}

impl Default for RequestFilter {
    fn default() -> Self {
        Self {
            sql_injection_patterns: vec![
                "'",
                "\"",
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
                "0x",
            ],
            path_traversal_patterns: vec![
                "../",
                "..\\",
                "%2e%2e",
                "%252e",
                "..%2f",
                "..%5c",
            ],
            crawler_user_agents: vec![
                "bot",
                "crawler",
                "spider",
                "scraper",
                "python-requests",
                "python-urllib",
                "curl",
                "wget",
                "httpclient",
                "java/",
                "okhttp",
                "apache-httpclient",
                "go-http-client",
                "node-fetch",
                "axios",
                "postman",
                "insomnia",
                "httpie",
            ],
            private_ip_ranges: vec![
                (IpAddr::V4("10.0.0.0".parse().unwrap()), 8),
                (IpAddr::V4("172.16.0.0".parse().unwrap()), 12),
                (IpAddr::V4("192.168.0.0".parse().unwrap()), 16),
                (IpAddr::V4("127.0.0.0".parse().unwrap()), 8),
                (IpAddr::V6("::1".parse().unwrap()), 128),
                (IpAddr::V6("fc00::".parse().unwrap()), 7),
                (IpAddr::V6("fe80::".parse().unwrap()), 10),
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
}

impl RequestFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_request(&self, uri: &str, user_agent: Option<&str>) -> FilterResult {
        let uri_lower = uri.to_lowercase();

        for pattern in &self.sql_injection_patterns {
            if uri_lower.contains(pattern) {
                return FilterResult::BlockedSqlInjection;
            }
        }

        for pattern in &self.path_traversal_patterns {
            if uri_lower.contains(pattern) {
                return FilterResult::BlockedPathTraversal;
            }
        }

        if let Some(ua) = user_agent {
            let ua_lower = ua.to_lowercase();
            for pattern in &self.crawler_user_agents {
                if ua_lower.contains(pattern) {
                    return FilterResult::BlockedCrawler;
                }
            }
        }

        FilterResult::Allowed
    }

    pub fn check_ip(&self, ip: &IpAddr) -> FilterResult {
        for (range_base, prefix_len) in &self.private_ip_ranges {
            if self.ip_in_range(ip, range_base, *prefix_len) {
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

    pub fn is_allowed(&self, uri: &str, user_agent: Option<&str>) -> bool {
        matches!(self.check_request(uri, user_agent), FilterResult::Allowed)
    }

    pub fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        matches!(self.check_ip(ip), FilterResult::Allowed)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RequestFilterConfig {
    pub filter_sql_injection: bool,
    pub filter_path_traversal: bool,
    pub filter_crawlers: bool,
    pub filter_private_ips: bool,
}

impl Default for RequestFilterConfig {
    fn default() -> Self {
        Self {
            filter_sql_injection: true,
            filter_path_traversal: true,
            filter_crawlers: true,
            filter_private_ips: false,
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
            filter.check_request("/announce?info_hash=' OR 1=1", None),
            FilterResult::BlockedSqlInjection
        );
        assert_eq!(
            filter.check_request("/announce?info_hash=union select", None),
            FilterResult::BlockedSqlInjection
        );
        assert_eq!(
            filter.check_request("/announce?info_hash=valid", None),
            FilterResult::Allowed
        );
    }

    #[test]
    fn test_path_traversal_detection() {
        let filter = RequestFilter::new();

        assert_eq!(
            filter.check_request("/../../../etc/passwd", None),
            FilterResult::BlockedPathTraversal
        );
        assert_eq!(
            filter.check_request("/announce?info_hash=valid", None),
            FilterResult::Allowed
        );
    }

    #[test]
    fn test_crawler_detection() {
        let filter = RequestFilter::new();

        assert_eq!(
            filter.check_request("/announce", Some("python-requests/2.28.0")),
            FilterResult::BlockedCrawler
        );
        assert_eq!(
            filter.check_request("/announce", Some("curl/7.68.0")),
            FilterResult::BlockedCrawler
        );
        assert_eq!(
            filter.check_request("/announce", Some("uTorrent/3.5.5")),
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
    }
}
