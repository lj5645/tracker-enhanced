use std::net::IpAddr;

use anyhow::Context;
use aquatic_common::trusted_proxies::{last_forwarded_for_ip, TrustedProxies};
use aquatic_http_protocol::request::Request;

use crate::config::{Config, ReverseProxyPeerIpHeaderFormat};

#[derive(Debug, thiserror::Error)]
pub enum RequestParseError {
    #[error("required peer ip header missing or invalid")]
    RequiredPeerIpHeaderMissing(anyhow::Error),
    #[error("more data needed")]
    MoreDataNeeded,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub struct ParsedRequest {
    pub request: Request,
    pub opt_peer_ip: Option<IpAddr>,
    pub opt_user_agent: Option<String>,
    /// Number of bytes belonging to this request. Bytes after it are a
    /// pipelined request and must be kept in the buffer.
    pub consumed: usize,
}

/// Parse a request from the start of `buffer`.
///
/// `trust_forwarded_ip` is only true when the socket peer is a configured
/// trusted proxy: an X-Forwarded-For header from any other peer is ignored.
pub fn parse_request(
    config: &Config,
    trust_forwarded_ip: bool,
    trusted_proxies: &TrustedProxies,
    buffer: &[u8],
) -> Result<ParsedRequest, RequestParseError> {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut http_request = httparse::Request::new(&mut headers);

    match http_request.parse(buffer).with_context(|| "httparse")? {
        httparse::Status::Complete(consumed) => {
            let path = http_request.path.ok_or(anyhow::anyhow!("no http path"))?;
            let request = Request::parse_http_get_path(path)?;

            let opt_peer_ip = if trust_forwarded_ip {
                let header_name = &config.network.reverse_proxy_ip_header_name;
                let header_format = config.network.reverse_proxy_ip_header_format;

                match parse_forwarded_header(
                    header_name,
                    header_format,
                    trusted_proxies,
                    http_request.headers,
                ) {
                    Ok(peer_ip) => Some(peer_ip),
                    Err(err) => {
                        return Err(RequestParseError::RequiredPeerIpHeaderMissing(err));
                    }
                }
            } else {
                None
            };

            let opt_user_agent = parse_user_agent_header(http_request.headers);

            Ok(ParsedRequest {
                request,
                opt_peer_ip,
                opt_user_agent,
                consumed,
            })
        }
        httparse::Status::Partial => Err(RequestParseError::MoreDataNeeded),
    }
}

fn parse_user_agent_header(headers: &[httparse::Header<'_>]) -> Option<String> {
    for header in headers {
        if header.name.eq_ignore_ascii_case("User-Agent") {
            if let Ok(ua) = ::std::str::from_utf8(header.value) {
                return Some(ua.to_string());
            }
        }
    }
    None
}

fn parse_forwarded_header(
    header_name: &str,
    header_format: ReverseProxyPeerIpHeaderFormat,
    trusted_proxies: &TrustedProxies,
    headers: &[httparse::Header<'_>],
) -> anyhow::Result<IpAddr> {
    // Proxies append to the header, so when it occurs more than once the
    // rightmost value of the last instance is the most recent one. Collect all
    // instances in order so trusted-proxy skipping sees the whole chain.
    let mut values = String::new();

    for header in headers {
        // HTTP header names are case-insensitive; proxies are not required to
        // preserve the capitalization used in the configuration file.
        if header.name.eq_ignore_ascii_case(header_name) {
            let value = ::std::str::from_utf8(header.value)?;

            if !values.is_empty() {
                values.push_str(", ");
            }

            values.push_str(value);
        }
    }

    if values.is_empty() {
        return Err(anyhow::anyhow!("header not present"));
    }

    match header_format {
        ReverseProxyPeerIpHeaderFormat::LastAddress => {
            last_forwarded_for_ip(&values, trusted_proxies)
                .ok_or_else(|| anyhow::anyhow!("no valid ip in header"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_START: &str = "GET /announce?info_hash=%04%0bkV%3f%5cr%14%a6%b7%98%adC%c3%c9.%40%24%00%b9&peer_id=-ABC940-5ert69muw5t8&port=12345&uploaded=1&downloaded=2&left=3&numwant=0&key=4ab4b877&compact=1&supportcrypto=1&event=started HTTP/1.1\r\nHost: example.com\r\n";

    fn parse(config: &Config, trusted: &TrustedProxies, request: &str) -> ParsedRequest {
        parse_request(config, config.network.runs_behind_reverse_proxy, trusted, request.as_bytes())
            .unwrap()
    }

    #[test]
    fn test_parse_peer_ip_header_multiple() {
        let mut config = Config::default();

        config.network.runs_behind_reverse_proxy = true;
        config.network.reverse_proxy_ip_header_name = "X-Forwarded-For".into();
        config.network.reverse_proxy_ip_header_format = ReverseProxyPeerIpHeaderFormat::LastAddress;

        let mut request = REQUEST_START.to_string();

        request.push_str("X-Forwarded-For: 200.0.0.1\r\n");
        request.push_str("X-Forwarded-For: 1.2.3.4, 5.6.7.8,9.10.11.12\r\n");
        request.push_str("\r\n");

        let expected_ip = IpAddr::from([9, 10, 11, 12]);

        assert_eq!(
            parse(&config, &TrustedProxies::default(), &request)
                .opt_peer_ip
                .unwrap(),
            expected_ip
        )
    }

    #[test]
    fn test_parse_peer_ip_header_single() {
        let mut config = Config::default();

        config.network.runs_behind_reverse_proxy = true;
        config.network.reverse_proxy_ip_header_name = "X-Forwarded-For".into();
        config.network.reverse_proxy_ip_header_format = ReverseProxyPeerIpHeaderFormat::LastAddress;

        let mut request = REQUEST_START.to_string();

        request.push_str("X-Forwarded-For: 1.2.3.4, 5.6.7.8,9.10.11.12\r\n");
        request.push_str("X-Forwarded-For: 200.0.0.1\r\n");
        request.push_str("\r\n");

        let expected_ip = IpAddr::from([200, 0, 0, 1]);

        assert_eq!(
            parse(&config, &TrustedProxies::default(), &request)
                .opt_peer_ip
                .unwrap(),
            expected_ip
        )
    }

    #[test]
    fn test_parse_peer_ip_header_name_is_case_insensitive() {
        let mut config = Config::default();

        config.network.runs_behind_reverse_proxy = true;
        // Some proxies lower-case header names; the config may use any case.
        config.network.reverse_proxy_ip_header_name = "x-forwarded-for".into();
        config.network.reverse_proxy_ip_header_format = ReverseProxyPeerIpHeaderFormat::LastAddress;

        let mut request = REQUEST_START.to_string();

        request.push_str("X-Forwarded-For: 203.0.113.9\r\n");
        request.push_str("\r\n");

        assert_eq!(
            parse(&config, &TrustedProxies::default(), &request)
                .opt_peer_ip
                .unwrap(),
            IpAddr::from([203, 0, 113, 9])
        )
    }

    #[test]
    fn test_parse_peer_ip_header_no_header() {
        let mut config = Config::default();

        config.network.runs_behind_reverse_proxy = true;

        let mut request = REQUEST_START.to_string();

        request.push_str("\r\n");

        let res = parse_request(
            &config,
            true,
            &TrustedProxies::default(),
            request.as_bytes(),
        );

        assert!(matches!(
            res,
            Err(RequestParseError::RequiredPeerIpHeaderMissing(_))
        ));
    }

    #[test]
    fn test_untrusted_peer_ignores_forwarded_header() {
        let mut config = Config::default();

        config.network.runs_behind_reverse_proxy = true;
        config.network.reverse_proxy_ip_header_name = "X-Forwarded-For".into();

        let mut request = REQUEST_START.to_string();

        request.push_str("X-Forwarded-For: 203.0.113.9\r\n");
        request.push_str("\r\n");

        // A request from a peer that is not a trusted proxy must not be
        // attributed to a client-chosen address.
        let parsed = parse_request(
            &config,
            false,
            &TrustedProxies::default(),
            request.as_bytes(),
        )
        .unwrap();

        assert!(parsed.opt_peer_ip.is_none());
    }

    #[test]
    fn test_parse_condition_skips_trusted_proxy_hops() {
        let mut config = Config::default();

        config.network.runs_behind_reverse_proxy = true;
        config.network.reverse_proxy_ip_header_name = "X-Forwarded-For".into();

        let trusted = TrustedProxies::from_iter(vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.0.2.0/24".parse().unwrap(),
        ]);

        let mut request = REQUEST_START.to_string();

        request.push_str("X-Forwarded-For: 4.3.2.1, 10.1.1.1, 192.0.2.10\r\n");
        request.push_str("\r\n");

        assert_eq!(
            parse(&config, &trusted, &request).opt_peer_ip.unwrap(),
            IpAddr::from([4, 3, 2, 1])
        );
    }

    #[test]
    fn test_consumed_bytes_allow_pipelining() {
        let config = Config::default();

        let mut request = REQUEST_START.to_string();
        request.push_str("\r\n");

        let consumed = request.len();

        let mut pipelined = request.clone();
        pipelined.push_str(REQUEST_START);
        pipelined.push_str("\r\n");

        let parsed = parse_request(
            &config,
            false,
            &TrustedProxies::default(),
            pipelined.as_bytes(),
        )
        .unwrap();

        assert_eq!(parsed.consumed, consumed);
    }
}
