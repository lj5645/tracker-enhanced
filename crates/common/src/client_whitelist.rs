use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Arc;

use aquatic_toml_config::TomlConfig;
use arc_swap::{ArcSwap, Cache};
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, TomlConfig, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientWhitelistMode {
    On,
    Off,
}

impl ClientWhitelistMode {
    pub fn is_on(&self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Clone, Debug, PartialEq, TomlConfig, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientWhitelistConfig {
    pub mode: ClientWhitelistMode,
    pub path: PathBuf,
}

impl Default for ClientWhitelistConfig {
    fn default() -> Self {
        Self {
            mode: ClientWhitelistMode::Off,
            path: "./client-whitelist.txt".into(),
        }
    }
}

/// Client whitelist.
///
/// A single file can contain two kinds of entries:
///
/// - User-Agent patterns, matched case-insensitively as substrings.
/// - peer_id prefixes starting with `-`, matched case-insensitively as
///   prefixes (for example `-ut` for uTorrent, `-tr` for Transmission).
///
/// HTTP and WebSocket clients usually have a User-Agent, while UDP clients
/// only have a peer_id. Keeping both kinds in one file lets one whitelist
/// serve all three tracker protocols without silently blocking every client.
#[derive(Default, Clone)]
pub struct ClientWhitelist {
    user_agent_patterns: HashSet<String>,
    peer_id_prefixes: HashSet<String>,
}

impl ClientWhitelist {
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

            let line = line.to_lowercase();

            if line.starts_with('-') {
                list.peer_id_prefixes.insert(line);
            } else {
                list.user_agent_patterns.insert(line);
            }
        }

        Ok(list)
    }

    pub fn is_empty(&self) -> bool {
        self.user_agent_patterns.is_empty() && self.peer_id_prefixes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.user_agent_patterns.len() + self.peer_id_prefixes.len()
    }

    pub fn has_user_agent_patterns(&self) -> bool {
        !self.user_agent_patterns.is_empty()
    }

    pub fn has_peer_id_patterns(&self) -> bool {
        !self.peer_id_prefixes.is_empty()
    }

    /// Check a User-Agent against the User-Agent patterns.
    ///
    /// An empty whitelist allows everything (the loader rejects an empty
    /// enabled whitelist in production, but this keeps the helper safe to
    /// use in tests and for disabled whitelists).
    pub fn is_allowed(&self, user_agent: &str) -> bool {
        if self.is_empty() {
            return true;
        }

        self.matches_user_agent(user_agent)
    }

    /// Check a peer_id against the peer_id prefixes.
    pub fn is_peer_id_allowed(&self, peer_id: &str) -> bool {
        if self.is_empty() {
            return true;
        }

        self.matches_peer_id(peer_id)
    }

    pub fn matches_user_agent(&self, user_agent: &str) -> bool {
        let user_agent_lower = user_agent.to_lowercase();

        self.user_agent_patterns
            .iter()
            .any(|pattern| user_agent_lower.contains(pattern))
    }

    pub fn matches_peer_id(&self, peer_id: &str) -> bool {
        let peer_id_lower = peer_id.to_lowercase();

        self.peer_id_prefixes
            .iter()
            .any(|prefix| peer_id_lower.starts_with(prefix))
    }

    /// Protocol-neutral check used by HTTP, UDP and WebSocket.
    ///
    /// A client is allowed when any applicable pattern matches: peer_id
    /// prefixes for peer_id entries and User-Agent patterns for User-Agent
    /// entries. If a protocol cannot supply the value for a pattern type
    /// (for example UDP has no User-Agent), that pattern type is simply not
    /// evaluated. A whitelist containing only peer_id prefixes therefore
    /// allows connection handshakes/scrapes that have no peer_id; a
    /// whitelist containing only User-Agent patterns blocks requests without
    /// a User-Agent.
    pub fn allows(&self, peer_id: Option<&str>, user_agent: Option<&str>) -> bool {
        if self.is_empty() {
            return true;
        }

        let user_agent_match = user_agent
            .map(|value| self.matches_user_agent(value))
            .unwrap_or(false);

        let peer_id_match = peer_id
            .map(|value| self.matches_peer_id(value))
            .unwrap_or(false);

        match (self.has_user_agent_patterns(), self.has_peer_id_patterns()) {
            (true, true) => user_agent_match || peer_id_match,
            (true, false) => user_agent_match,
            (false, true) => {
                if peer_id.is_some() {
                    peer_id_match
                } else {
                    // No peer_id to evaluate (connect/scrape). A peer_id only
                    // whitelist must not block requests that carry no peer_id.
                    true
                }
            }
            (false, false) => true,
        }
    }
}

pub trait ClientWhitelistQuery {
    fn update(&self, config: &ClientWhitelistConfig) -> anyhow::Result<()>;
    fn is_allowed(&self, user_agent: &str) -> bool;
    fn allows(&self, peer_id: Option<&str>, user_agent: Option<&str>) -> bool;
}

pub type ClientWhitelistArcSwap = ArcSwap<ClientWhitelist>;
pub type ClientWhitelistCache = Cache<Arc<ClientWhitelistArcSwap>, Arc<ClientWhitelist>>;

impl ClientWhitelistQuery for ClientWhitelistArcSwap {
    fn update(&self, config: &ClientWhitelistConfig) -> anyhow::Result<()> {
        let list = ClientWhitelist::create_from_path(&config.path)?;

        if list.is_empty() {
            return Err(anyhow::anyhow!(
                "client whitelist is enabled but '{}' contains no patterns; \
                 refusing to start with an empty whitelist (this would allow every client)",
                config.path.display()
            ));
        }

        self.store(Arc::new(list));
        Ok(())
    }

    fn is_allowed(&self, user_agent: &str) -> bool {
        self.load().is_allowed(user_agent)
    }

    fn allows(&self, peer_id: Option<&str>, user_agent: Option<&str>) -> bool {
        self.load().allows(peer_id, user_agent)
    }
}

pub fn create_client_whitelist_cache(arc_swap: &Arc<ClientWhitelistArcSwap>) -> ClientWhitelistCache {
    Cache::from(Arc::clone(arc_swap))
}

pub fn update_client_whitelist(
    config: &ClientWhitelistConfig,
    client_whitelist: &Arc<ClientWhitelistArcSwap>,
) -> anyhow::Result<()> {
    if config.mode.is_on() {
        match client_whitelist.update(config) {
            Ok(()) => {
                ::log::info!(
                    "Client whitelist updated ({} entries)",
                    client_whitelist.load().len()
                );
            }
            Err(err) => {
                ::log::error!("Updating client whitelist failed: {:#}", err);
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
    fn test_client_whitelist() {
        let mut list = ClientWhitelist::default();
        list.user_agent_patterns.insert("utorrent".to_string());
        list.user_agent_patterns.insert("transmission".to_string());
        list.user_agent_patterns.insert("qbittorrent".to_string());

        assert!(list.is_allowed("uTorrent/3.5.5"));
        assert!(list.is_allowed("Transmission/3.00"));
        assert!(list.is_allowed("qBittorrent/4.5.0"));

        assert!(!list.is_allowed("curl/7.68.0"));
        assert!(!list.is_allowed("python-requests/2.28.0"));
        assert!(!list.is_allowed("UnknownClient/1.0"));
    }

    #[test]
    fn test_empty_whitelist() {
        let list = ClientWhitelist::default();

        // Empty list allows everything in the helper layer. The config loader
        // rejects an empty list when the whitelist is enabled.
        assert!(list.is_allowed("uTorrent/3.5.5"));
        assert!(list.is_allowed("curl/7.68.0"));
        assert!(list.allows(Some("-UT1234-abc"), Some("curl/7.68.0")));
    }

    #[test]
    fn test_peer_id_patterns() {
        let mut list = ClientWhitelist::default();
        list.peer_id_prefixes.insert("-ut".to_string());
        list.peer_id_prefixes.insert("-tr".to_string());

        assert!(list.is_peer_id_allowed("-UT1234-abc123"));
        assert!(list.is_peer_id_allowed("-TR7890-def456"));
        assert!(!list.is_peer_id_allowed("-qB1234-ghi789"));

        // UDP announce: peer_id is available.
        assert!(list.allows(Some("-UT1234-abc123"), None));
        assert!(!list.allows(Some("-qB1234-ghi789"), None));

        // UDP connect/scrape: no peer_id, so a peer_id-only list cannot
        // evaluate and must not block.
        assert!(list.allows(None, None));
    }

    #[test]
    fn test_combined_whitelist_allows_either_protocol_value() {
        let mut list = ClientWhitelist::default();
        list.user_agent_patterns.insert("qbittorrent".to_string());
        list.peer_id_prefixes.insert("-tr".to_string());

        assert!(list.allows(Some("-TR1234-abc"), None));
        assert!(list.allows(None, Some("qBittorrent/4.5.0")));
        assert!(list.allows(Some("-TR1234-abc"), Some("qBittorrent/4.5.0")));
        assert!(!list.allows(Some("-qB1234-abc"), Some("unknown/1.0")));
    }

    #[test]
    fn test_user_agent_only_whitelist_blocks_missing_ua() {
        let mut list = ClientWhitelist::default();
        list.user_agent_patterns.insert("qbittorrent".to_string());

        assert!(list.allows(None, Some("qBittorrent/4.5.0")));
        assert!(!list.allows(None, None));
        // A peer_id does not satisfy a User-Agent-only whitelist.
        assert!(!list.allows(Some("-TR1234-abc"), None));
    }
}
