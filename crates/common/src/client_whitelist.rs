use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
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

#[derive(Clone, Debug, PartialEq, TomlConfig, Deserialize, Serialize)]
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

#[derive(Default, Clone)]
pub struct ClientWhitelist {
    allowed_patterns: HashSet<String>,
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

            list.allowed_patterns.insert(line.to_lowercase());
        }

        Ok(list)
    }

    pub fn is_allowed(&self, user_agent: &str) -> bool {
        if self.allowed_patterns.is_empty() {
            return true;
        }

        let ua_lower = user_agent.to_lowercase();

        for pattern in &self.allowed_patterns {
            if ua_lower.contains(pattern) {
                return true;
            }
        }

        false
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.allowed_patterns.len()
    }
}

pub trait ClientWhitelistQuery {
    fn update(&self, config: &ClientWhitelistConfig) -> anyhow::Result<()>;
    fn is_allowed(&self, user_agent: &str) -> bool;
}

pub type ClientWhitelistArcSwap = ArcSwap<ClientWhitelist>;
pub type ClientWhitelistCache = Cache<Arc<ClientWhitelistArcSwap>, Arc<ClientWhitelist>>;

impl ClientWhitelistQuery for ClientWhitelistArcSwap {
    fn update(&self, config: &ClientWhitelistConfig) -> anyhow::Result<()> {
        self.store(Arc::new(ClientWhitelist::create_from_path(&config.path)?));
        Ok(())
    }

    fn is_allowed(&self, user_agent: &str) -> bool {
        self.load().is_allowed(user_agent)
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
                ::log::info!("Client whitelist updated ({} entries)", client_whitelist.load().len());
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
        list.allowed_patterns.insert("utorrent".to_string());
        list.allowed_patterns.insert("transmission".to_string());
        list.allowed_patterns.insert("qbittorrent".to_string());

        // 应该允许（在白名单中）
        assert!(list.is_allowed("uTorrent/3.5.5"));
        assert!(list.is_allowed("Transmission/3.00"));
        assert!(list.is_allowed("qBittorrent/4.5.0"));

        // 不应该允许（不在白名单中）
        assert!(!list.is_allowed("curl/7.68.0"));
        assert!(!list.is_allowed("python-requests/2.28.0"));
        assert!(!list.is_allowed("UnknownClient/1.0"));
    }

    #[test]
    fn test_empty_whitelist() {
        let list = ClientWhitelist::default();

        // 空白名单应该允许所有请求
        assert!(list.is_allowed("uTorrent/3.5.5"));
        assert!(list.is_allowed("curl/7.68.0"));
        assert!(list.is_allowed("UnknownClient/1.0"));
    }
}
