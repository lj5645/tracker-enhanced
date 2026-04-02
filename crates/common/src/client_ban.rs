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
pub enum ClientBanMode {
    On,
    Off,
}

impl ClientBanMode {
    pub fn is_on(&self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Clone, Debug, PartialEq, TomlConfig, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientBanConfig {
    pub mode: ClientBanMode,
    pub path: PathBuf,
}

impl Default for ClientBanConfig {
    fn default() -> Self {
        Self {
            mode: ClientBanMode::Off,
            path: "./client-ban-list.txt".into(),
        }
    }
}

#[derive(Default, Clone)]
pub struct ClientBanList {
    banned_patterns: HashSet<String>,
}

impl ClientBanList {
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

            list.banned_patterns.insert(line.to_lowercase());
        }

        Ok(list)
    }

    pub fn is_banned(&self, peer_id: &str) -> bool {
        let peer_id_lower = peer_id.to_lowercase();
        
        for pattern in &self.banned_patterns {
            if peer_id_lower.contains(pattern) {
                return true;
            }
        }

        false
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.banned_patterns.len()
    }
}

pub trait ClientBanListQuery {
    fn update(&self, config: &ClientBanConfig) -> anyhow::Result<()>;
    fn is_banned(&self, peer_id: &str) -> bool;
}

pub type ClientBanListArcSwap = ArcSwap<ClientBanList>;
pub type ClientBanListCache = Cache<Arc<ClientBanListArcSwap>, Arc<ClientBanList>>;

impl ClientBanListQuery for ClientBanListArcSwap {
    fn update(&self, config: &ClientBanConfig) -> anyhow::Result<()> {
        self.store(Arc::new(ClientBanList::create_from_path(&config.path)?));
        Ok(())
    }

    fn is_banned(&self, peer_id: &str) -> bool {
        self.load().is_banned(peer_id)
    }
}

pub fn create_client_ban_list_cache(arc_swap: &Arc<ClientBanListArcSwap>) -> ClientBanListCache {
    Cache::from(Arc::clone(arc_swap))
}

pub fn update_client_ban_list(
    config: &ClientBanConfig,
    client_ban_list: &Arc<ClientBanListArcSwap>,
) -> anyhow::Result<()> {
    if config.mode.is_on() {
        match client_ban_list.update(config) {
            Ok(()) => {
                ::log::info!("Client ban list updated ({} entries)", client_ban_list.load().len());
            }
            Err(err) => {
                ::log::error!("Updating client ban list failed: {:#}", err);
                return Err(err);
            }
        }
    }

    Ok(())
}

pub fn is_vampire_client(peer_id: &str) -> bool {
    let vampire_prefixes = [
        "-xl",      // 迅雷
        "-sd",      // 迅雷
        "-qd",      // QQ旋风
        "-bn",      // BitComet
        "-bc",      // BitComet
        "-uw",      // uTorrent Web
        "-dt",      // DotTorrent
        "-fg",      // FlashGet
        "-fs",      // FrostWire
    ];

    let peer_id_lower = peer_id.to_lowercase();
    
    for prefix in &vampire_prefixes {
        if peer_id_lower.starts_with(prefix) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_ban() {
        let mut list = ClientBanList::default();
        list.banned_patterns.insert("-xl".to_string());
        list.banned_patterns.insert("vampire".to_string());

        assert!(list.is_banned("-XL0012-abc123"));
        assert!(list.is_banned("-SD1234-def456"));
        assert!(list.is_banned("some-vampire-client"));
        assert!(!list.is_banned("-UT1234-ghi789"));
    }

    #[test]
    fn test_vampire_detection() {
        assert!(is_vampire_client("-XL0012-abc123"));
        assert!(is_vampire_client("-SD1234-def456"));
        assert!(is_vampire_client("-QD5678-ghi012"));
        assert!(!is_vampire_client("-UT3456-jkl345"));
        assert!(!is_vampire_client("-TR7890-mno678"));
    }
}
