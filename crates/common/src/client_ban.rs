use std::path::{Path, PathBuf};
use std::sync::Arc;

use aquatic_toml_config::TomlConfig;
use arc_swap::{ArcSwap, Cache};
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};

use crate::list_file::read_list_file;

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
    /// Also ban the built-in list of known leech-only ("vampire") clients.
    ///
    /// The built-in prefixes (`-xl`, `-sd`, `-qd`, `-bn`, `-bc`, `-uw`,
    /// `-dt`, `-fg`, `-fs`) are applied in addition to the configured list.
    /// Set to false to leave the ban decision entirely to the list file.
    pub ban_vampire_clients: bool,
}

impl Default for ClientBanConfig {
    fn default() -> Self {
        Self {
            mode: ClientBanMode::Off,
            path: "./client-ban-list.txt".into(),
            ban_vampire_clients: true,
        }
    }
}

#[derive(Clone)]
pub struct ClientBanList {
    banned_patterns: HashSet<String>,
    ban_vampire_clients: bool,
}

impl Default for ClientBanList {
    fn default() -> Self {
        Self {
            banned_patterns: HashSet::new(),
            ban_vampire_clients: true,
        }
    }
}

impl ClientBanList {
    pub fn create_from_path(path: &Path, ban_vampire_clients: bool) -> anyhow::Result<Self> {
        let mut list = Self {
            banned_patterns: HashSet::new(),
            ban_vampire_clients,
        };

        for (_, line) in read_list_file(path)? {
            // peer_id prefixes are ASCII in practice; lowercasing once at load
            // time keeps the hot path allocation-light.
            list.banned_patterns.insert(line.to_ascii_lowercase());
        }

        Ok(list)
    }

    pub fn is_banned(&self, peer_id: &str) -> bool {
        // These prefixes are known leech-only ("vampire") clients. They apply
        // in addition to the configurable list so a stale list file cannot
        // silently re-enable them, unless the operator opts out.
        if self.ban_vampire_clients && is_vampire_client(peer_id) {
            return true;
        }

        if self.banned_patterns.is_empty() {
            return false;
        }

        let peer_id_lower = peer_id.to_ascii_lowercase();

        for pattern in &self.banned_patterns {
            if peer_id_lower.starts_with(pattern) {
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
        self.store(Arc::new(ClientBanList::create_from_path(
            &config.path,
            config.ban_vampire_clients,
        )?));
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

const VAMPIRE_PREFIXES: [&str; 9] = [
    "-xl", // 迅雷
    "-sd", // 迅雷
    "-qd", // QQ旋风
    "-bn", // BitComet
    "-bc", // BitComet
    "-uw", // uTorrent Web
    "-dt", // DotTorrent
    "-fg", // FlashGet
    "-fs", // FrostWire
];

pub fn is_vampire_client(peer_id: &str) -> bool {
    VAMPIRE_PREFIXES.iter().any(|prefix| {
        peer_id
            .get(..prefix.len())
            .map_or(false, |start| start.eq_ignore_ascii_case(prefix))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_ban() {
        let mut list = ClientBanList::default();
        list.banned_patterns.insert("-xl".to_string());
        list.banned_patterns.insert("-sd".to_string());

        // 应该被封禁（以 -xl 或 -sd 开头）
        assert!(list.is_banned("-XL0012-abc123"));
        assert!(list.is_banned("-SD1234-def456"));
        
        // 不应该被封禁（不以 -xl 或 -sd 开头）
        assert!(!list.is_banned("-UT1234-ghi789"));
        assert!(!list.is_banned("-TR7890-jkl012"));
        
        // 不应该被封禁（包含但不是开头）
        assert!(!list.is_banned("abc-xl-def"));
        assert!(!list.is_banned("some-sd-client"));
    }

    #[test]
    fn test_builtin_vampire_ban_applies_to_empty_list() {
        // An empty list file must still reject the built-in vampire clients,
        // otherwise the documented built-in detection is dead code.
        let list = ClientBanList::default();

        assert!(list.is_banned("-XL0012-abc123"));
        assert!(list.is_banned("-SD1234-def456"));
        assert!(list.is_banned("-QD5678-ghi012"));
        assert!(!list.is_banned("-UT3456-jkl345"));
        assert!(!list.is_banned("-TR7890-mno678"));
    }

    #[test]
    fn test_vampire_detection() {
        assert!(is_vampire_client("-XL0012-abc123"));
        assert!(is_vampire_client("-SD1234-def456"));
        assert!(is_vampire_client("-QD5678-ghi012"));
        assert!(!is_vampire_client("-UT3456-jkl345"));
        assert!(!is_vampire_client("-TR7890-mno678"));
    }

    #[test]
    fn test_vampire_ban_can_be_disabled() {
        let mut list = ClientBanList::default();
        list.ban_vampire_clients = false;

        assert!(!list.is_banned("-XL0012-abc123"));

        list.banned_patterns.insert("-xl".to_string());

        // An explicit list entry still applies.
        assert!(list.is_banned("-XL0012-abc123"));
    }

    #[test]
    fn test_load_tolerates_bom_comments_and_non_utf8() {
        let path = std::env::temp_dir().join("aquatic_client_ban_formats_test.txt");
        // A GBK-encoded comment, a BOM, CRLF, an inline comment and a pattern.
        std::fs::write(&path, b"\xc9\xa8\xc3\xe8\xc6\xf7\r\n\xef\xbb\xbf-MX # inline\r\n").unwrap();

        let list = ClientBanList::create_from_path(&path, false).unwrap();

        assert!(list.is_banned("-MX0001-abc"));
        assert!(!list.is_banned("-UT0001-abc"));

        let _ = std::fs::remove_file(&path);
    }
}
