use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aquatic_toml_config::TomlConfig;
use arc_swap::{ArcSwap, Cache};
use hashbrown::HashSet;
use serde::{Deserialize, Serialize};

use crate::auto_ban::AutoBanConfig;
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

/// How a client identity check reacts to a suspicious peer id.
///
/// `Warn` only logs (rate limited) and lets the request through, so operators
/// can observe false positives before switching to `Enforce`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TomlConfig, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerIdCheckMode {
    Off,
    Warn,
    Enforce,
}

impl PeerIdCheckMode {
    pub fn is_off(&self) -> bool {
        matches!(self, Self::Off)
    }

    pub fn is_enforce(&self) -> bool {
        matches!(self, Self::Enforce)
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
    /// `-dt`, `-fg`, `-fw`) are applied in addition to the configured list.
    /// Set to false to leave the ban decision entirely to the list file.
    pub ban_vampire_clients: bool,
    /// Structural peer id validation.
    ///
    /// Checks whether the announce peer id is a well-formed Azureus-style
    /// (`-XX1234-...`) or Mainline-style (`M4-3-0--...`) id, and whether the
    /// client version is plausible. This is independent of `mode`: the checks
    /// work even when the ban list itself is disabled.
    ///
    /// `off` does nothing, `warn` only logs and lets the request through,
    /// `enforce` rejects the announce.
    pub peer_id_strictness: PeerIdCheckMode,
    /// Compare the client family claimed by the peer id with the family
    /// claimed by the User-Agent (HTTP and WebSocket only).
    ///
    /// Only applies when the User-Agent names a known BitTorrent client, so
    /// browsers (WebTorrent in a tab) and unknown downloaders are not flagged.
    /// `off` does nothing, `warn` only logs, `enforce` rejects the announce.
    pub peer_id_user_agent_mismatch: PeerIdCheckMode,
    /// Optional file with extra peer id prefixes that are considered valid.
    ///
    /// One prefix per line, matched case-insensitively at the start of the
    /// peer id. Intended for legitimate clients whose ids are not in the
    /// built-in format tables, or whose User-Agent is misread. Exempts the
    /// client from both `peer_id_strictness` and
    /// `peer_id_user_agent_mismatch`.
    pub peer_id_allowlist_path: PathBuf,
}

impl Default for ClientBanConfig {
    fn default() -> Self {
        Self {
            mode: ClientBanMode::Off,
            path: "./client-ban-list.txt".into(),
            ban_vampire_clients: true,
            peer_id_strictness: PeerIdCheckMode::Off,
            peer_id_user_agent_mismatch: PeerIdCheckMode::Off,
            peer_id_allowlist_path: PathBuf::new(),
        }
    }
}

/// Result of a client identity check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityCheck {
    /// No problem found.
    Ok,
    /// A problem was found and logged, but the request may proceed.
    Warned,
    /// A problem was found and the request must be rejected.
    Rejected,
}

#[derive(Clone)]
pub struct ClientBanList {
    banned_patterns: HashSet<String>,
    /// Lowercased peer id prefixes that bypass `peer_id_strictness`.
    allowed_peer_id_prefixes: HashSet<String>,
    ban_vampire_clients: bool,
}

impl Default for ClientBanList {
    fn default() -> Self {
        Self {
            banned_patterns: HashSet::new(),
            allowed_peer_id_prefixes: HashSet::new(),
            ban_vampire_clients: true,
        }
    }
}

impl ClientBanList {
    pub fn create_from_path(path: &Path, ban_vampire_clients: bool) -> anyhow::Result<Self> {
        Self::create(Some(path), ban_vampire_clients, None)
    }

    /// Create a list from an optional ban list and an optional peer id
    /// allowlist. `None` means "do not read that file".
    pub fn create(
        ban_list_path: Option<&Path>,
        ban_vampire_clients: bool,
        allowlist_path: Option<&Path>,
    ) -> anyhow::Result<Self> {
        let mut list = Self {
            banned_patterns: HashSet::new(),
            allowed_peer_id_prefixes: HashSet::new(),
            ban_vampire_clients,
        };

        if let Some(path) = ban_list_path {
            for (_, line) in read_list_file(path)? {
                // peer_id prefixes are ASCII in practice; lowercasing once at
                // load time keeps the hot path allocation-light.
                list.banned_patterns.insert(line.to_ascii_lowercase());
            }
        }

        if let Some(path) = allowlist_path {
            for (line_number, line) in read_list_file(path)? {
                if line.len() > 20 {
                    ::log::warn!(
                        "Ignoring peer id allowlist entry at line {}: longer than 20 bytes",
                        line_number
                    );
                    continue;
                }

                list.allowed_peer_id_prefixes
                    .insert(line.to_ascii_lowercase());
            }
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

    pub fn is_peer_id_allowlisted(&self, peer_id: &[u8; 20]) -> bool {
        self.allowed_peer_id_prefixes.iter().any(|prefix| {
            let bytes = prefix.as_bytes();

            bytes.len() <= peer_id.len() && peer_id[..bytes.len()].eq_ignore_ascii_case(bytes)
        })
    }

    /// Check the structural validity of a peer id and the plausibility of the
    /// client version it claims.
    pub fn check_peer_id_format(
        &self,
        peer_id: &[u8; 20],
        mode: PeerIdCheckMode,
    ) -> IdentityCheck {
        if mode.is_off() || self.is_peer_id_allowlisted(peer_id) {
            return IdentityCheck::Ok;
        }

        let issue = match classify_peer_id(peer_id) {
            PeerIdStyle::Mainline => return IdentityCheck::Ok,
            PeerIdStyle::Unknown => PeerIdIssue::NonStandard,
            PeerIdStyle::Azureus => match implausible_version(peer_id) {
                Some(issue) => PeerIdIssue::UnsupportedVersion(issue),
                None => return IdentityCheck::Ok,
            },
        };

        report_identity_issue(issue, mode)
    }

    /// Check that the client family claimed by the peer id matches the one
    /// claimed by the User-Agent.
    ///
    /// Unknown peer id codes and unknown User-Agents are ignored, so clients
    /// without a recognizable identity are never flagged here.
    pub fn check_peer_id_user_agent(
        &self,
        peer_id: &[u8; 20],
        user_agent: &str,
        mode: PeerIdCheckMode,
    ) -> IdentityCheck {
        // The allowlist is the escape hatch for false positives. It has to
        // apply here as well, otherwise a client misdetected by its
        // User-Agent could only be exempted by disabling the check.
        if mode.is_off() || self.is_peer_id_allowlisted(peer_id) {
            return IdentityCheck::Ok;
        }

        let peer_id_family = match peer_id_family(peer_id) {
            Some(family) => family,
            None => return IdentityCheck::Ok,
        };
        let user_agent_family = match user_agent_family(user_agent) {
            Some(family) => family,
            None => return IdentityCheck::Ok,
        };

        if peer_id_family == user_agent_family {
            return IdentityCheck::Ok;
        }

        report_identity_issue(
            PeerIdIssue::UserAgentMismatch {
                peer_id_family,
                user_agent_family,
            },
            mode,
        )
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.banned_patterns.len()
    }

    pub fn allowlist_len(&self) -> usize {
        self.allowed_peer_id_prefixes.len()
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
        // The ban list is only read when it is enabled. The allowlist is
        // independent so `peer_id_strictness` can be used with `mode = off`.
        let ban_list_path = if config.mode.is_on() {
            Some(config.path.as_path())
        } else {
            None
        };
        let allowlist_path = if config.peer_id_allowlist_path.as_os_str().is_empty() {
            None
        } else {
            Some(config.peer_id_allowlist_path.as_path())
        };

        self.store(Arc::new(ClientBanList::create(
            ban_list_path,
            config.ban_vampire_clients,
            allowlist_path,
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
    // An allowlist has to be reloaded even when the ban list is disabled.
    let needs_ban_list = config.mode.is_on();
    let needs_allowlist = !config.peer_id_allowlist_path.as_os_str().is_empty();

    if needs_ban_list || needs_allowlist {
        match client_ban_list.update(config) {
            Ok(()) => {
                let list = client_ban_list.load();

                ::log::info!(
                    "Client ban list updated ({} entries, {} peer id allowlist entries)",
                    list.len(),
                    list.allowlist_len()
                );
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
    "-fw", // FrostWire
];

pub fn is_vampire_client(peer_id: &str) -> bool {
    VAMPIRE_PREFIXES.iter().any(|prefix| {
        peer_id
            .get(..prefix.len())
            .map_or(false, |start| start.eq_ignore_ascii_case(prefix))
    })
}

/// Shape of a peer id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerIdStyle {
    /// `-XX1234-` followed by twelve arbitrary bytes.
    Azureus,
    /// `M4-3-0--` style used by the original BitTorrent client.
    Mainline,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionIssue {
    /// Two-letter client code, e.g. `UT`.
    pub code: String,
    /// Major version claimed by the peer id.
    pub version: u8,
    /// Highest major version known for this client family.
    pub max_version: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerClientFamily {
    UTorrent,
    Transmission,
    QBittorrent,
    Deluge,
    Vuze,
    Libtorrent,
    WebTorrent,
    BitTorrent,
}

impl PeerClientFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UTorrent => "uTorrent",
            Self::Transmission => "Transmission",
            Self::QBittorrent => "qBittorrent",
            Self::Deluge => "Deluge",
            Self::Vuze => "Vuze",
            Self::Libtorrent => "libtorrent",
            Self::WebTorrent => "WebTorrent",
            Self::BitTorrent => "BitTorrent",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerIdIssue {
    NonStandard,
    UnsupportedVersion(VersionIssue),
    UserAgentMismatch {
        peer_id_family: PeerClientFamily,
        user_agent_family: PeerClientFamily,
    },
}

impl PeerIdIssue {
    pub fn describe(&self) -> String {
        match self {
            Self::NonStandard => "peer id is not Azureus- or Mainline-style".to_string(),
            Self::UnsupportedVersion(issue) => format!(
                "peer id claims {} major version {}, but the highest known version is {}",
                issue.code, issue.version, issue.max_version
            ),
            Self::UserAgentMismatch {
                peer_id_family,
                user_agent_family,
            } => format!(
                "peer id claims {}, but User-Agent claims {}",
                peer_id_family.as_str(),
                user_agent_family.as_str()
            ),
        }
    }
}

pub fn classify_peer_id(peer_id: &[u8; 20]) -> PeerIdStyle {
    if is_azureus_style(peer_id) {
        PeerIdStyle::Azureus
    } else if is_mainline_style(peer_id) {
        PeerIdStyle::Mainline
    } else {
        PeerIdStyle::Unknown
    }
}

fn is_azureus_style(peer_id: &[u8; 20]) -> bool {
    peer_id[0] == b'-'
        && peer_id[1].is_ascii_alphabetic()
        && peer_id[2].is_ascii_alphabetic()
        // Real clients use hex digits in the version part (`-lt0D80-`), so
        // accept any alphanumeric rather than only decimal digits.
        && peer_id[3..7].iter().all(|byte| byte.is_ascii_alphanumeric())
        && peer_id[7] == b'-'
}

fn is_mainline_style(peer_id: &[u8; 20]) -> bool {
    peer_id[0].is_ascii_alphabetic()
        && peer_id[1..7]
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b'-')
        && peer_id[7] == b'-'
}

/// Two-letter client code, uppercased, for Azureus-style peer ids.
fn peer_id_code(peer_id: &[u8; 20]) -> Option<[u8; 2]> {
    if !is_azureus_style(peer_id) {
        return None;
    }

    Some([
        peer_id[1].to_ascii_uppercase(),
        peer_id[2].to_ascii_uppercase(),
    ])
}

fn max_major_version(code: &[u8; 2]) -> Option<u8> {
    match code {
        b"UT" | b"UE" | b"UM" | b"UW" => Some(3), // uTorrent 3.x
        b"TR" => Some(4),                          // Transmission 4.x
        b"QB" => Some(5),                          // qBittorrent 5.x
        b"DE" => Some(2),                          // Deluge 2.x
        b"AZ" => Some(5),                          // Vuze 5.x
        b"LT" => Some(2),                          // libtorrent 2.x
        // WebTorrent and BitTorrent use several version schemes; checking
        // their major version would produce false positives.
        _ => None,
    }
}

fn implausible_version(peer_id: &[u8; 20]) -> Option<VersionIssue> {
    let code = peer_id_code(peer_id)?;
    let max_version = max_major_version(&code)?;
    let version_byte = peer_id[3];

    if !version_byte.is_ascii_digit() {
        return None;
    }

    let version = version_byte - b'0';

    if version > max_version {
        Some(VersionIssue {
            code: String::from_utf8_lossy(&code).into_owned(),
            version,
            max_version,
        })
    } else {
        None
    }
}

pub fn peer_id_family(peer_id: &[u8; 20]) -> Option<PeerClientFamily> {
    let code = peer_id_code(peer_id)?;

    match &code {
        b"UT" | b"UE" | b"UM" | b"UW" => Some(PeerClientFamily::UTorrent),
        b"TR" => Some(PeerClientFamily::Transmission),
        b"QB" => Some(PeerClientFamily::QBittorrent),
        b"DE" => Some(PeerClientFamily::Deluge),
        b"AZ" => Some(PeerClientFamily::Vuze),
        b"LT" => Some(PeerClientFamily::Libtorrent),
        b"WW" | b"WD" => Some(PeerClientFamily::WebTorrent),
        b"BT" => Some(PeerClientFamily::BitTorrent),
        _ => None,
    }
}

/// Client family named by a User-Agent, if any.
///
/// Only names that identify a BitTorrent client are recognized. Browsers and
/// unknown downloaders return `None`, which disables the mismatch check for
/// them (WebTorrent running in a browser sends a browser User-Agent).
pub fn user_agent_family(user_agent: &str) -> Option<PeerClientFamily> {
    let user_agent = user_agent.to_ascii_lowercase();

    // qBittorrent and uTorrent both contain "bittorrent", so check the most
    // specific names first.
    if user_agent.contains("qbittorrent") {
        Some(PeerClientFamily::QBittorrent)
    } else if user_agent.contains("utorrent") || user_agent.contains("µtorrent") {
        Some(PeerClientFamily::UTorrent)
    } else if user_agent.contains("transmission") {
        Some(PeerClientFamily::Transmission)
    } else if user_agent.contains("deluge") {
        Some(PeerClientFamily::Deluge)
    } else if user_agent.contains("vuze") || user_agent.contains("azureus") {
        Some(PeerClientFamily::Vuze)
    } else if user_agent.contains("libtorrent") {
        Some(PeerClientFamily::Libtorrent)
    } else if user_agent.contains("webtorrent") {
        Some(PeerClientFamily::WebTorrent)
    } else if user_agent.contains("bittorrent") {
        // Checked last because qBittorrent and uTorrent contain this substring.
        Some(PeerClientFamily::BitTorrent)
    } else {
        None
    }
}

const IDENTITY_LOG_INTERVAL_SECS: u64 = 60;

// Separate windows so a flood of warn-mode messages cannot hide the fact that
// announce requests are actually being rejected.
static LAST_IDENTITY_WARNING: AtomicU64 = AtomicU64::new(0);
static LAST_IDENTITY_REJECTION: AtomicU64 = AtomicU64::new(0);

fn report_identity_issue(issue: PeerIdIssue, mode: PeerIdCheckMode) -> IdentityCheck {
    if mode.is_enforce() {
        // Rejections must be visible at the default log level: without this,
        // users report "I cannot connect" while the server logs nothing.
        warn_rate_limited(
            &LAST_IDENTITY_REJECTION,
            &format!("client rejected: {}", issue.describe()),
        );
        IdentityCheck::Rejected
    } else {
        warn_rate_limited(
            &LAST_IDENTITY_WARNING,
            &format!("client warning: {}", issue.describe()),
        );
        IdentityCheck::Warned
    }
}

/// Log at most one identity message per minute per category.
///
/// Checks are meant to be left enabled while observing false positives, so an
/// unthrottled `warn!` could flood the log under load.
fn warn_rate_limited(last_log: &AtomicU64, message: &str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let last = last_log.load(Ordering::Relaxed);

    if now.saturating_sub(last) >= IDENTITY_LOG_INTERVAL_SECS
        && last_log
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        ::log::warn!("{}", message);
    }
}

/// Warn when identity checks can feed the auto-ban system.
///
/// In `enforce` mode a rejected announce counts as an auto-ban violation. A
/// false positive (stale version table, customized User-Agent, a client the
/// allowlist does not cover) can therefore turn into a permanent IP ban within
/// one threshold window, so make the combination explicit at startup.
pub fn warn_about_identity_enforce_with_auto_ban(
    client_ban: &ClientBanConfig,
    auto_ban: &AutoBanConfig,
) {
    if !auto_ban.enabled {
        return;
    }

    let mut enforced = Vec::new();

    if client_ban.peer_id_strictness.is_enforce() {
        enforced.push("peer_id_strictness");
    }

    if client_ban.peer_id_user_agent_mismatch.is_enforce() {
        enforced.push("peer_id_user_agent_mismatch");
    }

    if enforced.is_empty() {
        return;
    }

    ::log::warn!(
        "{} set to \"enforce\" while auto_ban is enabled: every rejected announce counts as \
         a violation, so a false positive can ban an IP within {} second(s). Run these checks \
         in \"warn\" mode first and add known-good peer ids to peer_id_allowlist_path.",
        enforced.join(", "),
        auto_ban.window_secs,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_id(bytes: &[u8; 20]) -> [u8; 20] {
        *bytes
    }

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
        assert!(is_vampire_client("-FW0012-abc123"));
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

    #[test]
    fn test_peer_id_styles() {
        assert_eq!(
            classify_peer_id(b"-UT3550-abcdefghijkl"),
            PeerIdStyle::Azureus
        );
        assert_eq!(
            classify_peer_id(b"-lt0D80-abcdefghijkl"),
            PeerIdStyle::Azureus
        );
        assert_eq!(
            classify_peer_id(b"M4-3-0--abcdefghijkl"),
            PeerIdStyle::Mainline
        );
        assert_eq!(
            classify_peer_id(b"not-a-peer-id-123456"),
            PeerIdStyle::Unknown
        );
    }

    #[test]
    fn test_standard_peer_ids_are_accepted() {
        let list = ClientBanList::default();

        for peer_id in [
            b"-UT3550-abcdefghijkl",
            b"-TR4050-abcdefghijkl",
            b"-qB4600-abcdefghijkl",
            b"-DE2130-abcdefghijkl",
            b"-AZ5700-abcdefghijkl",
            b"-lt2000-abcdefghijkl",
            b"M4-3-0--abcdefghijkl",
        ] {
            assert_eq!(
                list.check_peer_id_format(peer_id, PeerIdCheckMode::Enforce),
                IdentityCheck::Ok,
                "{:?} should not be flagged",
                String::from_utf8_lossy(peer_id)
            );
        }
    }

    #[test]
    fn test_non_standard_peer_ids() {
        let list = ClientBanList::default();

        assert_eq!(
            list.check_peer_id_format(b"not-a-peer-id-123456", PeerIdCheckMode::Warn),
            IdentityCheck::Warned
        );
        assert_eq!(
            list.check_peer_id_format(b"not-a-peer-id-123456", PeerIdCheckMode::Enforce),
            IdentityCheck::Rejected
        );
        // `off` ignores the problem entirely.
        assert_eq!(
            list.check_peer_id_format(b"not-a-peer-id-123456", PeerIdCheckMode::Off),
            IdentityCheck::Ok
        );
    }

    #[test]
    fn test_implausible_versions() {
        let list = ClientBanList::default();

        assert_eq!(
            list.check_peer_id_format(b"-UT9999-abcdefghijkl", PeerIdCheckMode::Enforce),
            IdentityCheck::Rejected
        );
        assert_eq!(
            list.check_peer_id_format(b"-TR9000-abcdefghijkl", PeerIdCheckMode::Enforce),
            IdentityCheck::Rejected
        );
        // Versions at the known maximum (or below) are accepted.
        assert_eq!(
            list.check_peer_id_format(b"-UT3999-abcdefghijkl", PeerIdCheckMode::Enforce),
            IdentityCheck::Ok
        );
        // Unknown client codes cannot be version-checked.
        assert_eq!(
            list.check_peer_id_format(b"-ZZ9999-abcdefghijkl", PeerIdCheckMode::Enforce),
            IdentityCheck::Ok
        );
    }

    #[test]
    fn test_allowlist_bypasses_strictness() {
        let mut list = ClientBanList::default();
        list.allowed_peer_id_prefixes
            .insert("-zz".to_string());

        assert!(list.is_peer_id_allowlisted(b"-ZZ9999-abcdefghijkl"));
        assert_eq!(
            list.check_peer_id_format(b"-ZZ9999-abcdefghijkl", PeerIdCheckMode::Enforce),
            IdentityCheck::Ok
        );
        // The allowlist does not magically make a broken id valid.
        assert_eq!(
            list.check_peer_id_format(b"not-a-peer-id-123456", PeerIdCheckMode::Enforce),
            IdentityCheck::Rejected
        );
    }

    #[test]
    fn test_user_agent_mismatch() {
        let list = ClientBanList::default();

        // qBittorrent peer id with a Transmission User-Agent.
        assert_eq!(
            list.check_peer_id_user_agent(
                b"-qB4600-abcdefghijkl",
                "Transmission/4.0.2",
                PeerIdCheckMode::Enforce
            ),
            IdentityCheck::Rejected
        );
        // Matching names are accepted.
        assert_eq!(
            list.check_peer_id_user_agent(
                b"-qB4600-abcdefghijkl",
                "qBittorrent/4.6.0",
                PeerIdCheckMode::Enforce
            ),
            IdentityCheck::Ok
        );
        // qBittorrent contains "bittorrent" but must not be read as BitTorrent.
        assert_eq!(
            list.check_peer_id_user_agent(
                b"-qB4600-abcdefghijkl",
                "BitTorrent/7.10",
                PeerIdCheckMode::Enforce
            ),
            IdentityCheck::Rejected
        );
    }

    #[test]
    fn test_allowlist_bypasses_user_agent_mismatch() {
        let mut list = ClientBanList::default();
        list.allowed_peer_id_prefixes
            .insert("-qb".to_string());

        assert_eq!(
            list.check_peer_id_user_agent(
                b"-qB4600-abcdefghijkl",
                "Transmission/4.0.2",
                PeerIdCheckMode::Enforce
            ),
            IdentityCheck::Ok
        );
        // A different peer id is still checked.
        assert_eq!(
            list.check_peer_id_user_agent(
                b"-TR4050-abcdefghijkl",
                "qBittorrent/4.6.0",
                PeerIdCheckMode::Enforce
            ),
            IdentityCheck::Rejected
        );
    }

    #[test]
    fn test_user_agent_mismatch_skips_unknown_identities() {
        let list = ClientBanList::default();

        // Browser User-Agent (WebTorrent in a tab): not flagged.
        assert_eq!(
            list.check_peer_id_user_agent(
                b"-WW0102-abcdefghijkl",
                "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
                PeerIdCheckMode::Enforce
            ),
            IdentityCheck::Ok
        );
        // Unknown peer id code: not flagged.
        assert_eq!(
            list.check_peer_id_user_agent(
                b"-ZZ1234-abcdefghijkl",
                "qBittorrent/4.6.0",
                PeerIdCheckMode::Enforce
            ),
            IdentityCheck::Ok
        );
    }
}
