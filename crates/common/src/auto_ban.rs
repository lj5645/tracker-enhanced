use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aquatic_toml_config::TomlConfig;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use crate::ip_ban::IpBanConfig;

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
    /// Ban duration in seconds. Use 0 for permanent ban (the default).
    ///
    /// Permanent bans (`0`) are appended to `ban_list_path` immediately, so
    /// they survive a restart. `ban_list_path` must be non-empty and equal to
    /// `ip_ban.path` with `ip_ban.mode = "on"`, otherwise the server refuses
    /// to start: a ban that is never reloaded would silently be lost.
    ///
    /// Note: When ban_duration_secs > 0 (temporary ban), auto-banned IPs are
    /// NOT written to the ban_list_path file because the file format doesn't
    /// support expiration times. Temporary bans are only kept in memory and
    /// will be lost on restart.
    pub ban_duration_secs: u64,
    /// Path to write permanently auto-banned IPs (one IP per line). Each ban
    /// is appended as soon as it happens; failed writes are retried by the
    /// periodic flush.
    pub ban_list_path: PathBuf,
    /// Interval in seconds for the periodic flush (retrying failed writes),
    /// reloading ip_ban_list and removing records that ip_ban_list now covers.
    /// Minimum value is 1.
    pub flush_interval_secs: u64,
    /// Ban duration in seconds for the first high-severity violation
    /// (SQL injection, path traversal, banned client). `0` — the default —
    /// means "inherit `ban_duration_secs`".
    ///
    /// Set a short value (for example 3600) if you prefer a reversible first
    /// strike: a misconfigured reverse proxy makes every request look like it
    /// comes from the proxy address, and a permanent ban would then lock out
    /// the whole entry point.
    pub immediate_ban_secs: u64,
    /// Escalate repeated offences to longer bans, ending in a permanent ban.
    ///
    /// Off by default: enabling it means permanent bans become possible even
    /// when `ban_duration_secs` is non-zero, which in turn requires a
    /// persistable ban list (see `validate_auto_ban_config`).
    pub escalation_enabled: bool,
    /// Ban durations, in seconds, for the 1st, 2nd, ... escalated offence of a
    /// heuristic violation (non-standard peer id, peer id / User-Agent
    /// mismatch). Comma-separated. Once the list is exhausted the next offence
    /// is banned permanently. Empty means "use `ban_duration_secs`".
    pub escalation_steps: String,
    /// Seconds without a new offence after which an IP's offence history is
    /// forgotten, so it starts again at the first step of the ladder.
    pub offense_decay_secs: u64,
    /// Ban duration for `client_banned` violations, in seconds. These bans are
    /// always temporary and never escalate to a permanent ban, so a client
    /// that is merely unwanted (Thunder, BitComet, ...) cannot get an address
    /// locked out forever.
    ///
    /// `0` means "inherit `immediate_ban_secs`" and therefore keeps the
    /// historical behaviour.
    pub client_ban_duration_secs: u64,
    /// Maximum random offset added to (or subtracted from) a client ban's
    /// expiry, in seconds. Spreading expiries avoids a request spike when a
    /// whole batch of bans written during one incident expires at the same
    /// moment.
    pub client_ban_jitter_secs: u64,
    /// File holding client-ban IPs with their expiry timestamps, one
    /// `<ip> <unix_seconds>` pair per line. Empty means memory-only.
    pub client_ban_list_path: PathBuf,
}

impl Default for AutoBanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: 10,
            window_secs: 60,
            // Default to permanent bans: a temporary ban is memory-only, so
            // enabling auto_ban without specifying a duration would silently
            // stop protecting the server after a restart.
            ban_duration_secs: 0,
            ban_list_path: PathBuf::from("./ip-ban-list.txt"),
            flush_interval_secs: 60,
            // Inherit `ban_duration_secs`: a permanent default duration must
            // not silently turn into a temporary high-severity ban.
            immediate_ban_secs: 0,
            escalation_enabled: false,
            escalation_steps: String::from("300,3600,86400"),
            offense_decay_secs: 86_400,
            // One day, matching the intent of "punish the client, not the
            // address forever".
            client_ban_duration_secs: 86_400,
            // Half an hour of spread, so 24h bans issued in one burst do not
            // all expire on the same second.
            client_ban_jitter_secs: 1_800,
            client_ban_list_path: PathBuf::from("./client-ban-ips.txt"),
        }
    }
}

/// Reason why an IP was flagged for auto-ban
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoBanReason {
    SqlInjection,
    PathTraversal,
    Crawler,
    MissingUserAgent,
    ClientBanned,
    PrivateIp,
    NonStandardPeerId,
    PeerIdUserAgentMismatch,
}

impl AutoBanReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SqlInjection => "sql_injection",
            Self::PathTraversal => "path_traversal",
            Self::Crawler => "crawler",
            Self::MissingUserAgent => "missing_user_agent",
            Self::ClientBanned => "client_banned",
            Self::PrivateIp => "private_ip",
            Self::NonStandardPeerId => "non_standard_peer_id",
            Self::PeerIdUserAgentMismatch => "peer_id_user_agent_mismatch",
        }
    }

    /// How severe a violation is, which decides how it is turned into a ban.
    pub fn tier(self) -> AutoBanTier {
        match self {
            // Unambiguous attack patterns and operator-declared bans: no need
            // to wait for a threshold.
            Self::SqlInjection | Self::PathTraversal | Self::ClientBanned => AutoBanTier::Immediate,
            // Pattern checks with a higher false-positive rate (bot user
            // agents, monitoring probes, private ranges behind a proxy). These
            // keep counting towards `threshold`.
            Self::Crawler | Self::MissingUserAgent | Self::PrivateIp => AutoBanTier::Suspicious,
            // Heuristics that cannot be verified from a single request: a
            // wrongly reported client version is not proof of abuse, so these
            // escalate gradually.
            Self::NonStandardPeerId | Self::PeerIdUserAgentMismatch => AutoBanTier::Heuristic,
        }
    }
}

/// Severity of an [`AutoBanReason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoBanTier {
    /// Ban on the first violation.
    Immediate,
    /// Count violations, ban when `threshold` is reached.
    Suspicious,
    /// Count violations, then escalate ban duration with every repeat offence.
    Heuristic,
}

impl AutoBanTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::Suspicious => "suspicious",
            Self::Heuristic => "heuristic",
        }
    }
}

/// How long a ban lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BanKind {
    Temporary(u64),
    Permanent,
}

impl BanKind {
    /// `0` seconds keeps the historical meaning of "permanent".
    fn from_secs(secs: u64) -> Self {
        if secs == 0 {
            Self::Permanent
        } else {
            Self::Temporary(secs)
        }
    }
}

/// Parse a comma-separated list of durations, ignoring empty entries.
fn parse_steps(raw: &str) -> Vec<u64> {
    raw.split(',')
        .filter_map(|part| {
            let part = part.trim();

            if part.is_empty() {
                None
            } else {
                part.parse::<u64>().ok()
            }
        })
        .collect()
}

/// Record for a single IP's violation count
struct IpRecord {
    count: u32,
    first_violation: Instant,
    /// Some(instant) for a temporary ban, None otherwise
    banned_until: Option<Instant>,
    /// Permanent bans (`ban_duration_secs == 0`) have no expiration instant.
    /// Tracking this explicitly avoids representing "permanent" as an
    /// arbitrary far-future instant.
    permanent: bool,
    /// Whether this ban has already been appended to the ban list file.
    /// Prevents unbounded duplicate lines when a reload keeps failing.
    persisted: bool,
    /// Number of bans this IP has received, kept across ban expiry so that a
    /// repeat offender can be escalated instead of starting from scratch.
    offenses: u32,
    /// When the last ban was issued, used to forget offence history after
    /// `offense_decay_secs` without a new violation.
    last_offense: Option<Instant>,
}

impl IpRecord {
    fn is_banned(&self, now: Instant) -> bool {
        self.permanent || self.banned_until.map_or(false, |until| now < until)
    }
}

/// Longest accepted temporary ban (10 years). `Instant + Duration` panics on
/// overflow, so unreasonably large values must be rejected at startup.
pub const MAX_BAN_DURATION_SECS: u64 = 10 * 365 * 24 * 60 * 60;

/// Whether a list file already ends with a newline.
///
/// Bans are appended with `OpenOptions::append`; without this check a file
/// whose last line lacked a terminating newline would get the first appended
/// ban glued to it, silently corrupting that entry.
fn file_ends_with_newline(path: &Path) -> bool {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return true,
    };

    if metadata.len() == 0 {
        return true;
    }

    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };

    if file.seek(SeekFrom::End(-1)).is_err() {
        return false;
    }

    let mut byte = [0u8; 1];

    file.read_exact(&mut byte).is_ok() && byte[0] == b'\n'
}

/// Append a single IP to a ban list file.
///
/// Callers must hold `AutoBanTracker::write_lock`, which serializes appends
/// from multiple worker threads.
fn append_ip_line(path: &Path, ip: &IpAddr) -> ::std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    let mut line = String::with_capacity(48);

    if !file_ends_with_newline(path) {
        line.push('\n');
    }

    line.push_str(&ip.to_string());
    line.push('\n');

    file.write_all(line.as_bytes())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|delta| delta.as_secs())
        .unwrap_or(0)
}

/// Append `<ip> <expire_unix>` to the client ban file.
///
/// Callers must hold `AutoBanTracker::write_lock`.
fn append_client_ban_line(path: &Path, ip: &IpAddr, expire_unix: u64) -> ::std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    let mut line = String::with_capacity(64);

    if !file_ends_with_newline(path) {
        line.push('\n');
    }

    // Manual formatting keeps the allocation count low; this runs on the
    // request path whenever a banned client is seen.
    line.push_str(&ip.to_string());
    line.push(' ');
    line.push_str(&expire_unix.to_string());
    line.push('\n');

    file.write_all(line.as_bytes())
}

/// Parse `<ip> <expire_unix>` lines into a map, keeping the latest expiry per
/// address and dropping entries that have already expired.
fn parse_client_ban_lines(content: &str, now_unix: u64) -> HashMap<IpAddr, u64> {
    let mut out: HashMap<IpAddr, u64> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.split_whitespace();

        let ip = match parts.next().and_then(|s| s.parse::<IpAddr>().ok()) {
            Some(ip) => ip,
            None => continue,
        };

        let expire = match parts.next().and_then(|s| s.parse::<u64>().ok()) {
            Some(expire) => expire,
            None => continue,
        };

        if expire <= now_unix {
            continue;
        }

        let slot = out.entry(ip).or_insert(expire);

        if expire > *slot {
            *slot = expire;
        }
    }

    out
}

/// Thread-safe auto-ban tracker using RwLock for correct concurrent access
pub struct AutoBanTracker {
    inner: RwLock<AutoBanInner>,
    /// Read-only policy, kept out of the lock so it is readable while a record
    /// is mutably borrowed.
    policy: AutoBanPolicy,
    ban_list_path: Option<PathBuf>,
    /// File holding client-ban IPs together with their expiry timestamps.
    client_ban_list_path: Option<PathBuf>,
    /// Serializes appends to the ban list. Multiple socket workers can ban
    /// different IPs at the same time and `write_all` is not atomic.
    write_lock: Mutex<()>,
}

struct AutoBanInner {
    records: HashMap<IpAddr, IpRecord>,
    threshold: u32,
    window_secs: u64,
    ban_duration_secs: u64,
    max_records: usize,
    /// Last time the O(n) capacity cleanup ran, so a full map does not turn
    /// every violation into an O(n) scan under the global write lock.
    last_capacity_cleanup: Option<Instant>,
    /// Last time the "record limit reached" warning was logged.
    last_overflow_log: Option<Instant>,
    /// Last time expired client bans were pruned from the client ban file.
    last_client_cleanup: Option<Instant>,
}

/// Immutable escalation policy. Kept outside the record lock so it can be read
/// while a record is being mutated.
struct AutoBanPolicy {
    /// Duration of the first high-severity ban; `0` means "inherit
    /// `ban_duration_secs`".
    immediate_ban_secs: u64,
    /// Fixed duration for `client_banned`; never escalates to permanent.
    client_ban_duration_secs: u64,
    /// Half-width of the expiry jitter applied to client bans.
    client_ban_jitter_secs: u64,
    escalation_enabled: bool,
    /// Escalation ladder for heuristic violations, already parsed.
    escalation_steps: Vec<u64>,
    offense_decay_secs: u64,
}

/// Deterministic per-address offset in `[-jitter, +jitter]`, in seconds.
///
/// Derived from the address itself rather than from a random source: the same
/// IP always lands in the same slot, so a restart does not reshuffle expiry
/// times, while different addresses still spread out.
fn client_jitter(ip: &IpAddr, jitter: u64) -> i64 {
    if jitter == 0 {
        return 0;
    }

    let hash = match ip {
        IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()) as u64,
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut acc = 0u64;
            for chunk in octets.chunks(8) {
                let mut buf = [0u8; 8];
                buf[..chunk.len()].copy_from_slice(chunk);
                acc = acc.rotate_left(7) ^ u64::from_be_bytes(buf);
            }
            acc
        }
    };

    let span = jitter.saturating_mul(2).saturating_add(1);
    let offset = hash % span;

    offset as i64 - jitter as i64
}

impl AutoBanPolicy {
    /// Duration in seconds for a `client_banned` violation, already jittered.
    ///
    /// Returns `0` only when the whole chain resolves to "permanent", which
    /// callers treat as the historical meaning.
    fn client_ban_secs(&self, ip: &IpAddr, fallback_secs: u64) -> u64 {
        let base = if self.client_ban_duration_secs != 0 {
            self.client_ban_duration_secs
        } else if self.immediate_ban_secs != 0 {
            self.immediate_ban_secs
        } else {
            fallback_secs
        };

        if base == 0 {
            return 0;
        }

        let delta = client_jitter(ip, self.client_ban_jitter_secs);

        let secs = if delta >= 0 {
            base.saturating_add(delta as u64)
        } else {
            base.saturating_sub(delta.unsigned_abs())
        };

        secs.max(1)
    }

    fn ban_kind(
        &self,
        reason: AutoBanReason,
        ip: &IpAddr,
        offenses: u32,
        fallback_secs: u64,
    ) -> BanKind {
        // Client bans are a service decision, not an attack signal: give them
        // one fixed, temporary duration and keep them out of the escalation
        // ladder entirely, otherwise a repeat offender ends up permanent.
        if reason == AutoBanReason::ClientBanned {
            return BanKind::from_secs(self.client_ban_secs(ip, fallback_secs));
        }

        match reason.tier() {
            AutoBanTier::Immediate => {
                // Second high-severity offence by the same IP is deliberate.
                if self.escalation_enabled && offenses >= 2 {
                    BanKind::Permanent
                } else if self.immediate_ban_secs == 0 {
                    BanKind::from_secs(fallback_secs)
                } else {
                    BanKind::from_secs(self.immediate_ban_secs)
                }
            }
            AutoBanTier::Suspicious => BanKind::from_secs(fallback_secs),
            AutoBanTier::Heuristic => {
                if !self.escalation_enabled {
                    return BanKind::from_secs(fallback_secs);
                }

                let index = offenses.saturating_sub(1) as usize;

                match self.escalation_steps.get(index) {
                    Some(secs) => BanKind::from_secs(*secs),
                    None => BanKind::Permanent,
                }
            }
        }
    }
}

/// Count one more offence for this IP, forgetting the history when the last
/// offence is older than `decay_secs`.
fn register_offense(record: &mut IpRecord, now: Instant, decay_secs: u64) -> u32 {
    let decayed = match record.last_offense {
        Some(last) => now.duration_since(last).as_secs() >= decay_secs,
        None => true,
    };

    if decayed {
        record.offenses = 0;
    }

    record.offenses = record.offenses.saturating_add(1);
    record.last_offense = Some(now);
    record.offenses
}

/// Apply a ban to a record. Overflow degrades to a permanent ban: panicking
/// while holding the write lock would poison it for every later request.
fn apply_ban(record: &mut IpRecord, kind: BanKind, now: Instant) {
    match kind {
        BanKind::Permanent => {
            record.banned_until = None;
            record.permanent = true;
        }
        BanKind::Temporary(secs) => match now.checked_add(Duration::from_secs(secs)) {
            Some(until) => {
                record.banned_until = Some(until);
                record.permanent = false;
            }
            None => {
                record.banned_until = None;
                record.permanent = true;
            }
        },
    }

    record.persisted = false;
}

impl AutoBanTracker {
    /// Construct a tracker with the default escalation policy. Kept for tests
    /// and for callers that only care about the threshold behaviour.
    pub fn new(threshold: u32, window_secs: u64, ban_duration_secs: u64, ban_list_path: Option<PathBuf>) -> Self {
        let policy = AutoBanConfig::default();

        Self::with_policy(
            threshold,
            window_secs,
            ban_duration_secs,
            ban_list_path,
            &policy,
        )
    }

    /// Construct a tracker from the `[auto_ban]` configuration section.
    pub fn from_config(config: &AutoBanConfig) -> Self {
        let ban_list_path = if config.ban_list_path.as_os_str().is_empty() {
            None
        } else {
            Some(config.ban_list_path.clone())
        };

        Self::with_policy(
            config.threshold,
            config.window_secs,
            config.ban_duration_secs,
            ban_list_path,
            config,
        )
    }

    fn with_policy(
        threshold: u32,
        window_secs: u64,
        ban_duration_secs: u64,
        ban_list_path: Option<PathBuf>,
        config: &AutoBanConfig,
    ) -> Self {
        let client_ban_list_path = if config.client_ban_list_path.as_os_str().is_empty() {
            None
        } else {
            Some(config.client_ban_list_path.clone())
        };

        Self {
            inner: RwLock::new(AutoBanInner {
                records: HashMap::new(),
                threshold,
                window_secs,
                ban_duration_secs,
                max_records: 100_000,
                last_capacity_cleanup: None,
                last_overflow_log: None,
                last_client_cleanup: None,
            }),
            policy: AutoBanPolicy {
                immediate_ban_secs: config.immediate_ban_secs,
                client_ban_duration_secs: config.client_ban_duration_secs,
                client_ban_jitter_secs: config.client_ban_jitter_secs,
                escalation_enabled: config.escalation_enabled,
                escalation_steps: parse_steps(&config.escalation_steps),
                offense_decay_secs: config.offense_decay_secs,
            },
            client_ban_list_path,
            ban_list_path,
            write_lock: Mutex::new(()),
        }
    }

    /// Record a violation for an IP. Returns true if the IP should be auto-banned.
    ///
    /// Permanent bans are written to the ban list file before this returns, so
    /// a ban cannot be lost to a restart that happens between the ban and the
    /// next periodic flush. Temporary bans stay memory-only by design.
    pub fn record_violation(&self, ip: &IpAddr, reason: AutoBanReason) -> bool {
        let (should_ban, is_permanent) = {
            let mut inner = self.inner.write().unwrap();
            let now = Instant::now();

            // Check if already banned
            if let Some(record) = inner.records.get(ip) {
                if record.is_banned(now) {
                    return false; // Already banned
                }
            }

            let threshold = inner.threshold;
            let window_secs = inner.window_secs;
            let ban_duration_secs = inner.ban_duration_secs;
            let max_records = inner.max_records;

            // Capacity guard for IPs that are not tracked yet. Records of
            // currently banned IPs are kept, so a full map could otherwise
            // rescan every entry on every violation while still growing.
            // Make room at most once per second and, if the map is still full,
            // stop tracking new IPs: dropping violations is cheaper than an
            // unbounded map and an O(n) hot path.
            if !inner.records.contains_key(ip) && inner.records.len() >= max_records {
                let cleanup_due = inner
                    .last_capacity_cleanup
                    .map_or(true, |last| now.duration_since(last).as_secs() >= 1);

                if cleanup_due {
                    inner.records.retain(|_, record| {
                        record.is_banned(now)
                            || now.duration_since(record.first_violation).as_secs() < window_secs
                    });
                    inner.last_capacity_cleanup = Some(now);
                }

                if inner.records.len() >= max_records {
                    let log_due = inner
                        .last_overflow_log
                        .map_or(true, |last| now.duration_since(last).as_secs() >= 60);

                    if log_due {
                        inner.last_overflow_log = Some(now);
                        ::log::warn!(
                            "auto-ban: record limit ({} IPs) reached, not tracking {}",
                            max_records,
                            ip,
                        );
                    }

                    return false;
                }
            }

            let policy = &self.policy;
            let tier = reason.tier();

            let (should_ban, is_permanent) = match inner.records.get_mut(ip) {
                Some(record) => {
                    // Reset if outside window
                    if now.duration_since(record.first_violation).as_secs() >= window_secs {
                        record.count = 0;
                        record.first_violation = now;
                    }

                    // Clear expired ban. Resetting the count as well means a single
                    // new violation after the ban expires does not immediately
                    // re-ban the IP. The offence history is kept separately so a
                    // repeat offender can be escalated.
                    if !record.permanent {
                        if let Some(banned_until) = record.banned_until {
                            if now >= banned_until {
                                record.banned_until = None;
                                record.persisted = false;
                                record.count = 0;
                                record.first_violation = now;
                            }
                        }
                    }

                    record.count += 1;

                    // High-severity violations are banned on the first hit;
                    // everything else has to reach the threshold.
                    let triggered = tier == AutoBanTier::Immediate || record.count >= threshold;

                    if triggered && !record.is_banned(now) {
                        let offenses =
                            register_offense(record, now, policy.offense_decay_secs);
                        let kind = policy.ban_kind(reason, ip, offenses, ban_duration_secs);

                        apply_ban(record, kind, now);

                        (true, record.permanent)
                    } else {
                        (false, false)
                    }
                }
                None => {
                    let triggered = tier == AutoBanTier::Immediate || threshold <= 1;

                    let mut record = IpRecord {
                        count: 1,
                        first_violation: now,
                        banned_until: None,
                        permanent: false,
                        persisted: false,
                        offenses: 0,
                        last_offense: None,
                    };

                    if triggered {
                        let offenses =
                            register_offense(&mut record, now, policy.offense_decay_secs);
                        let kind = policy.ban_kind(reason, ip, offenses, ban_duration_secs);

                        apply_ban(&mut record, kind, now);
                    }

                    let permanent = record.permanent;

                    inner.records.insert(*ip, record);

                    (triggered, permanent)
                }
            };

            if should_ban {
                let (count, offenses, permanent) = inner
                    .records
                    .get(ip)
                    .map(|record| (record.count, record.offenses, record.permanent))
                    .unwrap_or((0, 0, false));

                ::log::warn!(
                    "Auto-ban IP {} (reason: {}, tier: {}, count: {}/{}, offence: {}, {})",
                    ip,
                    reason.as_str(),
                    tier.as_str(),
                    count,
                    threshold,
                    offenses,
                    if permanent { "permanent" } else { "temporary" },
                );
            }

            (should_ban, is_permanent)
        };

        if should_ban {
            if is_permanent {
                self.persist_ip(ip);
            } else if reason == AutoBanReason::ClientBanned {
                // Temporary client bans are the only temporary bans that are
                // written to disk, so they survive a restart with their expiry.
                self.persist_client_ban(ip);
            }
        }

        should_ban
    }

    /// Append a permanent ban to the ban list immediately.
    ///
    /// The periodic flush still retries failed writes, but waiting for it
    /// would leave a window in which a restart unbans the IP.
    fn persist_ip(&self, ip: &IpAddr) {
        let path = match &self.ban_list_path {
            Some(path) if !path.as_os_str().is_empty() => path,
            _ => return,
        };

        let _write_guard = self.write_lock.lock().unwrap();

        // The periodic flush may have written this ban first while it was
        // waiting for the lock. Skip the duplicate append; the record is
        // already persistent.
        {
            let inner = self.inner.read().unwrap();

            match inner.records.get(ip) {
                Some(record) if record.permanent && !record.persisted => {}
                _ => return,
            }
        }

        if let Err(err) = append_ip_line(path, ip) {
            ::log::error!(
                "auto-ban: failed to persist {} to {}: {} (periodic flush will retry)",
                ip,
                path.display(),
                err,
            );
            return;
        }

        let mut inner = self.inner.write().unwrap();

        if let Some(record) = inner.records.get_mut(ip) {
            // Only mark the ban that was actually written. The record may have
            // been removed or replaced while the file was being written.
            if record.permanent {
                record.persisted = true;
            }
        }

        ::log::info!("auto-ban: persisted {} to {}", ip, path.display());
    }

    /// Check if an IP is currently auto-banned (in-memory check only)
    pub fn is_auto_banned(&self, ip: &IpAddr) -> bool {
        let inner = self.inner.read().unwrap();
        let now = Instant::now();

        if let Some(record) = inner.records.get(ip) {
            return record.is_banned(now);
        }

        false
    }

    /// Append a temporary client ban together with its expiry timestamp.
    ///
    /// Client bans are the one temporary ban type that survives a restart, so
    /// they get their own file with an explicit expiry on every line.
    fn persist_client_ban(&self, ip: &IpAddr) {
        let path = match &self.client_ban_list_path {
            Some(path) if !path.as_os_str().is_empty() => path,
            _ => return,
        };

        let expire_unix = {
            let inner = self.inner.read().unwrap();

            match inner.records.get(ip) {
                Some(record) if !record.permanent => match record.banned_until {
                    Some(until) => {
                        let remaining = until.saturating_duration_since(Instant::now());
                        unix_now().saturating_add(remaining.as_secs())
                    }
                    None => return,
                },
                _ => return,
            }
        };

        let _write_guard = self.write_lock.lock().unwrap();

        if let Err(err) = append_client_ban_line(path, ip, expire_unix) {
            ::log::error!(
                "auto-ban: failed to append {} to {}: {}",
                ip,
                path.display(),
                err,
            );
        }
    }

    /// Restore non-expired client bans from the client ban file.
    ///
    /// Returns the number of addresses restored. Called once at startup so a
    /// restart does not hand banned clients a clean slate.
    pub fn load_client_bans(&self) -> usize {
        let path = match &self.client_ban_list_path {
            Some(path) if !path.as_os_str().is_empty() => path,
            _ => return 0,
        };

        let content = match ::std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) if err.kind() == ::std::io::ErrorKind::NotFound => return 0,
            Err(err) => {
                ::log::error!("auto-ban: failed to read {}: {}", path.display(), err);
                return 0;
            }
        };

        let now_unix = unix_now();
        let parsed = parse_client_ban_lines(&content, now_unix);
        let count = parsed.len();

        if count == 0 {
            return 0;
        }

        let now = Instant::now();
        let mut inner = self.inner.write().unwrap();

        for (ip, expire_unix) in parsed {
            let remaining = Duration::from_secs(expire_unix.saturating_sub(now_unix));

            let until = match now.checked_add(remaining) {
                Some(until) => until,
                None => continue,
            };

            let record = inner.records.entry(ip).or_insert_with(|| IpRecord {
                count: 1,
                first_violation: now,
                banned_until: None,
                permanent: false,
                persisted: false,
                offenses: 0,
                last_offense: None,
            });

            // Keep whichever expiry is later when the address is already
            // banned in memory.
            let longer = match record.banned_until {
                Some(existing) => until > existing,
                None => true,
            };

            if !record.permanent && longer {
                record.banned_until = Some(until);
                record.persisted = false;
            }
        }

        count
    }

    /// Rewrite the client ban file without entries that have expired.
    ///
    /// Written to a temporary file and renamed into place so a crash cannot
    /// truncate the list.
    pub fn cleanup_client_bans(&self) -> usize {
        let path = match &self.client_ban_list_path {
            Some(path) if !path.as_os_str().is_empty() => path,
            _ => return 0,
        };

        let content = match ::std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(_) => return 0,
        };

        let now_unix = unix_now();
        let mut kept: Vec<(IpAddr, u64)> = parse_client_ban_lines(&content, now_unix)
            .into_iter()
            .collect();
        kept.sort_by(|a, b| a.0.cmp(&b.0));

        let mut out = String::with_capacity(kept.len() * 40 + 64);
        out.push_str("# auto_ban client bans, format: <ip> <expire_unix>\n");

        for (ip, expire) in &kept {
            out.push_str(&ip.to_string());
            out.push(' ');
            out.push_str(&expire.to_string());
            out.push('\n');
        }

        let tmp = path.with_extension("tmp");

        if let Err(err) = ::std::fs::write(&tmp, out.as_bytes()) {
            ::log::error!("auto-ban: failed to write {}: {}", tmp.display(), err);
            return 0;
        }

        if let Err(err) = ::std::fs::rename(&tmp, path) {
            ::log::error!("auto-ban: failed to replace {}: {}", path.display(), err);
            let _ = ::std::fs::remove_file(&tmp);
            return 0;
        }

        let before = content
            .lines()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty() && !line.starts_with('#')
            })
            .count();

        before.saturating_sub(kept.len())
    }

    /// Run the daily cleanup if it is due. Returns the number of pruned lines.
    ///
    /// Called from the periodic flush thread; the interval is a full day so a
    /// large client ban file does not get rewritten every minute.
    pub fn maybe_cleanup_client_bans(&self) -> usize {
        let due = {
            let inner = self.inner.read().unwrap();

            inner
                .last_client_cleanup
                .map_or(true, |last| last.elapsed().as_secs() >= 86_400)
        };

        if !due {
            return 0;
        }

        {
            let mut inner = self.inner.write().unwrap();
            inner.last_client_cleanup = Some(Instant::now());
        }

        self.cleanup_client_bans()
    }

    /// Flush permanently banned IPs that failed to persist immediately.
    /// Only IPs with ban_duration_secs == 0 (permanent bans) are written to
    /// file, because the file format doesn't support expiration times.
    /// Temporary bans are kept in memory only and cleaned up by cleanup().
    /// Records are NOT removed from memory yet - call remove_ips() after
    /// ip_ban_list has been successfully reloaded.
    pub fn flush_to_file(&self) -> Vec<IpAddr> {
        // Only permanent bans are written to file: the list format has no
        // expiration timestamps, so a temporary ban must stay in memory.
        let (banned, mut pending_write) = {
            let inner = self.inner.read().unwrap();

            // Only permanent bans are written to file: the list format has no
            // expiration timestamps. Escalation can still produce permanent
            // bans while `ban_duration_secs` is non-zero, so the guard has to
            // consider it as well.
            if inner.ban_duration_secs != 0 && !self.policy.escalation_enabled {
                return Vec::new();
            }

            let now = Instant::now();
            let mut banned = Vec::new();
            let mut pending_write = Vec::new();

            for (ip, record) in inner.records.iter() {
                if record.permanent && record.is_banned(now) {
                    banned.push(*ip);
                    if !record.persisted {
                        pending_write.push(*ip);
                    }
                }
            }

            (banned, pending_write)
        };

        if banned.is_empty() {
            return banned;
        }

        let path = match &self.ban_list_path {
            Some(path) if !path.as_os_str().is_empty() => path,
            // No file path configured. Don't report IPs as flushed, otherwise
            // the flush thread removes them from memory and they escape both
            // auto_ban and ip_ban_list.
            _ => return Vec::new(),
        };

        if !pending_write.is_empty() {
            let _write_guard = self.write_lock.lock().unwrap();

            // A ban may have been persisted directly by `persist_ip` after the
            // snapshot above. Re-check under the write lock so the same IP is
            // not appended twice.
            {
                let inner = self.inner.read().unwrap();

                pending_write.retain(|ip| {
                    inner
                        .records
                        .get(ip)
                        .map_or(false, |record| !record.persisted)
                });
            }

            if pending_write.is_empty() {
                return banned;
            }

            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(mut file) => {
                    let mut lines = String::with_capacity(pending_write.len() * 40 + 1);

                    // The previous write may have been interrupted, or the
                    // file may have been edited by hand, leaving no trailing
                    // newline. Without one the first appended address would be
                    // glued to the last line and silently become invalid.
                    if !file_ends_with_newline(path) {
                        lines.push('\n');
                    }

                    for ip in &pending_write {
                        lines.push_str(&ip.to_string());
                        lines.push('\n');
                    }
                    if let Err(err) = file.write_all(lines.as_bytes()) {
                        ::log::error!("Failed to flush auto-banned IPs to file: {}", err);
                        return Vec::new(); // Don't report as flushed if write failed
                    }
                    ::log::info!(
                        "Auto-ban flush: wrote {} IPs to {}",
                        pending_write.len(),
                        path.display(),
                    );
                }
                Err(err) => {
                    ::log::error!("Failed to open ban list file {}: {}", path.display(), err);
                    return Vec::new(); // Don't report as flushed if open failed
                }
            }

            let mut inner = self.inner.write().unwrap();
            for ip in &pending_write {
                if let Some(record) = inner.records.get_mut(ip) {
                    record.persisted = true;
                }
            }
        }

        // Return every currently banned IP, including ones written on an
        // earlier interval. The caller reloads ip_ban_list and only then
        // calls remove_ips, so a failed reload is retried instead of losing
        // the ban from both sources.
        banned
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
            .filter(|record| record.is_banned(now))
            .count()
    }

    /// Remove expired entries
    pub fn cleanup(&self) {
        let mut inner = self.inner.write().unwrap();
        let now = Instant::now();
        let window_secs = inner.window_secs;

        let before = inner.records.len();

        inner.records.retain(|_, record| {
            if record.is_banned(now) {
                true
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

/// Validate the interaction between auto-ban persistence and the IP ban list.
///
/// Permanent auto-bans are appended to `auto_ban.ban_list_path`, and after a
/// flush the server reloads `ip_ban.path` and drops the in-memory records.
/// If the two paths differ, the just-written bans are never loaded and the
/// IPs escape both systems until the next violation. Refuse to start rather
/// than silently weakening the ban list.
pub fn validate_auto_ban_config(
    auto: &AutoBanConfig,
    ip_ban: &IpBanConfig,
) -> anyhow::Result<()> {
    if !auto.enabled {
        return Ok(());
    }

    if auto.threshold == 0 {
        return Err(anyhow::anyhow!(
            "auto_ban.threshold must be at least 1 (got 0)"
        ));
    }

    if auto.window_secs == 0 {
        return Err(anyhow::anyhow!(
            "auto_ban.window_secs must be at least 1 (got 0)"
        ));
    }

    if auto.ban_duration_secs > MAX_BAN_DURATION_SECS {
        return Err(anyhow::anyhow!(
            "auto_ban.ban_duration_secs must be at most {} seconds (10 years), got {}; \
             larger values overflow Instant arithmetic",
            MAX_BAN_DURATION_SECS,
            auto.ban_duration_secs,
        ));
    }

    if auto.immediate_ban_secs > MAX_BAN_DURATION_SECS {
        return Err(anyhow::anyhow!(
            "auto_ban.immediate_ban_secs must be at most {} seconds (10 years), got {}; \
             larger values overflow Instant arithmetic",
            MAX_BAN_DURATION_SECS,
            auto.immediate_ban_secs,
        ));
    }

    if auto.client_ban_duration_secs > MAX_BAN_DURATION_SECS {
        return Err(anyhow::anyhow!(
            "auto_ban.client_ban_duration_secs must be at most {} seconds (10 years), got {}",
            MAX_BAN_DURATION_SECS,
            auto.client_ban_duration_secs,
        ));
    }

    if auto.client_ban_jitter_secs > MAX_BAN_DURATION_SECS {
        return Err(anyhow::anyhow!(
            "auto_ban.client_ban_jitter_secs must be at most {} seconds (10 years), got {}",
            MAX_BAN_DURATION_SECS,
            auto.client_ban_jitter_secs,
        ));
    }

    for entry in auto.escalation_steps.split(',') {
        let entry = entry.trim();

        if entry.is_empty() {
            continue;
        }

        match entry.parse::<u64>() {
            Ok(secs) if secs <= MAX_BAN_DURATION_SECS => (),
            Ok(secs) => {
                return Err(anyhow::anyhow!(
                    "auto_ban.escalation_steps entry '{}' must be at most {} seconds \
                     (10 years), got {}",
                    entry,
                    MAX_BAN_DURATION_SECS,
                    secs,
                ))
            }
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "auto_ban.escalation_steps must be a comma-separated list of \
                     seconds, but '{}' is not a number",
                    entry,
                ))
            }
        }
    }

    if auto.escalation_enabled && auto.offense_decay_secs == 0 {
        return Err(anyhow::anyhow!(
            "auto_ban.offense_decay_secs must be at least 1 when escalation is enabled: \
             a value of 0 would forget the offence history immediately and escalation \
             would never happen"
        ));
    }

    // A permanent ban can come from `ban_duration_secs == 0` or from
    // escalation, and both need a list that is loaded again after a restart.
    if auto.ban_duration_secs != 0 && !auto.escalation_enabled {
        return Ok(());
    }

    // Permanent bans must come back after a restart. That requires writing
    // each ban to a file AND loading that file as an IP ban list at startup.
    // Refuse to start rather than silently keeping the bans only in memory.
    if auto.ban_list_path.as_os_str().is_empty() {
        return Err(anyhow::anyhow!(
            "auto_ban is enabled with permanent bans (ban_duration_secs = 0) but \
             ban_list_path is empty: bans would be lost on restart. Set \
             ban_list_path to the ip_ban list path, or use a non-zero \
             ban_duration_secs for memory-only temporary bans"
        ));
    }

    if !ip_ban.mode.is_on() {
        return Err(anyhow::anyhow!(
            "auto_ban is enabled with permanent bans and ban_list_path '{}', but \
             ip_ban.mode is 'off': the file would never be loaded, so bans would \
             be lost on restart. Set ip_ban.mode = 'on' and ip_ban.path = '{}', \
             or use a non-zero ban_duration_secs for memory-only temporary bans",
            auto.ban_list_path.display(),
            auto.ban_list_path.display(),
        ));
    }

    if !paths_refer_to_same_file(&auto.ban_list_path, &ip_ban.path) {
        return Err(anyhow::anyhow!(
            "auto_ban.ban_list_path ('{}') must equal ip_ban.path ('{}') when \
             auto_ban uses permanent bans and ip_ban is enabled; otherwise \
             flushed bans are never reloaded",
            auto.ban_list_path.display(),
            ip_ban.path.display(),
        ));
    }

    Ok(())
}

/// Compare two paths after resolving them, so that `./ban-list.txt` and
/// `ban-list.txt` (or different spellings through symlinks) are recognized as
/// the same file. If a path does not exist yet (and therefore cannot be
/// canonicalized), fall back to a lexical comparison that collapses `.` and
/// empty components.
fn paths_refer_to_same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }

    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => normalize_path(a) == normalize_path(b),
    }
}

/// Lexically normalize a path without touching the filesystem.
fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(
                    normalized.components().next_back(),
                    Some(Component::Normal(_))
                ) {
                    normalized.pop();
                } else {
                    normalized.push(component.as_os_str());
                }
            }
            _ => normalized.push(component.as_os_str()),
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_auto_ban_threshold() {
        // `Crawler` belongs to the counting tier: high-severity reasons ban on
        // the first violation and are covered by their own test.
        let tracker = AutoBanTracker::new(3, 60, 3600, None);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        assert!(!tracker.is_auto_banned(&ip));

        assert!(!tracker.record_violation(&ip, AutoBanReason::Crawler));
        assert!(!tracker.record_violation(&ip, AutoBanReason::Crawler));
        assert!(tracker.record_violation(&ip, AutoBanReason::Crawler));

        assert!(tracker.is_auto_banned(&ip));
        assert!(!tracker.record_violation(&ip, AutoBanReason::Crawler));
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

        assert!(!tracker.record_violation(&ip1, AutoBanReason::Crawler));
        assert!(!tracker.record_violation(&ip2, AutoBanReason::Crawler));

        assert!(tracker.record_violation(&ip1, AutoBanReason::Crawler));
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

        // Ban two IPs (each needs two violations with threshold=2)
        assert!(!tracker.record_violation(&ip1, AutoBanReason::Crawler));
        assert!(tracker.record_violation(&ip1, AutoBanReason::Crawler));
        assert!(!tracker.record_violation(&ip2, AutoBanReason::Crawler));
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
    fn test_flush_does_not_duplicate_when_reload_fails() {
        let tmp = std::env::temp_dir().join("test_auto_ban_no_duplicate.txt");
        let _ = std::fs::remove_file(&tmp);

        let tracker = AutoBanTracker::new(1, 60, 0, Some(tmp.clone()));
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));

        assert!(tracker.record_violation(&ip, AutoBanReason::Crawler));

        // First flush writes the IP. A second flush before remove_ips simulates
        // a failed ip_ban_list reload: it must report the IP again so the
        // caller retries, but must not append a duplicate line.
        assert_eq!(tracker.flush_to_file(), vec![ip]);
        assert_eq!(tracker.flush_to_file(), vec![ip]);

        let contents = std::fs::read_to_string(&tmp).unwrap();
        assert_eq!(contents.matches("9.9.9.9").count(), 1);

        tracker.remove_ips(&[ip]);
        assert_eq!(tracker.banned_count(), 0);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_validate_auto_ban_requires_matching_paths() {
        use crate::ip_ban::{IpBanConfig, IpBanMode};

        let auto = AutoBanConfig {
            enabled: true,
            ban_duration_secs: 0,
            ban_list_path: "same.txt".into(),
            ..Default::default()
        };

        let matching = IpBanConfig {
            mode: IpBanMode::On,
            path: "same.txt".into(),
        };
        assert!(validate_auto_ban_config(&auto, &matching).is_ok());

        let mismatched = IpBanConfig {
            mode: IpBanMode::On,
            path: "other.txt".into(),
        };
        assert!(validate_auto_ban_config(&auto, &mismatched).is_err());

        // A disabled ip_ban list never reloads the file, so permanent bans
        // would be lost on restart. That is now a startup error rather than a
        // warning.
        let disabled = IpBanConfig {
            mode: IpBanMode::Off,
            path: "other.txt".into(),
        };
        assert!(validate_auto_ban_config(&auto, &disabled).is_err());

        // Temporary bans are memory-only and do not touch either file.
        let temporary = AutoBanConfig {
            ban_duration_secs: 3600,
            ..auto
        };
        assert!(validate_auto_ban_config(&temporary, &mismatched).is_ok());
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
    fn test_expired_temporary_ban_resets_count() {
        let tracker = AutoBanTracker::new(2, 1, 1, None);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7));

        assert!(!tracker.record_violation(&ip, AutoBanReason::Crawler));
        assert!(tracker.record_violation(&ip, AutoBanReason::Crawler));
        assert!(tracker.is_auto_banned(&ip));

        std::thread::sleep(std::time::Duration::from_millis(1_100));

        assert!(!tracker.is_auto_banned(&ip));

        // One violation after expiry must not immediately re-ban the IP: the
        // count belongs to the ban that just expired.
        assert!(!tracker.record_violation(&ip, AutoBanReason::Crawler));
        assert!(!tracker.is_auto_banned(&ip));
    }

    #[test]
    fn test_flush_adds_missing_leading_newline() {
        let tmp = std::env::temp_dir().join("test_auto_ban_missing_newline.txt");
        let _ = std::fs::remove_file(&tmp);

        // A file edited by hand may not end with a newline.
        std::fs::write(&tmp, "1.1.1.1").unwrap();

        let tracker = AutoBanTracker::new(1, 60, 0, Some(tmp.clone()));
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));

        assert!(tracker.record_violation(&ip, AutoBanReason::Crawler));
        assert_eq!(tracker.flush_to_file(), vec![ip]);

        let contents = std::fs::read_to_string(&tmp).unwrap();

        assert!(contents.contains("1.1.1.1\n9.9.9.9\n"), "contents: {:?}", contents);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_validate_auto_ban_rejects_zero_threshold_and_window() {
        let ip_ban = IpBanConfig {
            mode: crate::ip_ban::IpBanMode::Off,
            path: "unused.txt".into(),
        };

        let zero_threshold = AutoBanConfig {
            enabled: true,
            threshold: 0,
            ..Default::default()
        };
        assert!(validate_auto_ban_config(&zero_threshold, &ip_ban).is_err());

        let zero_window = AutoBanConfig {
            enabled: true,
            window_secs: 0,
            ..Default::default()
        };
        assert!(validate_auto_ban_config(&zero_window, &ip_ban).is_err());

        // Disabled auto-ban ignores these values.
        let disabled = AutoBanConfig {
            enabled: false,
            threshold: 0,
            window_secs: 0,
            ..Default::default()
        };
        assert!(validate_auto_ban_config(&disabled, &ip_ban).is_ok());
    }

    #[test]
    fn test_validate_auto_ban_compares_resolved_paths() {
        let dir = std::env::temp_dir();

        let path = dir.join("aquatic_auto_ban_path_test.txt");
        std::fs::write(&path, "").unwrap();

        let indirection = dir.join(".").join("aquatic_auto_ban_path_test.txt");

        assert!(paths_refer_to_same_file(&path, &indirection));
        assert!(!paths_refer_to_same_file(&path, &dir.join("other.txt")));

        let _ = std::fs::remove_file(&path);
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

    #[test]
    fn test_permanent_ban_is_persisted_immediately() {
        let tmp = std::env::temp_dir().join("test_auto_ban_immediate.txt");
        let _ = std::fs::remove_file(&tmp);

        let tracker = AutoBanTracker::new(1, 60, 0, Some(tmp.clone()));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40));

        assert!(tracker.record_violation(&ip, AutoBanReason::SqlInjection));

        // The ban must be on disk before any flush runs: a restart at this
        // point would otherwise unban the IP.
        let contents = std::fs::read_to_string(&tmp).unwrap();
        assert_eq!(contents, "10.20.30.40\n");

        // The periodic flush must not append the same IP again.
        assert_eq!(tracker.flush_to_file(), vec![ip]);
        let contents = std::fs::read_to_string(&tmp).unwrap();
        assert_eq!(contents.matches("10.20.30.40").count(), 1);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_default_config_uses_permanent_bans() {
        // Enabling auto_ban without specifying a duration must not fall back to
        // memory-only temporary bans: those disappear on restart.
        let auto = AutoBanConfig::default();
        assert_eq!(auto.ban_duration_secs, 0);
        assert!(auto.ban_list_path.to_string_lossy().contains("ip-ban-list"));
    }

    #[test]
    fn test_validate_auto_ban_rejects_missing_persistence() {
        let ip_ban_on = IpBanConfig {
            mode: crate::ip_ban::IpBanMode::On,
            path: "ban.txt".into(),
        };
        let ip_ban_off = IpBanConfig {
            mode: crate::ip_ban::IpBanMode::Off,
            path: "ban.txt".into(),
        };

        let empty_path = AutoBanConfig {
            enabled: true,
            ban_duration_secs: 0,
            ban_list_path: "".into(),
            ..Default::default()
        };
        assert!(validate_auto_ban_config(&empty_path, &ip_ban_on).is_err());

        let ip_ban_disabled = AutoBanConfig {
            enabled: true,
            ban_duration_secs: 0,
            ban_list_path: "ban.txt".into(),
            ..Default::default()
        };
        assert!(validate_auto_ban_config(&ip_ban_disabled, &ip_ban_off).is_err());

        // Temporary bans are memory-only by design, so they do not need a
        // persistent list.
        let temporary = AutoBanConfig {
            enabled: true,
            ban_duration_secs: 3600,
            ban_list_path: "".into(),
            ..Default::default()
        };
        assert!(validate_auto_ban_config(&temporary, &ip_ban_off).is_ok());
    }

    #[test]
    fn test_validate_auto_ban_rejects_excessive_duration() {
        let ip_ban = IpBanConfig {
            mode: crate::ip_ban::IpBanMode::Off,
            path: "ban.txt".into(),
        };

        let too_long = AutoBanConfig {
            enabled: true,
            ban_duration_secs: MAX_BAN_DURATION_SECS + 1,
            ..Default::default()
        };
        assert!(validate_auto_ban_config(&too_long, &ip_ban).is_err());

        let max = AutoBanConfig {
            enabled: true,
            ban_duration_secs: MAX_BAN_DURATION_SECS,
            ..Default::default()
        };
        assert!(validate_auto_ban_config(&max, &ip_ban).is_ok());
    }

    #[test]
    fn test_paths_compare_equal_before_file_exists() {
        // Neither file exists, so canonicalize fails and the lexical fallback
        // must still recognize the same relative path.
        assert!(paths_refer_to_same_file(
            Path::new("./aquatic-auto-ban-not-created.txt"),
            Path::new("aquatic-auto-ban-not-created.txt"),
        ));
        assert!(!paths_refer_to_same_file(
            Path::new("./aquatic-auto-ban-not-created.txt"),
            Path::new("./aquatic-auto-ban-other.txt"),
        ));
    }

    fn policy_config() -> AutoBanConfig {
        AutoBanConfig {
            enabled: true,
            threshold: 10,
            window_secs: 60,
            ban_duration_secs: 3600,
            ban_list_path: PathBuf::new(),
            immediate_ban_secs: 1,
            escalation_enabled: true,
            escalation_steps: String::from("1,1"),
            offense_decay_secs: 3600,
            ..Default::default()
        }
    }

    #[test]
    fn test_immediate_tier_bans_on_first_violation() {
        let tracker = AutoBanTracker::from_config(&policy_config());
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        // SQL injection is high severity: one hit is enough even though the
        // threshold is 10.
        assert!(tracker.record_violation(&ip, AutoBanReason::SqlInjection));
        assert!(tracker.is_auto_banned(&ip));
    }

    #[test]
    fn test_immediate_tier_second_offence_is_permanent() {
        let tracker = AutoBanTracker::from_config(&policy_config());
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));

        // First offence: temporary (immediate_ban_secs = 1).
        assert!(tracker.record_violation(&ip, AutoBanReason::PathTraversal));

        std::thread::sleep(std::time::Duration::from_millis(1_100));

        assert!(!tracker.is_auto_banned(&ip));

        // Second offence: escalated to a permanent ban.
        assert!(tracker.record_violation(&ip, AutoBanReason::PathTraversal));

        std::thread::sleep(std::time::Duration::from_millis(1_500));

        assert!(tracker.is_auto_banned(&ip));
    }

    #[test]
    fn test_heuristic_tier_escalates_through_the_ladder() {
        let mut config = policy_config();

        config.threshold = 1;

        let tracker = AutoBanTracker::from_config(&config);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12));

        // Offence 1 and 2 use the ladder (1 second each), offence 3 has no
        // step left and becomes permanent.
        for _ in 0..2 {
            assert!(tracker.record_violation(&ip, AutoBanReason::NonStandardPeerId));

            std::thread::sleep(std::time::Duration::from_millis(1_100));

            assert!(!tracker.is_auto_banned(&ip));
        }

        assert!(tracker.record_violation(&ip, AutoBanReason::NonStandardPeerId));

        std::thread::sleep(std::time::Duration::from_millis(1_500));

        assert!(tracker.is_auto_banned(&ip));
    }

    #[test]
    fn test_offence_history_decays() {
        let mut config = policy_config();

        config.threshold = 1;
        config.offense_decay_secs = 1;

        let tracker = AutoBanTracker::from_config(&config);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13));

        assert!(tracker.record_violation(&ip, AutoBanReason::PeerIdUserAgentMismatch));

        // Long enough for the ban to expire and for the offence history to be
        // forgotten, so the next offence starts at the first step again.
        std::thread::sleep(std::time::Duration::from_millis(2_200));

        assert!(tracker.record_violation(&ip, AutoBanReason::PeerIdUserAgentMismatch));

        std::thread::sleep(std::time::Duration::from_millis(1_500));

        assert!(!tracker.is_auto_banned(&ip));
    }

    #[test]
    fn test_validate_rejects_invalid_escalation_steps() {
        let ip_ban = IpBanConfig::default();

        let not_a_number = AutoBanConfig {
            enabled: true,
            escalation_enabled: true,
            escalation_steps: String::from("300,abc"),
            ..Default::default()
        };
        assert!(validate_auto_ban_config(&not_a_number, &ip_ban).is_err());

        let zero_decay = AutoBanConfig {
            enabled: true,
            escalation_enabled: true,
            offense_decay_secs: 0,
            ..Default::default()
        };
        assert!(validate_auto_ban_config(&zero_decay, &ip_ban).is_err());
    }

    fn client_ban_test_config() -> AutoBanConfig {
        let mut config = AutoBanConfig::default();

        config.enabled = true;
        config.threshold = 20;
        // High-severity reasons stay permanent ...
        config.ban_duration_secs = 0;
        config.immediate_ban_secs = 0;
        // ... while client bans get one day and never escalate.
        config.client_ban_duration_secs = 86_400;
        config.client_ban_jitter_secs = 0;
        config.escalation_enabled = true;
        config.ban_list_path = PathBuf::new();
        config.client_ban_list_path = PathBuf::new();

        config
    }

    #[test]
    fn test_client_ban_kind_never_becomes_permanent() {
        let mut config = client_ban_test_config();
        config.escalation_enabled = true;
        // A permanent `ban_duration_secs` would make other Immediate reasons
        // permanent; client bans must ignore that.
        config.ban_duration_secs = 0;

        let tracker = AutoBanTracker::from_config(&config);
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 9).into();

        for offenses in 0..10u32 {
            match tracker
                .policy
                .ban_kind(AutoBanReason::ClientBanned, &ip, offenses, 0)
            {
                BanKind::Temporary(secs) => assert_eq!(
                    secs, 86_400,
                    "jitter is disabled so every client ban is exactly one day",
                ),
                BanKind::Permanent => panic!(
                    "client ban escalated to permanent on offence {}",
                    offenses
                ),
            }
        }
    }

    #[test]
    fn test_client_ban_stays_temporary_with_escalation_enabled() {
        let mut config = client_ban_test_config();
        config.ban_list_path = PathBuf::from("./aquatic-test-client-ban-ip-list.txt");

        let tracker = AutoBanTracker::from_config(&config);
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 9).into();

        assert!(tracker.record_violation(&ip, AutoBanReason::ClientBanned));
        assert!(tracker.is_auto_banned(&ip));

        // A temporary ban is never flushed to the permanent ip list.
        assert!(tracker.flush_to_file().is_empty());
    }

    #[test]
    fn test_client_jitter_is_bounded_and_stable() {
        let jitter = 1_800u64;
        let a: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let b: IpAddr = Ipv4Addr::new(5, 6, 7, 8).into();

        let ja = client_jitter(&a, jitter);
        let jb = client_jitter(&b, jitter);

        assert!(ja.abs() <= jitter as i64);
        assert!(jb.abs() <= jitter as i64);
        // Same address always maps to the same offset, so restarts do not
        // reshuffle expiry times.
        assert_eq!(ja, client_jitter(&a, jitter));
        assert_eq!(client_jitter(&a, 0), 0);
    }

    #[test]
    fn test_client_ban_file_roundtrip_and_cleanup() {
        let path = PathBuf::from("./aquatic-test-client-bans.txt");
        let _ = std::fs::remove_file(&path);

        let mut config = client_ban_test_config();
        config.client_ban_list_path = path.clone();

        let now = unix_now();
        let expired = now.saturating_sub(60);
        let valid = now.saturating_add(3_600);

        let content = format!(
            "# comment\n192.0.2.1 {}\n192.0.2.2 {}\nnot-an-ip {}\n192.0.2.3 not-a-number\n",
            expired, valid, valid,
        );
        std::fs::write(&path, content).unwrap();

        let tracker = AutoBanTracker::from_config(&config);
        assert_eq!(tracker.load_client_bans(), 1);
        assert!(tracker.is_auto_banned(&"192.0.2.2".parse().unwrap()));
        assert!(!tracker.is_auto_banned(&"192.0.2.1".parse().unwrap()));

        // The rewrite keeps only the unexpired entry.
        assert_eq!(tracker.cleanup_client_bans(), 1);

        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(rewritten.contains("192.0.2.2"));
        assert!(!rewritten.contains("192.0.2.1"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_expired_client_ban_is_not_restored() {
        let path = PathBuf::from("./aquatic-test-client-bans-expired.txt");
        let _ = std::fs::remove_file(&path);

        let mut config = client_ban_test_config();
        config.client_ban_list_path = path.clone();

        std::fs::write(&path, format!("198.51.100.7 {}\n", unix_now().saturating_sub(1))).unwrap();

        let tracker = AutoBanTracker::from_config(&config);
        assert_eq!(tracker.load_client_bans(), 0);
        assert!(!tracker.is_auto_banned(&"198.51.100.7".parse().unwrap()));

        let _ = std::fs::remove_file(&path);
    }
}
