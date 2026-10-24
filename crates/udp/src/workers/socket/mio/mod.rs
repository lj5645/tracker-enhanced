mod socket;

use std::time::Duration;

use anyhow::Context;
use aquatic_common::access_list::AccessListCache;
use aquatic_common::ip_ban::{IpBanListCache, create_ip_ban_list_cache};
use aquatic_common::client_ban::{
    create_client_ban_list_cache, ClientBanListCache, IdentityCheck,
};
use aquatic_common::client_whitelist::{ClientWhitelistCache, create_client_whitelist_cache};
use aquatic_common::request_filter::RequestFilter;
use aquatic_common::auto_ban::{AutoBanReason};
use crossbeam_channel::Sender;
use mio::{Events, Interest, Poll, Token};

use aquatic_common::{
    access_list::create_access_list_cache, privileges::PrivilegeDropper, CanonicalSocketAddr,
    ValidUntil,
};
use aquatic_udp_protocol::*;
use rand::rngs::SmallRng;
use rand::SeedableRng;

use crate::common::*;
use crate::config::Config;

use socket::Socket;

use super::validator::ConnectionValidator;
use super::{EXTRA_PACKET_SIZE_IPV4, EXTRA_PACKET_SIZE_IPV6};

const TOKEN_V4: Token = Token(0);
const TOKEN_V6: Token = Token(1);

/// Count a client identity check outcome.
#[cfg(feature = "prometheus")]
fn count_identity_check(check: &'static str, result: &'static str) {
    ::metrics::counter!(
        "aquatic_client_identity_checks_total",
        "protocol" => "udp",
        "check" => check,
        "result" => result,
    )
    .increment(1);
}

#[cfg(not(feature = "prometheus"))]
fn count_identity_check(_check: &'static str, _result: &'static str) {}

pub fn run(
    config: Config,
    shared_state: State,
    statistics: CachePaddedArc<IpVersionStatistics<SocketWorkerStatistics>>,
    statistics_sender: Sender<StatisticsMessage>,
    validator: ConnectionValidator,
    mut priv_droppers: Vec<PrivilegeDropper>,
) -> anyhow::Result<()> {
    let mut opt_socket_ipv4 = if config.network.use_ipv4 {
        let priv_dropper = priv_droppers.pop().expect("not enough privilege droppers");

        Some(Socket::<self::socket::Ipv4>::create(&config, priv_dropper)?)
    } else {
        None
    };
    let mut opt_socket_ipv6 = if config.network.use_ipv6 {
        let priv_dropper = priv_droppers.pop().expect("not enough privilege droppers");

        Some(Socket::<self::socket::Ipv6>::create(&config, priv_dropper)?)
    } else {
        None
    };

    let access_list_cache = create_access_list_cache(&shared_state.access_list);
    let ip_ban_list_cache = create_ip_ban_list_cache(&shared_state.ip_ban_list);
    let client_ban_list_cache = create_client_ban_list_cache(&shared_state.client_ban_list);
    let client_whitelist_cache = create_client_whitelist_cache(&shared_state.client_whitelist);
    let request_filter = RequestFilter::new();
    let peer_valid_until = ValidUntil::new(
        shared_state.server_start_instant,
        config.cleaning.max_peer_age,
    );

    let mut shared = WorkerSharedData {
        config,
        shared_state,
        statistics,
        statistics_sender,
        access_list_cache,
        ip_ban_list_cache,
        client_ban_list_cache,
        client_whitelist_cache,
        request_filter,
        validator,
        buffer: [0; BUFFER_SIZE],
        rng: SmallRng::from_entropy(),
        peer_valid_until,
    };

    let mut events = Events::with_capacity(2);
    let mut poll = Poll::new().context("create poll")?;

    if let Some(socket) = opt_socket_ipv4.as_mut() {
        poll.registry()
            .register(&mut socket.socket, TOKEN_V4, Interest::READABLE)
            .context("register poll")?;
    }
    if let Some(socket) = opt_socket_ipv6.as_mut() {
        poll.registry()
            .register(&mut socket.socket, TOKEN_V6, Interest::READABLE)
            .context("register poll")?;
    }

    let poll_timeout = Duration::from_millis(shared.config.network.poll_timeout_ms);

    let mut iter_counter = 0u64;

    loop {
        poll.poll(&mut events, Some(poll_timeout)).context("poll")?;

        for event in events.iter() {
            if event.is_readable() {
                match event.token() {
                    TOKEN_V4 => {
                        if let Some(socket) = opt_socket_ipv4.as_mut() {
                            socket.read_and_handle_requests(&mut shared);
                        }
                    }
                    TOKEN_V6 => {
                        if let Some(socket) = opt_socket_ipv6.as_mut() {
                            socket.read_and_handle_requests(&mut shared);
                        }
                    }
                    _ => (),
                }
            }
        }

        if let Some(socket) = opt_socket_ipv4.as_mut() {
            socket.resend_failed(&mut shared);
        }
        if let Some(socket) = opt_socket_ipv6.as_mut() {
            socket.resend_failed(&mut shared);
        }

        if iter_counter % 256 == 0 {
            shared.validator.update_elapsed();

            shared.peer_valid_until = ValidUntil::new(
                shared.shared_state.server_start_instant,
                shared.config.cleaning.max_peer_age,
            );
        }

        iter_counter = iter_counter.wrapping_add(1);
    }
}

pub struct WorkerSharedData {
    config: Config,
    shared_state: State,
    statistics: CachePaddedArc<IpVersionStatistics<SocketWorkerStatistics>>,
    statistics_sender: Sender<StatisticsMessage>,
    access_list_cache: AccessListCache,
    ip_ban_list_cache: IpBanListCache,
    client_ban_list_cache: ClientBanListCache,
    client_whitelist_cache: ClientWhitelistCache,
    request_filter: RequestFilter,
    validator: ConnectionValidator,
    buffer: [u8; BUFFER_SIZE],
    rng: SmallRng,
    peer_valid_until: ValidUntil,
}

impl WorkerSharedData {
    /// Checks that only consult ban lists and never count violations.
    ///
    /// They are run before connection-id validation because they are cheap and
    /// because a listed IP should not even receive a connection id. They must
    /// not record auto-ban violations: UDP source addresses are trivially
    /// spoofable, so counting these would let anyone get an arbitrary victim
    /// auto-banned.
    fn is_list_banned(&mut self, src: &CanonicalSocketAddr) -> bool {
        let peer_ip = src.get().ip();

        if self.config.ip_ban.mode.is_on() && self.ip_ban_list_cache.load().is_banned(&peer_ip) {
            ::log::debug!("IP banned: {}", peer_ip);
            return true;
        }

        if let Some(tracker) = &self.shared_state.auto_ban_tracker {
            if tracker.is_auto_banned(&peer_ip) {
                ::log::debug!("Auto-banned IP: {}", peer_ip);
                return true;
            }
        }

        false
    }

    fn is_private_ip_blocked(&self, src: &CanonicalSocketAddr) -> bool {
        let peer_ip = src.get().ip();

        if self.config.request_filter.filter_private_ips && !self.request_filter.is_ip_allowed(&peer_ip)
        {
            ::log::debug!("Private IP filtered: {}", peer_ip);
            true
        } else {
            false
        }
    }

    /// Returns true if the request should be blocked.
    ///
    /// Only call this after validating the connection id: these checks record
    /// auto-ban violations, and doing so for unvalidated packets would let a
    /// spoofed source IP get someone else banned.
    fn run_security_checks(
        &mut self,
        src: &CanonicalSocketAddr,
        peer_id_opt: Option<&PeerId>,
    ) -> bool {
        let peer_ip = src.get().ip();

        // Private IP filter
        if self.is_private_ip_blocked(src) {
            if let Some(tracker) = &self.shared_state.auto_ban_tracker {
                tracker.record_violation(&peer_ip, AutoBanReason::PrivateIp);
            }
            return true;
        }

        let check_client_ban = self.config.client_ban.mode.is_on();
        let check_whitelist = self.config.client_whitelist.mode.is_on();
        let check_peer_id = !self.config.client_ban.peer_id_strictness.is_off();

        if !check_client_ban && !check_whitelist && !check_peer_id {
            return false;
        }

        let peer_id = match peer_id_opt {
            Some(peer_id) => peer_id,
            None => return false,
        };
        let peer_id_str = String::from_utf8_lossy(&peer_id.0);

        // Client ban check
        if check_client_ban && self.client_ban_list_cache.load().is_banned(&peer_id_str) {
            ::log::debug!("Client banned: {}", peer_id_str);
            if let Some(tracker) = &self.shared_state.auto_ban_tracker {
                tracker.record_violation(&peer_ip, AutoBanReason::ClientBanned);
            }
            return true;
        }

        // Client identity check. UDP has no User-Agent, so only the peer id
        // itself is validated here.
        if check_peer_id {
            let strictness = self.config.client_ban.peer_id_strictness;

            match self
                .client_ban_list_cache
                .load()
                .check_peer_id_format(&peer_id.0, strictness)
            {
                IdentityCheck::Ok => {}
                IdentityCheck::Warned => {
                    count_identity_check("peer_id_format", "warn");
                }
                IdentityCheck::Rejected => {
                    count_identity_check("peer_id_format", "reject");

                    ::log::debug!("Client identity rejected: {}", peer_id_str);

                    if let Some(tracker) = &self.shared_state.auto_ban_tracker {
                        tracker.record_violation(&peer_ip, AutoBanReason::NonStandardPeerId);
                    }

                    return true;
                }
            }
        }

        // Client whitelist check
        if check_whitelist
            && !self
                .client_whitelist_cache
                .load()
                .allows(Some(&peer_id_str), None)
        {
            ::log::debug!("Client not whitelisted: {}", peer_id_str);
            if let Some(tracker) = &self.shared_state.auto_ban_tracker {
                tracker.record_violation(&peer_ip, AutoBanReason::NotWhitelisted);
            }
            return true;
        }

        // All checks passed
        false
    }

    fn handle_request(&mut self, request: Request, src: CanonicalSocketAddr) -> Option<Response> {
        let access_list_mode = self.config.access_list.mode;

        // Ban lists are checked first so listed IPs never receive a connection
        // id. These checks do not record violations (see `is_list_banned`).
        if self.is_list_banned(&src) {
            return None;
        }

        match request {
            Request::Connect(request) => {
                // A Connect has no peer id, so the private-IP filter is
                // applied without counting a violation: the packet can be
                // spoofed and must not get an arbitrary IP auto-banned.
                if self.is_private_ip_blocked(&src) {
                    return None;
                }

                return Some(Response::Connect(ConnectResponse {
                    connection_id: self.validator.create_connection_id(src),
                    transaction_id: request.transaction_id,
                }));
            }
            Request::Announce(request) => {
                if !self
                    .validator
                    .connection_id_valid(src, request.connection_id)
                {
                    return None;
                }

                // Violation-recording checks run only for validated packets.
                if self.run_security_checks(&src, Some(&request.peer_id)) {
                    return None;
                }

                if self
                    .access_list_cache
                    .load()
                    .allows(access_list_mode, &request.info_hash.0)
                {
                    let response = self.shared_state.torrent_maps.announce(
                        &self.config,
                        &self.statistics_sender,
                        &mut self.rng,
                        &request,
                        src,
                        self.peer_valid_until,
                    );

                    Some(response)
                } else {
                    Some(Response::Error(ErrorResponse {
                        transaction_id: request.transaction_id,
                        message: "Info hash not allowed".into(),
                    }))
                }
            }
            Request::Scrape(request) => {
                if !self
                    .validator
                    .connection_id_valid(src, request.connection_id)
                {
                    return None;
                }

                if self.run_security_checks(&src, None) {
                    return None;
                }

                let filtered_request = request.filter_info_hashes(|info_hash| {
                    self.access_list_cache
                        .load()
                        .allows(access_list_mode, &info_hash.0)
                });

                Some(Response::Scrape(
                    self.shared_state.torrent_maps.scrape(filtered_request, src),
                ))
            }
        }
    }
}
