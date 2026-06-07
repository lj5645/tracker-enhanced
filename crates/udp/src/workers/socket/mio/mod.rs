mod socket;

use std::time::Duration;

use anyhow::Context;
use aquatic_common::access_list::AccessListCache;
use aquatic_common::ip_ban::{IpBanListCache, create_ip_ban_list_cache};
use aquatic_common::client_ban::{ClientBanListCache, create_client_ban_list_cache};
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
    /// Returns true if the request should be blocked
    fn run_security_checks(&self, src: &CanonicalSocketAddr, peer_id_opt: Option<&PeerId>) -> bool {
        let peer_ip = src.get().ip();

        // 1. IP ban check
        if self.config.ip_ban.mode.is_on() {
            if self.ip_ban_list_cache.load().is_banned(&peer_ip) {
                ::log::debug!("IP banned: {}", peer_ip);
                return true;
            }
        }

        // 2. Auto-ban check
        if let Some(tracker) = &self.shared_state.auto_ban_tracker {
            if tracker.is_auto_banned(&peer_ip) {
                ::log::debug!("Auto-banned IP: {}", peer_ip);
                return true;
            }
        }

        // 3. Private IP filter
        if self.config.request_filter.filter_private_ips && !self.request_filter.is_ip_allowed(&peer_ip) {
            ::log::debug!("Private IP filtered: {}", peer_ip);
            if let Some(tracker) = &self.shared_state.auto_ban_tracker {
                tracker.record_violation(&peer_ip, AutoBanReason::PrivateIp);
            }
            return true;
        }

        // 4. Client ban check (for announce requests with peer_id)
        if let Some(peer_id) = peer_id_opt {
            let peer_id_str = String::from_utf8_lossy(&peer_id.0);

            if self.config.client_ban.mode.is_on() {
                if self.client_ban_list_cache.load().is_banned(&peer_id_str) {
                    ::log::debug!("Client banned: {}", peer_id_str);
                    if let Some(tracker) = &self.shared_state.auto_ban_tracker {
                        tracker.record_violation(&peer_ip, AutoBanReason::ClientBanned);
                    }
                    return true;
                }
            }

            // 5. Client whitelist check
            if self.config.client_whitelist.mode.is_on() {
                if !self.client_whitelist_cache.load().is_peer_id_allowed(&peer_id_str) {
                    ::log::debug!("Client not whitelisted: {}", peer_id_str);
                    if let Some(tracker) = &self.shared_state.auto_ban_tracker {
                        tracker.record_violation(&peer_ip, AutoBanReason::NotWhitelisted);
                    }
                    return true;
                }
            }
        }

        // All checks passed
        false
    }

    fn handle_request(&mut self, request: Request, src: CanonicalSocketAddr) -> Option<Response> {
        let access_list_mode = self.config.access_list.mode;

        match request {
            Request::Connect(request) => {
                // Run security checks (no peer_id for connect)
                if self.run_security_checks(&src, None) {
                    return None;
                }

                return Some(Response::Connect(ConnectResponse {
                    connection_id: self.validator.create_connection_id(src),
                    transaction_id: request.transaction_id,
                }));
            }
            Request::Announce(request) => {
                // Run security checks with peer_id
                if self.run_security_checks(&src, Some(&request.peer_id)) {
                    return None;
                }

                if self
                    .validator
                    .connection_id_valid(src, request.connection_id)
                {
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

                        return Some(response);
                    } else {
                        return Some(Response::Error(ErrorResponse {
                            transaction_id: request.transaction_id,
                            message: "Info hash not allowed".into(),
                        }));
                    }
                }
            }
            Request::Scrape(request) => {
                // Run security checks (no peer_id for scrape)
                if self.run_security_checks(&src, None) {
                    return None;
                }

                if self
                    .validator
                    .connection_id_valid(src, request.connection_id)
                {
                    let filtered_request = request.filter_info_hashes(|info_hash| {
                        self.access_list_cache
                            .load()
                            .allows(access_list_mode, &info_hash.0)
                    });
                    
                    return Some(Response::Scrape(
                        self.shared_state.torrent_maps.scrape(filtered_request, src),
                    ));
                }
            }
        }

        None
    }
}
