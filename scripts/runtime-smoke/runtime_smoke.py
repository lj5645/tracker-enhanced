#!/usr/bin/env python3
"""Black-box runtime smoke tests for the three aquatic tracker binaries.

The tests start the real release binaries, talk to them over their public
protocols (UDP tracker, HTTP tracker, WebSocket/WebTorrent) and assert that the
enhanced security features behave as configured.

Run on Linux (HTTP/WS need glommio/io_uring):

    python3 -I runtime_smoke.py --bin-dir /tmp/bin --work-dir /tmp/runtime

Only the standard library is required for UDP/HTTP. WebSocket tests need the
`websockets` package.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

INFO_HASH = bytes(range(20))
INFO_HASH_STR = "0123456789abcdefghij"  # 20 ASCII characters for WS JSON
PEER_ALLOWED = b"-QB1234-abcdefghijkl"     # 20 bytes, whitelisted via -qb
PEER_BANNED = b"-BT1234-abcdefghijkl"      # 20 bytes, banned via -bt
PEER_OTHER = b"-XX1234-abcdefghijkl"       # 20 bytes, not whitelisted

UA_ALLOWED = "qBittorrent/4.6"
UA_CRAWLER = "curl/8.0"

PROTOCOL_ID = 0x41727101980

PASS = 0
FAIL = 0


def check(condition, message):
    global PASS, FAIL
    if not condition:
        FAIL += 1
        raise AssertionError(message)
    PASS += 1
    print(f"PASS {message}")


def write(path, text):
    path.write_text(text, encoding="utf-8")


def tcp_ready(port, timeout=20.0, host="127.0.0.1"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def assert_port_free(port, tcp, host="127.0.0.1"):
    """Fail early with a clear message instead of letting a stale process
    silently absorb the test traffic."""
    kind = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError as err:
            raise RuntimeError(f"port {host}:{port} is already in use: {err}") from err


def udp_port_bound(port, timeout=10.0):
    """Wait until the UDP port is actually bound.

    Sending a connect request is not usable here: several scenarios ban
    127.0.0.1, so a correct server may legitimately stay silent. Reading the
    kernel socket table works regardless of the ban configuration.
    """
    wanted = f"{port:04X}"
    deadline = time.time() + timeout

    while time.time() < deadline:
        for table in ("/proc/net/udp", "/proc/net/udp6"):
            try:
                lines = Path(table).read_text(encoding="ascii", errors="replace").splitlines()
            except OSError:
                continue

            for line in lines[1:]:
                fields = line.split()
                # fields[1] is local_address, e.g. "0100007F:1B39"
                if len(fields) > 1 and fields[1].rsplit(":", 1)[-1].upper() == wanted:
                    return True

        time.sleep(0.1)

    return False


class Server:
    def __init__(self, name, binary, workdir, port, tcp, host="127.0.0.1"):
        self.name = name
        self.binary = str(binary)
        self.workdir = workdir
        self.port = port
        self.tcp = tcp
        self.host = host
        self.log_path = workdir / "server.log"
        assert_port_free(port, tcp)
        self.log_file = open(self.log_path, "wb")
        try:
            self.proc = subprocess.Popen(
                [self.binary, "-c", "config.toml"],
                cwd=str(workdir),
                stdout=self.log_file,
                stderr=subprocess.STDOUT,
            )
        except Exception:
            # Do not leak the file handle when the binary cannot be started.
            self.log_file.close()
            raise

    def wait_ready(self):
        if self.tcp:
            ready = tcp_ready(self.port, host=self.host)
        else:
            ready = udp_port_bound(self.port)
        if not ready or self.proc.poll() is not None:
            raise RuntimeError(f"{self.name}: server failed to start\n{self.log_tail()}")

    def send_signal(self, sig):
        self.proc.send_signal(sig)

    def stop(self):
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.log_file.close()

    def log_tail(self, lines=80):
        try:
            self.log_file.flush()
            text = self.log_path.read_text(encoding="utf-8", errors="replace")
            return "\n".join(text.splitlines()[-lines:])
        except OSError:
            return "(no log)"


def list_files(directory, ip_ban="", client_ban="-bt\n", whitelist=""):
    write(directory / "ip-ban-list.txt", ip_ban or "# empty\n")
    write(directory / "client-ban-list.txt", client_ban or "# empty\n")
    write(directory / "client-whitelist.txt", whitelist or "# empty\n")
    write(directory / "access-list.txt", "# empty\n")


def udp_config(directory, port, *, ip_ban_on=True, client_ban_on=True,
               whitelist_on=False, private_filter=False, auto_ban=False,
               ipv6_only=False, metrics_port=None):
    metrics = ""
    if metrics_port:
        metrics = f"""
[statistics]
interval = 1
torrent_peer_histograms = false
peer_clients = false
print_to_stdout = false
write_html_to_file = false
html_file_path = "statistics.html"
run_prometheus_endpoint = true
prometheus_endpoint_address = "127.0.0.1:{metrics_port}"
prometheus_peer_id_prefixes = false
"""
    else:
        metrics = """
[statistics]
interval = 0
"""
    write(directory / "config.toml", f"""
socket_workers = 1
log_level = "info"

[network]
use_ipv4 = {str(not ipv6_only).lower()}
use_ipv6 = {str(ipv6_only).lower()}
address_ipv4 = "127.0.0.1:{port}"
address_ipv6 = "[::1]:{port}"
socket_recv_buffer_size = 0
poll_timeout_ms = 50
resend_buffer_max_len = 0
set_only_ipv6 = true

[protocol]
max_scrape_torrents = 70
max_response_peers = 50
peer_announce_interval = 120

[cleaning]
torrent_cleaning_interval = 30
max_connection_age = 120
max_peer_age = 1800
{metrics}
[access_list]
mode = "off"
path = "access-list.txt"

[ip_ban]
mode = "{'on' if ip_ban_on else 'off'}"
path = "ip-ban-list.txt"

[client_ban]
mode = "{'on' if client_ban_on else 'off'}"
path = "client-ban-list.txt"

[client_whitelist]
mode = "{'on' if whitelist_on else 'off'}"
path = "client-whitelist.txt"

[request_filter]
filter_sql_injection = false
filter_path_traversal = false
filter_crawlers = false
filter_private_ips = {str(private_filter).lower()}
filter_missing_user_agent = false

[auto_ban]
enabled = {str(auto_ban).lower()}
threshold = 2
window_secs = 30
ban_duration_secs = 0
ban_list_path = "ip-ban-list.txt"
flush_interval_secs = 1
""")


def http_config(directory, port, *, ip_ban_on=True, client_ban_on=True,
                whitelist_on=False, filters=None, private_filter=False,
                auto_ban=False, proxy=False, trusted_proxy="",
                dualstack=False, metrics_port=None):
    filters = filters or {}
    trusted = f"""
[trusted_proxies]
enabled = {str(bool(trusted_proxy)).lower()}
path = "{"trusted-proxies.txt" if trusted_proxy else ""}"
"""
    if trusted_proxy:
        write(directory / "trusted-proxies.txt", trusted_proxy + "\n")
    # A wildcard IPv6 address with `set_only_ipv6 = false` is a dual-stack
    # listener: IPv4 clients arrive as IPv4-mapped IPv6 addresses.
    ipv6_address = "[::]" if dualstack else "[::1]"
    metrics = f"""
[metrics]
run_prometheus_endpoint = {str(bool(metrics_port)).lower()}
prometheus_endpoint_address = "127.0.0.1:{metrics_port or 0}"
torrent_count_update_interval = 1
"""
    write(directory / "config.toml", f"""
socket_workers = 1
swarm_workers = 1
log_level = "info"

[network]
use_ipv4 = {str(not dualstack).lower()}
use_ipv6 = {str(dualstack).lower()}
address_ipv4 = "127.0.0.1:{port}"
address_ipv6 = "{ipv6_address}:{port}"
tcp_backlog = 128
enable_tls = false
tls_certificate_path = ""
tls_private_key_path = ""
keep_alive = false
runs_behind_reverse_proxy = {str(proxy).lower()}
reverse_proxy_ip_header_name = "X-Forwarded-For"
reverse_proxy_ip_header_format = "last_address"
set_only_ipv6 = {str(not dualstack).lower()}
socket_recv_buffer_size = 0
socket_send_buffer_size = 0
max_connections_per_worker = 1000
tcp_keepalive = false
tcp_keepalive_idle_secs = 60
tcp_keepalive_interval_secs = 10
tcp_keepalive_probes = 3

[protocol]
max_scrape_torrents = 100
max_peers = 100
peer_announce_interval = 120

[cleaning]
torrent_cleaning_interval = 30
connection_cleaning_interval = 60
max_peer_age = 1800
max_connection_idle = 180

[access_list]
mode = "off"
path = "access-list.txt"

[ip_ban]
mode = "{'on' if ip_ban_on else 'off'}"
path = "ip-ban-list.txt"

[client_ban]
mode = "{'on' if client_ban_on else 'off'}"
path = "client-ban-list.txt"

[client_whitelist]
mode = "{'on' if whitelist_on else 'off'}"
path = "client-whitelist.txt"

[request_filter]
filter_sql_injection = {str(filters.get('sql', False)).lower()}
filter_path_traversal = {str(filters.get('path', False)).lower()}
filter_crawlers = {str(filters.get('crawler', False)).lower()}
filter_private_ips = {str(private_filter).lower()}
filter_missing_user_agent = {str(filters.get('missing_ua', False)).lower()}
{trusted}
[auto_ban]
enabled = {str(auto_ban).lower()}
threshold = 2
window_secs = 30
ban_duration_secs = 0
ban_list_path = "ip-ban-list.txt"
flush_interval_secs = 1
{metrics}
""")


def ws_config(directory, port, *, ip_ban_on=True, client_ban_on=True,
              whitelist_on=False, filters=None, private_filter=False,
              auto_ban=False, trusted_proxy="", address=None,
              only_ipv6=False, metrics_port=None):
    if address is None:
        address = f"127.0.0.1:{port}"
    filters = filters or {}
    trusted = f"""
[trusted_proxies]
enabled = {str(bool(trusted_proxy)).lower()}
path = "{"trusted-proxies.txt" if trusted_proxy else ""}"
"""
    if trusted_proxy:
        write(directory / "trusted-proxies.txt", trusted_proxy + "\n")
    metrics = f"""
[metrics]
run_prometheus_endpoint = {str(bool(metrics_port)).lower()}
prometheus_endpoint_address = "127.0.0.1:{metrics_port or 0}"
torrent_count_update_interval = 1
peer_clients = false
peer_id_prefixes = false
"""
    write(directory / "config.toml", f"""
socket_workers = 1
swarm_workers = 1
log_level = "info"

[network]
address = "{address}"
only_ipv6 = {str(only_ipv6).lower()}
tcp_backlog = 128
enable_tls = false
tls_certificate_path = ""
tls_private_key_path = ""
websocket_max_message_size = 65536
websocket_max_frame_size = 16384
websocket_write_buffer_size = 8192
enable_http_health_checks = false

[protocol]
max_scrape_torrents = 255
max_offers = 10
peer_announce_interval = 120

[cleaning]
torrent_cleaning_interval = 30
max_peer_age = 180
max_offer_age = 120
connection_cleaning_interval = 30
max_connection_idle = 180
close_after_tls_update_grace_period = 216000

[access_list]
mode = "off"
path = "access-list.txt"

[ip_ban]
mode = "{'on' if ip_ban_on else 'off'}"
path = "ip-ban-list.txt"

[client_ban]
mode = "{'on' if client_ban_on else 'off'}"
path = "client-ban-list.txt"

[client_whitelist]
mode = "{'on' if whitelist_on else 'off'}"
path = "client-whitelist.txt"

[request_filter]
filter_sql_injection = {str(filters.get('sql', False)).lower()}
filter_path_traversal = {str(filters.get('path', False)).lower()}
filter_crawlers = {str(filters.get('crawler', False)).lower()}
filter_private_ips = {str(private_filter).lower()}
filter_missing_user_agent = {str(filters.get('missing_ua', False)).lower()}
{trusted}
[auto_ban]
enabled = {str(auto_ban).lower()}
threshold = 2
window_secs = 30
ban_duration_secs = 0
ban_list_path = "ip-ban-list.txt"
flush_interval_secs = 1
{metrics}
""")


# ---------------------------------------------------------------------------
# UDP probes
# ---------------------------------------------------------------------------

class UdpClient:
    def __init__(self, port, timeout=0.8, host="127.0.0.1"):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.addr = (host, port)
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.tx = 1000

    def close(self):
        self.sock.close()

    def _send(self, payload):
        self.sock.sendto(payload, self.addr)

    def _recv(self):
        try:
            data, _ = self.sock.recvfrom(2048)
            return data
        except socket.timeout:
            return None

    def connect(self):
        self.tx += 1
        self._send(struct.pack(">QII", PROTOCOL_ID, 0, self.tx))
        data = self._recv()
        if data is None:
            return None
        action, tx, connection_id = struct.unpack(">IIQ", data[:16])
        check(action == 0 and tx == self.tx, "UDP connect response")
        return connection_id

    def announce(self, connection_id, peer_id, event=2):
        self.tx += 1
        self._send(struct.pack(
            ">QII20s20sQQQIIIiH",
            connection_id, 1, self.tx, INFO_HASH, peer_id,
            0, 0, 0, event, 0, 0, -1, 6881,
        ))
        data = self._recv()
        if data is None:
            return None
        action, tx, interval, leechers, seeders = struct.unpack(">IIIII", data[:20])
        check(action == 1 and tx == self.tx, "UDP announce response")
        return {"interval": interval, "leechers": leechers, "seeders": seeders}

    def scrape(self, connection_id):
        self.tx += 1
        self._send(struct.pack(">QII20s", connection_id, 2, self.tx, INFO_HASH))
        data = self._recv()
        if data is None:
            return None
        action, tx = struct.unpack(">II", data[:8])
        check(action == 2 and tx == self.tx, "UDP scrape response")
        return struct.unpack(">III", data[8:20])


def udp_basic(port):
    c = UdpClient(port)
    try:
        cid = c.connect()
        check(cid is not None, "udp basic: allowed connect")
        check(c.announce(cid, PEER_ALLOWED) is not None, "udp basic: allowed announce")
        check(c.announce(cid, PEER_BANNED) is None, "udp basic: banned client dropped")
        check(c.scrape(cid) is not None, "udp basic: scrape")
    finally:
        c.close()


def udp_whitelist(port):
    c = UdpClient(port)
    try:
        cid = c.connect()
        check(cid is not None, "udp whitelist: connect")
        check(c.announce(cid, PEER_ALLOWED) is not None, "udp whitelist: allowed peer")
        check(c.announce(cid, PEER_OTHER) is None, "udp whitelist: other peer dropped")
    finally:
        c.close()


def udp_autoban(port, workdir):
    c = UdpClient(port)
    try:
        cid = c.connect()
        check(cid is not None, "udp autoban: connect")
        check(c.announce(cid, PEER_BANNED) is None, "udp autoban: violation 1 dropped")
        check(c.announce(cid, PEER_BANNED) is None, "udp autoban: violation 2 dropped")
        check(c.announce(cid, PEER_ALLOWED) is None, "udp autoban: allowed client blocked after ban")
        check(c.connect() is None, "udp autoban: connect blocked after ban")
    finally:
        c.close()
    # Shorter than flush_interval_secs (1s in this config): the ban must
    # already be on disk without waiting for the periodic flush.
    time.sleep(0.2)
    content = (workdir / "ip-ban-list.txt").read_text(encoding="utf-8")
    check("127.0.0.1" in content, "udp autoban: banned IP persisted immediately")


def udp_ipban(port):
    c = UdpClient(port)
    try:
        check(c.connect() is None, "udp ipban: connect blocked")
    finally:
        c.close()


def udp_ipban_ipv6(port):
    c = UdpClient(port, host="::1")
    try:
        check(c.connect() is None, "udp ipban ipv6: connect blocked")
    finally:
        c.close()


def udp_ipban_off(port):
    c = UdpClient(port)
    try:
        # The list contains the client IP, but ip_ban.mode = off.
        check(c.connect() is not None, "udp ipban off: connect allowed")
    finally:
        c.close()


def udp_private(port):
    c = UdpClient(port)
    try:
        check(c.connect() is None, "udp private filter: localhost blocked")
    finally:
        c.close()


def udp_hotreload(port, server, workdir):
    c = UdpClient(port)
    try:
        cid = c.connect()
        check(cid is not None, "udp hotreload: connect before reload")
        check(c.announce(cid, PEER_ALLOWED) is not None, "udp hotreload: announce before reload")
        (workdir / "ip-ban-list.txt").write_text("127.0.0.1\n", encoding="utf-8")
        server.send_signal(signal.SIGUSR2)
        time.sleep(1.0)
        check(c.announce(cid, PEER_ALLOWED) is None, "udp hotreload: announce blocked after SIGUSR2")
        check(c.connect() is None, "udp hotreload: connect blocked after SIGUSR2")

        # Removing the entry and reloading must lift the ban again.
        (workdir / "ip-ban-list.txt").write_text("# empty\n", encoding="utf-8")
        server.send_signal(signal.SIGUSR2)
        time.sleep(1.0)
        check(c.connect() is not None, "udp hotreload: unblocked after second SIGUSR2")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# HTTP probes
# ---------------------------------------------------------------------------

def http_request(port, target, *, user_agent=UA_ALLOWED, headers=None, timeout=5):
    lines = [f"GET {target} HTTP/1.1", "Host: 127.0.0.1", "Connection: close"]
    if user_agent is not None:
        lines.append(f"User-Agent: {user_agent}")
    for key, value in (headers or {}).items():
        lines.append(f"{key}: {value}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.sendall(raw)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    response = b"".join(chunks)
    head, _, body = response.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    status = int(status_line.split()[1]) if status_line else 0
    return status, body


def announce_target(peer_id, extra=""):
    qs = (
        "info_hash=" + urllib.parse.quote_from_bytes(INFO_HASH)
        + "&peer_id=" + urllib.parse.quote(peer_id)
        + "&port=6881&uploaded=0&downloaded=0&left=0&event=started&compact=1"
    )
    if extra:
        qs += "&" + extra
    return "/announce?" + qs


def scrape_target():
    return "/scrape?info_hash=" + urllib.parse.quote_from_bytes(INFO_HASH)


def http_response_body(port, target, **kwargs):
    status, body = http_request(port, target, **kwargs)
    check(status == 200, f"HTTP status 200 for {target.split('?')[0]}")
    return body


def http_allowed(port, target, label, **kwargs):
    body = http_response_body(port, target, **kwargs)
    check(b"8:interval" in body and b"5:peers" in body, f"{label}: successful announce")
    return body


def http_blocked(port, target, reason, label, **kwargs):
    body = http_response_body(port, target, **kwargs)
    check(reason.encode() in body, f"{label}: {reason}")


def http_basic(port):
    http_allowed(port, announce_target(PEER_ALLOWED), "http basic allowed")
    http_blocked(port, announce_target(PEER_BANNED), "Client banned", "http basic banned client")
    body = http_response_body(port, scrape_target())
    check(b"5:files" in body, "http basic: scrape")


def http_whitelist(port):
    http_allowed(port, announce_target(PEER_ALLOWED), "http whitelist allowed")
    http_blocked(port, announce_target(PEER_OTHER), "Client not allowed", "http whitelist blocked")


def http_filters(port):
    http_allowed(port, announce_target(PEER_ALLOWED), "http filters: normal request")
    http_blocked(port, announce_target(PEER_ALLOWED, "x=1%20union%20select%202"),
                 "Request filtered", "http filters: SQL injection")
    http_blocked(port, announce_target(PEER_ALLOWED, "x=..%2f..%2fetc%2fpasswd"),
                 "Request filtered", "http filters: path traversal")
    http_blocked(port, announce_target(PEER_ALLOWED), "Request filtered",
                 "http filters: crawler", user_agent=UA_CRAWLER)
    http_blocked(port, announce_target(PEER_ALLOWED), "Request filtered",
                 "http filters: missing user agent", user_agent=None)


def http_private(port):
    http_blocked(port, announce_target(PEER_ALLOWED), "Private IP not allowed",
                 "http private filter")


def http_ipban(port):
    http_blocked(port, announce_target(PEER_ALLOWED), "IP banned", "http ipban")


def http_ipban_off(port):
    http_allowed(port, announce_target(PEER_ALLOWED), "http ipban off: announce allowed")


def http_trusted_proxy(port):
    headers = {"X-Forwarded-For": "1.2.3.4, 203.0.113.9"}
    http_blocked(port, announce_target(PEER_ALLOWED), "IP banned",
                 "http trusted proxy: rightmost XFF banned", headers=headers)
    headers = {"X-Forwarded-For": "1.2.3.4"}
    http_allowed(port, announce_target(PEER_ALLOWED), "http trusted proxy: trusted client allowed",
                 headers=headers)


def http_autoban(port, workdir):
    http_blocked(port, announce_target(PEER_BANNED), "Client banned", "http autoban violation 1")
    http_blocked(port, announce_target(PEER_BANNED), "Client banned", "http autoban violation 2")
    http_blocked(port, announce_target(PEER_ALLOWED), "IP auto-banned",
                 "http autoban: allowed client blocked after ban")
    # Shorter than flush_interval_secs (1s in this config): the ban must
    # already be on disk without waiting for the periodic flush.
    time.sleep(0.2)
    content = (workdir / "ip-ban-list.txt").read_text(encoding="utf-8")
    check("127.0.0.1" in content, "http autoban: banned IP persisted immediately")


def http_hotreload(port, server, workdir):
    http_allowed(port, announce_target(PEER_ALLOWED), "http hotreload: announce before reload")
    (workdir / "ip-ban-list.txt").write_text("127.0.0.1\n", encoding="utf-8")
    server.send_signal(signal.SIGUSR2)
    time.sleep(1.0)
    http_blocked(port, announce_target(PEER_ALLOWED), "IP banned",
                 "http hotreload: blocked after SIGUSR2")

    # Removing the entry and reloading must lift the ban again.
    (workdir / "ip-ban-list.txt").write_text("# empty\n", encoding="utf-8")
    server.send_signal(signal.SIGUSR2)
    time.sleep(1.0)
    http_allowed(port, announce_target(PEER_ALLOWED),
                 "http hotreload: unbanned after second SIGUSR2")


# ---------------------------------------------------------------------------
# WebSocket probes
# ---------------------------------------------------------------------------

def ws_connect(port, *, user_agent=UA_ALLOWED, headers=None, timeout=5,
               host="127.0.0.1"):
    from websockets.sync.client import connect
    kwargs = {
        "open_timeout": timeout,
        "close_timeout": 1,
        "user_agent_header": user_agent,
    }
    if headers:
        kwargs["additional_headers"] = headers
    if ":" in host:
        host = f"[{host}]"
    return connect(f"ws://{host}:{port}/", **kwargs)


def ws_announce(ws, peer_id):
    ws.send(json.dumps({
        "action": "announce",
        "info_hash": INFO_HASH_STR,
        "peer_id": peer_id.decode(),
        "left": 0,
        "event": "started",
    }))
    return json.loads(ws.recv(timeout=3))


def ws_allowed(port, peer_id, label, **kwargs):
    with ws_connect(port, **kwargs) as ws:
        response = ws_announce(ws, peer_id)
        check(response.get("action") == "announce", f"{label}: successful announce")
        return response


def ws_blocked(port, peer_id, label, **kwargs):
    with ws_connect(port, **kwargs) as ws:
        response = ws_announce(ws, peer_id)
        check(response.get("failure reason") == "Access denied",
              f"{label}: Access denied")


def ws_blocked_anywhere(port, peer_id, label, **kwargs):
    """Assert that a banned IP is rejected either at the handshake or when it
    announces. IP/auto bans reject the WebSocket handshake; request-level
    filters reject the announce message."""
    try:
        with ws_connect(port, **kwargs) as ws:
            response = ws_announce(ws, peer_id)
            check(response.get("failure reason") == "Access denied",
                  f"{label}: Access denied")
    except AssertionError:
        raise
    except Exception:  # noqa: BLE001 - handshake rejection is a valid outcome
        check(True, f"{label}: handshake rejected")


def ws_basic(port):
    with ws_connect(port) as ws:
        response = ws_announce(ws, PEER_ALLOWED)
        check(response.get("action") == "announce", "ws basic: allowed announce")
        ws.send(json.dumps({"action": "scrape", "info_hash": INFO_HASH_STR}))
        scrape = json.loads(ws.recv(timeout=3))
        check(scrape.get("action") == "scrape", "ws basic: scrape")
        response = ws_announce(ws, PEER_BANNED)
        check(response.get("failure reason") == "Access denied", "ws basic: banned client blocked")


def ws_whitelist(port):
    ws_allowed(port, PEER_ALLOWED, "ws whitelist: allowed peer")
    ws_blocked(port, PEER_OTHER, "ws whitelist: other peer")


def ws_ipban(port):
    ws_blocked_anywhere(port, PEER_ALLOWED, "ws ipban")


def ws_ipban_ipv6(port):
    ws_blocked_anywhere(port, PEER_ALLOWED, "ws ipban ipv6", host="::1")


def ws_ipban_dualstack(port):
    # IPv4 client on a [::] listener: the server sees ::ffff:127.0.0.1, which
    # must still match the IPv4 entry in the ban list.
    ws_blocked_anywhere(port, PEER_ALLOWED, "ws ipban dualstack")


def ws_private(port):
    ws_blocked(port, PEER_ALLOWED, "ws private filter")


def ws_trusted_proxy(port):
    headers = {"X-Forwarded-For": "1.2.3.4, 203.0.113.9"}
    ws_blocked_anywhere(port, PEER_ALLOWED,
                        "ws trusted proxy: rightmost XFF banned", headers=headers)
    headers = {"X-Forwarded-For": "1.2.3.4"}
    ws_allowed(port, PEER_ALLOWED, "ws trusted proxy: trusted client allowed", headers=headers)


def ws_autoban(port, workdir):
    with ws_connect(port) as ws:
        check(ws_announce(ws, PEER_BANNED).get("failure reason") == "Access denied",
              "ws autoban: violation 1")
        check(ws_announce(ws, PEER_BANNED).get("failure reason") == "Access denied",
              "ws autoban: violation 2")
        check(ws_announce(ws, PEER_ALLOWED).get("failure reason") == "Access denied",
              "ws autoban: allowed client blocked after ban")
    # Shorter than flush_interval_secs (1s in this config): the ban must
    # already be on disk without waiting for the periodic flush.
    time.sleep(0.2)
    content = (workdir / "ip-ban-list.txt").read_text(encoding="utf-8")
    check("127.0.0.1" in content, "ws autoban: banned IP persisted immediately")


def ws_hotreload(port, server, workdir):
    ws_allowed(port, PEER_ALLOWED, "ws hotreload: announce before reload")
    (workdir / "ip-ban-list.txt").write_text("127.0.0.1\n", encoding="utf-8")
    server.send_signal(signal.SIGUSR2)
    time.sleep(1.0)
    ws_blocked_anywhere(port, PEER_ALLOWED, "ws hotreload: blocked after SIGUSR2")

    # Removing the entry and reloading must lift the ban again.
    (workdir / "ip-ban-list.txt").write_text("# empty\n", encoding="utf-8")
    server.send_signal(signal.SIGUSR2)
    time.sleep(1.0)
    ws_allowed(port, PEER_ALLOWED, "ws hotreload: unbanned after second SIGUSR2")


def ws_handshake_filters(port):
    # Missing User-Agent is rejected after the WebSocket handshake, closing the
    # connection before an announce can be processed.
    try:
        with ws_connect(port, user_agent=None) as ws:
            ws.send(json.dumps({
                "action": "announce",
                "info_hash": INFO_HASH_STR,
                "peer_id": PEER_ALLOWED.decode(),
                "left": 0,
                "event": "started",
            }))
            ws.recv(timeout=3)
        raise AssertionError("ws handshake filters: missing UA was not rejected")
    except Exception as exc:
        if isinstance(exc, AssertionError):
            raise
        check(True, "ws handshake filters: missing user agent rejected")

    try:
        with ws_connect(port, user_agent=UA_CRAWLER) as ws:
            ws.send(json.dumps({
                "action": "announce",
                "info_hash": INFO_HASH_STR,
                "peer_id": PEER_ALLOWED.decode(),
                "left": 0,
                "event": "started",
            }))
            ws.recv(timeout=3)
        raise AssertionError("ws handshake filters: crawler was not rejected")
    except Exception as exc:
        if isinstance(exc, AssertionError):
            raise
        check(True, "ws handshake filters: crawler user agent rejected")

    ws_allowed(port, PEER_ALLOWED, "ws handshake filters: normal client allowed")


def get_metrics(port, timeout=15):
    url = f"http://127.0.0.1:{port}/metrics"
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                body = response.read().decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001 - retried below
            last_error = exc
            time.sleep(0.5)
            continue

        if "aquatic_" in body:
            check(True, f"metrics endpoint {port} exposes aquatic metrics")
            return

        # The endpoint can answer before any metric has been registered yet.
        # Treat that as "not ready" and retry without counting a failed
        # assertion for what is only an intermediate state.
        last_error = "response contains no aquatic_ metrics yet"
        time.sleep(0.5)

    raise AssertionError(f"metrics endpoint {port} not ready: {last_error}")


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

def ipv6_available():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.bind(("::1", 0))
        return True
    except OSError:
        return False


def scenario(name, service, port, config, probe, *, tcp=None, host="127.0.0.1",
             requires_ipv6=False, metrics_port=None):
    return {
        "name": name,
        "service": service,
        "port": port,
        "config": config,
        "probe": probe,
        "tcp": (service != "udp") if tcp is None else tcp,
        "host": host,
        "requires_ipv6": requires_ipv6,
        "metrics_port": metrics_port,
    }


def build_scenarios():
    return [
        # UDP
        scenario("udp_basic", "udp", 18100,
                 lambda d, p: (list_files(d), udp_config(d, p)),
                 lambda s, d: udp_basic(s.port)),
        scenario("udp_whitelist", "udp", 18101,
                 lambda d, p: (list_files(d, whitelist="-qb\n"),
                               udp_config(d, p, whitelist_on=True)),
                 lambda s, d: udp_whitelist(s.port)),
        scenario("udp_autoban", "udp", 18102,
                 lambda d, p: (list_files(d), udp_config(d, p, auto_ban=True)),
                 lambda s, d: udp_autoban(s.port, d)),
        scenario("udp_ipban", "udp", 18103,
                 lambda d, p: (list_files(d, ip_ban="127.0.0.1/32\n"),
                               udp_config(d, p)),
                 lambda s, d: udp_ipban(s.port)),
        scenario("udp_private", "udp", 18104,
                 lambda d, p: (list_files(d), udp_config(d, p, private_filter=True)),
                 lambda s, d: udp_private(s.port)),
        scenario("udp_ipban_cidr", "udp", 18107,
                 lambda d, p: (list_files(d, ip_ban="127.0.0.0/8\n"),
                               udp_config(d, p)),
                 lambda s, d: udp_ipban(s.port)),
        scenario("udp_ipban_exact", "udp", 18108,
                 lambda d, p: (list_files(d, ip_ban="127.0.0.1\n"),
                               udp_config(d, p)),
                 lambda s, d: udp_ipban(s.port)),
        scenario("udp_ipban_ipv6", "udp", 18109,
                 lambda d, p: (list_files(d, ip_ban="::1\n"),
                               udp_config(d, p, ipv6_only=True)),
                 lambda s, d: udp_ipban_ipv6(s.port),
                 requires_ipv6=True),
        scenario("udp_ipban_off", "udp", 18110,
                 lambda d, p: (list_files(d, ip_ban="127.0.0.1\n"),
                               udp_config(d, p, ip_ban_on=False)),
                 lambda s, d: udp_ipban_off(s.port)),
        scenario("udp_hotreload", "udp", 18105,
                 lambda d, p: (list_files(d), udp_config(d, p)),
                 lambda s, d: udp_hotreload(s.port, s, d)),
        scenario("udp_metrics", "udp", 18106,
                 lambda d, p: (list_files(d), udp_config(d, p, metrics_port=18400)),
                 lambda s, d: (udp_basic(s.port), get_metrics(18400)),
                 metrics_port=18400),

        # HTTP
        scenario("http_basic", "http", 18200,
                 lambda d, p: (list_files(d), http_config(d, p, metrics_port=18410)),
                 lambda s, d: (http_basic(s.port), get_metrics(18410)),
                 metrics_port=18410),
        scenario("http_whitelist", "http", 18201,
                 lambda d, p: (list_files(d, whitelist="-qb\n"),
                               http_config(d, p, whitelist_on=True)),
                 lambda s, d: http_whitelist(s.port)),
        scenario("http_filters", "http", 18202,
                 lambda d, p: (list_files(d),
                               http_config(d, p, filters={
                                   "sql": True, "path": True,
                                   "crawler": True, "missing_ua": True,
                               })),
                 lambda s, d: http_filters(s.port)),
        scenario("http_private", "http", 18203,
                 lambda d, p: (list_files(d), http_config(d, p, private_filter=True)),
                 lambda s, d: http_private(s.port)),
        scenario("http_ipban", "http", 18204,
                 lambda d, p: (list_files(d, ip_ban="127.0.0.1/32\n"),
                               http_config(d, p)),
                 lambda s, d: http_ipban(s.port)),
        scenario("http_ipban_cidr", "http", 18209,
                 lambda d, p: (list_files(d, ip_ban="127.0.0.0/8\n"),
                               http_config(d, p)),
                 lambda s, d: http_ipban(s.port)),
        scenario("http_ipban_off", "http", 18210,
                 lambda d, p: (list_files(d, ip_ban="127.0.0.1\n"),
                               http_config(d, p, ip_ban_on=False)),
                 lambda s, d: http_ipban_off(s.port)),
        scenario("http_ipban_dualstack", "http", 18211,
                 lambda d, p: (list_files(d, ip_ban="127.0.0.1/32\n"),
                               http_config(d, p, dualstack=True)),
                 lambda s, d: http_ipban(s.port),
                 requires_ipv6=True),
        scenario("http_trusted_proxy", "http", 18205,
                 lambda d, p: (list_files(d, ip_ban="203.0.113.9\n"),
                               http_config(d, p, proxy=True, trusted_proxy="127.0.0.1/32")),
                 lambda s, d: http_trusted_proxy(s.port)),
        scenario("http_autoban", "http", 18206,
                 lambda d, p: (list_files(d), http_config(d, p, auto_ban=True)),
                 lambda s, d: http_autoban(s.port, d)),
        scenario("http_hotreload", "http", 18207,
                 lambda d, p: (list_files(d), http_config(d, p)),
                 lambda s, d: http_hotreload(s.port, s, d)),
        scenario("http_metrics", "http", 18208,
                 lambda d, p: (list_files(d), http_config(d, p, metrics_port=18411)),
                 lambda s, d: (http_basic(s.port), get_metrics(18411)),
                 metrics_port=18411),

        # WebSocket
        scenario("ws_basic", "ws", 18300,
                 lambda d, p: (list_files(d), ws_config(d, p, metrics_port=18420)),
                 lambda s, d: (ws_basic(s.port), get_metrics(18420)),
                 metrics_port=18420),
        scenario("ws_whitelist", "ws", 18301,
                 lambda d, p: (list_files(d, whitelist="-qb\n"),
                               ws_config(d, p, whitelist_on=True)),
                 lambda s, d: ws_whitelist(s.port)),
        scenario("ws_ipban", "ws", 18302,
                 lambda d, p: (list_files(d, ip_ban="127.0.0.1/32\n"),
                               ws_config(d, p)),
                 lambda s, d: ws_ipban(s.port)),
        scenario("ws_ipban_cidr", "ws", 18311,
                 lambda d, p: (list_files(d, ip_ban="127.0.0.0/8\n"),
                               ws_config(d, p)),
                 lambda s, d: ws_ipban(s.port)),
        scenario("ws_ipban_ipv6", "ws", 18309,
                 lambda d, p: (list_files(d, ip_ban="::1\n"),
                               ws_config(d, p, address=f"[::1]:{p}",
                                         only_ipv6=True)),
                 lambda s, d: ws_ipban_ipv6(s.port),
                 host="::1", requires_ipv6=True),
        scenario("ws_ipban_dualstack", "ws", 18310,
                 lambda d, p: (list_files(d, ip_ban="127.0.0.1/32\n"),
                               ws_config(d, p, address=f"[::]:{p}",
                                         only_ipv6=False)),
                 lambda s, d: ws_ipban_dualstack(s.port),
                 requires_ipv6=True),
        scenario("ws_private", "ws", 18303,
                 lambda d, p: (list_files(d), ws_config(d, p, private_filter=True)),
                 lambda s, d: ws_private(s.port)),
        scenario("ws_trusted_proxy", "ws", 18304,
                 lambda d, p: (list_files(d, ip_ban="203.0.113.9\n"),
                               ws_config(d, p, trusted_proxy="127.0.0.1/32")),
                 lambda s, d: ws_trusted_proxy(s.port)),
        scenario("ws_autoban", "ws", 18305,
                 lambda d, p: (list_files(d), ws_config(d, p, auto_ban=True)),
                 lambda s, d: ws_autoban(s.port, d)),
        scenario("ws_hotreload", "ws", 18306,
                 lambda d, p: (list_files(d), ws_config(d, p)),
                 lambda s, d: ws_hotreload(s.port, s, d)),
        scenario("ws_handshake_filters", "ws", 18307,
                 lambda d, p: (list_files(d),
                               ws_config(d, p, filters={
                                   "crawler": True, "missing_ua": True,
                               })),
                 lambda s, d: ws_handshake_filters(s.port)),
        scenario("ws_metrics", "ws", 18308,
                 lambda d, p: (list_files(d), ws_config(d, p, metrics_port=18421)),
                 lambda s, d: (ws_basic(s.port), get_metrics(18421)),
                 metrics_port=18421),
    ]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", default="/tmp/bin")
    parser.add_argument("--work-dir", default="/tmp/runtime")
    parser.add_argument("--udp-bin")
    parser.add_argument("--http-bin")
    parser.add_argument("--ws-bin")
    parser.add_argument("--services", default="udp,http,ws",
                        help="comma-separated subset of udp,http,ws")
    parser.add_argument("--only", default="",
                        help="comma-separated scenario names")
    args = parser.parse_args()

    services = {s.strip() for s in args.services.split(",") if s.strip()}
    only = {s.strip() for s in args.only.split(",") if s.strip()}
    bin_dir = Path(args.bin_dir)
    work_root = Path(args.work_dir)
    work_root.mkdir(parents=True, exist_ok=True)

    binaries = {
        "udp": Path(args.udp_bin) if args.udp_bin else bin_dir / "aquatic_udp",
        "http": Path(args.http_bin) if args.http_bin else bin_dir / "aquatic_http",
        "ws": Path(args.ws_bin) if args.ws_bin else bin_dir / "aquatic_ws",
    }

    scenarios = [
        s for s in build_scenarios()
        if s["service"] in services and (not only or s["name"] in only)
    ]
    if not scenarios:
        raise SystemExit("no scenarios selected")

    for s in scenarios:
        if not binaries[s["service"]].exists():
            raise SystemExit(f"missing binary: {binaries[s['service']]}")

    ipv6_ok = ipv6_available()

    failed = []
    for s in scenarios:
        if s.get("requires_ipv6") and not ipv6_ok:
            print(f"\n=== {s['name']} ===\nSKIP (IPv6 is not available)")
            continue

        print(f"\n=== {s['name']} ===")
        workdir = work_root / s["name"]
        if workdir.exists():
            shutil.rmtree(workdir)
        workdir.mkdir(parents=True)
        s["config"](workdir, s["port"])
        server = None
        try:
            server = Server(s["name"], binaries[s["service"]], workdir, s["port"],
                            s["tcp"], host=s["host"])
            server.wait_ready()
            s["probe"](server, workdir)
        except Exception as exc:  # noqa: BLE001 - report and continue
            failed.append(s["name"])
            print(f"FAIL {s['name']}: {exc}", file=sys.stderr)
            if server is not None:
                print(server.log_tail(), file=sys.stderr)
        finally:
            if server is not None:
                server.stop()

    print(f"\n{PASS} checks passed, {FAIL} assertions failed")
    if failed:
        print("failed scenarios: " + ", ".join(failed), file=sys.stderr)
        sys.exit(1)
    print("ALL RUNTIME SMOKE TESTS PASSED")


if __name__ == "__main__":
    main()
