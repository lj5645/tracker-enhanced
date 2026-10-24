# Aquatic BitTorrent Tracker - 增强版

基于 [Aquatic](https://github.com/greatest-ape/aquatic) 项目增强的高性能开源 BitTorrent Tracker。

## 功能概览

| 模块 | 协议 | 系统要求 |
|------|------|----------|
| aquatic_udp | BitTorrent over UDP | Linux / Windows |
| aquatic_http | BitTorrent over HTTP（可选 TLS） | Linux 5.8+ |
| aquatic_ws | WebTorrent（可选 TLS） | Linux 5.8+ |

### 核心特性

- 多线程设计，可处理大规模流量
- 全部数据存储在内存中（无需数据库）
- 同时支持 IPv4 和 IPv6
- 支持禁止/允许 info hash
- Prometheus 指标导出
- 自动化 CI 全流程文件传输测试

### 增强功能

- **IP 封禁** - 支持单个 IP 和 CIDR 网段封禁
- **客户端封禁** - 根据 peer_id 模式封禁吸血客户端
- **客户端白名单** - 按 User-Agent 子串或 peer_id 前缀限制客户端（HTTP / UDP / WebSocket 通用）
- **请求过滤** - 自动拦截 SQL 注入、路径遍历、爬虫等恶意请求
- **自动封禁** - 非法请求超过阈值自动封禁 IP，支持时间窗口和封禁时长配置
- **TCP Keepalive** - 快速检测和清理死连接
- **连接数限制** - 防止连接风暴导致内存耗尽
- **Socket 缓冲区** - 可配置的收发缓冲区大小，防止高负载丢包
- **CPU 绑定** - 可选的工作线程 CPU 核心绑定（需要 hwloc）
- **热重载** - 通过信号重载配置，无需重启服务

## 快速开始

### 1. 下载二进制文件

从 [GitHub Releases](https://github.com/lj5645/tracker-enhanced/releases) 下载最新版本。

### 2. 安装运行时依赖（仅 Linux HTTP 模式）

```bash
# 如果启用了 CPU 绑定功能（cpu-pinning feature）
sudo apt-get install -y libhwloc15

# 如果未启用 CPU 绑定，无需额外依赖
```

### 3. 配置

```bash
# 编辑配置文件（Release 资产中已附带三个示例）
vim aquatic-http-config.toml
```

### 4. 运行

```bash
# HTTP Tracker（仅 Linux）
chmod +x aquatic_http-linux-x86_64
./aquatic_http-linux-x86_64 -c aquatic-http-config.toml

# UDP Tracker（Linux / Windows）
chmod +x aquatic_udp-linux-x86_64
./aquatic_udp-linux-x86_64 -c aquatic-udp-config.toml

# WebTorrent / WebSocket Tracker（仅 Linux）
chmod +x aquatic_ws-linux-x86_64
./aquatic_ws-linux-x86_64 -c aquatic-ws-config.toml
```

### 5. 系统优化（推荐）

```bash
# 一键优化（自动检测系统、网卡、CPU，配置 sysctl/ulimit/RPS/开机自启）
bash scripts/optimize.sh
```

## 增强功能详细说明

### IP 封禁

支持封禁特定 IP 地址或 CIDR 范围。

**配置文件**: `ip-ban-list.txt`

```
# 封禁单个 IP
192.168.1.100

# 封禁 IP 段
10.0.0.0/8

# 封禁 IPv6 范围
2001:db8::/32

# 行尾注释、空行、Windows 换行（CRLF）和 UTF-8 BOM 均受支持
203.0.113.9  # 扫描器
```

说明:

- IPv4 与 IPv6 条目都支持，也支持 CIDR（如 `/8`、`/32`、`/64`、`/128`）。
- 双栈监听（WebSocket 绑定 `[::]` 且 `only_ipv6 = false`）下，IPv4 客户端的源地址是 `::ffff:a.b.c.d`，服务端会自动按 IPv4 匹配，因此 IPv4 封禁项依然生效。
- 格式错误的行会被跳过并在日志中给出警告，不会影响其余条目。
- WebSocket 服务在握手阶段即拒绝被封禁的 IP（自动封禁同样如此），不会先建立连接再逐条拦截。

**配置项**:

```toml
[ip_ban]
mode = "on"
path = "./ip-ban-list.txt"
```

### 客户端封禁

支持根据 peer_id 模式封禁特定 BitTorrent 客户端（如迅雷、QQ旋风等吸血客户端）。

**配置文件**: `client-ban-list.txt`

```
# 封禁迅雷
-xl
-sd

# 封禁 QQ 旋风
-qd

# 封禁 BitComet
-bn
-bc
```

**配置项**:

```toml
[client_ban]
mode = "on"
path = "./client-ban-list.txt"
```

### 客户端白名单

只允许特定的 BitTorrent 客户端访问，不在白名单中的客户端将被拒绝。
白名单不会覆盖客户端封禁：同一客户端即使匹配白名单，只要命中封禁列表仍然会被拒绝。

**配置文件**: `client-whitelist.txt`

```
# User-Agent 子串（HTTP / WebSocket，不区分大小写）
utorrent
transmission
qbittorrent
deluge
libtorrent

# peer_id 前缀（UDP / WebSocket，以 "-" 开头）
-ut
-tr
-qb
-de
-lt
```

**配置项**:

```toml
[client_whitelist]
mode = "on"
path = "./client-whitelist.txt"
```

匹配规则：

- 不以 `-` 开头的行：User-Agent 包含匹配，不区分大小写。
- 以 `-` 开头的行：peer_id 前缀匹配，不区分大小写。
- 两种行可以混在同一个文件中。只要有任意一个适用的模式匹配就放行。
- UDP 没有 User-Agent，所以使用 UDP 时文件里必须至少有一个 `-` 开头的
  peer_id 前缀，否则启动会报错。
- 只有 `client_whitelist` 模式为 `on` 时才会检查。

### 请求过滤

自动过滤恶意请求：

| 过滤项 | 说明 |
|--------|------|
| `filter_sql_injection` | 检测 URI 中的 SQL 关键字 |
| `filter_path_traversal` | 检测 `../` 及编码变体 |
| `filter_crawlers` | 检测爬虫 User-Agent（bot, curl, wget, python-requests 等） |
| `filter_private_ips` | 阻止私有 IP 地址请求 |
| `filter_missing_user_agent` | 阻止无 User-Agent 的请求 |

> **注意**: `filter_crawlers = true` 会导致 newTrackon 等 Tracker 检测网站显示 "Request filtered"，因为它们使用 python-requests 发请求。如需被检测网站识别，请设为 `false`；同时确认 `filter_missing_user_agent = false`。
>
> 所有 `filter_*` 选项默认都是 `false`（按需开启），只有显式写为 `true` 的检查才会执行。

### 自动封禁

当 IP 在时间窗口内非法请求次数达到阈值时自动封禁。只有已启用的检查才会产生违规记录：
SQL 注入、路径遍历、爬虫/扫描器、缺少 User-Agent（取决于 `[request_filter]`）、
客户端封禁、白名单拦截。已被 IP 封禁的请求会直接拒绝，不重复计数。

```toml
[auto_ban]
enabled = true              # 启用自动封禁
threshold = 10              # 非法请求次数阈值
window_secs = 60            # 统计时间窗口（秒）
ban_duration_secs = 0       # 封禁时长（秒），0 = 永久封禁
ban_list_path = "./ip-ban-list.txt"  # 封禁IP写入文件，重启后仍然生效
flush_interval_secs = 60    # 批量写入文件间隔（秒），写入后自动热重载
```

> 使用 `ban_duration_secs = 0`（永久封禁）时，`ban_list_path` 必须与
> `[ip_ban] path` 完全一致，否则写入的 IP 不会被重新加载，服务会拒绝启动并给出提示。
> 临时封禁只保存在内存中，不会写入文件。

### 性能优化配置

以下配置项在 `aquatic-http-config.toml` 中设置，优化脚本会根据硬件自动生成推荐值：

```toml
[network]
tcp_backlog = 4096
socket_recv_buffer_size = 2097152    # Socket 接收缓冲区（字节）
socket_send_buffer_size = 2097152    # Socket 发送缓冲区（字节）
max_connections_per_worker = 100000  # 每 worker 最大连接数，0 不限制
tcp_keepalive = true                 # TCP Keepalive
tcp_keepalive_idle_secs = 60
tcp_keepalive_interval_secs = 10
tcp_keepalive_probes = 3

[cpu_pinning]
active = false          # 启用需安装 hwloc: sudo apt-get install libhwloc15
direction = "ascending"
core_offset = 0
```

## 热重载配置

通过信号热重载配置，无需重启服务：

| 信号 | 功能 |
|------|------|
| `SIGUSR1` | 重载访问列表和 TLS 证书 |
| `SIGUSR2` | 重载 IP 封禁、客户端封禁、客户端白名单、可信代理列表 |

```bash
# 重载封禁和白名单列表
kill -SIGUSR2 $(pgrep aquatic_http)
```

## 监控

内置 Prometheus 指标导出，支持 Grafana 可视化。

```toml
[metrics]
run_prometheus_endpoint = true
prometheus_endpoint_address = "0.0.0.0:9000"
torrent_count_update_interval = 300
```

## 编译

```bash
# 安装依赖
sudo apt-get install -y cmake build-essential libhwloc-dev

# 编译 HTTP Tracker（含 CPU 绑定功能）
cargo build --release -p aquatic_http --features "metrics,cpu-pinning"

# 编译 HTTP Tracker（不含 CPU 绑定功能，无需 hwloc）
cargo build --release -p aquatic_http --features metrics

# 编译 UDP Tracker
cargo build --release -p aquatic_udp --features metrics
```

## 支持的 BEP 协议

| BEP | 名称 | 支持情况 |
|-----|------|----------|
| BEP-0003 | BitTorrent 协议 | 支持 |
| BEP-0007 | IPv6 Tracker 扩展 | 支持 |
| BEP-0015 | UDP Tracker 协议 | 支持 |
| BEP-0023 | Tracker 返回 Compact Peer 列表 | 支持 |
| BEP-0048 | Tracker Polling Interval | 支持 |

## 项目结构

```
crates/
├── common/              # 公共模块
│   └── src/
│       ├── ip_ban.rs        # IP 封禁
│       ├── client_ban.rs    # 客户端封禁
│       ├── client_whitelist.rs  # 客户端白名单
│       ├── request_filter.rs    # 请求过滤
│       ├── trusted_proxies.rs   # 可信代理
│       └── cpu_pinning.rs       # CPU 绑定
├── http/                # HTTP Tracker
├── udp/                 # UDP Tracker
└── ws/                  # WebTorrent Tracker
```

## 许可证

基于 Aquatic 项目（Apache-2.0），增强代码同样遵循 Apache-2.0 许可证。
