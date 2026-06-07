# Aquatic BitTorrent Tracker - 增强版

基于 [Aquatic](https://github.com/greatest-ape/aquatic) 项目增强的高性能开源 BitTorrent Tracker。

## 功能概览

| 模块 | 协议 | 系统要求 |
|------|------|----------|
| aquatic_udp | BitTorrent over UDP | Unix-like |
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
- **客户端白名单** - 仅允许指定 User-Agent 的客户端访问
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
# 编辑配置文件
vim aquatic-http.toml
```

### 4. 运行

```bash
# HTTP Tracker（仅 Linux）
chmod +x aquatic_http-linux-x86_64
./aquatic_http-linux-x86_64 -c aquatic-http.toml

# UDP Tracker（Linux / Windows）
chmod +x aquatic_udp-linux-x86_64
./aquatic_udp-linux-x86_64 -c aquatic-udp.toml
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
```

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

**配置文件**: `client-whitelist.txt`

```
utorrent
transmission
qbittorrent
deluge
libtorrent
```

**配置项**:

```toml
[client_whitelist]
mode = "on"
path = "./client-whitelist.txt"
```

匹配规则：使用包含匹配，大小写不敏感。

### 请求过滤

自动过滤恶意请求：

| 过滤项 | 说明 |
|--------|------|
| `filter_sql_injection` | 检测 URI 中的 SQL 关键字 |
| `filter_path_traversal` | 检测 `../` 及编码变体 |
| `filter_crawlers` | 检测爬虫 User-Agent（bot, curl, wget, python-requests 等） |
| `filter_private_ips` | 阻止私有 IP 地址请求 |
| `filter_missing_user_agent` | 阻止无 User-Agent 的请求 |

> **注意**: `filter_crawlers = true` 会导致 newTrackon 等 Tracker 检测网站显示 "Request filtered"，因为它们使用 python-requests 发请求。如需被检测网站识别，请设为 `false`。

### 自动封禁

当 IP 在时间窗口内非法请求次数达到阈值时自动封禁。非法请求包括：IP 已封禁、SQL 注入、路径遍历、爬虫/扫描器、缺少 User-Agent、客户端封禁、白名单拦截。

```toml
[auto_ban]
enabled = true              # 启用自动封禁
threshold = 10              # 非法请求次数阈值
window_secs = 60            # 统计时间窗口（秒）
ban_duration_secs = 3600    # 封禁时长（秒），0 = 永久封禁
```

### 性能优化配置

以下配置项在 `aquatic-http.toml` 中设置，优化脚本会根据硬件自动生成推荐值：

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
