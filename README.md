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

Release 只提供编译产物，不附带配置文件。示例配置在仓库根目录：

```bash
# 根据所用协议复制并修改示例配置
cp aquatic-http-config.toml aquatic-udp-config.toml aquatic-ws-config.toml /etc/aquatic/
vim /etc/aquatic/aquatic-http-config.toml
```

### 4. 运行

UDP、HTTP、WebSocket 编译在同一个二进制中，第一个参数选择协议：

```bash
# Linux
chmod +x aquatic-linux-x86_64
./aquatic-linux-x86_64 udp  -c aquatic-udp-config.toml
./aquatic-linux-x86_64 http -c aquatic-http-config.toml   # 仅当构建时包含 HTTP
./aquatic-linux-x86_64 ws   -c aquatic-ws-config.toml     # 仅当构建时包含 WebSocket

# Windows（仅 UDP）
.\aquatic-windows-x86_64.exe udp -c aquatic-udp-config.toml
```

运行 `./aquatic-linux-x86_64 --help` 可查看当前二进制实际包含的协议。

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
ban_vampire_clients = true   # 同时启用内置吸血客户端前缀（-xl/-sd/-qd/-bn/-bc 等）
```

> `ban_vampire_clients = false` 时只使用列表文件中的规则，内置前缀不再生效。

### 非标准 / 伪装客户端检测

封禁列表只能匹配固定的 peer_id 前缀，无法识别伪造版本号或冒用其他客户端
身份的客户端。以下两项检测由程序完成，UDP / HTTP / WebSocket 通用
（User-Agent 检测仅 HTTP / WebSocket 有意义）：

```toml
[client_ban]
# off | warn | enforce
peer_id_strictness = "off"
peer_id_user_agent_mismatch = "off"
peer_id_allowlist_path = ""
```

- `peer_id_strictness`：检查 peer_id 是否为合法的 Azureus（`-XX1234-`）或
  Mainline（`M4-3-0--`）格式，并识别不可能存在的客户端大版本号（例如
  `-UT9999-`，uTorrent 最高 3.x）。未知客户端代码只做格式检查。
- `peer_id_user_agent_mismatch`：peer_id 声称的客户端家族与 User-Agent 声称
  的不一致时触发，例如 peer_id 是 `-TR4050-` 但 UA 是 qBittorrent。UA 无法
  识别为 BT 客户端时跳过，因此浏览器里的 WebTorrent 不会被误判。
- 两者都支持 `off`（不检查）、`warn`（只写日志，每分钟最多一条，并累加
  `aquatic_client_identity_checks_total` 指标）、`enforce`（拒绝 announce；
  启用自动封禁时同时计为违规）。`enforce` 的拒绝同样限频写入 warn 日志
  （`client rejected: ...`），不会被日志级别淹没。
- `peer_id_allowlist_path` 指向一个每行一个 peer_id 前缀的文件，命中的
  peer_id 会**同时跳过两项检测**（`peer_id_strictness` 与
  `peer_id_user_agent_mismatch`），是误判的豁免通道。建议先用 `warn`
  观察一段时间，确认没有误判后再切换为 `enforce`。
- 这两项检测与 `mode` 解耦：即使 `mode = "off"`，只要对应选项不是 `off`
  就会执行。
- 如果同时启用了 `[auto_ban]`，服务启动时会打印警告：`enforce` 下的每次
  拒绝都会计入自动封禁违规，一次误判可能与阈值叠加，在 `window_secs` 内
  形成永久封禁。确认误判不会发生后再组合使用。

> 不要用 `-ut0` ~ `-ut9` 这样的前缀封禁“伪造版本号”：Azureus peer_id 的
> 第 4 个字符是版本首位，列出 0–9 等于封禁全部 uTorrent（`-tx*`、`-bc*`
> 同理）。仓库自带的 `client-ban-list.txt` 已移除这类规则，伪造版本请交给
> `peer_id_strictness`。

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
客户端封禁、非标准 peer_id、peer_id 与 User-Agent 不一致（后两项仅在
`enforce` 模式下计数）。已被 IP 封禁的请求会直接拒绝，不重复计数。

```toml
[auto_ban]
enabled = true              # 启用自动封禁
threshold = 10              # 非法请求次数阈值
window_secs = 60            # 统计时间窗口（秒）
ban_duration_secs = 0       # 封禁时长（秒），0 = 永久封禁（默认值）
ban_list_path = "./ip-ban-list.txt"  # 永久封禁触发时立即写入，重启后仍然生效
flush_interval_secs = 60    # 重试失败写入、热重载 ip_ban_list 的间隔（秒）
```

> 永久封禁在触发瞬间写入 `ban_list_path`，不需要等待 flush 间隔，因此重启不会
> 解除封禁。使用 `ban_duration_secs = 0` 时必须同时设置：
>
> - `ban_list_path` 非空；
> - `[ip_ban] mode = "on"`；
> - `ban_list_path` 与 `[ip_ban] path` 指向同一文件。
>
> 任一条件不满足，服务会拒绝启动并给出提示：否则封禁只会存在于内存，重启后失效。
> `ban_duration_secs` 默认为 `0`（永久封禁）；临时封禁（`> 0`）只保存在内存中，
> 不会写入文件，重启即失效。
>
> 示例配置中 `auto_ban.enabled` 默认为 `false`：自动封禁依赖各项过滤器计数，
> 过滤器一旦误判（例如把正常客户端识别为爬虫），大量正常用户会在短时间内被
> 永久封禁。请先观察日志确认过滤结果，再启用自动封禁。

### 反向代理与可信代理

HTTP Tracker 位于 nginx/CDN 等反向代理之后时，需要同时配置：

```toml
[network]
runs_behind_reverse_proxy = true
reverse_proxy_ip_header_name = "X-Forwarded-For"

[trusted_proxies]
enabled = true
path = "./trusted-proxies.txt"
```

`trusted-proxies.txt` 每行写一个代理 IP 或 CIDR（如 `127.0.0.1/32`、`10.0.0.0/8`）。

- 只有连接来自列表中的代理时，才会读取 `X-Forwarded-For`；其他来源的同名
  头部会被忽略，使用 socket 源地址，防止客户端伪造 IP 绕过封禁。
- 多级代理时取“从右往左第一个不在可信列表中的地址”，而不是简单取最右或
  最左地址：最右项是代理追加的，最左项可能由客户端提供。
- `runs_behind_reverse_proxy = true` 但 `trusted_proxies.enabled = false` 时
  程序拒绝启动；`enabled = true` 但列表为空同样拒绝启动。

WebSocket 服务也会在握手阶段按同样的规则解析 `X-Forwarded-For`。

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

> `tcp_keepalive*`、`socket_recv_buffer_size`、`socket_send_buffer_size` 仅 HTTP
> 服务支持。WebSocket 服务（长连接）使用 `max_connections_per_worker` 限制每个
> worker 的并发连接数（默认 100000，0 表示不限制），UDP 服务没有连接概念。

## 热重载配置

通过信号热重载配置，无需重启服务：

| 信号 | 功能 |
|------|------|
| `SIGUSR1` | 重载访问列表和 TLS 证书 |
| `SIGUSR2` | 重载 IP 封禁、客户端封禁、可信代理列表 |

```bash
# 重载封禁列表和可信代理列表
kill -SIGUSR2 $(pgrep -f "aquatic.*http")
```

## 监控

内置 Prometheus 指标导出，支持 Grafana 可视化。

```toml
[metrics]
run_prometheus_endpoint = true
# 指标端点没有认证，默认只监听本机；远程抓取请通过防火墙或反向代理限制来源
prometheus_endpoint_address = "127.0.0.1:9000"
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
│       ├── request_filter.rs    # 请求过滤
│       ├── trusted_proxies.rs   # 可信代理
│       └── cpu_pinning.rs       # CPU 绑定
├── http/                # HTTP Tracker
├── udp/                 # UDP Tracker
└── ws/                  # WebTorrent Tracker
```

## 许可证

基于 Aquatic 项目（Apache-2.0），增强代码同样遵循 Apache-2.0 许可证。
