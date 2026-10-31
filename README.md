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

Release 只提供编译产物，不附带配置文件。仓库根目录的 `config.toml` 是可直接使用的示例，
三个协议的配置都在同一个文件里：

```bash
sudo mkdir -p /etc/aquatic
sudo cp config.toml ip-ban-list.txt client-ban-list.txt /etc/aquatic/
sudo vim /etc/aquatic/config.toml
```

启动哪个协议由命令行决定，配置里不需要开关。要某个协议的全部默认字段，用
`./aquatic udp -p` 生成单协议配置，或 `./aquatic -p` 生成三段合并模板。

### 4. 运行

UDP、HTTP、WebSocket 编译在同一个二进制中，第一个参数选择协议：

```bash
# Linux
chmod +x aquatic-linux-x86_64
./aquatic-linux-x86_64 udp  -c config.toml
./aquatic-linux-x86_64 http -c config.toml   # 仅当构建时包含 HTTP
./aquatic-linux-x86_64 ws   -c config.toml   # 仅当构建时包含 WebSocket

# Windows（仅 UDP）
.\aquatic-windows-x86_64.exe udp -c config.toml
```

运行 `./aquatic-linux-x86_64 --help` 可查看当前二进制实际包含的协议。

三个协议也可以共用一份 `config.toml`（每个协议一张表）。启动时仍按协议分别启动，一条命令一个协议：

```bash
# 一份 config.toml，三个协议各自的配置都在里面
./aquatic udp  -c config.toml &
./aquatic http -c config.toml &
./aquatic ws   -c config.toml &
```

配置写法见[合并配置文件](#合并配置文件)，仓库根目录的 `config.toml` 可直接作为起点。

### 5. 系统优化（推荐）

```bash
# 一键优化（自动检测系统、网卡、CPU，配置 sysctl/ulimit/RPS/开机自启）
bash scripts/optimize.sh
```

## 合并配置文件

一份 `config.toml` 可以同时描述三个协议，每个协议一张表：

```toml
[udp.network]
address_ipv4 = "0.0.0.0:6969"
address_ipv6 = "[::]:6969"

[http.network]
address_ipv4 = "0.0.0.0:8080"
address_ipv6 = "[::]:8080"

[ws.network]
address = "0.0.0.0:8081"
```

启动时按协议分别启动，一条命令一个协议：

```bash
./aquatic udp  -c config.toml &
./aquatic http -c config.toml &
./aquatic ws   -c config.toml &
```

规则很简单：

| 命令 | 配置文件里 | 结果 |
|---|---|---|
| `aquatic udp -c config.toml` | 有 `[udp]` 段 | 用这段配置启动 UDP |
| `aquatic udp -c config.toml` | 没有 `[udp]` 段 | 报错，指出文件里没有该段 |
| `aquatic http -c config.toml` | 当前构建不含 HTTP | 报错，列出本构建支持的协议 |
| `aquatic -c config.toml` | 无所谓 | 报错，要求写明协议 |
| `aquatic udp -c 旧配置.toml` | 旧版单协议格式 | 按旧路径加载，行为不变 |

要点：

- **协议由启动命令决定，配置只提供参数**。没有 `enabled` 之类的开关，停某个协议就停对应进程（或对应 systemd unit）。
- 未被选中的协议表**不会被解析**，所以同一份文件可以同时给 Linux（跑三个）和 Windows（只有 UDP）使用，Windows 上不必删掉 `[http]`/`[ws]`。
- HTTP 与 WebSocket 同为 TCP，**不能共用同一端口**；UDP 与 TCP 端口空间独立，可以和 TCP 重号。仓库自带的 `config.toml` 已按 UDP 6969 / HTTP 8080 / WS 8081 错开。
- 没写出来的字段一律取默认值。完整模板用 `aquatic -p` 生成（三段全量、带注释、端口已错开），单个协议的默认配置用 `aquatic udp -p`。

生产环境建议用 systemd 模板：一份配置管三个进程，故障互不影响。

```ini
# /etc/systemd/system/aquatic@.service
[Unit]
Description=aquatic %i tracker
After=network.target

[Service]
ExecStart=/usr/local/bin/aquatic %i -c /etc/aquatic/config.toml
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now aquatic@udp aquatic@http aquatic@ws
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

当 IP 触发已启用的检查时，按**违规原因的严重程度**分级处理。只有已启用的检查才会
产生违规记录，已被 IP 封禁的请求直接拒绝、不重复计数。

| 档位 | 违规原因 | 处置 |
|---|---|---|
| 高危 | SQL 注入、路径遍历、客户端封禁（peer_id 命中列表） | **首次即封禁**，不等阈值 |
| 可疑 | 爬虫/扫描器、缺少 User-Agent、私有 IP | 计数达到 `threshold` 后封禁 |
| 启发式 | 非标准 peer_id、peer_id 与 User-Agent 不一致（仅 `enforce`） | 计数达到阈值后按阶梯升级 |

高危及可疑档受 `immediate_ban_secs` / `ban_duration_secs` 控制；启发式档在开启
`escalation_enabled` 后按 `escalation_steps` 逐级加长，阶梯用完后转为永久封禁。
每个 IP 的违规历史保留在内存中，`offense_decay_secs` 内没有新违规就清零，
所以偶发一次不会被当成累犯。

```toml
[auto_ban]
enabled = true              # 启用自动封禁
threshold = 10              # 可疑档 / 启发式档的计数阈值
window_secs = 60            # 统计时间窗口（秒）
ban_duration_secs = 0       # 可疑档封禁时长，0 = 永久（默认）
immediate_ban_secs = 0      # 高危档首次封禁时长，0 = 沿用 ban_duration_secs（默认）
ban_list_path = "./ip-ban-list.txt"  # 永久封禁触发时立即写入，重启后仍然生效
flush_interval_secs = 60    # 重试失败写入、热重载 ip_ban_list 的间隔（秒）

# 累进封禁（默认关闭）
escalation_enabled = false
escalation_steps = "300,3600,86400"  # 第 1/2/3 次，用完后转为永久
offense_decay_secs = 86400           # 24 小时无新违规则清空前科
```

> `immediate_ban_secs` 默认 `0`，即沿用 `ban_duration_secs`，因此在默认配置下高危档
> 一次命中就永久封禁。如果担心误判——反向代理配错时所有请求的源地址都会变成代理 IP，
> 一次扫描就会封掉整个入口——建议显式设为 `3600`：1 小时后自动解封，服务能自愈。

> **永久封禁在触发瞬间写入 `ban_list_path`**，不等待 flush 间隔，因此重启不会解除。
> 只要可能产生永久封禁——`ban_duration_secs = 0`，或 `escalation_enabled = true`
> ——就必须同时满足：
>
> - `ban_list_path` 非空；
> - `[ip_ban] mode = "on"`；
> - `ban_list_path` 与 `[ip_ban] path` 指向同一文件。
>
> 任一条件不满足，服务会拒绝启动并给出提示：否则封禁只会存在于内存，重启后失效。
> 临时封禁（时长 `> 0`）只保存在内存中，不写入文件，重启即失效。

> `escalation_steps` 是逗号分隔的秒数，非法条目会导致启动失败。`offense_decay_secs`
> 在开启累进时必须大于 0，否则每次违规都会清空前科，永远升不到永久。
>
> 示例配置中 `auto_ban.enabled` 默认为 `false`：自动封禁依赖各项过滤器计数，
> 过滤器一旦误判（例如把正常客户端识别为爬虫），大量正常用户会在短时间内被封禁。
> 请先用日志观察过滤结果，再启用自动封禁。

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
prometheus_endpoint_address = "127.0.0.1:9002"   # HTTP；UDP 用 9001，WS 用 9003
torrent_count_update_interval = 300
```

`aquatic -p` 生成的模板里三个协议的指标端口已错开：UDP 9001、HTTP 9002、WS 9003。

### 部署监控栈

`monitoring/` 目录提供 Prometheus + Grafana + node-exporter：

```bash
cd monitoring
GRAFANA_ADMIN_PASSWORD='strong-password' docker compose up -d
```

**Prometheus 必须以 `network_mode: host` 运行。** 指标端点只绑 `127.0.0.1`，bridge 容器访问不到宿主机的 loopback；`host.docker.internal` 也不行，它指向 docker0 网关，同样到不了 `127.0.0.1`。所以 `docker-compose.yml` 里 Prometheus 用 host 网络，Grafana 反过来通过 `host.docker.internal:9090` 访问它。

`prometheus.yml` 默认抓 UDP 9001 和 HTTP 9002。只跑一个协议时删掉另一个 job，否则那个 target 会一直显示 down。

### Grafana 面板

`monitoring/grafana/provisioning/dashboards/aquatic-dashboard.json`（uid `aquatic-tracker`）是一个合并面板，同时展示 UDP 与 TCP（HTTP）两个实例：

| 区块 | 内容 |
|---|---|
| Tracker 统计 | 种子数、Peer 数（v4 / v6 / 合计）—— 每个面板两条序列，UDP 与 TCP 并排 |
| 请求与流量 | 请求数、错误率、Announce、已过滤请求、请求类型、出入流量（**仅 UDP**） |
| 系统资源 | CPU / 内存 / 网卡，来自 node-exporter |
| 趋势对比 | 种子数、Peer 数的两条曲线 |

颜色约定通过 `byName` override 固定，不受查询顺序影响：**UDP = 蓝 `#5794F2`，TCP = 橙 `#FF9830`**。

**两个协议导出的指标不一样**，这是上游实现的差异，不是配置问题：

| 指标 | UDP | HTTP（TCP） |
|---|---|---|
| `aquatic_torrents` / `aquatic_peers` | ✅ | ✅ |
| `aquatic_requests_total` / `aquatic_responses_total` | ✅ | ❌ |
| `aquatic_rx_bytes` / `aquatic_tx_bytes` | ✅ | ❌ |
| `aquatic_active_connections` | ❌ | ❌ |

所以「请求与流量」整块只有 UDP 一条线，没有 TCP 对比——面板里放了文本说明标注这一点，避免误以为是面板坏了。`aquatic_active_connections` 任何构建都不导出，已从面板中移除。

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
