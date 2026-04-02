# Aquatic BitTorrent Tracker - Enhanced Version

基于 [Aquatic](https://github.com/greatest-ape/aquatic) 项目增强的 BitTorrent Tracker，新增了 IP 封禁、客户端封禁、请求过滤等功能。

## 新增功能

### 1. IP 封禁功能

支持封禁特定 IP 地址或 CIDR 范围。

**配置文件**: `config/ip-ban-list.txt`

```
# 封禁单个 IP
192.168.1.100

# 封禁 IP 段
10.0.0.0/8

# 封禁 IPv6 范围
2001:db8::/32
```

**配置项** (`config/aquatic-http.toml`):

```toml
[ip_ban]
mode = "on"
path = "config/ip-ban-list.txt"
```

### 2. 客户端封禁功能

支持根据 peer_id 模式封禁特定 BitTorrent 客户端。

**配置文件**: `config/client-ban-list.txt`

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

**配置项** (`config/aquatic-http.toml`):

```toml
[client_ban]
mode = "on"
path = "config/client-ban-list.txt"
```

### 3. 客户端白名单功能

只允许特定的 BitTorrent 客户端访问，不在白名单中的客户端将被拒绝。

**配置文件**: `config/client-whitelist.txt`

```
# 常见 BT 客户端
utorrent
bittorrent
transmission
qbittorrent
deluge
libtorrent
rtorrent
vuze
azureus
bitcomet
```

**配置项** (`config/aquatic-http.toml`):

```toml
[client_whitelist]
mode = "on"
path = "config/client-whitelist.txt"
```

**匹配规则**：
- 使用 `contains` 匹配（包含匹配）
- 大小写不敏感
- 版本号不影响匹配结果

**示例**：
- `uTorrent/3.5.5` → 匹配 `utorrent` → ✅ 允许
- `Transmission/3.00` → 匹配 `transmission` → ✅ 允许
- `curl/7.68.0` → 不匹配任何白名单项 → ❌ 拒绝

### 4. 请求过滤功能

自动过滤恶意请求，包括：
- SQL 注入攻击
- 路径遍历攻击
- 爬虫和扫描器
- 私有 IP 地址（可选）

**配置项** (`config/aquatic-http.toml`):

```toml
[request_filter]
filter_sql_injection = true
filter_path_traversal = true
filter_crawlers = true
filter_private_ips = false
```

### 5. Prometheus 监控

内置 Prometheus 指标导出，支持 Grafana 可视化。

**配置项** (`config/aquatic-http.toml`):

```toml
[metrics]
run_prometheus_endpoint = true
prometheus_endpoint_address = "0.0.0.0:9000"
```

## 快速开始

### 1. 编译项目

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 编译 HTTP Tracker
cargo build --release -p aquatic_http --features metrics

# 编译 UDP Tracker
cargo build --release -p aquatic_udp --features metrics
```

### 2. 配置

```bash
# 复制配置文件
cp config/aquatic-http.toml aquatic-http.toml

# 编辑配置
vim aquatic-http.toml
```

### 3. 运行

```bash
# 运行 HTTP Tracker
./target/release/aquatic_http -c aquatic-http.toml

# 运行 UDP Tracker
./target/release/aquatic_udp -c aquatic-udp.toml
```

### 4. 启动监控（可选）

```bash
# 启动 Prometheus 和 Grafana
docker-compose up -d

# 访问 Grafana
# http://localhost:3000
# 用户名: admin
# 密码: admin
```

## 热重载配置

项目支持通过信号进行热重载，无需重启服务：

| 信号 | 功能 | 说明 |
|------|------|------|
| `SIGUSR1` | 重载访问列表和 TLS 证书 | 重新加载 `access_list` 和 TLS 配置 |
| `SIGUSR2` | 重载封禁和白名单列表 | 重新加载 `ip_ban_list`、`client_ban_list` 和 `client_whitelist` |

### 使用方法

```bash
# 获取进程 PID
ps aux | grep aquatic_http

# 重载访问列表和 TLS 证书
kill -SIGUSR1 <pid>

# 重载 IP 封禁列表、客户端封禁列表和客户端白名单
kill -SIGUSR2 <pid>

# 或者使用 pkill
pkill -SIGUSR1 aquatic_http
pkill -SIGUSR2 aquatic_http
```

### 热重载示例

```bash
# 1. 编辑封禁列表
echo "192.168.1.100" >> config/ip-ban-list.txt
echo "-xl" >> config/client-ban-list.txt

# 2. 发送信号重载
kill -SIGUSR2 $(pgrep aquatic_http)

# 3. 查看日志确认
# [INFO] IP ban list updated (1 entries)
# [INFO] Client ban list updated (1 entries)
```

## 项目结构

```
OpenTracker/
├── crates/
│   ├── common/
│   │   ├── src/
│   │   │   ├── ip_ban.rs           # IP 封禁模块
│   │   │   ├── client_ban.rs       # 客户端封禁模块
│   │   │   ├── request_filter.rs   # 请求过滤模块
│   │   │   └── access_list.rs      # 原有访问控制
│   │   └── Cargo.toml
│   ├── http/
│   │   └── src/
│   │       └── config.rs           # HTTP 配置（已扩展）
│   └── udp/
│       └── ...
├── config/
│   ├── aquatic-http.toml           # HTTP 配置示例
│   ├── ip-ban-list.txt             # IP 封禁列表
│   ├── client-ban-list.txt         # 客户端封禁列表
│   ├── prometheus.yml              # Prometheus 配置
│   └── grafana/                    # Grafana 配置
├── docker-compose.yml              # Docker Compose 配置
└── README.md
```

## 性能对比

| 指标 | OpenTracker (C) | Aquatic (Rust) |
|------|-----------------|----------------|
| HTTP QPS | ~10,000 | ~80,000 |
| UDP QPS | ~100,000 | ~1,300,000 |
| 内存安全 | 手动管理 | 编译时保证 |
| 并发安全 | 手动加锁 | 所有权系统 |

## 许可证

- Aquatic: Apache-2.0
- 新增代码: Apache-2.0

## 参考资料

- [Aquatic GitHub](https://github.com/greatest-ape/aquatic)
- [BitTorrent BEP 003](http://www.bittorrent.org/beps/bep_0003.html)
- [BitTorrent BEP 015](http://www.bittorrent.org/beps/bep_0015.html)
