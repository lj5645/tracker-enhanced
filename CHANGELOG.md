# 更新日志

## v1.3.6

### 修复

- **修复 WS 白名单对缺失 User-Agent 的逻辑漏洞**：客户端白名单启用时，缺失 User-Agent 的 WebSocket 连接能绕过白名单检查（`if let Some` 跳过 None 情况）。现改为白名单启用但无 UA 时直接拦截
- **修复 ip_ban.mode=Off 时文件无限增长**：当 `ip_ban.mode = Off` 但 `auto_ban.enabled = true` 时，flush 线程仍写文件但从不调用 `remove_ips()`，导致每个 flush 周期重复追加相同的 IP，文件无限增长。现改为 `ip_ban.mode` 为 Off 时完全跳过文件写入，IP 保留在 auto_ban 内存中
- **修复 auto_ban.rs 测试代码**：测试使用 `ban_duration_secs=3600`（临时封禁）但期望 `flush_to_file()` 返回非空结果，与实际逻辑矛盾。同时移除了 `tempfile` 外部依赖，改用 `std::env::temp_dir()`
- **清理未使用的导入**：移除 `auto_ban.rs` 中未使用的 `Arc`，`mio/mod.rs` 和 `uring/mod.rs` 中未使用的 `IpAddr`

## v1.3.5

### 修复

- **修复 ip_ban.mode=Off 时 IP 逃逸**：当 `ip_ban.mode = Off` 但 `auto_ban.enabled = true` 时，`update_ip_ban_list()` 返回 Ok 但不加载文件，flush 线程仍调用 `remove_ips()` 导致 IP 被解封。现改为只有 `ip_ban.mode.is_on()` 时才从内存移除，否则保留在 auto_ban 内存中（影响 HTTP/UDP/WS 三个 tracker）
- **修复 ClientWhitelist 对 peer_id 匹配错误**：`is_allowed()` 使用 `contains()` 子串匹配，对 User-Agent 正确但对 peer_id（如 `-UT1234-abc`）会误匹配。新增 `is_peer_id_allowed()` 方法使用 `starts_with()` 前缀匹配，UDP/WS tracker 的 peer_id 白名单检查已改用此方法

## v1.3.4

### 新增

- **UDP 安全功能集成**：将 IP 封禁、客户端封禁、客户端白名单、自动封禁、私有 IP 过滤集成到 UDP tracker
  - IP 封禁：检查源 IP 是否在封禁列表中
  - 客户端封禁：检查 announce 请求中的 peer_id 是否被封禁
  - 客户端白名单：检查 peer_id 是否在白名单中
  - 自动封禁：违规超过阈值自动封禁 IP，定期刷入 ip_ban_list 文件
  - 私有 IP 过滤：过滤私有 IP 地址的请求
  - SIGUSR2 信号热重载：发送 SIGUSR2 信号重新加载 ip_ban_list、client_ban_list、client_whitelist
  - 注意：UDP 是二进制协议，不支持 SQL 注入/路径遍历检测、爬虫检测、可信代理

- **WS 安全功能集成**：将全部 7 项安全功能集成到 WebSocket (WebTorrent) tracker
  - IP 封禁、客户端封禁、客户端白名单、自动封禁、私有 IP 过滤
  - 可信代理：通过 `accept_hdr_async_with_config` 提取 X-Forwarded-For 头，解析真实客户端 IP
  - 爬虫检测：从 WebSocket 握手阶段的 User-Agent 头检测爬虫，检测到则拒绝连接
  - 客户端白名单同时检查 peer_id 和 User-Agent
  - SIGUSR2 信号热重载

### 修复

- **修复 io_uring 后端安全功能缺失**：UDP tracker 的 io_uring 后端完全没有安全检查（IP 封禁、客户端封禁、白名单、自动封禁、私有 IP 过滤），所有安全功能可被绕过。现已补全
- **修复 auto-ban IP 静默解封**：`ban_list_path` 为空时 `flush_to_file()` 仍返回被封禁 IP 列表，导致 flush 线程调用 `remove_ips()` 后 IP 既不在 auto_ban 内存中也不在 ip_ban_list 中，被静默解封。现改为无文件路径时返回空列表
- **修复 WS `is_crawler` 类型不匹配**：传入 `&String` 给 `Option<&str>` 参数导致编译失败，已修正为 `Some(ua.as_str())`
- **修复 WS 缺少 auto-ban flush 线程**：自动封禁的 IP 永远不会被写入文件、不会被清理，现已添加
- **修复 WS 爬虫检测未检查配置开关**：即使 `filter_crawlers = false` 也会拦截爬虫，现已加上配置检查
- **修复 WS 缺少 `filter_missing_user_agent` 检查**：缺少 User-Agent 的 WebSocket 连接不会被拦截，现已实现
- **修复 UDP flush 线程返回类型不一致**：与 HTTP 实现不一致，缺少注释，已统一
- **修复 auto-ban 内存泄漏**：`cleanup()` 之前仅在有新封禁 IP 时执行，导致未达阈值的过期条目永远不会被清理，内存持续增长。现改为每次 flush 周期都执行 cleanup
- **修复 TrustedProxies 安全漏洞**：空信任代理列表时 `is_trusted()` 返回 `true`，导致启用 `trusted_proxies.enabled` 但列表为空时所有请求都被信任，攻击者可伪造 IP。现改为空列表返回 `false`
- **修复私有 IP 过滤不记录违规**：私有 IP 被过滤后未调用 `record_violation()`，与其他安全过滤器不一致，现已补上
- **修复反向代理缺头崩溃**：配置了反向代理但请求缺少 X-Forwarded-For 头时 `panic!` 导致整个 socket worker 崩溃（DoS 漏洞），现改为返回错误并记录警告日志
- **优化已封禁 IP 性能**：已在 ip_ban_list 中的 IP 不再调用 `record_violation()`，避免每次请求都获取写锁
- **修复非永久封禁持久化问题**：`ban_duration_secs > 0`（临时封禁）时不再写入文件，因为文件格式不支持过期时间，之前会导致临时封禁变成永久封禁

## v1.3.3

### 修复

- **修复 AutoBanTracker 竞态条件**：将 `ArcSwap` 替换为 `RwLock`，消除多线程并发写入时数据丢失的问题
- **修复 `filter_private_ips` 配置无效**：该配置项之前未被实际调用，现已接入安全检查流程
- **修复 `flush_interval_secs=0` 导致 CPU 空转**：添加最小值校验，最小值为 1 秒
- **修复 flush 与 reload 空窗期**：拆分为 `flush_to_file` + `remove_ips` 两步，确保 ip_ban_list 重载成功后才移除内存记录
- 移除 `is_auto_banned` 中不可达的 `flushed` 分支死代码

## v1.3.1

### 新增

- **自动封禁批量写入**：封禁的 IP 先保存在内存中，定时批量写入 `ip-ban-list.txt`，避免频繁 I/O 阻塞请求处理
- **自动热重载**：写入文件后自动触发 `ip_ban_list` 热重载，无需手动发信号
- **内存自动释放**：写入文件后内存中的记录被清除（由 ip_ban_list 接管），避免内存持续增长
- 新增配置项 `flush_interval_secs`（批量写入间隔，默认60秒）

## v1.3.0

### 新增

- **自动封禁功能** (`[auto_ban]` 配置段)
  - IP 在时间窗口内非法请求次数达到阈值时自动封禁
  - 非法请求类型：IP已封禁、SQL注入、路径遍历、爬虫/扫描器、缺少User-Agent、客户端封禁、白名单拦截
  - 可配置阈值（默认10次）、时间窗口（默认60秒）、封禁时长（默认0=永久）
  - **批量写入文件**：封禁的 IP 先保存在内存中，定时批量写入 `ip-ban-list.txt`，避免频繁 I/O 阻塞请求处理
  - **自动热重载**：写入文件后自动触发 `ip_ban_list` 热重载，无需手动发信号
  - **内存自动释放**：写入文件后内存中的记录被清除（由 ip_ban_list 接管），避免内存持续增长
  - 可配置批量写入间隔（`flush_interval_secs`，默认60秒）
  - 自动清理过期记录，防止内存泄漏

### 变更

- `RequestFilter` 新增 `is_sql_injection()`、`is_path_traversal()`、`is_crawler()` 方法，支持精确识别过滤原因

## v1.2.0

### 新增

- **服务器一键优化脚本** (`scripts/optimize.sh`)
  - 自动检测 Linux 发行版（Debian/Ubuntu/CentOS/RHEL/Rocky/Alma/Fedora/Arch/openSUSE）
  - 自动检测包管理器并安装依赖（ethtool、hwloc 等）
  - 自动识别物理网卡（跳过 docker/br/veth 等虚拟网卡）
  - 优化 sysctl 网络参数（逐条检测内核是否支持，不支持的自动跳过）
  - 优化文件描述符限制（limits.conf + systemd）
  - 优化网卡环形缓冲区（自动检测最大值，不支持则跳过）
  - 配置 RPS 多核网络中断分发（自动计算 CPU 掩码）
  - 自动选择 systemd service 或 rc.local 实现开机自启
  - 安装 hwloc 运行时库（多版本包名兼容）
  - 根据 CPU 线程数生成 Tracker 配置建议
  - 完整性检查报告（6 大类检查，PASS/FAIL/SKIP/WARN 标记，汇总统计）
  - 所有操作均先检测是否支持，不支持的自动跳过，任何步骤失败不影响后续执行
  - 修改配置文件前自动备份原文件

---

## v1.1.0

### 新增

- **性能优化** - 防止高负载下的网络丢包问题
  - UDP io_uring ring_size 从 128 增大到 1024，防止 BufRing 耗尽
  - HTTP Channel 大小从 1024 增大到 4096，防止 Socket Worker 阻塞
  - 新增 TCP Socket 缓冲区大小配置（SO_RCVBUF/SO_SNDBUF，默认 2MB）
  - 新增每个 Worker 的最大连接数限制（默认 100,000），防止连接风暴导致 OOM
  - 新增 TCP Keepalive 支持（空闲 60s，间隔 10s，探测 3 次），快速清理死连接
  - 新增 CPU 绑定支持（可选 cpu-pinning feature，需要 hwloc 运行时库）
- **可信代理** - 新增 TrustedProxies 模块，防止 X-Forwarded-For 伪造攻击
- **文档更新** - 合并 README.md 和 README-CN.md 为中文 README，更新 CHANGELOG 和 Release 页面

### 修复

- 修复 TrustedProxies 未正确初始化导致 CPU 99% 占用的问题
- 修复 IpNetworkTable::len() 返回元组类型而非 usize 的问题
- 修复 UDP 模块中 completed_count 类型不匹配（u64 vs i32/usize）的问题
- 修复统计通道发送使用 expect() 可能导致 panic 的问题
- 修复 Scrape 请求未实时过滤访问列表的问题
- 修复 HTTP 连接未声明为 mutable 的编译错误
- 修复 "Too many open files" 错误（需要配合系统 ulimit 配置）

### 变更

- cpu_pinning 模块拆分：配置类型始终可用，绑定函数通过 feature gate 控制
- Release 工作流安装 libhwloc-dev 并启用 cpu-pinning feature 构建
- 配置文件新增 socket 缓冲区、连接限制、TCP keepalive、CPU 绑定等选项

---

## v1.0.2

### 修复

- 修复 IpNetworkTable::len() 返回 (usize, usize) 元组而非 usize 的问题，改用 iter().count()
- 修复 TrustedProxies 未在启动时正确初始化导致 CPU 99% 空转的问题，添加 update_trusted_proxies 调用

---

## v1.0.1

### 修复

- 修复 HTTP 模块编译错误：AnnounceEvent 类型不匹配、未使用的 TrustedProxies 导入、conn 未声明为 mut
- 修复 UDP 模块编译错误：completed_count 类型不匹配、统计通道 expect() 改为 if let Err
- 修复 TrustedProxies 的 Clone 和 Debug 实现（IpNetworkTable 不实现这些 trait）
- 修复 Cargo.toml 中 crate 名称错误（ip-network → ip_network，ip-network-table → ip_network_table）
- 修复安全审查发现的代码质量问题

---

## v1.0.0

### 新增

- **IP 封禁** - 支持单个 IP 和 CIDR 网段封禁，热重载支持（SIGUSR2）
- **客户端封禁** - 根据 peer_id 前缀模式封禁吸血客户端（迅雷、QQ旋风、BitComet 等）
- **客户端白名单** - 仅允许指定 User-Agent 的客户端访问，热重载支持（SIGUSR2）
- **请求过滤** - 自动拦截恶意请求
  - SQL 注入攻击检测（union, select, insert, delete, update, drop 等关键字）
  - 路径遍历攻击检测（../ 及编码变体）
  - 爬虫和扫描器检测（bot, crawler, spider, curl, wget, python-requests 等）
  - 私有 IP 地址过滤（10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 等）
  - 缺少 User-Agent 的请求过滤
- **安全集成** - 将 IP 封禁、客户端封禁、客户端白名单、请求过滤集成到 HTTP 请求处理流水线
- **Prometheus 监控** - 内置指标导出端点，支持 Grafana 可视化
- **热重载** - 通过信号重载配置，无需重启服务
  - SIGUSR1：重载访问列表和 TLS 证书
  - SIGUSR2：重载 IP 封禁、客户端封禁、客户端白名单、可信代理列表
- **GitHub Actions CI/CD** - 跨平台自动构建（Linux x86_64 + Windows x86_64）
- **Docker Compose 监控** - Prometheus + Grafana + node-exporter 一键部署
- **Grafana 仪表盘** - 中文标签，直观单位（万），5s 刷新

### 修复

- 修复 Windows 构建失败：将 privdrop 和 signal-hook 设为 Unix-only 依赖
- 修复 GitHub Actions Node.js 24 兼容性问题
- 修复 metrics crate 版本兼容性（升级到 0.24.2）
- 修复 set_reuse_port 在非 Unix 系统上的编译错误
- 修复 Windows 构建中 mimalloc 和 prometheus feature 的启用问题
- 修复 Release 工作流权限问题，添加 contents write 权限
- 修复 Release 工作流在 Windows 构建失败时仍可发布 Linux 产物

### 变更

- 客户端封禁匹配方式从 contains 改为 starts_with，更精确匹配 peer_id 前缀
- 移除 macOS 构建（HTTP 模块仅支持 Linux）
- 统计模块中未使用变量警告的抑制

---

## 基于

本项目基于 Aquatic v0.9.0 (https://github.com/greatest-ape/aquatic) 开发，以下是上游项目的更新日志供参考：

---

## 上游 Aquatic 更新日志

## 0.9.0

### 通用

#### 新增

- 新增 aquatic_peer_id crate，提取 peer 客户端信息
- 新增 aquatic_bencher crate，自动化基准测试

### aquatic_udp

#### 新增

- 支持报告 peer 客户端信息

#### 变更

- 从 socket worker/swarm worker 分工改为单一 worker 类型，提升性能
- 按 packet 源 IP 和提供的端口索引 peer，而非 peer_id，防止用户冒充
- 对 2 个或更少 peer 的 torrent 避免堆分配，节省内存
- 改进 announce 性能，避免过滤响应 peer
- 在 announce 响应统计中不包括正在 announce 的 peer
- 加固 ConnectionValidator，使 IP 伪造更困难
- 移除配置键 network.poll_event_capacity（始终使用 1）
- 使用 zerocopy 加速请求和响应的解析与序列化
- 按 worker 报告 socket worker 相关的 prometheus 统计
- 移除 CPU 绑定支持

#### 修复

- 任何 worker 线程退出时退出整个应用
- 禁止端口值为 0 的 announce 请求
- 修复 io_uring UB 问题

### aquatic_http

#### 新增

- 在 SIGUSR1 时重载 TLS 证书和密钥
- 支持无 TLS 运行
- 支持反向代理

#### 变更

- 按 packet 源 IP 和提供的端口索引 peer
- 对 4 个或更少 peer 的 torrent 避免堆分配
- 改进 announce 性能
- 移除 CPU 绑定支持

#### 修复

- 修复关闭连接后清理不总是完成的问题
- 任何 worker 线程退出时退出整个应用
- 修复在反向代理后运行 metrics 时发送失败响应的 panic
- 不再总是在发送失败响应后关闭连接

### aquatic_ws

#### 新增

- 支持报告 peer 客户端信息
- 在 SIGUSR1 时重载 TLS 证书和密钥
- 跟踪 peer 发送的 offer，只允许匹配的 answer

#### 变更

- peer 使用 AnnounceEvent::Stopped announce 时不再生成响应
- 不再需要编译时启用 SIMD 扩展
- 只将 announce 和 scrape 响应视为连接仍然存活的标志
- 降低默认 max_peer_age 和 max_connection_idle 配置值
- 移除 CPU 绑定支持

#### 修复

- 修复内存泄漏
- 修复关闭连接后清理不总是完成的问题
- 修复错误响应的双重计数
- 实际关闭发送响应过慢的连接
- 允许使用 AnnounceEvent::Stopped announce 的 peer 稍后在同一 torrent 上使用不同 peer_id

## 0.8.0

### 通用

#### 新增

- 支持 Prometheus 指标端点
- 添加打印解析配置的 CLI 标志
- 添加 aquatic_http_private 实验性私有 tracker 集成

#### 变更

- 将 request workers 重命名为 swarm workers
- 切换到 thin LTO 以加快编译时间
- 使用 Rust 1.64 workspace 继承
- 将 ValidUntil 结构体从 128 位减少到 32 位
- 使用常规 indexmap 替代 amortized-indexmap
- 改进权限降级
- 任何线程 panic 时退出整个程序

### aquatic_udp

#### 新增

- 实验性 io_uring 后端，吞吐量更高
- 可选响应重发缓冲区
- 可选扩展统计（每 torrent peer 直方图）
- 添加 Dockerfile

#### 变更

- 用 BLAKE3 连接验证器替换 ConnectionMap，大幅减少内存消耗
- announce event 为 stopped 时不返回响应 peer
- 忽略源端口值为零的请求

#### 修复

- 计算带宽统计时包括协议头大小

### aquatic_http

#### 变更

- announce event 为 stopped 时不返回响应 peer

### aquatic_http_protocol

#### 修复

- 显式检查 /scrape 路径
- 在头部完全解析前返回 NeedMoreData
- 修复 ScrapeRequest::write 和 AnnounceRequest::write 问题

### aquatic_ws

#### 新增

- 无 TLS 运行时添加 HTTP 健康检查路由

#### 变更

- 使 TLS 可选
- 支持反向代理
- 减少各种结构体大小

#### 修复

- 连接关闭时立即从 swarm 中移除 peer
- 允许 peer 使用多个 peer ID（每个 info hash 只用一个）
