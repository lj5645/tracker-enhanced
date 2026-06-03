# 更新日志

## v1.1.0 - 2026-06-03

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

## v1.0.2 - 2026-05-14

### 修复

- 修复 IpNetworkTable::len() 返回 (usize, usize) 元组而非 usize 的问题，改用 iter().count()
- 修复 TrustedProxies 未在启动时正确初始化导致 CPU 99% 空转的问题，添加 update_trusted_proxies 调用

---

## v1.0.1 - 2026-05-10

### 修复

- 修复 HTTP 模块编译错误：AnnounceEvent 类型不匹配、未使用的 TrustedProxies 导入、conn 未声明为 mut
- 修复 UDP 模块编译错误：completed_count 类型不匹配、统计通道 expect() 改为 if let Err
- 修复 TrustedProxies 的 Clone 和 Debug 实现（IpNetworkTable 不实现这些 trait）
- 修复 Cargo.toml 中 crate 名称错误（ip-network → ip_network，ip-network-table → ip_network_table）
- 修复安全审查发现的代码质量问题

---

## v1.0.0 - 2026-04-03

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

## 0.9.0 - 2024-04-03

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

## 0.8.0 - 2023-03-17

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
