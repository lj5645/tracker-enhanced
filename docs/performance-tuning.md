# 内核与网络调优（tracker-tune.sh）

面向 BT tracker 生产部署的内核参数与 conntrack 调优方案。脚本位于
`deploy/tracker-tune.sh`，服务器上的副本在 `/usr/local/sbin/tracker-tune.sh`。

---

## 1. 为什么要调优

BT tracker 的负载与普通 Web 服务差异很大：

| 特征 | 对内核的影响 |
|---|---|
| **UDP 占绝对大头**（实测 UDP 请求量约为 HTTP 的 20 倍） | 高 PPS + 大 socket 缓冲需求（`rmem_max`、`netdev_max_backlog`） |
| 大量**短连接/短请求**（announce 每 120 秒一轮，connect 握手更频繁） | 连接建立/回收速率高，需要更大的 `somaxconn`、`backlog`，更短的 `tcp_fin_timeout` |
| 公网暴露，持续被扫描（HTTP 侧每秒被拒 ~3000 次） | SYN 队列、TIME_WAIT 上限、conntrack 表压力 |
| 单机承担 200 万 peers / 上千 MB/s 流量 | socket 缓冲上限必须放开 |

不做调优的典型后果：`nf_conntrack: table full, dropping packet`（丢包且
tracker 无感知）、SYN 溢出、TIME_WAIT 耗尽端口。

---

## 2. 参数清单与取舍

### 2.1 脚本管理的参数

| 参数 | 默认值 | 调优值 | 作用与理由 |
|---|---|---|---|
| `net.netfilter.nf_conntrack_max` | 262144 | **4194304** | conntrack 表上限。公网扫描 + BT 流量会快速堆积连接条目，表满即**静默丢包**。16 倍余量，配合 NOTRACK 实际使用率很低 |
| `net.netfilter.nf_conntrack_tcp_timeout_established` | 432000（5 天） | **86400（1 天）** | 注意这是**调小**：已建立连接条目的保留时间。tracker 侧连接多是短命/半开，5 天保留纯属浪费表空间，1 天足够 |
| `net.core.rmem_max` | 212992 | **16777216（16 MB）** | 单 socket 接收缓冲上限。UDP tracker 高吞吐下，缓冲太小导致内核丢包（`netstat -su` 的 receive buffer errors） |
| `net.core.wmem_max` | 212992 | **16777216（16 MB）** | 同上，发送方向 |
| `net.core.netdev_max_backlog` | 1000 | **65535** | 网卡收包队列。高 PPS 下队列太短会丢包 |
| `net.core.somaxconn` | 4096 | **65535** | accept 队列上限。突发连接（大量客户端同时 announce）时防止 SYN/accept 溢出 |
| `net.ipv4.tcp_max_syn_backlog` | 1024 | **65535** | 半开连接（SYN 已收、握手未完成）队列。公网扫描下必须放大 |
| `net.ipv4.tcp_max_tw_buckets` | 65536 | **262144** | TIME_WAIT 数量上限。超过后内核会丢弃并打日志，tracker 短连接多 |
| `net.ipv4.tcp_fin_timeout` | 60 | **15** | FIN_WAIT_2 超时（秒）。更快的连接回收 |
| `net.ipv4.tcp_tw_reuse` | 2（仅 loopback） | **1（全部启用）** | 允许复用 TIME_WAIT 连接。对 tracker 作为**服务端**影响有限（主要利好主动连接），但无害 |
| `net.ipv4.ip_local_port_range` | 32768-60999 | **10240-65535** | 临时端口范围。tracker 主动连接（如拉取配置/回源）或系统内其他客户端进程需要 |

### 2.2 脚本额外处理的事项

- **`nf_conntrack hashsize = 1048576`**（`/etc/modprobe.d/nf_conntrack.conf` +
  `/sys/module/nf_conntrack/parameters/hashsize`）：哈希桶数量。建议为
  `conntrack_max / 4`，桶太少会让 conntrack 查找退化成链表遍历，CPU 飙升。
  该值**只能在线调大**，无法降回（重启恢复）。
- **NOTRACK 豁免**（`tracker-notrack.service`）：对 tracker 端口
  （默认 6969，可 `notrack-add` 追加）在 `raw` 表打 NOTRACK，
  **让 tracker 流量根本不进 conntrack 表**。这比单纯调大
  `conntrack_max` 更根本：tracker 的百万级连接不再占用 conntrack 条目，
  表压力几乎归零。
- **两个 systemd unit**：
  - `conntrack-tune.service`：开机时 `sysctl -p /etc/sysctl.d/99-conntrack.conf`
    （防止其他 sysctl 文件覆盖；oneshot + `RemainAfterExit=yes`，执行后
    保持 active 状态便于确认）
  - `tracker-notrack.service`：开机时重新安装 NOTRACK 规则
    （iptables 规则不持久化，重启会丢失）

---

## 3. 使用方法

```bash
# 首次部署：先自检环境，再应用（幂等，可重复执行）
sudo /usr/local/sbin/tracker-tune.sh check
sudo /usr/local/sbin/tracker-tune.sh apply

# 查看状态（参数一致性 + conntrack 使用率 + NOTRACK 命中 + tracker 进程）
sudo /usr/local/sbin/tracker-tune.sh status

# 微调单个参数（会写入 sysctl.d 并立即生效）
sudo /usr/local/sbin/tracker-tune.sh set net.core.somaxconn 65535

# 如果 tracker 换了端口或多开，追加 NOTRACK
sudo /usr/local/sbin/tracker-tune.sh notrack-add 6970
sudo /usr/local/sbin/tracker-tune.sh notrack-remove 6970

# 回滚全部改动（备份到 /root/network-backup/）
sudo /usr/local/sbin/tracker-tune.sh rollback
```

配置文件：

| 文件 | 内容 |
|---|---|
| `/etc/tracker-tune/params.conf` | 当前期望的内核参数（`set` 会更新这里） |
| `/etc/tracker-tune/ports.conf` | 免 conntrack 跟踪的端口列表 |
| `/etc/sysctl.d/99-conntrack.conf` | 由脚本生成，勿手改 |
| `/usr/local/sbin/tracker-notrack.sh` | 由脚本生成，勿手改 |

---

## 4. 兼容性

脚本**不是**在所有 Linux 上都能工作，它有一组明确的前提假设。运行
`tracker-tune.sh check` 会在不修改任何配置的情况下逐项检查：

```
=== 兼容性自检 ===
  [OK]   init: systemd
  [OK]   bash: 5.2.37（关联数组可用）
  [OK]   iptables: nf_tables（NOTRACK 在 nf_tables 后端会翻译为 ct notrack）
  [OK]   firewalld: 未运行
  [OK]   nf_conntrack: 模块可用
  [OK]   sysctl: 可用

自检结果：全部通过。
```

`apply` 会先跑这套自检，有 FAIL 项时中止（`apply --force` 可强制继续）。

### 4.1 前提假设

| 假设 | 不满足时的表现 | 替代做法 |
|---|---|---|
| init 是 **systemd** | 无 `systemctl`，两个 unit 无法安装/开机自启 | 手动把 `tracker-notrack.sh` 加入 `/etc/rc.local` 或对应 init 脚本，并用 `sysctl -p` 应用参数 |
| **bash 4.0+** | 关联数组语法错误 | 升级 bash（几乎所有现代发行版均满足） |
| 有 **iptables** 命令 | NOTRACK 规则无法安装 | 纯 nftables 环境直接写：`nft add rule ip raw prerouting tcp dport 6969 notrack`（udp 同理），并自行做成开机任务 |
| **firewalld 未运行** | `firewall-cmd --reload` 会清空 raw 表规则 | 用 firewalld direct 规则，或 reload 后重跑 `tracker-notrack.sh` |
| 内核有 **nf_conntrack** 模块 | 所有 conntrack 参数无法调整 | 无替代：该内核不支持连接跟踪 |
| 存在 `/usr/sbin/sysctl`、`/etc/sysctl.d` | 参数无法持久化 | 按发行版实际路径调整 `SYSCTL_FILE` |

### 4.2 支持矩阵

| 系统 | 状态 | 说明 |
|---|---|---|
| Debian 12/13 | ✅ 已验证（生产） | iptables 默认 nf_tables 后端，`-j NOTRACK` 由兼容层翻译为 `ct notrack`，实测命中正常 |
| Ubuntu 22.04/24.04 | ✅ 预期可用 | 同上（与 Debian 系一致） |
| RHEL / Rocky / Alma 9 | ⚠️ 需处理 firewalld | 默认启用 firewalld，reload 会清 raw 表规则；建议先配置 firewalld direct 规则或停用 |
| Alpine / OpenRC 系 | ❌ 不支持开箱运行 | 无 systemd；需手工集成（见 4.1） |
| 容器（无 systemd） | ❌ 不支持 | `sysctl` 多为只读，且无法安装 unit；调优应在宿主机做 |
| 纯 nftables（无 iptables 兼容层） | ⚠️ 部分可用 | sysctl 部分正常，NOTRACK 需改用 nft 命令 |

### 4.3 判断当前环境

```bash
ps -p 1 -o comm=                        # 应为 systemd
iptables -V                             # 看是 legacy 还是 nf_tables
systemctl is-active firewalld           # active 则需额外处理
ls /sys/module/nf_conntrack             # 存在则模块已加载
```

---

## 5. 重要限制与坑

### 4.1 NOTRACK 与 NAT / Docker 端口映射冲突

**NOTRACK 会让该端口上的连接不被 conntrack 跟踪，而 DNAT（端口映射）依赖
conntrack**。因此：

- ✅ 适用：tracker 直接监听宿主机端口，公网 IP 绑在服务器上（或 NAT 在
  上级路由器完成，不在这台机器上）——**当前部署属于这种**
- ❌ 禁用：tracker 端口通过 `iptables DNAT` 或 `docker -p 6969:6969` 映射
  到宿主机。这种情况下加 NOTRACK 会导致端口映射失效、客户端连不上

判断方法：`iptables -t nat -L PREROUTING -n | grep 6969`，如果有 DNAT
规则，就不要对该端口 `notrack-add`。

### 4.2 与 /etc/sysctl.conf 的重复配置冲突

同一参数若同时出现在 `/etc/sysctl.conf` 和 `/etc/sysctl.d/99-conntrack.conf`
且取值不同，谁生效取决于加载顺序（`sysctl --system` 会读
`/etc/sysctl.d/*.conf` → `/run/sysctl.d/*.conf` → `/usr/lib/sysctl.d/*.conf`
→ 最后是 `/etc/sysctl.conf`，后者覆盖前者；但 systemd 的
`systemd-sysctl.service` 只按目录顺序读，不读 `/etc/sysctl.conf`）。

**建议**：把 `/etc/sysctl.conf` 中与 tracker 相关的重复条目删掉，全部交给
`/etc/sysctl.d/99-conntrack.conf` 管理。排查时直接看
`tracker-tune.sh status` 的「不一致」行。

### 4.3 tcp_tw_reuse 的语义

- `0` = 关闭
- `1` = 对所有连接启用
- `2` = **仅对 loopback 启用**（较新内核的默认值）

tracker 作为服务端基本不主动建连，这项主要影响本机上的其他客户端程序，
调成 1 收益有限但安全。

### 4.4 hashsize 不可逆

`hashsize` 只能在线**调大**，调小必须重启。`rollback` 会提示这一点。

---

## 6. 验证与监控

### 5.1 部署后验证

```bash
# 参数是否全部生效（每行应为 OK）
sudo /usr/local/sbin/tracker-tune.sh status

# 是否还有 conntrack 丢包（应为 0）
dmesg | grep -c 'table full'

# NOTRACK 规则是否命中（pkts 应该持续增长）
iptables -t raw -L PREROUTING -n -v | grep 6969

# 内核 UDP 丢包（应为 0 或极低）
netstat -su | grep -E 'receive buffer errors|packet receive errors'
```

### 5.2 常态化关注

| 指标 | 健康范围 | 异常时的处理 |
|---|---|---|
| `nf_conntrack_count / max` | < 20% | 接近上限时先检查是否漏配 NOTRACK，再考虑调大 max |
| `dmesg \| grep 'table full'` 计数 | 保持 0 | 出现即说明有流量未被 NOTRACK 覆盖 |
| `nstat -az TcpExtListenOverflows` | 保持 0 | 增长说明 `somaxconn`/`backlog` 不够 |
| `netstat -su` 的 receive buffer errors | 0 | 增长说明 `rmem_max` 仍偏小或 PPS 超过网卡能力 |

### 5.3 未纳入脚本、但值得评估的参数

| 参数 | 建议 | 说明 |
|---|---|---|
| `net.ipv4.tcp_rmem` / `net.ipv4.tcp_wmem` | `4096 87380 16777216` | 只改 `rmem_max` 时自动调优上限仍是默认的 6 MB；如需单连接跑满 16 MB 缓冲，需同步调整三元组 |
| `net.ipv4.tcp_syncookies` | `1` | SYN flood 保护，多数发行版默认已开 |
| `fs.file-max` / `ulimit -n` | 1000000 / 65535 | 连接数极大时检查；tracker 的 `LimitNOFILE` 建议 >= 65535 |
| `vm.swappiness` | `10` | 降低换页倾向，避免大内存进程（tracker 常驻 1 GB+）被换出 |
| `net.core.default_qdisc` + `net.ipv4.tcp_congestion_control` | `fq` + `bbr` | 主要是出站 TCP 吞吐优化，tracker 出站流量小，收益有限 |

---

## 7. 与其他部署环节的关系

- **tracker 自身配置**：`auto_ban` 的封禁记录上限（v1.5.14 起自动扩容至
  200 万）与内核调优无关，但两者都会随流量规模增长——观察时一起看。
- **日志**：`logrotate` 配置见服务器 `/etc/logrotate.d/aquatic`（每天或
  100 MB 轮转，保留 7 份）。内核调优不改变日志量。
- **Docker 监控栈**（Grafana / Prometheus）在同一台机器上，NOTRACK 只作用于
  tracker 端口，不影响监控组件。

---

## 8. 回滚

```bash
sudo /usr/local/sbin/tracker-tune.sh rollback
```

会：删除 sysctl.d / modprobe 配置文件、清掉 NOTRACK 规则、停用两个 systemd
unit、把参数恢复为内核默认值，并把当前状态备份到
`/root/network-backup/tracker-tune-<时间戳>/`。

回滚后 **hashsize 不会立即恢复**（内核限制），重启生效。
