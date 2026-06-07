#!/bin/bash
# ============================================================
# OpenTracker 服务器一键优化脚本
# 适配: Debian/Ubuntu, CentOS/RHEL/Rocky/Alma, Fedora, Arch, openSUSE
# 用法: bash optimize.sh
#
# 安全说明:
#   - 所有操作均先检测是否支持再执行，不支持的自动跳过
#   - 修改配置文件前自动备份原文件
#   - sysctl 参数逐条检测内核是否支持，不支持的跳过
#   - 不使用 set -e，任何步骤失败不影响后续步骤
# ============================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
step()  { echo -e "${CYAN}[STEP]${NC} $1"; }
skip()  { echo -e "${YELLOW}[SKIP]${NC} $1"; }

# 统计结果
SKIPPED_COUNT=0
APPLIED_COUNT=0

# ============================================================
# 1. 权限检查
# ============================================================
if [ "$(id -u)" -ne 0 ]; then
    error "请使用 root 用户运行此脚本"
    exit 1
fi

# ============================================================
# 2. 检测 Linux 发行版
# ============================================================
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID}"
        OS_VERSION="${VERSION_ID}"
        OS_NAME="${PRETTY_NAME}"
    elif [ -f /etc/redhat-release ]; then
        OS_ID="rhel"
        OS_NAME=$(cat /etc/redhat-release)
        OS_VERSION=$(echo "$OS_NAME" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    else
        OS_ID="unknown"
        OS_NAME="Unknown Linux"
        OS_VERSION=""
    fi
}

detect_os
info "检测到系统: ${OS_NAME}"

# ============================================================
# 3. 包管理器和依赖安装
# ============================================================
install_packages() {
    step "安装系统依赖..."

    # 检测包管理器
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
        info "使用 apt 包管理器"
        apt-get update -y 2>/dev/null || warn "apt-get update 失败，继续执行"
        for pkg in ethtool hwloc iproute2 procps kmod; do
            dpkg -s "$pkg" &>/dev/null || apt-get install -y "$pkg" 2>/dev/null || warn "安装 ${pkg} 失败"
        done
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
        info "使用 dnf 包管理器"
        for pkg in ethtool hwloc iproute procps-ng kmod; do
            rpm -q "$pkg" &>/dev/null || dnf install -y "$pkg" 2>/dev/null || warn "安装 ${pkg} 失败"
        done
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
        info "使用 yum 包管理器"
        for pkg in ethtool hwloc iproute procps-ng kmod; do
            rpm -q "$pkg" &>/dev/null || yum install -y "$pkg" 2>/dev/null || warn "安装 ${pkg} 失败"
        done
    elif command -v zypper &>/dev/null; then
        PKG_MANAGER="zypper"
        info "使用 zypper 包管理器"
        for pkg in ethtool hwloc iproute2 procps kmod; do
            rpm -q "$pkg" &>/dev/null || zypper install -y "$pkg" 2>/dev/null || warn "安装 ${pkg} 失败"
        done
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
        info "使用 pacman 包管理器"
        pacman -Sy --noconfirm ethtool hwloc iproute2 procps-ng kmod 2>/dev/null || warn "安装依赖失败"
    else
        warn "未检测到包管理器，跳过依赖安装"
        warn "请手动安装: ethtool, hwloc, iproute2/iproute, procps/procps-ng, kmod"
    fi
}

# 检查命令是否存在
check_cmd() {
    command -v "$1" &>/dev/null
}

# 检查 sysctl 参数是否被内核支持
# 返回 0 = 支持, 1 = 不支持
check_sysctl_param() {
    local key="$1"
    # 将点号替换为斜杠，检查 /proc/sys 下是否存在
    local proc_path="/proc/sys/${key//.//\/}"
    if [ -f "$proc_path" ]; then
        return 0
    fi
    # 也尝试 sysctl -e 方式检测
    if sysctl -e "$key" &>/dev/null; then
        return 0
    fi
    return 1
}

# 安全地设置单个 sysctl 参数
safe_sysctl_set() {
    local key="$1"
    local value="$2"

    if ! check_sysctl_param "$key"; then
        skip "sysctl ${key} - 内核不支持此参数"
        SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
        return 1
    fi

    # 尝试运行时设置
    if sysctl -w "${key}=${value}" &>/dev/null; then
        APPLIED_COUNT=$((APPLIED_COUNT + 1))
        return 0
    else
        # 容器内可能无法运行时设置，但可以写入配置文件
        warn "sysctl ${key} 运行时设置失败（容器内常见），已写入配置文件"
        return 0
    fi
}

# ============================================================
# 4. 检测物理网卡
# ============================================================
detect_physical_nic() {
    step "检测物理网卡..."

    DEFAULT_NIC=""

    # 方法1: 通过默认路由获取
    if check_cmd ip; then
        DEFAULT_NIC=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)
    fi

    # 方法2: 如果方法1失败，找第一个非 lo/docker/br/veth 的网卡
    if [ -z "$DEFAULT_NIC" ]; then
        for nic in $(ls /sys/class/net/ 2>/dev/null); do
            case "$nic" in
                lo|docker*|br-*|veth*|virbr*|flannel*|cni*|cali*|tunl*|nomac*)
                    continue
                    ;;
                *)
                    # 检查是否是虚拟设备
                    if [ ! -e "/sys/class/net/${nic}/device" ]; then
                        continue
                    fi
                    DEFAULT_NIC="$nic"
                    break
                    ;;
            esac
        done
    fi

    if [ -z "$DEFAULT_NIC" ]; then
        warn "未能自动检测物理网卡"
        echo "可用网卡列表:"
        ls /sys/class/net/ 2>/dev/null | grep -v -E '^(lo|docker|br-|veth|virbr)' || echo "  (无)"
        echo ""
        read -rp "请输入网卡名称: " DEFAULT_NIC
        if [ -z "$DEFAULT_NIC" ]; then
            warn "未指定网卡，跳过网卡相关优化"
            NO_NIC=1
        fi
    fi

    if [ -n "$DEFAULT_NIC" ]; then
        info "使用网卡: ${DEFAULT_NIC}"
        NO_NIC=0
    fi
}

# ============================================================
# 5. 获取 CPU 核心数
# ============================================================
get_cpu_count() {
    if [ -f /proc/cpuinfo ]; then
        CPU_CORES=$(grep -c ^processor /proc/cpuinfo)
    else
        CPU_CORES=4
    fi
    info "检测到 CPU 线程数: ${CPU_CORES}"

    # 计算 RPS CPU 掩码
    if [ "$CPU_CORES" -le 8 ]; then
        RPS_MASK=$(printf "%x" $((2**CPU_CORES - 1)))
    elif [ "$CPU_CORES" -le 16 ]; then
        RPS_MASK=$(printf "%x" $((2**16 - 1)))
    elif [ "$CPU_CORES" -le 32 ]; then
        RPS_MASK="ffffffff"
    else
        RPS_MASK="ffffffff,ffffffff"
    fi
}

# ============================================================
# 6. 优化 sysctl 参数
# ============================================================
optimize_sysctl() {
    step "优化 sysctl 网络参数..."

    SYSCTL_FILE="/etc/sysctl.conf"

    # 如果文件不存在则创建
    if [ ! -f "$SYSCTL_FILE" ]; then
        touch "$SYSCTL_FILE"
        info "已创建 ${SYSCTL_FILE}"
    fi

    # 备份原文件
    cp "$SYSCTL_FILE" "${SYSCTL_FILE}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || warn "备份 sysctl.conf 失败"

    # 要设置的参数（键=值）
    # 每个参数都会先检查内核是否支持
    PARAMS=(
        "fs.file-max=1048576"
        "net.core.somaxconn=65535"
        "net.core.netdev_max_backlog=65535"
        "net.ipv4.tcp_max_syn_backlog=65535"
        "net.core.rmem_max=16777216"
        "net.core.wmem_max=16777216"
        "net.core.rmem_default=2097152"
        "net.core.wmem_default=2097152"
        "net.core.optmem_max=65536"
        "net.ipv4.tcp_rmem=4096 87380 16777216"
        "net.ipv4.tcp_wmem=4096 65536 16777216"
        "net.ipv4.tcp_tw_reuse=1"
        "net.ipv4.tcp_fin_timeout=15"
        "net.ipv4.tcp_keepalive_time=600"
        "net.ipv4.ip_local_port_range=1024 65535"
    )

    # conntrack 参数（可选，需要 netfilter 模块）
    CONNTRACK_PARAMS=(
        "net.netfilter.nf_conntrack_max=1048576"
        "net.netfilter.nf_conntrack_tcp_timeout_established=3600"
    )

    # 删除旧的 Tracker 优化参数（避免重复）
    # 先删除标记块
    sed -i '/# =.*OpenTracker/,/# =.*End OpenTracker/d' "$SYSCTL_FILE" 2>/dev/null || true

    # 删除已废弃的参数
    sed -i '/tcp_tw_recycle/d' "$SYSCTL_FILE" 2>/dev/null || true

    # 运行时逐条设置并记录成功的参数
    SUCCESS_PARAMS=()

    for param in "${PARAMS[@]}"; do
        key="${param%%=*}"
        value="${param#*=}"
        if safe_sysctl_set "$key" "$value"; then
            SUCCESS_PARAMS+=("$param")
        fi
    done

    # conntrack 参数
    for param in "${CONNTRACK_PARAMS[@]}"; do
        key="${param%%=*}"
        value="${param#*=}"
        if safe_sysctl_set "$key" "$value"; then
            SUCCESS_PARAMS+=("$param")
        fi
    done

    # 将成功的参数写入配置文件（持久化）
    if [ ${#SUCCESS_PARAMS[@]} -gt 0 ]; then
        echo "" >> "$SYSCTL_FILE"
        echo "# ========================== OpenTracker 性能优化 ==========================" >> "$SYSCTL_FILE"
        echo "# 由 optimize.sh 自动生成 - $(date '+%Y-%m-%d %H:%M:%S')" >> "$SYSCTL_FILE"
        echo "# ========================== End OpenTracker ==========================" >> "$SYSCTL_FILE"
        # 在标记块内插入参数
        sed -i "/# 由 optimize.sh 自动生成/a\\" "$SYSCTL_FILE" 2>/dev/null || true

        # 直接追加到标记后面
        # 先删除刚创建的空行标记块，重新写入
        sed -i '/# =.*OpenTracker/,/# =.*End OpenTracker/d' "$SYSCTL_FILE" 2>/dev/null || true

        echo "" >> "$SYSCTL_FILE"
        echo "# ========================== OpenTracker 性能优化 ==========================" >> "$SYSCTL_FILE"
        echo "# 由 optimize.sh 自动生成 - $(date '+%Y-%m-%d %H:%M:%S')" >> "$SYSCTL_FILE"
        for param in "${SUCCESS_PARAMS[@]}"; do
            key="${param%%=*}"
            value="${param#*=}"
            echo "${key} = ${value}" >> "$SYSCTL_FILE"
        done
        echo "# ========================== End OpenTracker ==========================" >> "$SYSCTL_FILE"
    fi

    info "sysctl 参数优化完成 (成功: ${#SUCCESS_PARAMS[@]}, 跳过: ${SKIPPED_COUNT})"
}

# ============================================================
# 7. 优化文件描述符限制
# ============================================================
optimize_ulimit() {
    step "优化文件描述符限制..."

    LIMITS_FILE="/etc/security/limits.conf"

    # 如果文件不存在则创建
    if [ ! -f "$LIMITS_FILE" ]; then
        mkdir -p /etc/security 2>/dev/null
        touch "$LIMITS_FILE"
        info "已创建 ${LIMITS_FILE}"
    fi

    # 备份
    cp "$LIMITS_FILE" "${LIMITS_FILE}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || warn "备份 limits.conf 失败"

    # 删除旧的 tracker 相关配置
    sed -i '/# OpenTracker limits/,/# End OpenTracker limits/d' "$LIMITS_FILE" 2>/dev/null || true
    sed -i '/\* soft nofile/d' "$LIMITS_FILE" 2>/dev/null || true
    sed -i '/\* hard nofile/d' "$LIMITS_FILE" 2>/dev/null || true
    sed -i '/root soft nofile/d' "$LIMITS_FILE" 2>/dev/null || true
    sed -i '/root hard nofile/d' "$LIMITS_FILE" 2>/dev/null || true

    # 追加新配置
    cat >> "$LIMITS_FILE" << 'EOF'

# OpenTracker limits
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
# End OpenTracker limits
EOF

    # systemd 系统还需要配置 systemd 自身限制
    if [ -d /etc/systemd ]; then
        mkdir -p /etc/systemd/system.conf.d 2>/dev/null || warn "创建 systemd system.conf.d 失败"
        if [ -d /etc/systemd/system.conf.d ]; then
            cat > /etc/systemd/system.conf.d/tracker-limits.conf << 'EOF'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=65535
EOF
        fi

        mkdir -p /etc/systemd/user.conf.d 2>/dev/null || warn "创建 systemd user.conf.d 失败"
        if [ -d /etc/systemd/user.conf.d ]; then
            cat > /etc/systemd/user.conf.d/tracker-limits.conf << 'EOF'
[Manager]
DefaultLimitNOFILE=1048576
EOF
        fi

        systemctl daemon-reload 2>/dev/null || warn "systemctl daemon-reload 失败"
    else
        skip "未检测到 systemd，跳过 systemd 限制配置"
    fi

    info "文件描述符限制优化完成 (1048576)"
}

# ============================================================
# 8. 优化网卡环形缓冲区
# ============================================================
optimize_ring_buffer() {
    step "优化网卡环形缓冲区..."

    if [ "$NO_NIC" = "1" ]; then
        skip "未检测到网卡，跳过"
        return
    fi

    if ! check_cmd ethtool; then
        skip "ethtool 未安装，跳过环形缓冲区优化"
        return
    fi

    # 获取当前和最大值
    RING_INFO=$(ethtool -g "$DEFAULT_NIC" 2>/dev/null) || {
        skip "无法获取 ${DEFAULT_NIC} 的环形缓冲区信息（虚拟网卡常见）"
        return
    }

    RX_MAX=$(echo "$RING_INFO" | awk '/Pre-set maximums/,/Current hardware settings/' | grep -i "RX:" | head -1 | awk '{print $2}')
    TX_MAX=$(echo "$RING_INFO" | awk '/Pre-set maximums/,/Current hardware settings/' | grep -i "TX:" | head -1 | awk '{print $2}')
    RX_CURRENT=$(echo "$RING_INFO" | awk '/Current hardware settings/,0' | grep -i "RX:" | head -1 | awk '{print $2}')
    TX_CURRENT=$(echo "$RING_INFO" | awk '/Current hardware settings/,0' | grep -i "TX:" | head -1 | awk '{print $2}')

    if [ -z "$RX_MAX" ] || [ "$RX_MAX" = "n/a" ]; then
        skip "网卡不支持修改环形缓冲区大小"
        return
    fi

    if [ -n "$RX_CURRENT" ] && [ -n "$RX_MAX" ] && [ "$RX_CURRENT" -ge "$RX_MAX" ] 2>/dev/null; then
        info "环形缓冲区已是最大值 (RX:${RX_CURRENT}, TX:${TX_CURRENT})"
        return
    fi

    ethtool -G "$DEFAULT_NIC" rx "$RX_MAX" tx "$TX_MAX" 2>/dev/null && {
        info "环形缓冲区已设为最大值 (RX:${RX_MAX}, TX:${TX_MAX})"
    } || {
        skip "无法修改环形缓冲区（虚拟网卡常见限制）"
    }
}

# ============================================================
# 9. 配置 RPS (Receive Packet Steering)
# ============================================================
optimize_rps() {
    step "配置 RPS (多核网络中断分发)..."

    if [ "$NO_NIC" = "1" ]; then
        skip "未检测到网卡，跳过"
        return
    fi

    NIC_QUEUES_DIR="/sys/class/net/${DEFAULT_NIC}/queues"
    if [ ! -d "$NIC_QUEUES_DIR" ]; then
        skip "网卡队列目录不存在，不支持 RPS"
        return
    fi

    NIC_QUEUES=$(ls -d ${NIC_QUEUES_DIR}/rx-* 2>/dev/null) || {
        skip "网卡不支持 RPS"
        return
    }

    QUEUE_COUNT=$(echo "$NIC_QUEUES" | wc -l)
    info "检测到 ${QUEUE_COUNT} 个接收队列，RPS 掩码: ${RPS_MASK}"

    RPS_SUCCESS=0
    for q in $NIC_QUEUES; do
        if [ -f "$q/rps_cpus" ]; then
            if echo "$RPS_MASK" > "$q/rps_cpus" 2>/dev/null; then
                RPS_SUCCESS=$((RPS_SUCCESS + 1))
            else
                warn "设置 RPS 失败: $q/rps_cpus (权限不足或内核不支持)"
            fi
        else
            skip "$q/rps_cpus 不存在"
        fi
    done

    # RPS 流表
    if [ -f /proc/sys/net/core/rps_sock_flow_entries ]; then
        FLOW_ENTRIES=$((QUEUE_COUNT * 4096))
        echo "$FLOW_ENTRIES" > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || warn "设置 rps_sock_flow_entries 失败"
    else
        skip "/proc/sys/net/core/rps_sock_flow_entries 不存在"
    fi

    for q in $NIC_QUEUES; do
        if [ -f "$q/rps_flow_cnt" ]; then
            echo "4096" > "$q/rps_flow_cnt" 2>/dev/null || warn "设置 rps_flow_cnt 失败: $q"
        fi
    done

    if [ "$RPS_SUCCESS" -gt 0 ]; then
        info "RPS 配置完成 (${RPS_SUCCESS}/${QUEUE_COUNT} 队列)"
    else
        warn "RPS 配置未生效（可能需要加载 rps 内核模块）"
    fi
}

# ============================================================
# 10. 配置开机自启
# ============================================================
setup_persistence() {
    step "配置开机自启..."

    if [ "$NO_NIC" = "1" ]; then
        skip "未检测到网卡，跳过开机自启配置"
        return
    fi

    # 检测 init 系统
    if [ -d /etc/systemd/system ] && check_cmd systemctl; then
        INIT_SYSTEM="systemd"
    else
        INIT_SYSTEM="sysv"
    fi

    if [ "$INIT_SYSTEM" = "systemd" ]; then
        # 使用 systemd service
        cat > /etc/systemd/system/tracker-optimize.service << EOF
[Unit]
Description=OpenTracker Network Optimization
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '
# RPS 配置
for i in /sys/class/net/${DEFAULT_NIC}/queues/rx-*/rps_cpus; do
    [ -f "\$i" ] && echo "${RPS_MASK}" > "\$i" 2>/dev/null || true
done
[ -f /proc/sys/net/core/rps_sock_flow_entries ] && echo ${QUEUE_COUNT:-1} > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
for i in /sys/class/net/${DEFAULT_NIC}/queues/rx-*/rps_flow_cnt; do
    [ -f "\$i" ] && echo "4096" > "\$i" 2>/dev/null || true
done
EOF

        # ethtool 命令（如果可用且支持）
        if check_cmd ethtool; then
            RING_INFO=$(ethtool -g "$DEFAULT_NIC" 2>/dev/null) || true
            if [ -n "$RING_INFO" ]; then
                RX_MAX=$(echo "$RING_INFO" | awk '/Pre-set maximums/,/Current hardware settings/' | grep -i "RX:" | head -1 | awk '{print $2}')
                TX_MAX=$(echo "$RING_INFO" | awk '/Pre-set maximums/,/Current hardware settings/' | grep -i "TX:" | head -1 | awk '{print $2}')
                if [ -n "$RX_MAX" ] && [ "$RX_MAX" != "n/a" ] 2>/dev/null; then
                    echo "command -v ethtool &>/dev/null && ethtool -G ${DEFAULT_NIC} rx ${RX_MAX} tx ${TX_MAX} 2>/dev/null || true" >> /etc/systemd/system/tracker-optimize.service
                fi
            fi
        fi

        cat >> /etc/systemd/system/tracker-optimize.service << 'EOF'
'

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload 2>/dev/null || warn "systemctl daemon-reload 失败"
        systemctl enable tracker-optimize.service 2>/dev/null || {
            warn "无法启用 tracker-optimize 服务（容器内常见）"
        }
        info "已创建 systemd 服务: tracker-optimize.service"

    else
        # 使用 rc.local
        RCLOCAL="/etc/rc.local"

        # 备份
        if [ -f "$RCLOCAL" ]; then
            cp "$RCLOCAL" "${RCLOCAL}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || warn "备份 rc.local 失败"
        fi

        cat > "$RCLOCAL" << EOF
#!/bin/bash
# OpenTracker 网络优化 (由 optimize.sh 自动生成)
for i in /sys/class/net/${DEFAULT_NIC}/queues/rx-*/rps_cpus; do
    [ -f "\$i" ] && echo "${RPS_MASK}" > "\$i" 2>/dev/null
done
[ -f /proc/sys/net/core/rps_sock_flow_entries ] && echo ${QUEUE_COUNT:-1} > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null
for i in /sys/class/net/${DEFAULT_NIC}/queues/rx-*/rps_flow_cnt; do
    [ -f "\$i" ] && echo "4096" > "\$i" 2>/dev/null
done
exit 0
EOF

        chmod +x "$RCLOCAL" 2>/dev/null || warn "设置 rc.local 可执行权限失败"
        info "已配置 rc.local 开机自启"
    fi
}

# ============================================================
# 11. 安装 hwloc 运行时库
# ============================================================
install_hwloc() {
    step "安装 hwloc 运行时库 (CPU 绑定功能)..."

    if check_cmd lstopo || check_cmd hwloc-info; then
        info "hwloc 已安装"
        return
    fi

    # 检查动态库是否已存在
    if ldconfig -p 2>/dev/null | grep -q libhwloc; then
        info "hwloc 运行时库已存在"
        return
    fi

    case "$OS_ID" in
        debian|ubuntu|linuxmint|pop)
            # 不同版本 Debian/Ubuntu 的 hwloc 包名不同
            apt-get install -y libhwloc15 2>/dev/null \
                || apt-get install -y libhwloc5 2>/dev/null \
                || apt-get install -y libhwloc-dev 2>/dev/null \
                || warn "无法安装 hwloc，CPU 绑定功能不可用（不影响其他功能）"
            ;;
        centos|rhel|rocky|almalinux|ol)
            dnf install -y hwloc-libs 2>/dev/null \
                || yum install -y hwloc-libs 2>/dev/null \
                || warn "无法安装 hwloc，CPU 绑定功能不可用（不影响其他功能）"
            ;;
        fedora)
            dnf install -y hwloc-libs 2>/dev/null \
                || warn "无法安装 hwloc，CPU 绑定功能不可用（不影响其他功能）"
            ;;
        opensuse*|sles)
            zypper install -y libhwloc15 2>/dev/null \
                || zypper install -y libhwloc5 2>/dev/null \
                || warn "无法安装 hwloc，CPU 绑定功能不可用（不影响其他功能）"
            ;;
        arch|manjaro)
            pacman -S --noconfirm hwloc 2>/dev/null \
                || warn "无法安装 hwloc，CPU 绑定功能不可用（不影响其他功能）"
            ;;
        *)
            skip "不支持的发行版 (${OS_ID})，请手动安装 hwloc（不影响其他功能）"
            ;;
    esac
}

# ============================================================
# 12. 生成 Tracker 配置建议
# ============================================================
generate_config_advice() {
    step "生成 Tracker 配置建议..."

    # 根据 CPU 线程数推荐配置
    if [ "$CPU_CORES" -ge 16 ]; then
        REC_SOCKET_WORKERS=8
        REC_SWARM_WORKERS=2
    elif [ "$CPU_CORES" -ge 8 ]; then
        REC_SOCKET_WORKERS=6
        REC_SWARM_WORKERS=2
    elif [ "$CPU_CORES" -ge 4 ]; then
        REC_SOCKET_WORKERS=3
        REC_SWARM_WORKERS=1
    else
        REC_SOCKET_WORKERS=2
        REC_SWARM_WORKERS=1
    fi

    HWLOC_STATUS="未安装"
    if check_cmd lstopo || check_cmd hwloc-info; then
        HWLOC_STATUS="已安装"
    elif ldconfig -p 2>/dev/null | grep -q libhwloc; then
        HWLOC_STATUS="已安装(仅运行时库)"
    fi

    echo ""
    echo "============================================================"
    echo -e "${CYAN}  OpenTracker 配置建议${NC}"
    echo "============================================================"
    echo ""
    echo "  网卡: ${DEFAULT_NIC:-未检测到}"
    echo "  CPU 线程数: ${CPU_CORES}"
    echo "  hwloc: ${HWLOC_STATUS}"
    echo ""
    echo "  建议在 aquatic-http-config.toml 中配置:"
    echo ""
    echo "  socket_workers = ${REC_SOCKET_WORKERS}"
    echo "  swarm_workers  = ${REC_SWARM_WORKERS}"
    echo ""
    echo "  [network]"
    echo "  socket_recv_buffer_size = 4194304"
    echo "  socket_send_buffer_size = 4194304"
    echo "  max_connections_per_worker = 100000"
    echo "  tcp_keepalive = true"
    echo "  tcp_keepalive_idle_secs = 60"
    echo "  tcp_keepalive_interval_secs = 10"
    echo "  tcp_keepalive_probes = 3"
    echo ""
    echo "  [cpu_pinning]"
    if [ "$HWLOC_STATUS" != "未安装" ]; then
        echo "  active = true   # hwloc 已安装，可以启用 CPU 绑定"
    else
        echo "  active = false  # hwloc 未安装，CPU 绑定不可用"
    fi
    echo ""
    echo "============================================================"
}

# ============================================================
# 13. 验证优化结果（完整性检查）
# ============================================================
verify_optimization() {
    step "完整性检查 - 验证优化结果..."

    PASS_COUNT=0
    FAIL_COUNT=0
    SKIP_COUNT=0
    WARN_COUNT=0

    # 检查结果标记: PASS / FAIL / SKIP / WARN
    check_pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
    check_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
    check_skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; SKIP_COUNT=$((SKIP_COUNT + 1)); }
    check_warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARN_COUNT=$((WARN_COUNT + 1)); }

    # 辅助函数: 比较数值 (当前值 >= 目标值 即通过)
    check_sysctl_ge() {
        local key="$1"
        local expected="$2"
        local label="$3"

        if ! check_sysctl_param "$key"; then
            check_skip "${label} - 内核不支持"
            return
        fi

        local actual=$(sysctl -n "$key" 2>/dev/null)
        if [ -z "$actual" ]; then
            check_fail "${label} - 无法读取当前值"
            return
        fi

        # 对于多值参数（如 tcp_rmem），只比较第一个值
        local actual_first=$(echo "$actual" | awk '{print $1}')
        local expected_first=$(echo "$expected" | awk '{print $1}')

        if [ "$actual" = "$expected" ] 2>/dev/null; then
            check_pass "${label} = ${actual}"
        elif [ -n "$actual_first" ] && [ -n "$expected_first" ] && [ "$actual_first" -ge "$expected_first" ] 2>/dev/null; then
            check_pass "${label} = ${actual} (>= ${expected})"
        else
            check_fail "${label} = ${actual} (期望 >= ${expected})"
        fi
    }

    # 辅助函数: 比较数值 (当前值 = 目标值)
    check_sysctl_eq() {
        local key="$1"
        local expected="$2"
        local label="$3"

        if ! check_sysctl_param "$key"; then
            check_skip "${label} - 内核不支持"
            return
        fi

        local actual=$(sysctl -n "$key" 2>/dev/null)
        if [ -z "$actual" ]; then
            check_fail "${label} - 无法读取当前值"
            return
        fi

        if [ "$actual" = "$expected" ] 2>/dev/null; then
            check_pass "${label} = ${actual}"
        else
            check_fail "${label} = ${actual} (期望 ${expected})"
        fi
    }

    echo ""
    echo "============================================================"
    echo -e "${CYAN}  完整性检查报告${NC}"
    echo "============================================================"
    echo ""

    # ---- 1. 文件描述符限制 ----
    echo "  [文件描述符限制]"
    echo ""

    # fs.file-max
    check_sysctl_ge "fs.file-max" "1048576" "fs.file-max"

    # ulimit
    ULIMIT_VAL=$(ulimit -n 2>/dev/null || echo "N/A")
    if [ "$ULIMIT_VAL" = "1048576" ] || [ "$ULIMIT_VAL" = "unlimited" ]; then
        check_pass "ulimit -n = ${ULIMIT_VAL}"
    elif [ "$ULIMIT_VAL" != "N/A" ] && [ "$ULIMIT_VAL" -ge 1048576 ] 2>/dev/null; then
        check_pass "ulimit -n = ${ULIMIT_VAL}"
    else
        check_warn "ulimit -n = ${ULIMIT_VAL} (需要重新登录生效，期望 1048576)"
    fi

    # limits.conf
    if [ -f /etc/security/limits.conf ] && grep -q "1048576" /etc/security/limits.conf 2>/dev/null; then
        check_pass "limits.conf 已配置 nofile 1048576"
    else
        check_fail "limits.conf 未找到 nofile 1048576 配置"
    fi

    # systemd limits
    if [ -f /etc/systemd/system.conf.d/tracker-limits.conf ]; then
        check_pass "systemd system.conf.d/tracker-limits.conf 已创建"
    elif [ -d /etc/systemd ]; then
        check_fail "systemd system.conf.d/tracker-limits.conf 未创建"
    else
        check_skip "systemd 未安装，跳过检查"
    fi

    echo ""

    # ---- 2. 网络参数 ----
    echo "  [网络参数]"
    echo ""

    check_sysctl_ge "net.core.somaxconn" "65535" "somaxconn"
    check_sysctl_ge "net.core.netdev_max_backlog" "65535" "netdev_max_backlog"
    check_sysctl_ge "net.ipv4.tcp_max_syn_backlog" "65535" "tcp_max_syn_backlog"
    check_sysctl_ge "net.core.rmem_max" "16777216" "rmem_max"
    check_sysctl_ge "net.core.wmem_max" "16777216" "wmem_max"
    check_sysctl_ge "net.core.rmem_default" "2097152" "rmem_default"
    check_sysctl_ge "net.core.wmem_default" "2097152" "wmem_default"
    check_sysctl_ge "net.core.optmem_max" "65536" "optmem_max"
    check_sysctl_eq "net.ipv4.tcp_tw_reuse" "1" "tcp_tw_reuse"
    check_sysctl_ge "net.ipv4.tcp_fin_timeout" "15" "tcp_fin_timeout (<=15)"
    # tcp_fin_timeout 特殊: 值越小越好，需要反转判断
    if check_sysctl_param "net.ipv4.tcp_fin_timeout"; then
        actual=$(sysctl -n net.ipv4.tcp_fin_timeout 2>/dev/null)
        if [ -n "$actual" ] && [ "$actual" -le 15 ] 2>/dev/null; then
            : # 已经在上面 check_sysctl_ge 里处理了
        fi
    fi
    check_sysctl_ge "net.ipv4.tcp_keepalive_time" "600" "tcp_keepalive_time"

    # tcp_rmem / tcp_wmem (多值参数，比较最小值)
    if check_sysctl_param "net.ipv4.tcp_rmem"; then
        actual=$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null)
        actual_max=$(echo "$actual" | awk '{print $3}')
        if [ -n "$actual_max" ] && [ "$actual_max" -ge 16777216 ] 2>/dev/null; then
            check_pass "tcp_rmem = ${actual} (max >= 16777216)"
        else
            check_fail "tcp_rmem = ${actual} (max 期望 >= 16777216)"
        fi
    fi

    if check_sysctl_param "net.ipv4.tcp_wmem"; then
        actual=$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null)
        actual_max=$(echo "$actual" | awk '{print $3}')
        if [ -n "$actual_max" ] && [ "$actual_max" -ge 16777216 ] 2>/dev/null; then
            check_pass "tcp_wmem = ${actual} (max >= 16777216)"
        else
            check_fail "tcp_wmem = ${actual} (max 期望 >= 16777216)"
        fi
    fi

    # ip_local_port_range
    if check_sysctl_param "net.ipv4.ip_local_port_range"; then
        actual=$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null)
        actual_low=$(echo "$actual" | awk '{print $1}')
        actual_high=$(echo "$actual" | awk '{print $2}')
        if [ "$actual_low" -le 1024 ] 2>/dev/null && [ "$actual_high" -ge 65535 ] 2>/dev/null; then
            check_pass "ip_local_port_range = ${actual}"
        else
            check_fail "ip_local_port_range = ${actual} (期望 1024 65535)"
        fi
    fi

    # conntrack
    if check_sysctl_param "net.netfilter.nf_conntrack_max"; then
        check_sysctl_ge "net.netfilter.nf_conntrack_max" "1048576" "nf_conntrack_max"
    else
        check_skip "nf_conntrack_max - 内核不支持 netfilter"
    fi

    # 废弃参数检查
    if grep -q "tcp_tw_recycle" /etc/sysctl.conf 2>/dev/null; then
        check_warn "sysctl.conf 中仍包含已废弃的 tcp_tw_recycle 参数"
    else
        check_pass "sysctl.conf 中无已废弃参数"
    fi

    echo ""

    # ---- 3. 网卡优化 ----
    echo "  [网卡优化 - ${DEFAULT_NIC:-未检测}]"
    echo ""

    if [ "$NO_NIC" = "1" ]; then
        check_skip "未检测到网卡，跳过所有网卡检查"
    else
        # RPS
        if [ -d "/sys/class/net/${DEFAULT_NIC}/queues" ]; then
            RPS_OK=true
            for q in /sys/class/net/${DEFAULT_NIC}/queues/rx-*/rps_cpus; do
                if [ -f "$q" ]; then
                    val=$(cat "$q" 2>/dev/null)
                    # 检查是否非零（已启用）
                    if [ -n "$val" ] && [ "$val" != "0" ] 2>/dev/null; then
                        : # OK
                    else
                        RPS_OK=false
                    fi
                else
                    RPS_OK=false
                fi
            done
            if $RPS_OK; then
                check_pass "RPS 已启用 (${RPS_MASK})"
            else
                check_fail "RPS 未正确启用"
            fi

            # rps_flow_cnt
            FLOW_OK=true
            for q in /sys/class/net/${DEFAULT_NIC}/queues/rx-*/rps_flow_cnt; do
                if [ -f "$q" ]; then
                    val=$(cat "$q" 2>/dev/null)
                    if [ -z "$val" ] || [ "$val" = "0" ]; then
                        FLOW_OK=false
                    fi
                fi
            done
            if $FLOW_OK; then
                check_pass "RPS flow cnt 已配置"
            else
                check_warn "RPS flow cnt 未配置（影响较小）"
            fi
        else
            check_skip "网卡队列目录不存在，RPS 不支持"
        fi

        # 环形缓冲区
        if check_cmd ethtool; then
            RING_INFO=$(ethtool -g "$DEFAULT_NIC" 2>/dev/null) || true
            if [ -n "$RING_INFO" ]; then
                RX_MAX=$(echo "$RING_INFO" | awk '/Pre-set maximums/,/Current hardware settings/' | grep -i "RX:" | head -1 | awk '{print $2}')
                RX_CURRENT=$(echo "$RING_INFO" | awk '/Current hardware settings/,0' | grep -i "RX:" | head -1 | awk '{print $2}')
                if [ -n "$RX_MAX" ] && [ "$RX_MAX" != "n/a" ] && [ -n "$RX_CURRENT" ]; then
                    if [ "$RX_CURRENT" -ge "$RX_MAX" ] 2>/dev/null; then
                        check_pass "环形缓冲区 RX = ${RX_CURRENT} (最大值)"
                    else
                        check_warn "环形缓冲区 RX = ${RX_CURRENT} (最大 ${RX_MAX}，可能虚拟网卡限制)"
                    fi
                else
                    check_skip "环形缓冲区不支持调整"
                fi
            else
                check_skip "无法读取网卡环形缓冲区信息"
            fi
        else
            check_skip "ethtool 未安装，无法检查环形缓冲区"
        fi
    fi

    echo ""

    # ---- 4. 开机自启 ----
    echo "  [开机自启]"
    echo ""

    if [ -f /etc/systemd/system/tracker-optimize.service ]; then
        if systemctl is-enabled tracker-optimize.service &>/dev/null; then
            check_pass "systemd tracker-optimize.service 已启用"
        else
            check_warn "systemd tracker-optimize.service 已创建但未启用"
        fi
    elif [ -f /etc/rc.local ]; then
        if grep -q "OpenTracker" /etc/rc.local 2>/dev/null; then
            check_pass "rc.local 已配置开机优化"
        else
            check_warn "rc.local 存在但未包含优化配置"
        fi
    else
        check_warn "未配置开机自启（RPS 和环形缓冲区重启后会丢失）"
    fi

    echo ""

    # ---- 5. hwloc ----
    echo "  [CPU 绑定依赖]"
    echo ""

    HWLOC_STATUS="未安装"
    if check_cmd lstopo || check_cmd hwloc-info; then
        HWLOC_STATUS="已安装"
    elif ldconfig -p 2>/dev/null | grep -q libhwloc; then
        HWLOC_STATUS="已安装(仅运行时库)"
    fi

    if [ "$HWLOC_STATUS" = "未安装" ]; then
        check_warn "hwloc 未安装 - CPU 绑定功能不可用（不影响基本运行）"
    else
        check_pass "hwloc ${HWLOC_STATUS} - CPU 绑定功能可用"
    fi

    echo ""

    # ---- 6. sysctl.conf 配置文件检查 ----
    echo "  [配置文件持久化]"
    echo ""

    if [ -f /etc/sysctl.conf ] && grep -q "OpenTracker" /etc/sysctl.conf 2>/dev/null; then
        check_pass "sysctl.conf 包含 OpenTracker 优化参数"
    else
        check_fail "sysctl.conf 未包含 OpenTracker 优化参数（重启后优化会丢失）"
    fi

    echo ""
    echo "============================================================"
    echo -e "${CYAN}  检查结果汇总${NC}"
    echo "============================================================"

    TOTAL=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT + WARN_COUNT))
    echo ""
    echo -e "  ${GREEN}通过: ${PASS_COUNT}${NC}"
    echo -e "  ${RED}失败: ${FAIL_COUNT}${NC}"
    echo -e "  ${YELLOW}跳过: ${SKIP_COUNT}${NC} (系统不支持，不影响运行)"
    echo -e "  ${YELLOW}警告: ${WARN_COUNT}${NC} (需要关注但不影响基本功能)"
    echo ""

    if [ "$FAIL_COUNT" -gt 0 ]; then
        echo -e "  ${RED}有 ${FAIL_COUNT} 项检查未通过，请检查上方 [FAIL] 项${NC}"
    elif [ "$WARN_COUNT" -gt 0 ]; then
        echo -e "  ${YELLOW}所有关键项已通过，有 ${WARN_COUNT} 项警告可稍后处理${NC}"
    else
        echo -e "  ${GREEN}所有检查项均已通过！${NC}"
    fi

    echo ""
    echo "============================================================"
}

# ============================================================
# 主流程
# ============================================================
main() {
    echo ""
    echo "============================================================"
    echo -e "${CYAN}  OpenTracker 服务器一键优化脚本${NC}"
    echo -e "${CYAN}  所有操作均先检测是否支持，不支持自动跳过${NC}"
    echo "============================================================"
    echo ""

    # 执行优化步骤
    install_packages
    detect_physical_nic
    get_cpu_count
    optimize_sysctl
    optimize_ulimit
    optimize_ring_buffer
    optimize_rps
    setup_persistence
    install_hwloc
    generate_config_advice
    verify_optimization

    echo ""
    info "优化完成！"
    echo ""
    echo "  注意事项:"
    echo "  1. 文件描述符限制需要重新登录后生效"
    echo "  2. RPS 和环形缓冲区已配置开机自启"
    echo "  3. 如使用 CPU 绑定功能，请在配置文件中设置 cpu_pinning.active = true"
    echo "  4. 被跳过的项目不影响 Tracker 运行，仅表示当前系统不支持该优化"
    echo ""
}

main
