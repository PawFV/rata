#!/bin/bash
#===============================================================================
# RATA - Real-time Attack Tracking & Alerting
# Audit Script: Captures current system state for forensic analysis
#===============================================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
# Resolve script directory and project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
RATA_DIR="$(dirname "$SCRIPT_DIR")"
AUDIT_DIR="${RATA_DIR}/forensics/audit_${TIMESTAMP}"
HASH_DIR="${AUDIT_DIR}/hashes"

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN} $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        log_info "Run: sudo $0"
        exit 1
    fi
}

create_dirs() {
    mkdir -p "${AUDIT_DIR}"/{processes,network,filesystem,persistence,kernel,users,packages}
    mkdir -p "${HASH_DIR}"
    # Hacer el directorio accesible para el usuario normal
    chmod -R 777 "${AUDIT_DIR}"
    log_success "Audit directory created: ${AUDIT_DIR}"
}

audit_processes() {
    header "RUNNING PROCESSES"
    
    log_info "Capturing process list..."
    ps auxwww > "${AUDIT_DIR}/processes/ps_aux.txt" 2>/dev/null || true
    
    log_info "Process tree..."
    pstree -p > "${AUDIT_DIR}/processes/pstree.txt" 2>/dev/null || true
    
    log_info "Processes with network connections..."
    lsof -i -n -P > "${AUDIT_DIR}/processes/lsof_network.txt" 2>/dev/null || true
    
    log_info "Processes with open files..."
    lsof +D /tmp > "${AUDIT_DIR}/processes/lsof_tmp.txt" 2>/dev/null || true
    lsof +D /dev/shm > "${AUDIT_DIR}/processes/lsof_shm.txt" 2>/dev/null || true
    
    log_info "Process memory..."
    cat /proc/*/maps 2>/dev/null | grep -E "(deleted|memfd)" > "${AUDIT_DIR}/processes/suspicious_memory.txt" 2>/dev/null || true
    
    log_info "Processes without binary on disk..."
    for pid in /proc/[0-9]*; do
        if [[ -d "$pid" ]]; then
            exe_link=$(readlink "$pid/exe" 2>/dev/null || echo "")
            if [[ "$exe_link" == *"(deleted)"* ]] || [[ "$exe_link" == *"memfd:"* ]]; then
                echo "PID: $(basename $pid) -> $exe_link" >> "${AUDIT_DIR}/processes/deleted_exe.txt"
            fi
        fi
    done
    
    log_info "Searching for hidden processes with unhide..."
    if command -v unhide &> /dev/null; then
        log_info "Running unhide (max 10s)..."
        timeout 10 unhide proc > "${AUDIT_DIR}/processes/unhide_proc.txt" 2>&1 || true
        timeout 10 unhide sys > "${AUDIT_DIR}/processes/unhide_sys.txt" 2>&1 || true
    else
        log_warn "unhide not installed - install with: apt install unhide"
    fi
    
    log_success "Process audit completed"
}

audit_network() {
    header "NETWORK CONNECTIONS"
    
    log_info "Active connections (ss)..."
    ss -tulpan > "${AUDIT_DIR}/network/ss_all.txt" 2>/dev/null || true
    
    log_info "Active connections (netstat)..."
    netstat -tulpan > "${AUDIT_DIR}/network/netstat_all.txt" 2>/dev/null || true
    
    log_info "Listening ports..."
    ss -tlnp > "${AUDIT_DIR}/network/listening_ports.txt" 2>/dev/null || true
    
    log_info "Established connections..."
    ss -tnp state established > "${AUDIT_DIR}/network/established.txt" 2>/dev/null || true
    
    log_info "Routing table..."
    ip route > "${AUDIT_DIR}/network/routes.txt" 2>/dev/null || true
    
    log_info "ARP table..."
    ip neigh > "${AUDIT_DIR}/network/arp.txt" 2>/dev/null || true
    
    log_info "Network interfaces..."
    ifconfig -a > "${AUDIT_DIR}/network/ifconfig.txt" 2>/dev/null || ip addr > "${AUDIT_DIR}/network/ip_addr.txt"
    
    log_info "iptables rules..."
    iptables-save > "${AUDIT_DIR}/network/iptables.txt" 2>/dev/null || true
    
    log_info "nftables rules..."
    nft list ruleset > "${AUDIT_DIR}/network/nftables.txt" 2>/dev/null || true
    
    log_info "Configured DNS..."
    cat /etc/resolv.conf > "${AUDIT_DIR}/network/resolv.conf" 2>/dev/null || true
    
    log_info "Hosts file..."
    cat /etc/hosts > "${AUDIT_DIR}/network/hosts" 2>/dev/null || true
    
    log_info "Searching for hidden ports with unhide..."
    if command -v unhide-tcp &> /dev/null; then
        timeout 10 unhide-tcp > "${AUDIT_DIR}/network/unhide_tcp.txt" 2>&1 || true
    fi
    
    log_success "Network audit completed"
}

audit_persistence() {
    header "PERSISTENCE MECHANISMS"
    
    log_info "System crontabs..."
    cat /etc/crontab > "${AUDIT_DIR}/persistence/crontab_system.txt" 2>/dev/null || true
    ls -la /etc/cron.* > "${AUDIT_DIR}/persistence/cron_dirs.txt" 2>/dev/null || true
    
    log_info "User crontabs..."
    ls -la /var/spool/cron/crontabs > "${AUDIT_DIR}/persistence/cron_users.txt" 2>/dev/null || true
    
    log_info "systemd services..."
    systemctl list-units --type=service --all > "${AUDIT_DIR}/persistence/systemd_services.txt" 2>/dev/null || true
    
    log_info "Enabled services..."
    systemctl list-unit-files --state=enabled > "${AUDIT_DIR}/persistence/enabled_services.txt" 2>/dev/null || true
    
    log_info "systemd timers..."
    systemctl list-timers --all > "${AUDIT_DIR}/persistence/systemd_timers.txt" 2>/dev/null || true
    
    log_info "Init scripts..."
    ls -la /etc/init.d/ > "${AUDIT_DIR}/persistence/init_d.txt" 2>/dev/null || true
    
    log_info "RC scripts..."
    ls -laR /etc/rc*.d/ > "${AUDIT_DIR}/persistence/rc_d.txt" 2>/dev/null || true
    
    log_info "XDG autostart..."
    ls -laR /etc/xdg/autostart/ > "${AUDIT_DIR}/persistence/xdg_autostart_system.txt" 2>/dev/null || true
    find /home -name "*autostart*" -ls 2>/dev/null > "${AUDIT_DIR}/persistence/xdg_autostart_users.txt" || true
    
    log_info "SSH authorized_keys..."
    find /home /root -name "authorized_keys" -ls -exec cat {} \; > "${AUDIT_DIR}/persistence/ssh_keys.txt" 2>/dev/null || true
    
    log_info "PAM configuration..."
    cat /etc/pam.d/common-auth > "${AUDIT_DIR}/persistence/pam_common_auth.txt" 2>/dev/null || true
    
    log_info "LD_PRELOAD and libraries..."
    grep -r "LD_PRELOAD" /etc /home /root > "${AUDIT_DIR}/persistence/ld_preload_search.txt" 2>/dev/null || true
    cat /etc/ld.so.preload > "${AUDIT_DIR}/persistence/ld_so_preload.txt" 2>/dev/null || true
    
    log_success "Persistence audit completed"
}

audit_filesystem() {
    header "FILESYSTEM"
    
    log_info "Files modified in last 7 days (critical dirs only)..."
    timeout 30 find /home /root /etc /var /usr/local /opt -type f -mtime -7 -ls 2>/dev/null | head -5000 > "${AUDIT_DIR}/filesystem/modified_7days.txt" || true
    
    log_info "Files modified in last 24 hours (critical dirs only)..."
    timeout 30 find /home /root /etc /var /usr/local /opt -type f -mtime -1 -ls 2>/dev/null | head -2000 > "${AUDIT_DIR}/filesystem/modified_24h.txt" || true
    
    log_info "SUID/SGID files..."
    timeout 60 find /usr /bin /sbin /home /root /opt -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null > "${AUDIT_DIR}/filesystem/suid_sgid.txt" || true
    
    log_info "Files without owner..."
    timeout 30 find /home /tmp /var -nouser -o -nogroup 2>/dev/null | head -1000 > "${AUDIT_DIR}/filesystem/no_owner.txt" || true
    
    log_info "Hidden files in /tmp, /var/tmp, /dev/shm..."
    find /tmp /var/tmp /dev/shm -name ".*" -ls 2>/dev/null > "${AUDIT_DIR}/filesystem/hidden_temp.txt" || true
    
    log_info "Executable files in /tmp..."
    find /tmp -type f -executable -ls 2>/dev/null > "${AUDIT_DIR}/filesystem/exec_tmp.txt" || true
    
    log_info "World-writable files (critical dirs only)..."
    timeout 30 find /home /usr/local /opt -type f -perm -0002 -ls 2>/dev/null | head -1000 > "${AUDIT_DIR}/filesystem/world_writable.txt" || true
    
    log_info "Current mounts..."
    mount > "${AUDIT_DIR}/filesystem/mounts.txt" 2>/dev/null || true
    cat /etc/fstab > "${AUDIT_DIR}/filesystem/fstab.txt" 2>/dev/null || true
    
    log_success "Filesystem audit completed"
}

audit_kernel() {
    header "KERNEL AND MODULES"
    
    log_info "Kernel version..."
    uname -a > "${AUDIT_DIR}/kernel/uname.txt"
    
    log_info "Loaded modules..."
    lsmod > "${AUDIT_DIR}/kernel/lsmod.txt"
    
    log_info "Kernel parameters..."
    sysctl -a > "${AUDIT_DIR}/kernel/sysctl.txt" 2>/dev/null || true
    
    log_info "Kernel messages (dmesg)..."
    dmesg > "${AUDIT_DIR}/kernel/dmesg.txt" 2>/dev/null || true
    
    log_success "Kernel audit completed"
}

audit_users() {
    header "USERS AND AUTHENTICATION"
    
    log_info "System users..."
    cat /etc/passwd > "${AUDIT_DIR}/users/passwd.txt"
    
    log_info "Groups..."
    cat /etc/group > "${AUDIT_DIR}/users/group.txt"
    
    log_info "Shadow (hashes)..."
    cat /etc/shadow > "${AUDIT_DIR}/users/shadow.txt" 2>/dev/null || true
    
    log_info "Users with valid shell..."
    grep -v '/nologin\|/false' /etc/passwd > "${AUDIT_DIR}/users/valid_shells.txt"
    
    log_info "Users with UID 0..."
    awk -F: '$3 == 0 {print}' /etc/passwd > "${AUDIT_DIR}/users/uid_zero.txt"
    
    log_info "Sudoers..."
    cat /etc/sudoers > "${AUDIT_DIR}/users/sudoers.txt" 2>/dev/null || true
    cat /etc/sudoers.d/* > "${AUDIT_DIR}/users/sudoers_d.txt" 2>/dev/null || true
    
    log_info "Last logins..."
    last -100 > "${AUDIT_DIR}/users/last.txt"
    lastb -100 > "${AUDIT_DIR}/users/lastb.txt" 2>/dev/null || true
    
    log_info "Who is logged in..."
    who > "${AUDIT_DIR}/users/who.txt"
    w > "${AUDIT_DIR}/users/w.txt"
    
    log_info "Auth logs..."
    cat /var/log/auth.log > "${AUDIT_DIR}/users/auth_log.txt" 2>/dev/null || true
    journalctl -u ssh --no-pager > "${AUDIT_DIR}/users/ssh_journal.txt" 2>/dev/null || true
    
    log_success "Users audit completed"
}

audit_packages() {
    header "PACKAGES AND INTEGRITY"
    
    log_info "Installed packages (dpkg)..."
    dpkg -l > "${AUDIT_DIR}/packages/dpkg_list.txt"
    
    log_info "Package integrity verification (debsums - critical)..."
    if command -v debsums &> /dev/null; then
        timeout 60 debsums -c > "${AUDIT_DIR}/packages/debsums_errors.txt" 2>&1 || true
    else
        log_warn "debsums not installed"
    fi
    
    log_success "Package audit completed"
}

fix_permissions() {
    header "FINALIZING"
    log_info "Setting permissions for user..."
    if [ -n "${SUDO_USER:-}" ]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$AUDIT_DIR"
        log_success "Ownership transferred to $SUDO_USER"
    else
        chmod -R 777 "$AUDIT_DIR"
        log_success "Permissions set to 777 (no sudo user found)"
    fi
}

main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           RATA - SYSTEM FORENSIC AUDIT                        ║"
    echo "║         Real-time Attack Tracking & Alerting                  ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    
    check_root
    create_dirs
    
    audit_processes
    audit_network
    audit_persistence
    audit_filesystem
    audit_kernel
    audit_users
    audit_packages
    
    fix_permissions
    
    header "AUDIT COMPLETE"
    log_success "Report saved to: ${AUDIT_DIR}"
    echo ""
}

main
