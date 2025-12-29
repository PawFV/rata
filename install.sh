#!/bin/bash
#===============================================================================
# RATA - Real-time Attack Tracking & Alerting
# Dependency installer and initial configuration
#===============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
RATA_DIR="$SCRIPT_DIR"

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

check_kali() {
    if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
        log_warn "This system does not appear to be Kali Linux"
        log_warn "Some tools might not be available"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
}

install_system_packages() {
    header "INSTALLING SYSTEM PACKAGES"
    
    log_info "Updating repositories..."
    apt-get update
    
    PACKAGES=(
        # Network monitoring
        suricata
        tcpdump
        tshark
        nmap
        netcat-openbsd
        
        # System monitoring
        auditd
        audispd-plugins
        sysstat
        htop
        iotop
        
        # eBPF and tracing
        bpftrace
        bpfcc-tools
        linux-headers-$(uname -r)
        
        # File integrity
        aide
        debsums
        rkhunter
        chkrootkit
        unhide
        
        # Forensic analysis
        sleuthkit
        foremost
        
        # Python for dashboard
        python3
        python3-pip
        python3-venv
        
        # Utilities
        jq
        yq
        inotify-tools
        libnotify-bin
        
        # osquery (if available)
        # Installed separately
    )
    
    for pkg in "${PACKAGES[@]}"; do
        log_info "Installing $pkg..."
        apt-get install -y "$pkg" 2>/dev/null || log_warn "Could not install $pkg"
    done
    
    log_success "System packages installed"
}

install_osquery() {
    header "INSTALLING OSQUERY"
    
    if command -v osqueryi &> /dev/null; then
        log_info "osquery is already installed"
        return
    fi
    
    log_info "Downloading osquery..."
    
    OSQUERY_VERSION="5.11.0"
    OSQUERY_DEB="osquery_${OSQUERY_VERSION}-1.linux_amd64.deb"
    
    wget -q "https://pkg.osquery.io/deb/${OSQUERY_DEB}" -O "/tmp/${OSQUERY_DEB}" 2>/dev/null || {
        log_warn "Could not download osquery - manual installation required"
        log_info "Visit: https://osquery.io/downloads"
        return
    }
    
    dpkg -i "/tmp/${OSQUERY_DEB}" || apt-get install -f -y
    rm -f "/tmp/${OSQUERY_DEB}"
    
    log_success "osquery installed"
}

setup_python_env() {
    header "CONFIGURING PYTHON ENVIRONMENT"
    
    log_info "Creating virtual environment..."
    python3 -m venv "${RATA_DIR}/venv"
    
    source "${RATA_DIR}/venv/bin/activate"
    
    log_info "Installing Python dependencies..."
    pip install --upgrade pip
    
    pip install \
        scapy \
        psutil \
        watchdog \
        pyyaml \
        rich \
        textual \
        python-daemon \
        pyinotify \
        netifaces \
        dnspython \
        requests \
        cryptography
    
    deactivate
    
    log_success "Python environment configured"
}

configure_auditd() {
    header "CONFIGURING AUDITD"
    
    log_info "Copying audit rules..."
    
    cp "${RATA_DIR}/rules/auditd.rules" /etc/audit/rules.d/rata.rules 2>/dev/null || {
        log_warn "Custom auditd rules not found"
    }
    
    log_info "Restarting auditd..."
    systemctl restart auditd || true
    systemctl enable auditd || true
    
    log_success "auditd configured"
}

configure_suricata() {
    header "CONFIGURING SURICATA"
    
    SURICATA_DIR="/etc/suricata"
    
    log_info "Updating Suricata rules..."
    suricata-update 2>/dev/null || log_warn "Could not update rules"
    
    log_info "Copying custom rules..."
    if [[ -f "${RATA_DIR}/rules/suricata_custom.rules" ]]; then
        cp "${RATA_DIR}/rules/suricata_custom.rules" "${SURICATA_DIR}/rules/"
        
        if ! grep -q "suricata_custom.rules" "${SURICATA_DIR}/suricata.yaml"; then
            log_info "Adding custom rules to suricata.yaml..."
        fi
    fi
    
    log_info "Enabling Suricata..."
    systemctl enable suricata || true
    
    log_success "Suricata configured"
}

configure_aide() {
    header "CONFIGURING AIDE (File Integrity)"
    
    log_info "Initializing AIDE database..."
    
    if [[ ! -f /var/lib/aide/aide.db ]]; then
        aideinit 2>/dev/null || aide --init || log_warn "Could not initialize AIDE"
        
        if [[ -f /var/lib/aide/aide.db.new ]]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        fi
    else
        log_info "AIDE database already exists"
    fi
    
    log_success "AIDE configured"
}

setup_nftables() {
    header "CONFIGURING NFTABLES"
    
    if [[ -f "${RATA_DIR}/rules/nftables.conf" ]]; then
        log_info "Applying nftables rules..."
        
        cp "${RATA_DIR}/rules/nftables.conf" /etc/nftables.conf.rata
        
        log_warn "nftables rules will NOT be activated automatically"
        log_info "To activate: nft -f /etc/nftables.conf.rata"
    fi
    
    log_success "nftables configured"
}

create_directories() {
    header "CREATING DIRECTORY STRUCTURE"
    
    mkdir -p "${RATA_DIR}"/{forensics,logs,pcap,alerts,baseline}
    mkdir -p "${RATA_DIR}/forensics"/{audit,captures,evidence}
    
    chmod 700 "${RATA_DIR}/forensics"
    chmod 700 "${RATA_DIR}/logs"
    
    log_success "Directories created"
}

setup_systemd_service() {
    header "CONFIGURING SYSTEMD SERVICE"
    
    cat > /etc/systemd/system/rata-monitor.service << EOF
[Unit]
Description=RATA - Real-time Attack Tracking & Alerting
After=network.target auditd.service

[Service]
Type=simple
User=root
WorkingDirectory=${RATA_DIR}
ExecStart=${RATA_DIR}/venv/bin/python ${RATA_DIR}/dashboard.py --daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    log_success "systemd service configured"
    log_info "To start: systemctl start rata-monitor"
    log_info "To enable at boot: systemctl enable rata-monitor"
}

print_post_install() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN} INSTALLATION COMPLETED${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "Next steps:"
    echo ""
    echo -e "  ${CYAN}1. Run initial audit:${NC}"
    echo -e "     sudo ${RATA_DIR}/scripts/audit_current.sh"
    echo ""
    echo -e "  ${CYAN}2. Review and adjust configuration:${NC}"
    echo -e "     ${RATA_DIR}/config.yaml"
    echo ""
    echo -e "  ${CYAN}3. Capture system baseline:${NC}"
    echo -e "     sudo ${RATA_DIR}/scripts/baseline_capture.sh"
    echo ""
    echo -e "  ${CYAN}4. Start monitoring:${NC}"
    echo -e "     cd ${RATA_DIR} && sudo ./venv/bin/python dashboard.py"
    echo ""
    echo -e "  ${CYAN}5. (Optional) Enable service:${NC}"
    echo -e "     sudo systemctl enable --now rata-monitor"
    echo ""
}

main() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           RATA - INSTALLER                                    ║${NC}"
    echo -e "${CYAN}║         Real-time Attack Tracking & Alerting                  ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    check_root
    check_kali
    create_directories
    install_system_packages
    install_osquery
    setup_python_env
    configure_auditd
    configure_suricata
    configure_aide
    setup_nftables
    setup_systemd_service
    print_post_install
}

main "$@"

