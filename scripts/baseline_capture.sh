#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
RATA_DIR="$(dirname "$SCRIPT_DIR")"
BASELINE_DIR="${RATA_DIR}/baseline"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} Run as root: sudo $0"
        exit 1
    fi
}

create_dirs() {
    mkdir -p "${BASELINE_DIR}"/{configs,hashes}
    log_success "Baseline directory created"
}

hash_binaries() {
    log_info "Hashing system binaries..."
    
    find /bin /sbin /usr/bin /usr/sbin -type f -executable 2>/dev/null | \
        xargs sha256sum > "${BASELINE_DIR}/hashes/binaries_${TIMESTAMP}.sha256" 2>/dev/null || true
    
    log_success "Binary hashes saved"
}

hash_libraries() {
    log_info "Hashing shared libraries..."
    
    find /lib /lib64 /usr/lib -name "*.so*" -type f 2>/dev/null | \
        xargs sha256sum > "${BASELINE_DIR}/hashes/libraries_${TIMESTAMP}.sha256" 2>/dev/null || true
    
    log_success "Library hashes saved"
}

backup_configs() {
    log_info "Backing up critical configs..."
    
    CONFIG_BACKUP="${BASELINE_DIR}/configs/${TIMESTAMP}"
    mkdir -p "${CONFIG_BACKUP}"
    
    cp -a /etc/passwd "${CONFIG_BACKUP}/" 2>/dev/null || true
    cp -a /etc/shadow "${CONFIG_BACKUP}/" 2>/dev/null || true
    cp -a /etc/group "${CONFIG_BACKUP}/" 2>/dev/null || true
    cp -a /etc/sudoers "${CONFIG_BACKUP}/" 2>/dev/null || true
    cp -a /etc/ssh/sshd_config "${CONFIG_BACKUP}/" 2>/dev/null || true
    cp -a /etc/hosts "${CONFIG_BACKUP}/" 2>/dev/null || true
    cp -a /etc/resolv.conf "${CONFIG_BACKUP}/" 2>/dev/null || true
    cp -a /etc/crontab "${CONFIG_BACKUP}/" 2>/dev/null || true
    
    log_success "Config backups saved"
}

capture_system_state() {
    log_info "Capturing system state..."
    
    STATE_FILE="${BASELINE_DIR}/system_state_${TIMESTAMP}.txt"
    
    {
        echo "=== BASELINE CAPTURE ==="
        echo "Timestamp: $(date)"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo ""
        
        echo "=== LOADED KERNEL MODULES ==="
        lsmod
        echo ""
        
        echo "=== LISTENING PORTS ==="
        ss -tlnp
        echo ""
        
        echo "=== RUNNING SERVICES ==="
        systemctl list-units --type=service --state=running
        echo ""
        
        echo "=== ENABLED SERVICES ==="
        systemctl list-unit-files --state=enabled
        echo ""
        
    } > "${STATE_FILE}"
    
    log_success "System state captured"
}

create_rata_self_baseline() {
    log_info "Creating RATA self-verification baseline..."
    
    SELF_HASHES="${BASELINE_DIR}/self_hashes.json"
    
    python3 << EOF
import json
import hashlib
from pathlib import Path
from datetime import datetime

rata_dir = Path("${RATA_DIR}")
files = {}

for pattern in ["*.py", "core/*.py", "scripts/*.sh", "rules/*"]:
    for f in rata_dir.glob(pattern):
        if f.is_file():
            h = hashlib.sha256()
            h.update(f.read_bytes())
            files[str(f)] = h.hexdigest()

data = {
    "timestamp": datetime.now().isoformat(),
    "files": files
}

with open("${SELF_HASHES}", "w") as f:
    json.dump(data, f, indent=2)

print(f"Hashed {len(files)} RATA files")
EOF
    
    log_success "Self-verification baseline created"
}

symlink_latest() {
    ln -sf "hashes/binaries_${TIMESTAMP}.sha256" "${BASELINE_DIR}/binary_hashes.sha256"
    log_success "Latest baseline linked"
}

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     RATA - Baseline Capture                ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    check_root
    create_dirs
    hash_binaries
    hash_libraries
    backup_configs
    capture_system_state
    create_rata_self_baseline
    symlink_latest
    
    echo ""
    echo -e "${GREEN}Baseline capture complete: ${BASELINE_DIR}${NC}"
    echo ""
}

main "$@"

