#!/bin/bash
# RATA - Canary Files Setup
# Creates honeypot files defined in config.yaml
# Dependencies: python3, pyyaml

set -u

# Get real user home directory even when running with sudo
if [ -n "${SUDO_USER:-}" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    REAL_USER="$SUDO_USER"
else
    USER_HOME=$HOME
    REAL_USER="$USER"
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
RATA_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${RATA_DIR}/config.yaml"
AUDIT_RULES_FILE="/etc/audit/rules.d/rata_canaries.rules"

# Check config
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Configuration file not found: $CONFIG_FILE"
    echo "Please copy config.example.yaml to config.yaml and edit it."
    exit 1
fi

echo "Setting up canaries from $CONFIG_FILE..."

# Initialize audit rules file
echo "# RATA Canary File Monitoring" > "$AUDIT_RULES_FILE"

# Use Python to parse YAML and create canaries
python3 << EOF
import yaml
import os
from pathlib import Path

with open("${CONFIG_FILE}") as f:
    config = yaml.safe_load(f)

canaries_config = config.get('canaries', {})
if not canaries_config.get('enabled', False):
    print("Canaries are disabled in config.yaml")
    exit(0)

canaries = canaries_config.get('files', [])
user_home = "${USER_HOME}"
real_user = "${REAL_USER}"
audit_rules = []

for canary in canaries:
    name = canary['name']
    rel_path = canary['path']
    content = canary['content']
    trigger = canary['trigger_key']
    
    # Resolve full path
    if rel_path.startswith('/'):
        full_path = rel_path
    else:
        full_path = os.path.join(user_home, rel_path)
    
    dir_path = os.path.dirname(full_path)
    
    print(f"[-] Deploying canary: {name} -> {full_path}")
    
    # Create directory if missing
    if not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)
        os.chown(dir_path, os.stat(user_home).st_uid, os.stat(user_home).st_gid)
    
    # Write content
    with open(full_path, 'w') as f:
        f.write(content)
    
    # Set ownership and permissions
    os.chown(full_path, os.stat(user_home).st_uid, os.stat(user_home).st_gid)
    os.chmod(full_path, 0o600)
    
    # Store audit rule
    audit_rules.append(f"-w {full_path} -p rwa -k {trigger}")

# Write audit rules
with open("${AUDIT_RULES_FILE}", 'a') as f:
    for rule in audit_rules:
        f.write(rule + '\\n')

print(f"\\nCreated {len(canaries)} canary files")
EOF

# Reload audit rules
if pgrep auditd >/dev/null; then
    echo "Reloading auditd rules..."
    augenrules --load
fi

echo ""
echo "Canaries deployed successfully."
echo "Audit rules updated in $AUDIT_RULES_FILE"
echo "Verify with: ausearch -k <trigger_key>"
