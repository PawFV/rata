# RATA - Real-time Attack Tracking & Alerting

**Network and system monitoring for detecting RAT/spyware in real-time.**

Designed for high-threat environments. Zero Trust architecture.

---

## Quick Start

```bash
# 1. Copy and edit configuration
cp config.example.yaml config.yaml
# Edit config.yaml with your network/system specifics

# 2. Install dependencies (requires root)
sudo ./install.sh

# 3. Run initial system audit
sudo ./scripts/audit_current.sh

# 4. Capture baseline (for integrity monitoring)
sudo ./scripts/baseline_capture.sh

# 5. Deploy canary files (honeypots)
sudo ./scripts/setup_canaries.sh

# 6. Start monitoring
sudo ./venv/bin/python dashboard.py
```

---

## Components

- **Kernel Monitor**: eBPF + auditd for syscall-level visibility
- **Network Monitor**: Connection tracking, beaconing detection, DNS tunneling detection
- **Integrity Checker**: File hash monitoring, self-verification
- **Alerter**: Desktop notifications, sound alerts, logging
- **Forensics**: Evidence capture with chain of custody
- **Kill Switch**: Emergency network isolation with forensic capture
- **IP Resolver**: Reverse DNS + whois + cloud provider detection

---

## Configuration

Edit `config.yaml` to customize:
- **Whitelists**: IPs/domains/processes/ports you trust
- **Detection**: Thresholds for beaconing, data exfiltration, suspicious ports
- **Alerts**: Sound, notifications, actions on threat levels
- **Canaries**: Honeypot files to detect unauthorized access (paths are **relative to user home**)
- **Kill Switch**: Auto-isolation on CRITICAL threats

**IMPORTANT**: Never commit your real `config.yaml` to version control. It contains your canary paths and whitelist specifics.

---

## Canary Files (Honeypots)

Canaries are fake sensitive files that trigger alerts when accessed.

**How it works:**
1. Define canaries in `config.yaml` under `canaries.files`
2. Run `sudo ./scripts/setup_canaries.sh` to deploy
3. Auditd monitors these files for read/write/attribute changes
4. Any access triggers an alert with the `trigger_key`

**Example canaries** (from `config.example.yaml`):
- `Documents/.wallet_backup.txt` → fake crypto wallet seed
- `.aws/credentials_backup` → fake AWS keys
- `Documents/passwords_old.txt` → fake password file

**OPSEC**: Edit `config.yaml` to use **custom paths/names** that only you know. Don't use the examples in production.

Check for canary triggers:
```bash
sudo ausearch -k canary_crypto
sudo ausearch -k canary_cloud
sudo ausearch -k canary_creds
```

---

## Modes

```bash
# Interactive dashboard
sudo ./venv/bin/python dashboard.py

# Daemon mode
sudo ./venv/bin/python dashboard.py --daemon

# Audit only
sudo ./venv/bin/python dashboard.py --audit
```

---

## Testing

```bash
./test.py --quick          # Syntax check only
./test.py                  # Full test suite
./test.py -c network       # Test network monitor
./test.py -c integrity     # Test integrity checker
```

---

## Kill Switch

Emergency network isolation with evidence capture.

**Manual trigger:**
```bash
sudo python3 core/kill_switch.py --kill
```

**Auto-trigger** (configured in `config.yaml`):
```yaml
alerts:
  blocking:
    kill_switch:
      enabled: true
      on_threat_level: CRITICAL
      capture_before_kill: true
      capture_duration_seconds: 10
```

**When triggered:**
1. Captures processes, connections, pcap (configurable duration)
2. Kills all network interfaces (nmcli → ip → iptables fallback)
3. Saves evidence to `forensics/emergency/emergency_<timestamp>/`

---

## Directory Structure

```
rata/
├── dashboard.py              # Main entry point
├── config.yaml               # Your configuration (gitignored)
├── config.example.yaml       # Template configuration
├── test.py                   # Test runner
├── install.sh                # Dependency installer
├── core/                     # Python modules
│   ├── kernel_monitor.py
│   ├── network_monitor.py
│   ├── integrity_check.py
│   ├── alerter.py
│   ├── forensics.py
│   ├── kill_switch.py
│   ├── ip_resolver.py
│   └── config_manager.py
├── rules/                    # Detection rules
│   ├── auditd.rules
│   ├── nftables.conf
│   ├── suricata_custom.rules
│   └── blocklist_ips.txt
├── scripts/                  # Utility scripts
│   ├── audit_current.sh
│   ├── baseline_capture.sh
│   └── setup_canaries.sh
├── docs/                     # Documentation
│   └── external_capture.md
├── forensics/                # Evidence storage (gitignored)
├── logs/                     # Application logs (gitignored)
├── pcap/                     # Packet captures (gitignored)
├── alerts/                   # Alert logs (gitignored)
└── baseline/                 # System baselines (gitignored)
```

---

## Threat Model

RATA is designed for environments where adversaries may have:
- Persistent access (rootkits, implants)
- Behavioral OPSEC (low-and-slow exfiltration)
- Advanced capabilities

**Defense Strategy:**
- **Assume Breach**: Monitor everything, trust nothing
- **Defense in Depth**: Kernel + Network + File + Process layers
- **Evidence First**: Capture forensics before reacting
- **Zero Trust**: Whitelist-only model for known-good entities

---

## OPSEC Considerations

1. **Don't commit sensitive configs**: Your `config.yaml` contains your whitelist, canary paths, and detection thresholds. Keep it local.
2. **Customize canaries**: Use unique file names/paths that only you know. The examples are public.
3. **Rotate indicators**: If you suspect compromise, change canary names/paths and re-deploy.
4. **External capture**: For advanced scenarios, use a network tap/span port for traffic capture (see `docs/external_capture.md`).

---

## License

MIT License. Use at your own risk. No warranties.
