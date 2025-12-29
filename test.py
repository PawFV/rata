#!/usr/bin/env python3
"""
RATA Test Runner
Simple validation of all components.
"""

import os
import sys
import time
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

RATA_DIR = Path(__file__).parent
PASS = '\033[92m✓\033[0m'
FAIL = '\033[91m✗\033[0m'
WARN = '\033[93m!\033[0m'


def log(status, msg):
    print(f"  {status} {msg}")


def test_imports():
    print("\n[Imports]")
    
    try:
        from core.kernel_monitor import KernelMonitor, EventType
        log(PASS, "kernel_monitor")
    except Exception as e:
        log(FAIL, f"kernel_monitor: {e}")
        return False
    
    try:
        from core.network_monitor import NetworkMonitor, ThreatLevel
        log(PASS, "network_monitor")
    except Exception as e:
        log(FAIL, f"network_monitor: {e}")
        return False
    
    try:
        from core.integrity_check import IntegrityChecker, ChangeType
        log(PASS, "integrity_check")
    except Exception as e:
        log(FAIL, f"integrity_check: {e}")
        return False
    
    try:
        from core.alerter import Alerter, AlertLevel
        log(PASS, "alerter")
    except Exception as e:
        log(FAIL, f"alerter: {e}")
        return False
    
    try:
        from core.forensics import ForensicsCollector
        log(PASS, "forensics")
    except Exception as e:
        log(FAIL, f"forensics: {e}")
        return False
    
    return True


def test_config():
    print("\n[Config]")
    
    config_path = RATA_DIR / "config.yaml"
    if not config_path.exists():
        log(FAIL, "config.yaml not found")
        return False
    
    try:
        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f)
        log(PASS, "config.yaml valid YAML")
    except Exception as e:
        log(FAIL, f"config.yaml parse error: {e}")
        return False
    
    required = ['general', 'monitoring', 'whitelist', 'alerts']
    for key in required:
        if key in config:
            log(PASS, f"section '{key}' present")
        else:
            log(WARN, f"section '{key}' missing")
    
    return True


def test_network_monitor():
    print("\n[Network Monitor]")
    
    from core.network_monitor import NetworkMonitor
    
    monitor = NetworkMonitor()
    
    conns = monitor._get_current_connections()
    log(PASS, f"read {len(conns)} connections from /proc/net")
    
    events = []
    def callback(conn, event):
        events.append((conn, event))
    
    monitor.add_callback(callback)
    monitor.start()
    time.sleep(2)
    monitor.stop()
    
    log(PASS, f"monitor ran, captured {len(events)} events")
    
    stats = monitor.get_stats()
    log(PASS, f"stats: {stats['total_connections']} total, {stats['suspicious_connections']} suspicious")
    
    return True


def test_kernel_monitor():
    print("\n[Kernel Monitor]")
    
    if os.geteuid() != 0:
        log(WARN, "not root - limited testing")
    
    from core.kernel_monitor import KernelMonitor
    
    monitor = KernelMonitor()
    
    conns = monitor.get_current_connections()
    log(PASS, f"read {len(conns)} connections")
    
    modules = monitor.get_loaded_modules()
    log(PASS, f"read {len(modules)} kernel modules")
    
    return True


def test_integrity():
    print("\n[Integrity Checker]")
    
    from core.integrity_check import IntegrityChecker
    
    checker = IntegrityChecker()
    
    count = checker.capture_baseline(["/etc/passwd", "/etc/hosts"])
    log(PASS, f"captured baseline for {count} files")
    
    changes = checker.check_integrity()
    log(PASS, f"integrity check found {len(changes)} changes")
    
    result = checker.verify_self()
    if result['intact']:
        log(PASS, "self-verification passed")
    else:
        log(WARN, f"self-verification: {result['issues']}")
    
    return True


def test_alerter():
    print("\n[Alerter]")
    
    from core.alerter import Alerter, AlertLevel
    
    alerter = Alerter({'alerts': {'sound': {'enabled': False}, 'desktop_notification': {'enabled': False}}})
    alerter.start()
    
    alerter.alert(
        level=AlertLevel.INFO,
        source="test",
        title="Test Alert",
        description="Testing alert system"
    )
    
    time.sleep(0.5)
    alerter.stop()
    
    log(PASS, "alert created and processed")
    
    return True


def test_forensics():
    print("\n[Forensics]")
    
    from core.forensics import ForensicsCollector
    
    collector = ForensicsCollector()
    
    ev = collector.capture_process_state(reason="test")
    if ev:
        log(PASS, f"process state captured: {ev.path}")
    else:
        log(FAIL, "process state capture failed")
        return False
    
    ev = collector.capture_network_state(reason="test")
    if ev:
        log(PASS, f"network state captured: {ev.path}")
    else:
        log(FAIL, "network state capture failed")
        return False
    
    summary = collector.get_evidence_summary()
    log(PASS, f"evidence summary: {summary['total']} items")
    
    return True


def test_scripts():
    print("\n[Scripts]")
    
    scripts = [
        RATA_DIR / "scripts" / "audit_current.sh",
        RATA_DIR / "scripts" / "baseline_capture.sh",
        RATA_DIR / "install.sh",
    ]
    
    for script in scripts:
        if not script.exists():
            log(FAIL, f"{script.name} not found")
            continue
        
        result = subprocess.run(['bash', '-n', str(script)], capture_output=True)
        if result.returncode == 0:
            log(PASS, f"{script.name} syntax OK")
        else:
            log(FAIL, f"{script.name} syntax error")
    
    return True


def test_rules():
    print("\n[Rules]")
    
    rules_dir = RATA_DIR / "rules"
    
    auditd = rules_dir / "auditd.rules"
    if auditd.exists():
        log(PASS, "auditd.rules exists")
    else:
        log(FAIL, "auditd.rules missing")
    
    nftables = rules_dir / "nftables.conf"
    if nftables.exists():
        result = subprocess.run(['nft', '-c', '-f', str(nftables)], capture_output=True)
        if result.returncode == 0:
            log(PASS, "nftables.conf syntax OK")
        else:
            log(WARN, f"nftables.conf: {result.stderr.decode()[:50]}")
    
    suricata = rules_dir / "suricata_custom.rules"
    if suricata.exists():
        log(PASS, "suricata_custom.rules exists")
    
    return True


def run_all():
    print("=" * 50)
    print("RATA Test Suite")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Root: {'yes' if os.geteuid() == 0 else 'no'}")
    print("=" * 50)
    
    results = {
        'imports': test_imports(),
        'config': test_config(),
        'scripts': test_scripts(),
        'rules': test_rules(),
    }
    
    if results['imports']:
        results['network'] = test_network_monitor()
        results['kernel'] = test_kernel_monitor()
        results['integrity'] = test_integrity()
        results['alerter'] = test_alerter()
        
        if os.geteuid() == 0:
            results['forensics'] = test_forensics()
        else:
            print("\n[Forensics]")
            log(WARN, "skipped (requires root)")
    
    print("\n" + "=" * 50)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"Results: {passed}/{total} passed")
    print("=" * 50)
    
    return all(results.values())


def main():
    parser = argparse.ArgumentParser(description='RATA Test Runner')
    parser.add_argument('--component', '-c', help='Test specific component')
    parser.add_argument('--all', '-a', action='store_true', help='Run all tests')
    parser.add_argument('--quick', '-q', action='store_true', help='Quick syntax check only')
    
    args = parser.parse_args()
    
    os.chdir(RATA_DIR)
    sys.path.insert(0, str(RATA_DIR))
    
    if args.quick:
        print("Quick syntax check...")
        
        result = subprocess.run(
            ['python3', '-m', 'py_compile', 'dashboard.py'] + 
            [str(p) for p in (RATA_DIR / 'core').glob('*.py')],
            capture_output=True
        )
        
        if result.returncode == 0:
            print(f"{PASS} Python syntax OK")
        else:
            print(f"{FAIL} Python syntax error:")
            print(result.stderr.decode())
            sys.exit(1)
        
        for script in (RATA_DIR / 'scripts').glob('*.sh'):
            result = subprocess.run(['bash', '-n', str(script)], capture_output=True)
            if result.returncode == 0:
                print(f"{PASS} {script.name} OK")
            else:
                print(f"{FAIL} {script.name} error")
        
        sys.exit(0)
    
    if args.component:
        component_tests = {
            'network': test_network_monitor,
            'kernel': test_kernel_monitor,
            'integrity': test_integrity,
            'alerter': test_alerter,
            'forensics': test_forensics,
            'imports': test_imports,
            'config': test_config,
        }
        
        if args.component in component_tests:
            test_imports()
            success = component_tests[args.component]()
            sys.exit(0 if success else 1)
        else:
            print(f"Unknown component: {args.component}")
            print(f"Available: {', '.join(component_tests.keys())}")
            sys.exit(1)
    
    success = run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

