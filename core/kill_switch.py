#!/usr/bin/env python3
"""
RATA - Kill Switch
Emergency network isolation with evidence capture.
"""

import os
import sys
import subprocess
import threading
import time
from pathlib import Path
from datetime import datetime
from typing import Optional


from .config_manager import config_manager

class KillSwitch:
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        
        dir_cfg = self.config.get('general', {}).get('forensics_dir')
        base_forensics = config_manager.get_path(dir_cfg) or config_manager.get_path('forensics')
        self.forensics_dir = base_forensics / "emergency"
        
        self.forensics_dir.mkdir(parents=True, exist_ok=True)
        
        ks_config = self.config.get('alerts', {}).get('blocking', {}).get('kill_switch', {})
        self.enabled = ks_config.get('enabled', False)
        self.capture_before_kill = ks_config.get('capture_before_kill', True)
        self.capture_duration = ks_config.get('capture_duration_seconds', 10)
        
        self._killed = False
    
    def emergency_isolate(self, reason: str = "Manual trigger") -> bool:
        if self._killed:
            print("Already isolated", file=sys.stderr)
            return True
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        evidence_dir = self.forensics_dir / f"emergency_{timestamp}"
        evidence_dir.mkdir(exist_ok=True)
        
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"KILL SWITCH ACTIVATED: {reason}", file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)
        
        if self.capture_before_kill:
            print("Capturing evidence before isolation...", file=sys.stderr)
            self._capture_evidence(evidence_dir)
        
        print("Isolating network...", file=sys.stderr)
        success = self._kill_network()
        
        if success:
            self._killed = True
            self._save_isolation_log(evidence_dir, reason)
            print(f"\nNetwork ISOLATED. Evidence saved to: {evidence_dir}", file=sys.stderr)
        else:
            print("FAILED to isolate network!", file=sys.stderr)
        
        return success
    
    def _capture_evidence(self, evidence_dir: Path):
        try:
            ps_out = evidence_dir / "processes.txt"
            with open(ps_out, 'w') as f:
                subprocess.run(['ps', 'auxwww'], stdout=f, timeout=5)
        except Exception:
            pass
        
        try:
            ss_out = evidence_dir / "connections.txt"
            with open(ss_out, 'w') as f:
                subprocess.run(['ss', '-tulpan'], stdout=f, timeout=5)
        except Exception:
            pass
        
        try:
            pcap_out = evidence_dir / "last_traffic.pcap"
            proc = subprocess.Popen(
                ['tcpdump', '-i', 'any', '-c', '1000', '-w', str(pcap_out)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(self.capture_duration)
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            pass
        
        try:
            netstat_out = evidence_dir / "netstat.txt"
            with open(netstat_out, 'w') as f:
                subprocess.run(
                    ['netstat', '-tulpan'], 
                    stdout=f, 
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
        except Exception:
            pass
    
    def _kill_network(self) -> bool:
        methods = [
            self._kill_via_nmcli,
            self._kill_via_ip,
            self._kill_via_iptables,
        ]
        
        for method in methods:
            try:
                if method():
                    return True
            except Exception:
                continue
        
        return False
    
    def _kill_via_nmcli(self) -> bool:
        result = subprocess.run(
            ['nmcli', 'networking', 'off'],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    
    def _kill_via_ip(self) -> bool:
        interfaces = ['eth0', 'wlan0', 'enp0s3', 'nordlynx']
        success = False
        
        for iface in interfaces:
            try:
                result = subprocess.run(
                    ['ip', 'link', 'set', iface, 'down'],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    success = True
            except Exception:
                continue
        
        return success
    
    def _kill_via_iptables(self) -> bool:
        commands = [
            ['iptables', '-P', 'INPUT', 'DROP'],
            ['iptables', '-P', 'OUTPUT', 'DROP'],
            ['iptables', '-P', 'FORWARD', 'DROP'],
            ['iptables', '-F'],
            ['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
            ['iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
            except Exception:
                pass
        
        return True
    
    def _save_isolation_log(self, evidence_dir: Path, reason: str):
        log_file = evidence_dir / "isolation_log.txt"
        
        with open(log_file, 'w') as f:
            f.write(f"RATA Emergency Isolation Log\n")
            f.write(f"{'='*40}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Reason: {reason}\n")
            f.write(f"Evidence captured: {self.capture_before_kill}\n")
            f.write(f"\nFiles in this directory:\n")
            for item in evidence_dir.iterdir():
                f.write(f"  - {item.name}\n")
    
    def restore_network(self) -> bool:
        if not self._killed:
            return True
        
        try:
            result = subprocess.run(
                ['nmcli', 'networking', 'on'],
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                self._killed = False
                return True
        except Exception:
            pass
        
        try:
            subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], timeout=5)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], timeout=5)
            subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], timeout=5)
            subprocess.run(['iptables', '-F'], timeout=5)
            self._killed = False
            return True
        except Exception:
            pass
        
        return False


def manual_kill():
    print("RATA Emergency Kill Switch")
    print("="*40)
    print("This will IMMEDIATELY disconnect all network.")
    print("Evidence will be captured first.")
    print()
    
    confirm = input("Type 'KILL' to confirm: ")
    if confirm == 'KILL':
        ks = KillSwitch({'alerts': {'blocking': {'kill_switch': {
            'enabled': True,
            'capture_before_kill': True,
            'capture_duration_seconds': 5
        }}}})
        ks.emergency_isolate("Manual emergency trigger")
    else:
        print("Aborted.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == '--kill':
        manual_kill()
    else:
        print("Usage: ./kill_switch.py --kill")
        print("       For emergency network isolation")

