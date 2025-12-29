#!/usr/bin/env python3
"""
RATA - Forensics Module
Evidence capture and preservation.
"""

import os
import sys
import subprocess
import threading
import shutil
import json
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Dict, List
from enum import Enum


class EvidenceType(Enum):
    PCAP = "pcap"
    PROCESS_DUMP = "process_dump"
    MEMORY_DUMP = "memory_dump"
    FILE_COPY = "file_copy"
    LOG_SNAPSHOT = "log_snapshot"
    NETWORK_STATE = "network_state"


@dataclass
class Evidence:
    evidence_id: str
    evidence_type: EvidenceType
    timestamp: datetime
    source: str
    path: str
    sha256: str
    size: int
    metadata: Dict


from .config_manager import config_manager

class ForensicsCollector:
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        
        dir_cfg = self.config.get('general', {}).get('forensics_dir')
        self.evidence_dir = config_manager.get_path(dir_cfg) or config_manager.get_path('forensics')
        
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        self.chain_of_custody: List[Evidence] = []
        self._lock = threading.Lock()
        
        self.pcap_buffer_seconds = self.config.get('forensics', {}).get(
            'pcap', {}).get('buffer_seconds', 60)
    
    def _generate_id(self) -> str:
        return datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    
    def _hash_file(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    
    def _record_evidence(self, evidence: Evidence):
        with self._lock:
            self.chain_of_custody.append(evidence)
            
            manifest_path = self.evidence_dir / "chain_of_custody.json"
            
            existing = []
            if manifest_path.exists():
                try:
                    with open(manifest_path) as f:
                        existing = json.load(f)
                except Exception:
                    pass
            
            existing.append({
                'id': evidence.evidence_id,
                'type': evidence.evidence_type.value,
                'timestamp': evidence.timestamp.isoformat(),
                'source': evidence.source,
                'path': evidence.path,
                'sha256': evidence.sha256,
                'size': evidence.size,
                'metadata': evidence.metadata
            })
            
            with open(manifest_path, 'w') as f:
                json.dump(existing, f, indent=2)
    
    def capture_pcap(self, duration: int = 30, interface: str = "any", 
                     reason: str = "") -> Optional[Evidence]:
        evidence_id = self._generate_id()
        pcap_dir = self.evidence_dir / "pcap"
        pcap_dir.mkdir(exist_ok=True)
        
        pcap_path = pcap_dir / f"capture_{evidence_id}.pcap"
        
        try:
            process = subprocess.Popen(
                ['tcpdump', '-i', interface, '-w', str(pcap_path), '-G', str(duration), '-W', '1'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            process.wait(timeout=duration + 5)
            
            if pcap_path.exists():
                evidence = Evidence(
                    evidence_id=evidence_id,
                    evidence_type=EvidenceType.PCAP,
                    timestamp=datetime.now(),
                    source=f"tcpdump on {interface}",
                    path=str(pcap_path),
                    sha256=self._hash_file(str(pcap_path)),
                    size=pcap_path.stat().st_size,
                    metadata={'duration': duration, 'interface': interface, 'reason': reason}
                )
                
                self._record_evidence(evidence)
                return evidence
                
        except subprocess.TimeoutExpired:
            process.kill()
        except Exception as e:
            print(f"PCAP capture failed: {e}", file=sys.stderr)
        
        return None
    
    def capture_process_state(self, pid: int = None, reason: str = "") -> Optional[Evidence]:
        evidence_id = self._generate_id()
        proc_dir = self.evidence_dir / "processes"
        proc_dir.mkdir(exist_ok=True)
        
        output_path = proc_dir / f"state_{evidence_id}.json"
        
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'reason': reason,
                'processes': [],
                'connections': [],
                'target_pid': pid
            }
            
            ps_result = subprocess.run(
                ['ps', 'auxwww'],
                capture_output=True,
                text=True
            )
            data['processes_raw'] = ps_result.stdout
            
            ss_result = subprocess.run(
                ['ss', '-tulpan'],
                capture_output=True,
                text=True
            )
            data['connections_raw'] = ss_result.stdout
            
            if pid:
                proc_path = Path(f"/proc/{pid}")
                if proc_path.exists():
                    data['target_process'] = {
                        'cmdline': (proc_path / "cmdline").read_text() if (proc_path / "cmdline").exists() else None,
                        'environ': (proc_path / "environ").read_text() if (proc_path / "environ").exists() else None,
                        'cwd': os.readlink(proc_path / "cwd") if (proc_path / "cwd").exists() else None,
                        'exe': os.readlink(proc_path / "exe") if (proc_path / "exe").exists() else None,
                    }
                    
                    maps_path = proc_path / "maps"
                    if maps_path.exists():
                        data['target_process']['maps'] = maps_path.read_text()
            
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            evidence = Evidence(
                evidence_id=evidence_id,
                evidence_type=EvidenceType.PROCESS_DUMP,
                timestamp=datetime.now(),
                source="process_state",
                path=str(output_path),
                sha256=self._hash_file(str(output_path)),
                size=output_path.stat().st_size,
                metadata={'target_pid': pid, 'reason': reason}
            )
            
            self._record_evidence(evidence)
            return evidence
            
        except Exception as e:
            print(f"Process state capture failed: {e}", file=sys.stderr)
            return None
    
    def capture_network_state(self, reason: str = "") -> Optional[Evidence]:
        evidence_id = self._generate_id()
        net_dir = self.evidence_dir / "network"
        net_dir.mkdir(exist_ok=True)
        
        output_path = net_dir / f"network_{evidence_id}.json"
        
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'reason': reason
            }
            
            commands = {
                'ss': ['ss', '-tulpan'],
                'netstat': ['netstat', '-tulpan'],
                'routes': ['ip', 'route'],
                'arp': ['ip', 'neigh'],
                'interfaces': ['ip', 'addr'],
                'iptables': ['iptables-save'],
                'nftables': ['nft', 'list', 'ruleset'],
            }
            
            for name, cmd in commands.items():
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    data[name] = result.stdout
                except Exception:
                    data[name] = None
            
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            evidence = Evidence(
                evidence_id=evidence_id,
                evidence_type=EvidenceType.NETWORK_STATE,
                timestamp=datetime.now(),
                source="network_state",
                path=str(output_path),
                sha256=self._hash_file(str(output_path)),
                size=output_path.stat().st_size,
                metadata={'reason': reason}
            )
            
            self._record_evidence(evidence)
            return evidence
            
        except Exception as e:
            print(f"Network state capture failed: {e}", file=sys.stderr)
            return None
    
    def copy_file_as_evidence(self, source_path: str, reason: str = "") -> Optional[Evidence]:
        evidence_id = self._generate_id()
        files_dir = self.evidence_dir / "files"
        files_dir.mkdir(exist_ok=True)
        
        source = Path(source_path)
        if not source.exists():
            return None
        
        dest_path = files_dir / f"{evidence_id}_{source.name}"
        
        try:
            shutil.copy2(source, dest_path)
            
            evidence = Evidence(
                evidence_id=evidence_id,
                evidence_type=EvidenceType.FILE_COPY,
                timestamp=datetime.now(),
                source=str(source_path),
                path=str(dest_path),
                sha256=self._hash_file(str(dest_path)),
                size=dest_path.stat().st_size,
                metadata={
                    'original_path': str(source_path),
                    'reason': reason
                }
            )
            
            self._record_evidence(evidence)
            return evidence
            
        except Exception as e:
            print(f"File copy failed: {e}", file=sys.stderr)
            return None
    
    def capture_logs(self, reason: str = "") -> Optional[Evidence]:
        evidence_id = self._generate_id()
        logs_dir = self.evidence_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        
        output_path = logs_dir / f"logs_{evidence_id}.json"
        
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'reason': reason,
                'logs': {}
            }
            
            log_sources = [
                ('/var/log/auth.log', 'auth'),
                ('/var/log/syslog', 'syslog'),
                ('/var/log/kern.log', 'kernel'),
            ]
            
            for path, name in log_sources:
                if os.path.exists(path):
                    try:
                        result = subprocess.run(
                            ['tail', '-n', '1000', path],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        data['logs'][name] = result.stdout
                    except Exception:
                        pass
            
            try:
                result = subprocess.run(
                    ['journalctl', '-n', '500', '--no-pager', '-o', 'json'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                data['logs']['journal'] = result.stdout
            except Exception:
                pass
            
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            evidence = Evidence(
                evidence_id=evidence_id,
                evidence_type=EvidenceType.LOG_SNAPSHOT,
                timestamp=datetime.now(),
                source="system_logs",
                path=str(output_path),
                sha256=self._hash_file(str(output_path)),
                size=output_path.stat().st_size,
                metadata={'reason': reason}
            )
            
            self._record_evidence(evidence)
            return evidence
            
        except Exception as e:
            print(f"Log capture failed: {e}", file=sys.stderr)
            return None
    
    def full_snapshot(self, reason: str = "") -> List[Evidence]:
        evidences = []
        
        ev = self.capture_process_state(reason=reason)
        if ev:
            evidences.append(ev)
        
        ev = self.capture_network_state(reason=reason)
        if ev:
            evidences.append(ev)
        
        ev = self.capture_logs(reason=reason)
        if ev:
            evidences.append(ev)
        
        return evidences
    
    def get_evidence_summary(self) -> Dict:
        manifest_path = self.evidence_dir / "chain_of_custody.json"
        
        if not manifest_path.exists():
            return {'total': 0, 'by_type': {}}
        
        try:
            with open(manifest_path) as f:
                records = json.load(f)
            
            by_type = {}
            for record in records:
                t = record['type']
                by_type[t] = by_type.get(t, 0) + 1
            
            return {
                'total': len(records),
                'by_type': by_type,
                'latest': records[-1] if records else None
            }
        except Exception:
            return {'total': 0, 'by_type': {}}


class PcapRotator:
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        
        pcap_cfg = self.config.get('monitoring', {}).get('network', {}).get('pcap_dir')
        self.pcap_dir = config_manager.get_path(pcap_cfg) or config_manager.get_path('pcap')
        
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        
        self.rotation_hours = self.config.get('monitoring', {}).get(
            'network', {}).get('pcap_rotation_hours', 24)
        self.max_size_mb = self.config.get('monitoring', {}).get(
            'network', {}).get('pcap_max_size_mb', 500)
        
        self.process: Optional[subprocess.Popen] = None
        self.running = False
    
    def start(self, interface: str = "any"):
        if self.running:
            return
        
        self.running = True
        
        pcap_file = self.pcap_dir / "capture_%Y%m%d_%H%M%S.pcap"
        
        rotation_seconds = self.rotation_hours * 3600
        
        try:
            self.process = subprocess.Popen([
                'tcpdump',
                '-i', interface,
                '-w', str(pcap_file),
                '-G', str(rotation_seconds),
                '-C', str(self.max_size_mb),
                '-Z', 'root'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"Failed to start pcap rotation: {e}", file=sys.stderr)
            self.running = False
    
    def stop(self):
        self.running = False
        if self.process:
            self.process.terminate()
            self.process = None
    
    def cleanup_old(self, keep_days: int = 7):
        import time
        
        cutoff = time.time() - (keep_days * 86400)
        
        for pcap in self.pcap_dir.glob("*.pcap"):
            if pcap.stat().st_mtime < cutoff:
                try:
                    pcap.unlink()
                except Exception:
                    pass


if __name__ == "__main__":
    collector = ForensicsCollector()
    
    print("Capturing full system snapshot...")
    evidences = collector.full_snapshot(reason="test capture")
    
    print(f"\nCaptured {len(evidences)} evidence items:")
    for ev in evidences:
        print(f"  - {ev.evidence_type.value}: {ev.path}")
    
    print("\nEvidence summary:")
    summary = collector.get_evidence_summary()
    print(f"  Total: {summary['total']}")
    print(f"  By type: {summary['by_type']}")

