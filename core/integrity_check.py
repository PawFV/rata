#!/usr/bin/env python3
"""
RATA - Integrity Checker
File integrity monitoring and self-verification.
"""

import os
import sys
import hashlib
import json
import threading
import time
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, List, Set
from enum import Enum


class ChangeType(Enum):
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    PERMISSIONS = "permissions"


@dataclass
class FileChange:
    path: str
    change_type: ChangeType
    old_hash: Optional[str]
    new_hash: Optional[str]
    old_permissions: Optional[str]
    new_permissions: Optional[str]
    timestamp: datetime


@dataclass
class FileState:
    path: str
    sha256: str
    size: int
    permissions: str
    mtime: float
    uid: int
    gid: int


from .config_manager import config_manager

class IntegrityChecker:
    
    CRITICAL_PATHS = [
        "/bin", "/sbin", "/usr/bin", "/usr/sbin",
        "/lib", "/lib64", "/usr/lib",
        "/etc/passwd", "/etc/shadow", "/etc/group",
        "/etc/sudoers", "/etc/ssh/sshd_config",
        "/etc/crontab", "/etc/cron.d",
        "/etc/systemd/system",
    ]
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.baseline: Dict[str, FileState] = {}
        self.callbacks: List[Callable[[FileChange], None]] = []
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        hash_file_cfg = self.config.get('integrity', {}).get('binary_hashes', {}).get('hash_file')
        self.baseline_file = config_manager.get_path(hash_file_cfg) or config_manager.get_path('baseline/binary_hashes.json')
        
        self.watch_paths = self.config.get('monitoring', {}).get('files', {}).get(
            'watch_paths', self.CRITICAL_PATHS
        )
        
        self.ignore_patterns = set(self.config.get('monitoring', {}).get('files', {}).get(
            'ignore_patterns', ['*.log', '*.tmp', '/etc/mtab']
        ))
    
    def add_callback(self, callback: Callable[[FileChange], None]):
        self.callbacks.append(callback)
    
    def _notify(self, change: FileChange):
        for callback in self.callbacks:
            try:
                callback(change)
            except Exception as e:
                print(f"Callback error: {e}", file=sys.stderr)
    
    def _hash_file(self, path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except (IOError, PermissionError):
            return None
    
    def _get_file_state(self, path: str) -> Optional[FileState]:
        try:
            stat = os.stat(path)
            file_hash = self._hash_file(path) if os.path.isfile(path) else ""
            
            return FileState(
                path=path,
                sha256=file_hash or "",
                size=stat.st_size,
                permissions=oct(stat.st_mode)[-3:],
                mtime=stat.st_mtime,
                uid=stat.st_uid,
                gid=stat.st_gid
            )
        except (OSError, PermissionError):
            return None
    
    def _should_ignore(self, path: str) -> bool:
        for pattern in self.ignore_patterns:
            if pattern.startswith('*'):
                if path.endswith(pattern[1:]):
                    return True
            elif pattern in path:
                return True
        return False
    
    def capture_baseline(self, paths: List[str] = None) -> int:
        paths = paths or self.watch_paths
        count = 0
        
        with self._lock:
            self.baseline.clear()
            
            for base_path in paths:
                p = Path(base_path)
                
                if not p.exists():
                    continue
                
                if p.is_file():
                    state = self._get_file_state(str(p))
                    if state and not self._should_ignore(str(p)):
                        self.baseline[str(p)] = state
                        count += 1
                elif p.is_dir():
                    try:
                        for item in p.rglob('*'):
                            if item.is_file() and not self._should_ignore(str(item)):
                                state = self._get_file_state(str(item))
                                if state:
                                    self.baseline[str(item)] = state
                                    count += 1
                    except PermissionError:
                        continue
        
        return count
    
    def save_baseline(self, path: str = None) -> bool:
        path = Path(path) if path else self.baseline_file
        path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with self._lock:
                data = {
                    'timestamp': datetime.now().isoformat(),
                    'files': {
                        k: {
                            'sha256': v.sha256,
                            'size': v.size,
                            'permissions': v.permissions,
                            'mtime': v.mtime,
                            'uid': v.uid,
                            'gid': v.gid
                        }
                        for k, v in self.baseline.items()
                    }
                }
            
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error saving baseline: {e}", file=sys.stderr)
            return False
    
    def load_baseline(self, path: str = None) -> bool:
        path = Path(path) if path else self.baseline_file
        
        if not path.exists():
            return False
        
        try:
            with open(path) as f:
                data = json.load(f)
            
            with self._lock:
                self.baseline.clear()
                
                for filepath, info in data.get('files', {}).items():
                    self.baseline[filepath] = FileState(
                        path=filepath,
                        sha256=info['sha256'],
                        size=info['size'],
                        permissions=info['permissions'],
                        mtime=info['mtime'],
                        uid=info['uid'],
                        gid=info['gid']
                    )
            
            return True
        except Exception as e:
            print(f"Error loading baseline: {e}", file=sys.stderr)
            return False
    
    def check_integrity(self) -> List[FileChange]:
        changes = []
        
        with self._lock:
            checked = set()
            
            for path, old_state in self.baseline.items():
                checked.add(path)
                
                if not os.path.exists(path):
                    changes.append(FileChange(
                        path=path,
                        change_type=ChangeType.DELETED,
                        old_hash=old_state.sha256,
                        new_hash=None,
                        old_permissions=old_state.permissions,
                        new_permissions=None,
                        timestamp=datetime.now()
                    ))
                    continue
                
                new_state = self._get_file_state(path)
                if not new_state:
                    continue
                
                if new_state.sha256 != old_state.sha256:
                    changes.append(FileChange(
                        path=path,
                        change_type=ChangeType.MODIFIED,
                        old_hash=old_state.sha256,
                        new_hash=new_state.sha256,
                        old_permissions=old_state.permissions,
                        new_permissions=new_state.permissions,
                        timestamp=datetime.now()
                    ))
                elif new_state.permissions != old_state.permissions:
                    changes.append(FileChange(
                        path=path,
                        change_type=ChangeType.PERMISSIONS,
                        old_hash=old_state.sha256,
                        new_hash=new_state.sha256,
                        old_permissions=old_state.permissions,
                        new_permissions=new_state.permissions,
                        timestamp=datetime.now()
                    ))
        
        return changes
    
    def verify_self(self) -> Dict:
        rata_dir = Path(__file__).resolve().parent.parent
        results = {
            'intact': True,
            'checked_files': 0,
            'issues': []
        }
        
        critical_files = [
            rata_dir / "dashboard.py",
            rata_dir / "core" / "kernel_monitor.py",
            rata_dir / "core" / "network_monitor.py",
            rata_dir / "core" / "integrity_check.py",
            rata_dir / "core" / "alerter.py",
        ]
        
        self_baseline_file = rata_dir / "baseline" / "self_hashes.json"
        
        if self_baseline_file.exists():
            try:
                with open(self_baseline_file) as f:
                    self_baseline = json.load(f)
                
                for filepath in critical_files:
                    if not filepath.exists():
                        continue
                    
                    current_hash = self._hash_file(str(filepath))
                    stored_hash = self_baseline.get('files', {}).get(str(filepath))
                    
                    results['checked_files'] += 1
                    
                    if stored_hash and current_hash != stored_hash:
                        results['intact'] = False
                        results['issues'].append({
                            'file': str(filepath),
                            'issue': 'hash_mismatch',
                            'expected': stored_hash,
                            'actual': current_hash
                        })
                        
            except Exception as e:
                results['issues'].append({
                    'file': str(self_baseline_file),
                    'issue': 'load_error',
                    'error': str(e)
                })
        else:
            self._create_self_baseline(critical_files, self_baseline_file)
            results['issues'].append({
                'file': str(self_baseline_file),
                'issue': 'created_new_baseline'
            })
        
        return results
    
    def _create_self_baseline(self, files: List[Path], output: Path):
        output.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'timestamp': datetime.now().isoformat(),
            'files': {}
        }
        
        for filepath in files:
            if filepath.exists():
                h = self._hash_file(str(filepath))
                if h:
                    data['files'][str(filepath)] = h
        
        with open(output, 'w') as f:
            json.dump(data, f, indent=2)
    
    def start(self) -> bool:
        if self.running:
            return True
        
        if not self.baseline:
            self.load_baseline()
        
        self.running = True
        
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="IntegrityChecker-Monitor"
        )
        self._thread.start()
        
        return True
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
    
    def _monitor_loop(self):
        interval = self.config.get('integrity', {}).get('self_check', {}).get(
            'interval_seconds', 300
        )
        
        while self.running:
            try:
                changes = self.check_integrity()
                
                for change in changes:
                    self._notify(change)
                
                self_result = self.verify_self()
                if not self_result['intact']:
                    print("WARNING: RATA self-verification failed!", file=sys.stderr)
                    for issue in self_result['issues']:
                        print(f"  {issue}", file=sys.stderr)
                
            except Exception as e:
                print(f"Integrity check error: {e}", file=sys.stderr)
            
            time.sleep(interval)


if __name__ == "__main__":
    def on_change(change: FileChange):
        print(f"[{change.change_type.value.upper()}] {change.path}")
        if change.old_hash and change.new_hash:
            print(f"  Old: {change.old_hash[:16]}...")
            print(f"  New: {change.new_hash[:16]}...")
    
    checker = IntegrityChecker()
    checker.add_callback(on_change)
    
    print("Capturing baseline...")
    count = checker.capture_baseline(["/etc/passwd", "/etc/shadow", "/bin/ls"])
    print(f"Captured {count} files")
    
    print("\nChecking integrity...")
    changes = checker.check_integrity()
    print(f"Found {len(changes)} changes")
    
    print("\nSelf-verification...")
    result = checker.verify_self()
    print(f"Intact: {result['intact']}")

