#!/usr/bin/env python3
"""
RATA - Alert System
Notifications, logging, and automated responses.
"""

import os
import sys
import json
import subprocess
import threading
import queue
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, Callable, Dict, List, Any
from enum import Enum


class AlertLevel(Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Alert:
    timestamp: datetime
    level: AlertLevel
    source: str
    title: str
    description: str
    details: Dict[str, Any]
    actions_taken: List[str]
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'level': self.level.name,
            'source': self.source,
            'title': self.title,
            'description': self.description,
            'details': self.details,
            'actions_taken': self.actions_taken
        }


from .config_manager import config_manager

class Alerter:
    
    LEVEL_COLORS = {
        AlertLevel.INFO: '\033[0;36m',
        AlertLevel.LOW: '\033[0;32m',
        AlertLevel.MEDIUM: '\033[0;33m',
        AlertLevel.HIGH: '\033[0;31m',
        AlertLevel.CRITICAL: '\033[1;31m',
    }
    RESET = '\033[0m'
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.alert_queue = queue.Queue()
        self.callbacks: List[Callable[[Alert], None]] = []
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        log_cfg = self.config.get('alerts', {}).get('log_to_file', {}).get('file')
        self.alert_log = config_manager.get_path(log_cfg) or config_manager.get_path('alerts/alerts.log')
        
        self.alert_log.parent.mkdir(parents=True, exist_ok=True)
        
        forensics_cfg = self.config.get('general', {}).get('forensics_dir')
        self.forensics_dir = config_manager.get_path(forensics_cfg) or config_manager.get_path('forensics')
        
        self.sound_enabled = self.config.get('alerts', {}).get('sound', {}).get('enabled', True)
        self.desktop_enabled = self.config.get('alerts', {}).get('desktop_notification', {}).get('enabled', True)
    
    def add_callback(self, callback: Callable[[Alert], None]):
        self.callbacks.append(callback)
    
    def alert(
        self,
        level: AlertLevel,
        source: str,
        title: str,
        description: str,
        details: Dict = None,
        actions: List[str] = None
    ) -> Alert:
        alert = Alert(
            timestamp=datetime.now(),
            level=level,
            source=source,
            title=title,
            description=description,
            details=details or {},
            actions_taken=actions or []
        )
        
        self.alert_queue.put(alert)
        return alert
    
    def start(self) -> bool:
        if self.running:
            return True
        
        self.running = True
        
        self._thread = threading.Thread(
            target=self._process_alerts,
            daemon=True,
            name="Alerter-Processor"
        )
        self._thread.start()
        
        return True
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
    
    def _process_alerts(self):
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                self._handle_alert(alert)
            except queue.Empty:
                continue
    
    def _handle_alert(self, alert: Alert):
        self._log_alert(alert)
        self._print_alert(alert)
        
        if alert.level.value >= AlertLevel.MEDIUM.value:
            if self.desktop_enabled:
                self._desktop_notify(alert)
            
            if self.sound_enabled and alert.level.value >= AlertLevel.HIGH.value:
                self._play_sound(alert.level)
        
        for callback in self.callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Alert callback error: {e}", file=sys.stderr)
        
        if alert.level == AlertLevel.CRITICAL:
            self._execute_critical_actions(alert)
    
    def _log_alert(self, alert: Alert):
        try:
            with open(self.alert_log, 'a') as f:
                f.write(json.dumps(alert.to_dict()) + '\n')
        except Exception as e:
            print(f"Failed to log alert: {e}", file=sys.stderr)
    
    def _print_alert(self, alert: Alert):
        color = self.LEVEL_COLORS.get(alert.level, '')
        
        print(f"\n{color}{'='*60}{self.RESET}")
        print(f"{color}[{alert.level.name}] {alert.title}{self.RESET}")
        print(f"Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source: {alert.source}")
        print(f"Description: {alert.description}")
        
        if alert.details:
            print("Details:")
            for key, value in alert.details.items():
                print(f"  {key}: {value}")
        
        print(f"{color}{'='*60}{self.RESET}\n")
    
    def _desktop_notify(self, alert: Alert):
        try:
            urgency = 'critical' if alert.level == AlertLevel.CRITICAL else 'normal'
            
            subprocess.Popen([
                'notify-send',
                '-u', urgency,
                f'RATA [{alert.level.name}]',
                f'{alert.title}\n{alert.description}'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            pass
        except Exception:
            pass
    
    def _play_sound(self, level: AlertLevel):
        sounds = self.config.get('alerts', {}).get('sound', {})
        
        if level == AlertLevel.CRITICAL:
            sound_file = sounds.get('critical', '/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga')
        else:
            sound_file = sounds.get('warning', '/usr/share/sounds/freedesktop/stereo/bell.oga')
        
        if os.path.exists(sound_file):
            try:
                subprocess.Popen(
                    ['paplay', sound_file],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except FileNotFoundError:
                try:
                    subprocess.Popen(
                        ['aplay', sound_file],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                except FileNotFoundError:
                    pass
    
    def _execute_critical_actions(self, alert: Alert):
        actions = self.config.get('alerts', {}).get('actions', {}).get('on_critical', [])
        
        for action in actions:
            if action == 'capture_pcap':
                self._capture_pcap(alert)
            elif action == 'capture_process_info':
                self._capture_process_info(alert)
    
    def _capture_pcap(self, alert: Alert):
        evidence_dir = self.forensics_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_file = evidence_dir / f"alert_{timestamp}.pcap"
        
        try:
            process = subprocess.Popen(
                ['tcpdump', '-i', 'any', '-c', '1000', '-w', str(pcap_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            threading.Timer(30, lambda: process.terminate()).start()
            
            alert.actions_taken.append(f"Started pcap capture: {pcap_file}")
        except Exception as e:
            alert.actions_taken.append(f"Failed to start pcap: {e}")
    
    def _capture_process_info(self, alert: Alert):
        evidence_dir = self.forensics_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        info_file = evidence_dir / f"processes_{timestamp}.txt"
        
        try:
            with open(info_file, 'w') as f:
                f.write(f"Captured at: {datetime.now().isoformat()}\n")
                f.write(f"Alert: {alert.title}\n\n")
                
                result = subprocess.run(['ps', 'auxwww'], capture_output=True, text=True)
                f.write("=== PROCESSES ===\n")
                f.write(result.stdout)
                
                result = subprocess.run(['ss', '-tulpan'], capture_output=True, text=True)
                f.write("\n=== CONNECTIONS ===\n")
                f.write(result.stdout)
            
            alert.actions_taken.append(f"Captured process info: {info_file}")
        except Exception as e:
            alert.actions_taken.append(f"Failed to capture process info: {e}")
    
    def get_recent_alerts(self, count: int = 100, min_level: AlertLevel = None) -> List[Alert]:
        alerts = []
        
        try:
            if self.alert_log.exists():
                with open(self.alert_log) as f:
                    lines = f.readlines()[-count:]
                
                for line in lines:
                    try:
                        data = json.loads(line.strip())
                        level = AlertLevel[data['level']]
                        
                        if min_level and level.value < min_level.value:
                            continue
                        
                        alerts.append(Alert(
                            timestamp=datetime.fromisoformat(data['timestamp']),
                            level=level,
                            source=data['source'],
                            title=data['title'],
                            description=data['description'],
                            details=data['details'],
                            actions_taken=data['actions_taken']
                        ))
                    except (json.JSONDecodeError, KeyError):
                        continue
        except Exception:
            pass
        
        return alerts


class AlertAggregator:
    
    def __init__(self, alerter: Alerter, window_seconds: int = 60):
        self.alerter = alerter
        self.window_seconds = window_seconds
        self.pending: Dict[str, List[Dict]] = {}
        self._lock = threading.Lock()
    
    def add(self, key: str, level: AlertLevel, source: str, title: str, details: Dict = None):
        with self._lock:
            if key not in self.pending:
                self.pending[key] = []
            
            self.pending[key].append({
                'timestamp': datetime.now(),
                'level': level,
                'source': source,
                'title': title,
                'details': details or {}
            })
    
    def flush(self):
        with self._lock:
            for key, items in self.pending.items():
                if not items:
                    continue
                
                max_level = max(item['level'] for item in items)
                
                self.alerter.alert(
                    level=max_level,
                    source=items[0]['source'],
                    title=f"{items[0]['title']} ({len(items)} events)",
                    description=f"Aggregated {len(items)} similar events",
                    details={'events': len(items), 'key': key}
                )
            
            self.pending.clear()


if __name__ == "__main__":
    alerter = Alerter()
    alerter.start()
    
    alerter.alert(
        level=AlertLevel.INFO,
        source="test",
        title="Test Info Alert",
        description="This is a test info alert"
    )
    
    alerter.alert(
        level=AlertLevel.HIGH,
        source="test",
        title="Test High Alert",
        description="This is a test high priority alert",
        details={'ip': '192.168.1.100', 'port': 4444}
    )
    
    import time
    time.sleep(2)
    
    alerter.stop()
    print("Alerter test complete")

