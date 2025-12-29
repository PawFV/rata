#!/usr/bin/env python3
"""
RATA - Real-time Attack Tracking & Alerting
Main dashboard and monitoring interface.
"""

import os
import sys
import time
import signal
import argparse
import threading
import yaml
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from core.kernel_monitor import KernelMonitor, KernelEvent, EventType
from core.network_monitor import NetworkMonitor, Connection, ThreatLevel
from core.integrity_check import IntegrityChecker, FileChange, ChangeType
from core.alerter import Alerter, AlertLevel, Alert
from core.kill_switch import KillSwitch
from core.ip_resolver import get_resolver


class RATADashboard:
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.running = False
        
        self.kernel_monitor = KernelMonitor(self.config)
        self.network_monitor = NetworkMonitor(self.config)
        self.integrity_checker = IntegrityChecker(self.config)
        self.alerter = Alerter(self.config)
        self.kill_switch = KillSwitch(self.config)
        
        ks_config = self.config.get('alerts', {}).get('blocking', {}).get('kill_switch', {})
        self.auto_kill_enabled = ks_config.get('enabled', False)
        
        self._setup_callbacks()
        
        self.stats = {
            'start_time': None,
            'connections_total': 0,
            'connections_suspicious': 0,
            'kernel_events': 0,
            'integrity_changes': 0,
            'alerts': {level.name: 0 for level in AlertLevel}
        }
        
        if RICH_AVAILABLE:
            self.console = Console()
    
    def _load_config(self, path: str = None) -> dict:
        if path is None:
            path = Path(__file__).parent / "config.yaml"
        
        try:
            with open(path) as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Could not load config: {e}", file=sys.stderr)
            return {}
    
    def _setup_callbacks(self):
        self.kernel_monitor.add_callback(self._on_kernel_event)
        self.network_monitor.add_callback(self._on_network_event)
        self.integrity_checker.add_callback(self._on_integrity_change)
        self.alerter.add_callback(self._on_alert)
    
    def _on_alert(self, alert: Alert):
        if alert.level == AlertLevel.CRITICAL and self.auto_kill_enabled:
            print("\n" + "!"*60, file=sys.stderr)
            print("CRITICAL THREAT - AUTO KILL SWITCH TRIGGERED", file=sys.stderr)
            print("!"*60 + "\n", file=sys.stderr)
            self.kill_switch.emergency_isolate(
                reason=f"Auto-trigger: {alert.title}"
            )
    
    def _on_kernel_event(self, event: KernelEvent):
        self.stats['kernel_events'] += 1
        
        if event.event_type == EventType.NETWORK_CONNECT:
            if event.dst_port and event.dst_port in NetworkMonitor.SUSPICIOUS_PORTS:
                self.alerter.alert(
                    level=AlertLevel.HIGH,
                    source="kernel",
                    title=f"Suspicious outbound connection",
                    description=f"Process {event.comm} (pid {event.pid}) connecting to port {event.dst_port}",
                    details={
                        'pid': event.pid,
                        'process': event.comm,
                        'dst_ip': event.dst_ip,
                        'dst_port': event.dst_port
                    }
                )
        
        elif event.event_type == EventType.MODULE_LOAD:
            self.alerter.alert(
                level=AlertLevel.HIGH,
                source="kernel",
                title="Kernel module loaded",
                description=f"New kernel module loaded by process {event.comm}",
                details={'pid': event.pid, 'process': event.comm}
            )
        
        elif event.event_type == EventType.PTRACE:
            self.alerter.alert(
                level=AlertLevel.CRITICAL,
                source="kernel",
                title="Process injection detected",
                description=f"ptrace called by {event.comm} (pid {event.pid})",
                details={'pid': event.pid, 'process': event.comm}
            )
    
    def _on_network_event(self, conn: Connection, event_type: str):
        self.stats['connections_total'] += 1
        
        if conn.threat_level.value >= ThreatLevel.MEDIUM.value:
            self.stats['connections_suspicious'] += 1
            
            level = AlertLevel.MEDIUM
            if conn.threat_level == ThreatLevel.HIGH:
                level = AlertLevel.HIGH
            elif conn.threat_level == ThreatLevel.CRITICAL:
                level = AlertLevel.CRITICAL
            
            self.alerter.alert(
                level=level,
                source="network",
                title=f"Suspicious connection: {conn.remote_ip}:{conn.remote_port}",
                description=", ".join(conn.threat_reasons),
                details={
                    'process': conn.process_name,
                    'pid': conn.pid,
                    'remote_ip': conn.remote_ip,
                    'remote_port': conn.remote_port,
                    'protocol': conn.protocol
                }
            )
        
        if event_type == "beaconing":
            self.alerter.alert(
                level=AlertLevel.CRITICAL,
                source="network",
                title=f"Beaconing pattern detected",
                description=f"Regular connections to {conn.remote_ip}:{conn.remote_port}",
                details={
                    'remote_ip': conn.remote_ip,
                    'remote_port': conn.remote_port,
                    'reasons': conn.threat_reasons
                }
            )
    
    def _on_integrity_change(self, change: FileChange):
        self.stats['integrity_changes'] += 1
        
        level = AlertLevel.MEDIUM
        if change.path.startswith('/bin') or change.path.startswith('/sbin'):
            level = AlertLevel.CRITICAL
        elif change.path.startswith('/etc'):
            level = AlertLevel.HIGH
        
        self.alerter.alert(
            level=level,
            source="integrity",
            title=f"File {change.change_type.value}: {change.path}",
            description=f"File integrity change detected",
            details={
                'path': change.path,
                'change_type': change.change_type.value,
                'old_hash': change.old_hash[:16] + '...' if change.old_hash else None,
                'new_hash': change.new_hash[:16] + '...' if change.new_hash else None
            }
        )
    
    def start(self):
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        self.alerter.start()
        self.kernel_monitor.start()
        self.network_monitor.start()
        self.integrity_checker.start()
        
        self.alerter.alert(
            level=AlertLevel.INFO,
            source="system",
            title="RATA Monitor Started",
            description="All monitoring systems active"
        )
    
    def stop(self):
        self.running = False
        
        self.kernel_monitor.stop()
        self.network_monitor.stop()
        self.integrity_checker.stop()
        self.alerter.stop()
    
    def _build_connections_table(self) -> Table:
        table = Table(title="Active Connections", expand=True)
        table.add_column("Process", style="cyan", width=15)
        table.add_column("Remote", style="white", width=28)
        table.add_column("Port", style="white", width=6)
        table.add_column("Threat", width=10)
        
        connections = self.network_monitor.get_active_connections()
        resolver = get_resolver()
        
        for conn in sorted(connections, key=lambda c: -c.threat_level.value)[:15]:
            threat_style = {
                ThreatLevel.NONE: "green",
                ThreatLevel.LOW: "yellow",
                ThreatLevel.MEDIUM: "orange1",
                ThreatLevel.HIGH: "red",
                ThreatLevel.CRITICAL: "bold red"
            }.get(conn.threat_level, "white")
            
            remote_display = resolver.get_display_name(conn.remote_ip)
            
            table.add_row(
                conn.process_name or "unknown",
                remote_display,
                str(conn.remote_port),
                Text(conn.threat_level.name, style=threat_style)
            )
        
        return table
    
    def _build_stats_panel(self) -> Panel:
        uptime = datetime.now() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        text = Text()
        text.append(f"Uptime: {uptime}\n", style="cyan")
        text.append(f"Connections: {self.stats['connections_total']}\n")
        text.append(f"Suspicious: {self.stats['connections_suspicious']}\n", style="yellow")
        text.append(f"Kernel Events: {self.stats['kernel_events']}\n")
        text.append(f"Integrity Changes: {self.stats['integrity_changes']}\n")
        
        return Panel(text, title="Statistics")
    
    def _build_alerts_panel(self) -> Panel:
        alerts = self.alerter.get_recent_alerts(10)
        
        text = Text()
        for alert in reversed(alerts[-5:]):
            style = {
                AlertLevel.INFO: "cyan",
                AlertLevel.LOW: "green",
                AlertLevel.MEDIUM: "yellow",
                AlertLevel.HIGH: "red",
                AlertLevel.CRITICAL: "bold red"
            }.get(alert.level, "white")
            
            text.append(f"[{alert.level.name}] ", style=style)
            text.append(f"{alert.title}\n")
        
        if not alerts:
            text.append("No recent alerts", style="dim")
        
        return Panel(text, title="Recent Alerts")
    
    def _build_layout(self) -> Layout:
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        layout["body"].split_row(
            Layout(name="connections", ratio=2),
            Layout(name="sidebar", ratio=1)
        )
        
        layout["sidebar"].split_column(
            Layout(name="stats"),
            Layout(name="alerts")
        )
        
        header_text = Text()
        header_text.append("  RATA ", style="bold white on red")
        header_text.append(" Real-time Attack Tracking & Alerting ", style="bold")
        header_text.append(f"  [{datetime.now().strftime('%H:%M:%S')}]", style="dim")
        
        layout["header"].update(Panel(header_text))
        layout["connections"].update(self._build_connections_table())
        layout["stats"].update(self._build_stats_panel())
        layout["alerts"].update(self._build_alerts_panel())
        layout["footer"].update(Panel(Text("Press Ctrl+C to exit", style="dim")))
        
        return layout
    
    def run_interactive(self):
        self.start()
        
        if RICH_AVAILABLE:
            try:
                with Live(self._build_layout(), refresh_per_second=1, screen=True) as live:
                    while self.running:
                        live.update(self._build_layout())
                        time.sleep(1)
            except KeyboardInterrupt:
                pass
        else:
            print("RATA Monitor Started (install 'rich' for interactive dashboard)")
            print("Press Ctrl+C to stop\n")
            
            try:
                while self.running:
                    stats = self.network_monitor.get_stats()
                    print(f"\r[{datetime.now().strftime('%H:%M:%S')}] "
                          f"Connections: {stats['total_connections']} | "
                          f"Suspicious: {stats['suspicious_connections']}", end="")
                    time.sleep(2)
            except KeyboardInterrupt:
                print()
        
        self.stop()
    
    def run_daemon(self):
        self.start()
        
        def signal_handler(sig, frame):
            self.running = False
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        while self.running:
            time.sleep(1)
        
        self.stop()


def main():
    parser = argparse.ArgumentParser(description='RATA - Real-time Attack Tracking & Alerting')
    parser.add_argument('--config', '-c', help='Path to config file')
    parser.add_argument('--daemon', '-d', action='store_true', help='Run in daemon mode')
    parser.add_argument('--audit', '-a', action='store_true', help='Run system audit only')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("Warning: Running without root privileges. Some features will be limited.", 
              file=sys.stderr)
    
    if args.audit:
        import subprocess
        audit_script = Path(__file__).parent / "scripts" / "audit_current.sh"
        if audit_script.exists():
            subprocess.run(['sudo', 'bash', str(audit_script)])
        else:
            print(f"Audit script not found: {audit_script}", file=sys.stderr)
        return
    
    dashboard = RATADashboard(args.config)
    
    if args.daemon:
        dashboard.run_daemon()
    else:
        dashboard.run_interactive()


if __name__ == "__main__":
    main()

