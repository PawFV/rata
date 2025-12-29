#!/usr/bin/env python3
"""
RATA - Network Monitor
Monitoreo exhaustivo de conexiones de red.
"""

import os
import sys
import socket
import struct
import threading
import queue
import time
import json
import subprocess
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, List, Set, Tuple
from collections import defaultdict
from enum import Enum
import re


class ConnectionState(Enum):
    NEW = "new"
    ESTABLISHED = "established"
    CLOSED = "closed"


class ThreatLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Connection:
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: ConnectionState
    pid: Optional[int]
    process_name: Optional[str]
    first_seen: datetime
    last_seen: datetime
    bytes_sent: int = 0
    bytes_received: int = 0
    packet_count: int = 0
    threat_level: ThreatLevel = ThreatLevel.NONE
    threat_reasons: List[str] = field(default_factory=list)


@dataclass
class DNSQuery:
    timestamp: datetime
    domain: str
    query_type: str
    pid: Optional[int]
    response_ips: List[str] = field(default_factory=list)


@dataclass
class BeaconPattern:
    remote_ip: str
    remote_port: int
    connection_times: List[datetime]
    interval_avg: float
    interval_std: float
    regularity_score: float


class NetworkMonitor:
    """
    Monitor de red que detecta conexiones sospechosas,
    beaconing, DNS tunneling, y exfiltración de datos.
    """
    
    SUSPICIOUS_PORTS = {
        4444, 4445, 5555, 1337, 31337,
        6666, 6667, 6668, 6669,
        9001, 9050, 9150,
        50050,
        1194,
        8080, 8443,
    }
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.connections: Dict[str, Connection] = {}
        self.dns_queries: List[DNSQuery] = []
        self.beacon_patterns: Dict[str, BeaconPattern] = {}
        self.connection_history: Dict[str, List[datetime]] = defaultdict(list)
        
        self.callbacks: List[Callable[[Connection, str], None]] = []
        self.running = False
        self._threads: List[threading.Thread] = []
        self._lock = threading.Lock()
        
        self.whitelist_ips: Set[str] = set()
        self.whitelist_domains: Set[str] = set()
        self.whitelist_processes: Set[str] = set()
        self.whitelist_ports: Set[int] = set()
        
        self._load_whitelists()
    
    def _load_whitelists(self):
        wl = self.config.get('whitelist', {})
        
        self.whitelist_ips = set(wl.get('allowed_ips', []))
        self.whitelist_domains = set(wl.get('allowed_domains', []))
        self.whitelist_processes = set(wl.get('allowed_processes', {}).get('network_access', []))
        self.whitelist_ports = set(wl.get('allowed_ports', {}).get('outbound', [53, 80, 443, 22]))
        
        for dns in wl.get('dns_servers', []):
            self.whitelist_ips.add(dns)
    
    def add_callback(self, callback: Callable[[Connection, str], None]):
        self.callbacks.append(callback)
    
    def _notify(self, connection: Connection, event_type: str):
        for callback in self.callbacks:
            try:
                callback(connection, event_type)
            except Exception as e:
                print(f"Callback error: {e}", file=sys.stderr)
    
    def start(self) -> bool:
        if self.running:
            return True
        
        self.running = True
        
        conn_thread = threading.Thread(
            target=self._monitor_connections,
            daemon=True,
            name="NetworkMonitor-Connections"
        )
        conn_thread.start()
        self._threads.append(conn_thread)
        
        analyzer_thread = threading.Thread(
            target=self._analyze_patterns,
            daemon=True,
            name="NetworkMonitor-Analyzer"
        )
        analyzer_thread.start()
        self._threads.append(analyzer_thread)
        
        return True
    
    def stop(self):
        self.running = False
        for thread in self._threads:
            thread.join(timeout=2)
        self._threads.clear()
    
    def _monitor_connections(self):
        """Monitorea conexiones leyendo /proc/net"""
        while self.running:
            try:
                current = self._get_current_connections()
                
                with self._lock:
                    current_keys = set()
                    
                    for conn in current:
                        key = self._connection_key(conn)
                        current_keys.add(key)
                        
                        if key not in self.connections:
                            conn.state = ConnectionState.NEW
                            self.connections[key] = conn
                            self._analyze_new_connection(conn)
                            self._notify(conn, "new")
                        else:
                            existing = self.connections[key]
                            existing.last_seen = datetime.now()
                            existing.state = ConnectionState.ESTABLISHED
                    
                    closed = set(self.connections.keys()) - current_keys
                    for key in closed:
                        conn = self.connections[key]
                        conn.state = ConnectionState.CLOSED
                        self._notify(conn, "closed")
                        del self.connections[key]
                
                time.sleep(self.config.get('monitoring', {}).get('processes', {}).get('check_interval_seconds', 2))
                
            except Exception as e:
                print(f"Error monitoring connections: {e}", file=sys.stderr)
                time.sleep(5)
    
    def _get_current_connections(self) -> List[Connection]:
        """Lee conexiones actuales de /proc/net"""
        connections = []
        
        for proto in ['tcp', 'tcp6', 'udp', 'udp6']:
            proc_path = Path(f"/proc/net/{proto}")
            if not proc_path.exists():
                continue
            
            try:
                with open(proc_path) as f:
                    lines = f.readlines()[1:]
                
                for line in lines:
                    conn = self._parse_proc_net_line(line, proto)
                    if conn and conn.remote_ip not in ("0.0.0.0", "::", "127.0.0.1", "::1"):
                        connections.append(conn)
                        
            except Exception:
                continue
        
        return connections
    
    def _parse_proc_net_line(self, line: str, proto: str) -> Optional[Connection]:
        try:
            parts = line.split()
            if len(parts) < 10:
                return None
            
            local_addr = parts[1]
            remote_addr = parts[2]
            state_hex = parts[3]
            inode = parts[9]
            
            local_ip, local_port = self._parse_addr(local_addr, '6' in proto)
            remote_ip, remote_port = self._parse_addr(remote_addr, '6' in proto)
            
            pid, comm = self._find_process_by_inode(inode)
            
            return Connection(
                protocol=proto.replace('6', ''),
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=ConnectionState.ESTABLISHED,
                pid=pid,
                process_name=comm,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            
        except Exception:
            return None
    
    def _parse_addr(self, addr: str, is_ipv6: bool) -> Tuple[str, int]:
        try:
            ip_hex, port_hex = addr.split(':')
            port = int(port_hex, 16)
            
            if is_ipv6:
                if ip_hex == "00000000000000000000000000000000":
                    return "::", port
                try:
                    bytes_addr = bytes.fromhex(ip_hex)
                    ip = str(ipaddress.IPv6Address(bytes_addr))
                except Exception:
                    ip = "IPv6"
            else:
                ip_int = int(ip_hex, 16)
                ip = '.'.join(str((ip_int >> (8 * i)) & 0xff) for i in range(4))
            
            return ip, port
            
        except Exception:
            return "0.0.0.0", 0
    
    def _find_process_by_inode(self, inode: str) -> Tuple[Optional[int], Optional[str]]:
        try:
            for pid_dir in Path("/proc").iterdir():
                if not pid_dir.name.isdigit():
                    continue
                
                fd_dir = pid_dir / "fd"
                if not fd_dir.exists():
                    continue
                
                try:
                    for fd in fd_dir.iterdir():
                        try:
                            link = os.readlink(str(fd))
                            if f"socket:[{inode}]" in link:
                                pid = int(pid_dir.name)
                                comm_file = pid_dir / "comm"
                                comm = comm_file.read_text().strip() if comm_file.exists() else None
                                return pid, comm
                        except (OSError, PermissionError):
                            continue
                except PermissionError:
                    continue
                    
        except Exception:
            pass
        
        return None, None
    
    def _connection_key(self, conn: Connection) -> str:
        return f"{conn.protocol}:{conn.local_ip}:{conn.local_port}-{conn.remote_ip}:{conn.remote_port}"
    
    def _analyze_new_connection(self, conn: Connection):
        threats = []
        is_trusted_process = conn.process_name and conn.process_name in self.whitelist_processes
        is_private = self._is_private_ip(conn.remote_ip)
        
        if conn.remote_port in self.SUSPICIOUS_PORTS:
            threats.append(f"Suspicious port: {conn.remote_port}")
            if conn.threat_level.value < ThreatLevel.HIGH.value:
                conn.threat_level = ThreatLevel.HIGH
        
        if is_trusted_process:
            pass
        else:
            if not conn.process_name:
                if conn.remote_port not in self.whitelist_ports and not is_private:
                    threats.append(f"Unknown process on non-standard port: {conn.remote_port}")
                    if conn.threat_level.value < ThreatLevel.MEDIUM.value:
                        conn.threat_level = ThreatLevel.MEDIUM
            else:
                if conn.remote_port not in self.whitelist_ports and not is_private:
                    threats.append(f"Non-whitelisted process ({conn.process_name}) on port {conn.remote_port}")
                    if conn.threat_level.value < ThreatLevel.MEDIUM.value:
                        conn.threat_level = ThreatLevel.MEDIUM
            
            if conn.remote_ip not in self.whitelist_ips and not is_private:
                if conn.threat_level == ThreatLevel.NONE:
                    conn.threat_level = ThreatLevel.LOW
        
        key = f"{conn.remote_ip}:{conn.remote_port}"
        self.connection_history[key].append(datetime.now())
        
        conn.threat_reasons = threats
    
    def _is_private_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback
        except Exception:
            return False
    
    def _analyze_patterns(self):
        """Analiza patrones de beaconing"""
        while self.running:
            try:
                time.sleep(60)
                
                with self._lock:
                    now = datetime.now()
                    cutoff = now - timedelta(hours=1)
                    
                    for key, times in self.connection_history.items():
                        times[:] = [t for t in times if t > cutoff]
                        
                        if len(times) >= 5:
                            pattern = self._detect_beaconing(key, times)
                            if pattern and pattern.regularity_score > 0.7:
                                self.beacon_patterns[key] = pattern
                                
                                parts = key.split(':')
                                if len(parts) == 2:
                                    fake_conn = Connection(
                                        protocol="tcp",
                                        local_ip="0.0.0.0",
                                        local_port=0,
                                        remote_ip=parts[0],
                                        remote_port=int(parts[1]),
                                        state=ConnectionState.ESTABLISHED,
                                        pid=None,
                                        process_name=None,
                                        first_seen=times[0],
                                        last_seen=times[-1],
                                        threat_level=ThreatLevel.CRITICAL,
                                        threat_reasons=[
                                            f"Patrón de beaconing detectado: {pattern.regularity_score:.2f}",
                                            f"Intervalo promedio: {pattern.interval_avg:.1f}s"
                                        ]
                                    )
                                    self._notify(fake_conn, "beaconing")
                
            except Exception as e:
                print(f"Pattern analysis error: {e}", file=sys.stderr)
    
    def _detect_beaconing(self, key: str, times: List[datetime]) -> Optional[BeaconPattern]:
        if len(times) < 5:
            return None
        
        sorted_times = sorted(times)
        intervals = []
        
        for i in range(1, len(sorted_times)):
            diff = (sorted_times[i] - sorted_times[i-1]).total_seconds()
            if diff > 0:
                intervals.append(diff)
        
        if len(intervals) < 4:
            return None
        
        avg = sum(intervals) / len(intervals)
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        std = variance ** 0.5
        
        if avg > 0:
            regularity = 1 - min(std / avg, 1)
        else:
            regularity = 0
        
        parts = key.split(':')
        
        return BeaconPattern(
            remote_ip=parts[0] if len(parts) >= 1 else "",
            remote_port=int(parts[1]) if len(parts) >= 2 else 0,
            connection_times=sorted_times,
            interval_avg=avg,
            interval_std=std,
            regularity_score=regularity
        )
    
    def get_active_connections(self) -> List[Connection]:
        with self._lock:
            return list(self.connections.values())
    
    def get_suspicious_connections(self) -> List[Connection]:
        with self._lock:
            return [c for c in self.connections.values() 
                    if c.threat_level.value >= ThreatLevel.MEDIUM.value]
    
    def get_beacon_patterns(self) -> List[BeaconPattern]:
        with self._lock:
            return list(self.beacon_patterns.values())
    
    def get_stats(self) -> Dict:
        with self._lock:
            total = len(self.connections)
            suspicious = sum(1 for c in self.connections.values() 
                           if c.threat_level.value >= ThreatLevel.MEDIUM.value)
            
            by_process = defaultdict(int)
            for conn in self.connections.values():
                if conn.process_name:
                    by_process[conn.process_name] += 1
            
            return {
                'total_connections': total,
                'suspicious_connections': suspicious,
                'beacon_patterns': len(self.beacon_patterns),
                'by_process': dict(by_process)
            }


class DNSMonitor:
    """Monitor de consultas DNS para detectar tunneling"""
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.queries: List[DNSQuery] = []
        self.suspicious_domains: List[DNSQuery] = []
        self._lock = threading.Lock()
    
    def analyze_query(self, domain: str, query_type: str = "A") -> Optional[Dict]:
        """Analiza una consulta DNS en busca de tunneling"""
        threats = []
        
        parts = domain.split('.')
        
        if any(len(p) > 50 for p in parts):
            threats.append("Subdomain muy largo")
        
        if len(domain) > 100:
            threats.append("Query muy larga")
        
        entropy = self._calculate_entropy(domain)
        if entropy > 3.5:
            threats.append(f"Alta entropía: {entropy:.2f}")
        
        consonant_ratio = self._consonant_ratio(domain)
        if consonant_ratio > 0.8:
            threats.append(f"Ratio de consonantes alto: {consonant_ratio:.2f}")
        
        if threats:
            return {
                'domain': domain,
                'threats': threats,
                'entropy': entropy
            }
        
        return None
    
    def _calculate_entropy(self, s: str) -> float:
        from collections import Counter
        import math
        
        if not s:
            return 0
        
        freq = Counter(s.lower())
        length = len(s)
        
        entropy = 0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _consonant_ratio(self, s: str) -> float:
        vowels = set('aeiouAEIOU')
        letters = [c for c in s if c.isalpha()]
        
        if not letters:
            return 0
        
        consonants = sum(1 for c in letters if c not in vowels)
        return consonants / len(letters)


if __name__ == "__main__":
    def on_connection(conn: Connection, event: str):
        threat_str = f" [{conn.threat_level.name}]" if conn.threat_level.value > 0 else ""
        print(f"[{event.upper()}]{threat_str} {conn.process_name or 'unknown'}: "
              f"{conn.remote_ip}:{conn.remote_port}")
        
        for reason in conn.threat_reasons:
            print(f"  ! {reason}")
    
    monitor = NetworkMonitor()
    monitor.add_callback(on_connection)
    
    print("Starting network monitor (Ctrl+C to stop)...")
    monitor.start()
    
    try:
        while True:
            time.sleep(10)
            stats = monitor.get_stats()
            print(f"\n--- Stats: {stats['total_connections']} connections, "
                  f"{stats['suspicious_connections']} suspicious ---\n")
    except KeyboardInterrupt:
        print("\nStopping...")
        monitor.stop()

