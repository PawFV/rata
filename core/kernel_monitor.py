#!/usr/bin/env python3
"""
RATA - Kernel Monitor
Interface with eBPF and auditd for kernel-level monitoring.
This layer is the hardest to evade from userspace malware.
"""

import os
import sys
import subprocess
import threading
import queue
import re
import time
import json
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Callable, Dict, List
from enum import Enum


class EventType(Enum):
    EXEC = "exec"
    NETWORK_CONNECT = "network_connect"
    NETWORK_ACCEPT = "network_accept"
    NETWORK_BIND = "network_bind"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    MODULE_LOAD = "module_load"
    PTRACE = "ptrace"
    PRIVILEGE_CHANGE = "privilege_change"


@dataclass
class KernelEvent:
    timestamp: datetime
    event_type: EventType
    pid: int
    ppid: int
    uid: int
    comm: str
    exe: str
    args: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    path: Optional[str] = None
    raw: Optional[str] = None


class AuditdParser:
    
    SYSCALL_PATTERN = re.compile(
        r'type=SYSCALL.*?'
        r'syscall=(\d+).*?'
        r'pid=(\d+).*?'
        r'ppid=(\d+).*?'
        r'uid=(\d+).*?'
        r'comm="([^"]*)".*?'
        r'exe="([^"]*)"'
    )
    
    EXECVE_PATTERN = re.compile(
        r'type=EXECVE.*?'
        r'a0="([^"]*)"'
    )
    
    SOCKADDR_PATTERN = re.compile(
        r'type=SOCKADDR.*?'
        r'saddr=([0-9A-Fa-f]+)'
    )
    
    PATH_PATTERN = re.compile(
        r'type=PATH.*?'
        r'name="([^"]*)"'
    )
    
    SYSCALL_MAP = {
        59: "execve",
        41: "socket",
        42: "connect",
        43: "accept",
        49: "bind",
        101: "ptrace",
        175: "init_module",
        313: "finit_module",
    }
    
    def parse_line(self, line: str) -> Optional[KernelEvent]:
        try:
            syscall_match = self.SYSCALL_PATTERN.search(line)
            if not syscall_match:
                return None
            
            syscall_num = int(syscall_match.group(1))
            pid = int(syscall_match.group(2))
            ppid = int(syscall_match.group(3))
            uid = int(syscall_match.group(4))
            comm = syscall_match.group(5)
            exe = syscall_match.group(6)
            
            event_type = self._syscall_to_event_type(syscall_num)
            if not event_type:
                return None
            
            event = KernelEvent(
                timestamp=datetime.now(),
                event_type=event_type,
                pid=pid,
                ppid=ppid,
                uid=uid,
                comm=comm,
                exe=exe,
                raw=line
            )
            
            if syscall_num == 59:
                execve_match = self.EXECVE_PATTERN.search(line)
                if execve_match:
                    event.args = execve_match.group(1)
            
            if syscall_num in (42, 43, 49):
                sockaddr_match = self.SOCKADDR_PATTERN.search(line)
                if sockaddr_match:
                    addr_info = self._parse_sockaddr(sockaddr_match.group(1))
                    if addr_info:
                        event.dst_ip = addr_info.get('ip')
                        event.dst_port = addr_info.get('port')
            
            path_match = self.PATH_PATTERN.search(line)
            if path_match:
                event.path = path_match.group(1)
            
            return event
            
        except Exception:
            return None
    
    def _syscall_to_event_type(self, syscall_num: int) -> Optional[EventType]:
        mapping = {
            59: EventType.EXEC,
            42: EventType.NETWORK_CONNECT,
            43: EventType.NETWORK_ACCEPT,
            49: EventType.NETWORK_BIND,
            101: EventType.PTRACE,
            175: EventType.MODULE_LOAD,
            313: EventType.MODULE_LOAD,
        }
        return mapping.get(syscall_num)
    
    def _parse_sockaddr(self, hex_addr: str) -> Optional[Dict]:
        try:
            if len(hex_addr) < 8:
                return None
            
            family = int(hex_addr[2:4] + hex_addr[0:2], 16)
            
            if family == 2 and len(hex_addr) >= 16:
                port = int(hex_addr[4:8], 16)
                ip_hex = hex_addr[8:16]
                ip = '.'.join(str(int(ip_hex[i:i+2], 16)) for i in range(0, 8, 2))
                return {'ip': ip, 'port': port}
            
            return None
        except Exception:
            return None


class EBPFMonitor:
    """Monitor usando eBPF via bpftrace"""
    
    CONNECT_TRACE = """
    tracepoint:syscalls:sys_enter_connect
    {
        $sk = (struct sockaddr_in *)args->uservaddr;
        if ($sk->sin_family == AF_INET) {
            printf("connect pid=%d comm=%s ip=%s port=%d\\n",
                pid, comm,
                ntop($sk->sin_addr.s_addr),
                ($sk->sin_port >> 8) | (($sk->sin_port & 0xff) << 8));
        }
    }
    """
    
    EXEC_TRACE = """
    tracepoint:syscalls:sys_enter_execve
    {
        printf("exec pid=%d ppid=%d uid=%d comm=%s\\n",
            pid, (curtask->parent->pid), uid, comm);
    }
    """
    
    def __init__(self):
        self.process = None
        self.running = False
    
    def check_available(self) -> bool:
        try:
            result = subprocess.run(
                ['bpftrace', '--version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def start(self, callback: Callable[[str], None]) -> bool:
        if not self.check_available():
            return False
        
        self.running = True
        
        trace_script = """
        tracepoint:syscalls:sys_enter_connect
        {
            printf("EBPF_CONNECT|%d|%s|%d\\n", pid, comm, uid);
        }
        
        tracepoint:syscalls:sys_enter_execve
        {
            printf("EBPF_EXEC|%d|%s|%d\\n", pid, comm, uid);
        }
        """
        
        try:
            self.process = subprocess.Popen(
                ['bpftrace', '-e', trace_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            def reader():
                while self.running and self.process:
                    line = self.process.stdout.readline()
                    if line:
                        callback(line.strip())
                    else:
                        break
            
            thread = threading.Thread(target=reader, daemon=True)
            thread.start()
            
            return True
            
        except Exception:
            return False
    
    def stop(self):
        self.running = False
        if self.process:
            self.process.terminate()
            self.process = None


class KernelMonitor:
    """
    Monitor principal a nivel kernel.
    Combina auditd y eBPF para máxima cobertura.
    """
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.event_queue = queue.Queue()
        self.callbacks: List[Callable[[KernelEvent], None]] = []
        self.running = False
        self.auditd_parser = AuditdParser()
        self.ebpf_monitor = EBPFMonitor()
        self._threads: List[threading.Thread] = []
    
    def add_callback(self, callback: Callable[[KernelEvent], None]):
        self.callbacks.append(callback)
    
    def _notify_callbacks(self, event: KernelEvent):
        for callback in self.callbacks:
            try:
                callback(event)
            except Exception as e:
                print(f"Error in callback: {e}", file=sys.stderr)
    
    def _process_events(self):
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
                self._notify_callbacks(event)
            except queue.Empty:
                continue
    
    def _read_auditd_pipe(self):
        """Lee eventos de audit.log o ausearch"""
        audit_log = Path("/var/log/audit/audit.log")
        
        if audit_log.exists():
            try:
                process = subprocess.Popen(
                    ['tail', '-F', str(audit_log)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                while self.running:
                    line = process.stdout.readline()
                    if line:
                        event = self.auditd_parser.parse_line(line)
                        if event:
                            self.event_queue.put(event)
                
                process.terminate()
                
            except Exception as e:
                print(f"Error reading auditd: {e}", file=sys.stderr)
        else:
            try:
                process = subprocess.Popen(
                    ['journalctl', '-f', '-u', 'auditd', '-o', 'cat'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                while self.running:
                    line = process.stdout.readline()
                    if line:
                        event = self.auditd_parser.parse_line(line)
                        if event:
                            self.event_queue.put(event)
                
                process.terminate()
                
            except Exception as e:
                print(f"Error reading journalctl: {e}", file=sys.stderr)
    
    def _ebpf_callback(self, line: str):
        try:
            parts = line.split('|')
            if len(parts) >= 4:
                event_type_str = parts[0]
                pid = int(parts[1])
                comm = parts[2]
                uid = int(parts[3])
                
                if event_type_str == "EBPF_CONNECT":
                    event_type = EventType.NETWORK_CONNECT
                elif event_type_str == "EBPF_EXEC":
                    event_type = EventType.EXEC
                else:
                    return
                
                event = KernelEvent(
                    timestamp=datetime.now(),
                    event_type=event_type,
                    pid=pid,
                    ppid=0,
                    uid=uid,
                    comm=comm,
                    exe="",
                    raw=line
                )
                
                self.event_queue.put(event)
                
        except Exception:
            pass
    
    def start(self) -> bool:
        if self.running:
            return True
        
        self.running = True
        
        event_processor = threading.Thread(
            target=self._process_events,
            daemon=True,
            name="KernelMonitor-EventProcessor"
        )
        event_processor.start()
        self._threads.append(event_processor)
        
        if os.geteuid() == 0:
            auditd_thread = threading.Thread(
                target=self._read_auditd_pipe,
                daemon=True,
                name="KernelMonitor-Auditd"
            )
            auditd_thread.start()
            self._threads.append(auditd_thread)
            
            if self.config.get('use_ebpf', True):
                self.ebpf_monitor.start(self._ebpf_callback)
        else:
            print("Warning: Not running as root, kernel monitoring limited", 
                  file=sys.stderr)
        
        return True
    
    def stop(self):
        self.running = False
        self.ebpf_monitor.stop()
        
        for thread in self._threads:
            thread.join(timeout=2)
        
        self._threads.clear()
    
    def get_current_connections(self) -> List[Dict]:
        """Obtiene conexiones actuales usando /proc"""
        connections = []
        
        for proto in ['tcp', 'tcp6', 'udp', 'udp6']:
            proc_path = Path(f"/proc/net/{proto}")
            if not proc_path.exists():
                continue
            
            try:
                with open(proc_path) as f:
                    lines = f.readlines()[1:]
                
                for line in lines:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = parts[3]
                    inode = parts[9]
                    
                    local_ip, local_port = self._parse_proc_addr(local_addr)
                    remote_ip, remote_port = self._parse_proc_addr(remote_addr)
                    
                    if remote_ip != "0.0.0.0" and remote_ip != "::":
                        pid = self._find_pid_by_inode(inode)
                        
                        connections.append({
                            'protocol': proto,
                            'local_ip': local_ip,
                            'local_port': local_port,
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'state': state,
                            'pid': pid,
                            'comm': self._get_comm(pid) if pid else None
                        })
                        
            except Exception:
                continue
        
        return connections
    
    def _parse_proc_addr(self, addr: str) -> tuple:
        try:
            ip_hex, port_hex = addr.split(':')
            port = int(port_hex, 16)
            
            if len(ip_hex) == 8:
                ip_int = int(ip_hex, 16)
                ip = '.'.join(str((ip_int >> (8 * i)) & 0xff) for i in range(4))
            else:
                ip = "IPv6"
            
            return ip, port
        except Exception:
            return "0.0.0.0", 0
    
    def _find_pid_by_inode(self, inode: str) -> Optional[int]:
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
                                return int(pid_dir.name)
                        except (OSError, PermissionError):
                            continue
                except PermissionError:
                    continue
                    
        except Exception:
            pass
        
        return None
    
    def _get_comm(self, pid: int) -> Optional[str]:
        try:
            with open(f"/proc/{pid}/comm") as f:
                return f.read().strip()
        except Exception:
            return None
    
    def get_loaded_modules(self) -> List[Dict]:
        """Obtiene módulos del kernel cargados"""
        modules = []
        
        try:
            with open("/proc/modules") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        modules.append({
                            'name': parts[0],
                            'size': int(parts[1]),
                            'used_by': parts[3] if len(parts) > 3 else ""
                        })
        except Exception:
            pass
        
        return modules


if __name__ == "__main__":
    def print_event(event: KernelEvent):
        print(f"[{event.timestamp}] {event.event_type.value}: "
              f"pid={event.pid} comm={event.comm}")
        if event.dst_ip:
            print(f"  -> {event.dst_ip}:{event.dst_port}")
    
    monitor = KernelMonitor()
    monitor.add_callback(print_event)
    
    print("Starting kernel monitor (Ctrl+C to stop)...")
    monitor.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        monitor.stop()

