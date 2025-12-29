#!/usr/bin/env python3
"""
RATA - IP Resolver
Reverse DNS, whois caching, and IP identification.
"""

import socket
import subprocess
import threading
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict
from dataclasses import dataclass
import json


@dataclass
class IPInfo:
    ip: str
    hostname: Optional[str]
    org: Optional[str]
    country: Optional[str]
    is_cloud: bool
    cloud_provider: Optional[str]
    last_updated: datetime


class IPResolver:
    
    CLOUD_RANGES = {
        'AWS': ['52.', '54.', '18.', '3.', '100.'],
        'Google': ['142.250.', '142.251.', '172.217.', '216.58.', '34.'],
        'Cloudflare': ['104.16.', '104.17.', '104.18.', '104.19.'],
        'Microsoft': ['13.', '20.', '40.', '52.'],
        'NordVPN': ['10.5.', '10.246.'],
    }
    
    KNOWN_SERVICES = {
        'ec2-': 'AWS EC2',
        'compute-1': 'AWS EC2',
        'cloudfront': 'AWS CloudFront',
        'google': 'Google',
        'googleapis': 'Google APIs',
        '1e100.net': 'Google',
        'fbcdn': 'Facebook CDN',
        'akamai': 'Akamai CDN',
        'cloudflare': 'Cloudflare',
        'azure': 'Microsoft Azure',
        'github': 'GitHub',
        'githubusercontent': 'GitHub',
    }
    
    def __init__(self, cache_file: str = None):
        self.cache: Dict[str, IPInfo] = {}
        if cache_file:
            self.cache_file = Path(cache_file)
        else:
            # Use relative path from project root
            base_dir = Path(__file__).resolve().parent.parent
            self.cache_file = base_dir / "baseline" / "ip_cache.json"
            
        self.cache_ttl = timedelta(hours=24)
        self._lock = threading.Lock()
        self._load_cache()
    
    def _load_cache(self):
        if self.cache_file.exists():
            try:
                with open(self.cache_file) as f:
                    data = json.load(f)
                for ip, info in data.items():
                    self.cache[ip] = IPInfo(
                        ip=ip,
                        hostname=info.get('hostname'),
                        org=info.get('org'),
                        country=info.get('country'),
                        is_cloud=info.get('is_cloud', False),
                        cloud_provider=info.get('cloud_provider'),
                        last_updated=datetime.fromisoformat(info['last_updated'])
                    )
            except Exception:
                pass
    
    def _save_cache(self):
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            data = {}
            for ip, info in self.cache.items():
                data[ip] = {
                    'hostname': info.hostname,
                    'org': info.org,
                    'country': info.country,
                    'is_cloud': info.is_cloud,
                    'cloud_provider': info.cloud_provider,
                    'last_updated': info.last_updated.isoformat()
                }
            with open(self.cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass
    
    def resolve(self, ip: str) -> IPInfo:
        with self._lock:
            if ip in self.cache:
                cached = self.cache[ip]
                if datetime.now() - cached.last_updated < self.cache_ttl:
                    return cached
            
            info = self._do_resolve(ip)
            self.cache[ip] = info
            self._save_cache()
            return info
    
    def _do_resolve(self, ip: str) -> IPInfo:
        hostname = self._reverse_dns(ip)
        org, country = self._quick_whois(ip)
        cloud_provider = self._detect_cloud(ip, hostname)
        
        return IPInfo(
            ip=ip,
            hostname=hostname,
            org=org,
            country=country,
            is_cloud=cloud_provider is not None,
            cloud_provider=cloud_provider,
            last_updated=datetime.now()
        )
    
    def _reverse_dns(self, ip: str) -> Optional[str]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def _quick_whois(self, ip: str) -> tuple:
        try:
            result = subprocess.run(
                ['whois', ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            org = None
            country = None
            
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                if 'orgname:' in line_lower or 'org-name:' in line_lower:
                    org = line.split(':', 1)[1].strip()
                elif 'country:' in line_lower:
                    country = line.split(':', 1)[1].strip()
                    
            return org, country
        except Exception:
            return None, None
    
    def _detect_cloud(self, ip: str, hostname: Optional[str]) -> Optional[str]:
        for provider, prefixes in self.CLOUD_RANGES.items():
            for prefix in prefixes:
                if ip.startswith(prefix):
                    return provider
        
        if hostname:
            hostname_lower = hostname.lower()
            for pattern, service in self.KNOWN_SERVICES.items():
                if pattern in hostname_lower:
                    return service
        
        return None
    
    def get_display_name(self, ip: str) -> str:
        info = self.resolve(ip)
        
        if info.cloud_provider:
            if info.hostname:
                short_host = info.hostname.split('.')[0][:20]
                return f"{info.cloud_provider}/{short_host}"
            return info.cloud_provider
        
        if info.hostname:
            parts = info.hostname.split('.')
            if len(parts) > 2:
                return '.'.join(parts[-3:])[:25]
            return info.hostname[:25]
        
        if info.org:
            return info.org[:20]
        
        return ip
    
    def get_full_info(self, ip: str) -> str:
        info = self.resolve(ip)
        lines = [f"IP: {ip}"]
        
        if info.hostname:
            lines.append(f"Host: {info.hostname}")
        if info.org:
            lines.append(f"Org: {info.org}")
        if info.country:
            lines.append(f"Country: {info.country}")
        if info.cloud_provider:
            lines.append(f"Cloud: {info.cloud_provider}")
        
        return " | ".join(lines)


_resolver = None

def get_resolver() -> IPResolver:
    global _resolver
    if _resolver is None:
        _resolver = IPResolver()
    return _resolver


def resolve_ip(ip: str) -> str:
    return get_resolver().get_display_name(ip)


def get_ip_info(ip: str) -> IPInfo:
    return get_resolver().resolve(ip)


if __name__ == "__main__":
    import sys
    
    resolver = IPResolver()
    
    test_ips = sys.argv[1:] if len(sys.argv) > 1 else [
        "52.207.108.103",
        "142.250.185.214",
        "34.36.137.203",
        "104.16.208.203"
    ]
    
    for ip in test_ips:
        print(f"\n{ip}:")
        info = resolver.resolve(ip)
        print(f"  Hostname: {info.hostname}")
        print(f"  Org: {info.org}")
        print(f"  Country: {info.country}")
        print(f"  Cloud: {info.cloud_provider}")
        print(f"  Display: {resolver.get_display_name(ip)}")

