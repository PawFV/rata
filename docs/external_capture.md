# External Traffic Capture Guide

Capturing traffic from an external device is the most reliable method - malware cannot evade monitoring it doesn't control.

## Option 1: Raspberry Pi as Network Tap

### Requirements
- Raspberry Pi 3/4/5
- Two Ethernet adapters (built-in + USB)
- Fresh Raspberry Pi OS Lite

### Setup

```bash
# On the Raspberry Pi

# Install tools
sudo apt update && sudo apt install -y tcpdump bridge-utils

# Create bridge between interfaces
sudo brctl addbr br0
sudo brctl addif br0 eth0
sudo brctl addif br0 eth1
sudo ifconfig br0 up

# Enable IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Start capture
sudo tcpdump -i br0 -w /home/pi/capture_%Y%m%d_%H%M%S.pcap -G 3600 -C 100
```

### Network Topology
```
[Your Kali] --> [RPi eth0] --bridge-- [RPi eth1] --> [Router/Internet]
                              |
                        tcpdump here
```

## Option 2: Dedicated Laptop with Two NICs

```bash
# Same bridge setup as RPi
# Or use as WiFi AP:

# Install hostapd
sudo apt install hostapd dnsmasq

# Configure as AP, all traffic goes through and is captured
```

## Option 3: Router with Port Mirroring

Many managed routers/switches support port mirroring (SPAN):

1. Access router admin interface
2. Find port mirroring settings
3. Mirror the port your Kali is connected to
4. Connect capture device to mirror destination port

### Routers with this feature:
- MikroTik (all models)
- Ubiquiti EdgeRouter
- pfSense/OPNsense
- OpenWrt (with switch chip support)

## Option 4: WiFi Monitor Mode (if using WiFi)

```bash
# On a separate device with monitor-capable WiFi

# Put interface in monitor mode
sudo airmon-ng start wlan0

# Capture all traffic on your channel
sudo airodump-ng wlan0mon -c 6 --bssid YOUR_AP_MAC -w capture
```

## Analyzing Captured Traffic

### Quick Analysis with tshark

```bash
# List all external connections
tshark -r capture.pcap -Y "ip.dst != 10.0.0.0/8 and ip.dst != 172.16.0.0/12 and ip.dst != 192.168.0.0/16"

# Find beaconing (regular intervals)
tshark -r capture.pcap -q -z io,stat,60,"COUNT(frame) frame"

# DNS queries
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# HTTP hosts
tshark -r capture.pcap -Y "http.host" -T fields -e http.host | sort | uniq -c | sort -rn

# TLS SNI (HTTPS destinations)
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name | sort | uniq -c | sort -rn
```

### With Suricata

```bash
# Run Suricata on captured file
suricata -r capture.pcap -l /tmp/suricata-output/

# Check alerts
cat /tmp/suricata-output/fast.log
```

### With Zeek

```bash
# Analyze with Zeek
zeek -r capture.pcap

# Check connection log
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | sort | uniq -c | sort -rn
```

## Signs of RAT/C2 Traffic

1. **Regular beaconing**: Connections at fixed intervals (e.g., every 60s)
2. **Unusual ports**: Connections to non-standard ports
3. **Encoded data**: High entropy in payloads
4. **Long DNS queries**: Possible DNS tunneling
5. **Connections during sleep/idle**: Activity when you're not using the system
6. **Geographic anomalies**: Connections to unexpected countries
7. **Self-signed certs**: TLS connections with invalid certificates

## Automated Analysis Script

```bash
#!/bin/bash
# analyze_capture.sh

PCAP=$1

echo "=== External Connections ==="
tshark -r "$PCAP" -Y "ip.dst != 10.0.0.0/8 and ip.dst != 172.16.0.0/12 and ip.dst != 192.168.0.0/16" \
    -T fields -e ip.dst -e tcp.dstport 2>/dev/null | sort | uniq -c | sort -rn | head -20

echo ""
echo "=== DNS Queries ==="
tshark -r "$PCAP" -Y "dns.qry.name" -T fields -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -rn | head -20

echo ""
echo "=== TLS Destinations ==="
tshark -r "$PCAP" -Y "tls.handshake.extensions_server_name" \
    -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort | uniq -c | sort -rn | head -20
```

