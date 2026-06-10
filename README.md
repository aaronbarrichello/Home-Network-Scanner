# NetScanner — Home Network Device Scanner

Maps your home network, identifies devices by manufacturer (MAC OUI lookup),
flags unknown devices, and displays everything in a real-time dashboard.

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run (root required for ARP scanning)
```bash
sudo python app.py
```

Then open **http://localhost:5000** in your browser.

> **Why sudo?** ARP packet crafting with Scapy requires raw socket access,
> which needs root/admin privileges. Without root it falls back to a ping
> sweep + ARP cache read (less accurate but still works).

---

## Features

| Feature | Detail |
|---|---|
| **ARP Scan** | Crafts raw ARP packets via Scapy for reliable host discovery |
| **MAC OUI Lookup** | Bundled 150+ vendor table — no internet needed |
| **Port Scan** | Quick TCP connect scan on 9 common ports (SSH, HTTP, MQTT, RTSP…) |
| **Device Typing** | Classifies: router, computer, smartphone, IoT, server, camera, etc. |
| **Unknown Flagging** | Any device not in your trusted list is highlighted in red |
| **Trust Management** | Mark/unmark devices as trusted — persists to `known_devices.json` |
| **History Chart** | Sparkline of device counts across scans |
| **CSV Export** | Download full device table |
| **Reverse DNS** | Hostname lookup for each IP |

## Architecture

```
app.py              Flask app + scan engine
  ├── arp_scan()    Scapy ARP sweep (falls back to ping)
  ├── lookup_vendor() OUI table lookup
  ├── get_open_ports() TCP port scan
  └── guess_device_type() Heuristic classifier

templates/
  └── index.html    Full dashboard (pure HTML/CSS/JS, no npm)

known_devices.json  Persisted trusted MAC addresses
```

## Scan Flow

1. Detect default gateway + network CIDR from `/proc/net/route`
2. ARP sweep the entire subnet (e.g. 192.168.1.0/24)
3. For each responding host:
   - Reverse DNS hostname lookup
   - MAC OUI → vendor name
   - TCP port scan (22, 80, 443, 554, 1883, …)
   - Device type heuristic
   - Flag if not in trusted list
4. Results rendered in real-time dashboard

## Network Requirements

The scanner must run **on the same network** as the devices you want to
discover. It cannot see devices on other subnets or VLANs.
