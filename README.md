# 🛰 NetScanner — Home Network Device Scanner
> Built with Python + Scapy + Flask. No cloud. No dependencies on external APIs. Runs entirely on your machine.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.3+-black?style=flat-square&logo=flask)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)

---

## ✨ Features

- **ARP Scanning** — Crafts raw ARP packets via Scapy for fast, reliable host discovery
- **MAC OUI Lookup** — Identifies device manufacturer from the first 3 bytes of the MAC address using a bundled vendor table (no internet required)
- **Auto Network Detection** — Automatically detects your active WiFi/LAN subnet on startup, so you can click & go
- **Port Scanning** — Quick TCP connect scan on 9 common ports (SSH, HTTP, HTTPS, RTSP, MQTT, etc.)
- **Device Classification** — Heuristically classifies devices: router, computer, smartphone, IoT, server, IP camera, single-board computer
- **Unknown Device Flagging** — Any device not in your trusted list is highlighted and flagged
- **Trust Management** — Mark devices as trusted or untrusted; persists across sessions
- **Scan History** — Sparkline chart tracking device count across scans
- **CSV Export** — Download the full device table
- **Windows + Linux + macOS** — Works cross-platform

---

## 📸 Dashboard Preview
<img width="1919" height="1060" alt="Screenshot 2026-06-10 130736" src="https://github.com/user-attachments/assets/cb8ca331-22a5-4dbb-8ef1-54d0d4dd8d1e" />


---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/netscanner.git
cd netscanner
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run

```bash
# Linux / macOS — root required for raw ARP sockets
sudo python app.py

# Windows — run Command Prompt as Administrator
python app.py
```

### 4. Open in browser

```
http://localhost:5000
```

The dashboard will automatically detect your active network subnet. Click **Scan** to begin.

---

---

## ⚙️ How It Works

### Scan Pipeline

```
1. Auto-detect active subnet (ipconfig / ip addr / socket)
        ↓
2. ARP sweep entire subnet with Scapy
   (falls back to ping sweep if no root/admin)
        ↓
3. For each responding host:
   ├── Reverse DNS hostname lookup
   ├── MAC OUI → manufacturer name
   ├── TCP port scan (9 common ports)
   ├── Device type classification
   └── Flag if not in trusted list
        ↓
4. Results rendered live in browser dashboard
```

### MAC OUI Lookup

Every network device has a MAC address like `EC:08:6B:AA:BB:CC`.  
The first 3 bytes (`EC:08:6B`) are the **OUI (Organizationally Unique Identifier)** — registered to a specific manufacturer (in this case, TP-Link).

NetScanner includes a bundled table of 150+ common vendors so no internet connection is needed for lookups. Devices not in the table show as `Unknown Vendor`.

### Fallback Mode (No Root / No Admin)

If run without elevated privileges, Scapy cannot craft raw packets. NetScanner automatically falls back to:

1. ICMP ping sweep using the system `ping` command
2. Reading the OS ARP cache (`arp -a` on Windows, `arp -n` on Linux) to recover MAC addresses

Results are less reliable than full ARP mode but still useful for basic discovery.

---

## 🔒 Trust Management

On first scan, **all discovered devices are marked as unknown** (flagged in red).

- Click any device → **Mark as Trusted** to add it to your whitelist
- Trusted MACs are saved to `known_devices.json`
- Any new device appearing on future scans that is not whitelisted gets flagged automatically

This is especially useful for **fixed networks** (office, home lab, school network) where you know exactly which devices should be present. **You can also add your known/trusted mac addr manually on `app.py`**

---

---

---

## ⚠️ Legal Disclaimer

This tool is intended for use **on networks you own or have explicit permission to scan**.  
Unauthorized network scanning may violate local laws. Use responsibly.

---
