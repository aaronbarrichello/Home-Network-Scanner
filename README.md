# 🛰 NetScanner — Home Network Device Scanner

A lightweight network scanner that maps every device on your local network, identifies them by manufacturer using MAC OUI lookup, flags unknown devices, and presents everything in a real-time web dashboard.

> Built with Python + Scapy + Flask. No cloud. No dependencies on external APIs. Runs entirely on your machine.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.3+-black?style=flat-square&logo=flask)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)

---

## ✨ Features

- **ARP Scanning** — Crafts raw ARP packets via Scapy for fast, reliable host discovery
- **MAC OUI Lookup** — Identifies device manufacturer from the first 3 bytes of the MAC address using a bundled vendor table (no internet required)
- **Auto Network Detection** — Automatically detects your active WiFi/LAN subnet on startup
- **Port Scanning** — Quick TCP connect scan on 9 common ports (SSH, HTTP, HTTPS, RTSP, MQTT, etc.)
- **Device Classification** — Heuristically classifies devices: router, computer, smartphone, IoT, server, IP camera, single-board computer
- **Unknown Device Flagging** — Any device not in your trusted list is highlighted and flagged
- **Trust Management** — Mark devices as trusted or untrusted; persists across sessions
- **Scan History** — Sparkline chart tracking device count across scans
- **CSV Export** — Download the full device table
- **Windows + Linux + macOS** — Works cross-platform

---

## 📸 Dashboard Preview

```
┌─────────────────────────────────────────────────────────────┐
│  🛰 NetScanner          [Target: 192.168.1.0/24 ⟳]  [Scan] │
├──────────┬──────────┬──────────┬──────────────────────────  │
│ Devices  │ Unknown  │ Open     │ Status                      │
│    12    │    2     │   8      │ ✓ Done                      │
├─────────────────────────────────────────────────────────────┤
│ 🌐 router.local     192.168.1.1    TP-Link      GW          │
│ 💻 DESKTOP-ABC      192.168.1.5    Intel                     │
│ 📱 iPhone-Aaron     192.168.1.8    Apple                     │
│ ⚠️  Unknown Device   192.168.1.11   Samsung   ← FLAGGED      │
│ 🔌 esp32-sensor     192.168.1.14   Espressif    IoT          │
└─────────────────────────────────────────────────────────────┘
```

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

## 📁 Project Structure

```
netscanner/
├── app.py                  # Flask app + scan engine
├── requirements.txt        # Python dependencies
├── known_devices.json      # Persisted trusted MAC addresses (auto-created)
└── templates/
    └── index.html          # Dashboard UI (single file, no npm needed)
```

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

This is especially useful for **fixed networks** (office, home lab, school network) where you know exactly which devices should be present.

---

## 🌐 Platform Support

| Platform | ARP Scan | Ping Fallback | Auto-detect Subnet |
|----------|----------|---------------|--------------------|
| Windows  | ✅ (as Administrator) | ✅ | ✅ via `ipconfig` |
| Linux    | ✅ (as root) | ✅ | ✅ via `ip addr` |
| macOS    | ✅ (as root) | ✅ | ✅ via `netstat` |

---

## 📦 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `flask` | ≥ 2.3 | Web server & dashboard |
| `scapy` | ≥ 2.5 | Raw packet crafting for ARP scan |

No frontend build tools required. The dashboard is a single self-contained HTML file with zero npm dependencies.

---

## 🆚 How Is This Different from nmap?

| Feature | NetScanner | nmap |
|---------|-----------|------|
| Interface | Web dashboard (browser) | CLI |
| Ease of use | Click and go | Requires knowing syntax |
| Trust/whitelist | ✅ Persistent | ❌ |
| Scan history chart | ✅ | ❌ |
| OS fingerprinting | ❌ Basic only | ✅ Very accurate |
| Script engine | ❌ | ✅ NSE (powerful) |
| Scan speed & depth | Basic | Advanced |
| Vulnerability detection | ❌ | ✅ via NSE scripts |

NetScanner is best described as **nmap with a GUI and device trust tracking** — designed for visibility on networks where you already know what *should* be there.

---

## 🗺 Roadmap

- [ ] Scheduled auto-scan (every N minutes, runs in background)
- [ ] Email / webhook alert when an unknown device is detected
- [ ] Full IEEE OUI database integration (35,000+ vendors)
- [ ] Per-device connection history timeline
- [ ] Network topology map (visual graph of who's connected)
- [ ] Docker support

---

## ⚠️ Legal Disclaimer

This tool is intended for use **on networks you own or have explicit permission to scan**.  
Unauthorized network scanning may violate local laws. Use responsibly.

---

## 📄 License

MIT License — free to use, modify, and distribute.
