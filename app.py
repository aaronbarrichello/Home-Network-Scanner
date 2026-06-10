#!/usr/bin/env python3
"""
NetScanner - Home Network Device Scanner
Uses Scapy for ARP scanning + MAC OUI lookup for manufacturer identification
"""

import os
import json
import time
import socket
import struct
import threading
import subprocess
import ipaddress
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from collections import defaultdict

app = Flask(__name__)

# ─── In-memory store ────────────────────────────────────────────────────────
scan_state = {
    "running": False,
    "progress": 0,
    "last_scan": None,
    "devices": [],
    "history": [],       # list of {timestamp, count}
    "scan_log": [],
}

# Known-safe devices the user has acknowledged (stored by MAC)
KNOWN_DEVICES_FILE = "known_devices.json"

def load_known_devices():
    if os.path.exists(KNOWN_DEVICES_FILE):
        with open(KNOWN_DEVICES_FILE) as f:
            return set(json.load(f))
    return set()

def save_known_devices(macs):
    with open(KNOWN_DEVICES_FILE, "w") as f:
        json.dump(list(macs), f)

known_devices = load_known_devices()

# ─── OUI / MAC Vendor Database ───────────────────────────────────────────────
# Bundled mini-OUI table (top vendors) — no network required
OUI_TABLE = {
    "00:00:0C": "Cisco Systems",
    "00:00:5E": "IANA (Cisco VRRP)",
    "00:0C:29": "VMware",
    "00:1A:2B": "Cisco-Linksys",
    "00:1B:63": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:7E": "Cisco-Linksys",
    "00:1E:58": "D-Link",
    "00:1F:33": "Apple",
    "00:21:27": "Apple",
    "00:23:12": "Apple",
    "00:23:6C": "Apple",
    "00:25:00": "Apple",
    "00:26:B9": "Dell",
    "00:50:56": "VMware",
    "00:90:27": "Intel",
    "00:A0:C9": "Intel",
    "00:E0:4C": "Realtek",
    "08:00:27": "VirtualBox",
    "10:02:B5": "Intel",
    "18:03:73": "Apple",
    "18:65:90": "Apple",
    "1C:1B:0D": "Apple",
    "20:47:47": "Google",
    "24:F6:77": "Amazon",
    "28:CF:DA": "Apple",
    "2C:F0:A2": "Samsung",
    "30:10:B3": "Apple",
    "30:F7:C5": "Apple",
    "34:36:3B": "Apple",
    "38:C9:86": "Apple",
    "3C:22:FB": "Apple",
    "3C:D0:F8": "Intel",
    "40:4D:7F": "Apple",
    "44:65:0D": "Apple",
    "48:A9:1C": "TP-Link",
    "4C:32:75": "Intel",
    "50:7B:9D": "Apple",
    "54:26:96": "Apple",
    "54:72:4F": "Google",
    "5C:AD:CF": "Huawei",
    "60:03:08": "Apple",
    "60:F4:45": "Apple",
    "64:76:BA": "Apple",
    "64:9A:BE": "Apple",
    "68:5B:35": "Apple",
    "6C:40:08": "Apple",
    "70:3E:AC": "Apple",
    "74:DA:38": "Edimax",
    "7C:11:BE": "Samsung",
    "80:00:6E": "Intel",
    "80:1F:02": "D-Link",
    "84:10:0D": "Samsung",
    "84:38:35": "Intel",
    "84:8E:0C": "Apple",
    "88:53:2E": "Apple",
    "88:66:A5": "Apple",
    "8C:85:90": "Apple",
    "90:8D:6C": "Apple",
    "90:B2:1F": "HP",
    "98:01:A7": "Apple",
    "98:5A:EB": "Apple",
    "9C:8E:99": "Apple",
    "A4:5E:60": "Apple",
    "A4:83:E7": "Apple",
    "A8:20:66": "Apple",
    "A8:66:7F": "Apple",
    "AC:22:0B": "Apple",
    "AC:37:43": "HTC",
    "AC:BC:32": "Apple",
    "B0:34:95": "Apple",
    "B0:70:2D": "Apple",
    "B4:8B:19": "Samsung",
    "B8:27:EB": "Raspberry Pi",
    "B8:8D:12": "Apple",
    "BC:92:6B": "Apple",
    "C0:CE:CD": "Apple",
    "C4:2C:03": "Apple",
    "C8:2A:14": "Apple",
    "C8:6C:87": "Apple",
    "C8:BC:C8": "Samsung",
    "CC:08:8D": "Apple",
    "CC:44:63": "Apple",
    "D0:03:4B": "Apple",
    "D0:23:DB": "Apple",
    "D4:61:9D": "Apple",
    "D4:90:9C": "Apple",
    "D8:1D:72": "Apple",
    "D8:96:95": "Apple",
    "DC:2B:2A": "Apple",
    "DC:86:D8": "Apple",
    "E0:AC:CB": "Apple",
    "E4:8B:7F": "Apple",
    "E8:80:2E": "Apple",
    "EC:35:86": "Apple",
    "F0:18:98": "Apple",
    "F0:9F:C2": "Ubiquiti",
    "F4:0F:24": "Apple",
    "F4:5C:89": "Apple",
    "F8:1E:DF": "Apple",
    "F8:27:93": "Apple",
    "FC:25:3F": "Apple",
    "FC:FC:48": "Apple",
    # Networking gear
    "00:18:F8": "D-Link",
    "14:91:82": "TP-Link",
    "50:C7:BF": "TP-Link",
    "8C:8D:28": "TP-Link",
    "B0:BE:76": "TP-Link",
    "C4:E9:84": "TP-Link",
    "EC:08:6B": "TP-Link",
    "F8:D1:11": "TP-Link",
    "00:26:F2": "Netgear",
    "20:E5:2A": "Netgear",
    "28:C6:8E": "Netgear",
    "30:46:9A": "Netgear",
    "44:94:FC": "Netgear",
    "A0:40:A0": "Netgear",
    "E0:46:9A": "Netgear",
    "00:1A:70": "Cisco",
    "00:1B:D4": "Cisco",
    "00:17:94": "Cisco",
    "2C:3E:CF": "Huawei",
    "48:AD:08": "Huawei",
    "54:89:98": "Huawei",
    "70:72:CF": "Huawei",
    "AC:E2:15": "Huawei",
    # IoT / Smart home
    "18:B4:30": "Nest",
    "64:16:66": "Nest",
    "D8:31:CF": "Chromecast (Google)",
    "F4:F5:D8": "Google Home",
    "6C:AD:F8": "Amazon Echo",
    "40:B4:CD": "Amazon Echo",
    "FC:A1:83": "Amazon Fire TV",
    "00:17:88": "Philips Hue",
    "EC:B5:FA": "Philips Hue",
}

def lookup_vendor(mac: str) -> str:
    """Return vendor name from MAC OUI prefix."""
    if not mac:
        return "Unknown"
    mac_upper = mac.upper().replace("-", ":")
    oui = mac_upper[:8]
    return OUI_TABLE.get(oui, "Unknown Vendor")

# ─── Network Utilities ───────────────────────────────────────────────────────

def get_default_gateway_and_iface():
    """Detect default gateway — works on Windows, Linux, and macOS."""
    import platform
    gw = None

    # ── Windows ──────────────────────────────────────────────────────────
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw = parts[2]
                    return gw, None
        except Exception:
            pass

    # ── Linux: /proc/net/route ────────────────────────────────────────────
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if parts[1] == "00000000":
                    iface = parts[0]
                    gw = socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
                    return gw, iface
    except Exception:
        pass

    # ── macOS / fallback: netstat ─────────────────────────────────────────
    try:
        result = subprocess.run(
            ["netstat", "-rn"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts and parts[0] in ("0.0.0.0", "default"):
                gw = parts[1]
                iface = parts[-1] if len(parts) > 5 else None
                return gw, iface
    except Exception:
        pass

    return None, None


def get_local_ip_and_subnet(iface):
    """
    Get local IP + CIDR for the active network adapter.
    Works on Windows, Linux, macOS.
    """
    import platform

    # ── Windows: use socket to find local IP, then ipconfig for mask ─────
    if platform.system() == "Windows":
        try:
            # Connect to a public IP to discover which local IP is used
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # Parse ipconfig for the subnet mask of this IP
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.splitlines()
            for i, line in enumerate(lines):
                if local_ip in line:
                    # Search nearby lines for subnet mask
                    for j in range(max(0, i-2), min(len(lines), i+5)):
                        if "Subnet Mask" in lines[j] or "subnet mask" in lines[j].lower():
                            mask = lines[j].split(":")[-1].strip()
                            try:
                                prefix = ipaddress.IPv4Network(
                                    f"0.0.0.0/{mask}", strict=False
                                ).prefixlen
                                network = ipaddress.IPv4Network(
                                    f"{local_ip}/{prefix}", strict=False
                                )
                                return str(network)
                            except Exception:
                                pass
            # Fallback: assume /24
            parts = local_ip.rsplit(".", 1)
            return f"{parts[0]}.0/24"
        except Exception:
            pass

    # ── Linux: ip addr show ───────────────────────────────────────────────
    if iface:
        try:
            result = subprocess.run(
                ["ip", "addr", "show", iface],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "scope global" in line:
                    return line.split()[1]
        except Exception:
            pass

    # ── Universal socket fallback ─────────────────────────────────────────
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        pass

    return None

def get_hostname(ip: str) -> str:
    """Reverse-DNS lookup with short timeout."""
    try:
        socket.setdefaulttimeout(0.3)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)

def get_open_ports(ip: str, ports=(22, 23, 80, 443, 8080, 8443, 5000, 554, 1883)):
    """Quick TCP connect scan on common ports."""
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.15)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports

PORT_SERVICES = {
    22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 5000: "UPnP/Dev",
    554: "RTSP (Camera)", 1883: "MQTT (IoT)",
}

def guess_device_type(vendor: str, ports: list, hostname: str) -> str:
    vendor_l = vendor.lower()
    hostname_l = hostname.lower()
    if any(x in vendor_l for x in ["apple"]):
        if any(x in hostname_l for x in ["iphone", "phone"]):
            return "smartphone"
        if any(x in hostname_l for x in ["ipad"]):
            return "tablet"
        return "computer"
    if any(x in vendor_l for x in ["samsung", "htc", "huawei"]) and not any(x in vendor_l for x in ["router", "switch"]):
        return "smartphone"
    if any(x in vendor_l for x in ["raspberry"]):
        return "single-board"
    if any(x in vendor_l for x in ["nest", "chromecast", "amazon", "google home", "philips"]):
        return "iot"
    if any(x in vendor_l for x in ["tp-link", "netgear", "cisco", "d-link", "ubiquiti", "edimax"]):
        return "router"
    if 554 in ports:
        return "camera"
    if 1883 in ports:
        return "iot"
    if 80 in ports or 443 in ports:
        return "server"
    if 22 in ports:
        return "server"
    return "unknown"

# ─── ARP Scanner ─────────────────────────────────────────────────────────────

def arp_scan(network_cidr: str, log_fn=None):
    """
    Perform ARP scan using scapy. Falls back to pure-Python ARP
    if scapy isn't available or lacks root.
    Returns list of {ip, mac}.
    """
    results = []

    def log(msg):
        if log_fn:
            log_fn(msg)

    try:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0
        log(f"[scapy] Scanning {network_cidr} ...")
        arp = ARP(pdst=network_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered, _ = srp(packet, timeout=2, retry=1)
        for sent, received in answered:
            results.append({
                "ip": received.psrc,
                "mac": received.hwsrc.upper(),
            })
        log(f"[scapy] Found {len(results)} host(s) via ARP")
    except Exception as e:
        log(f"[scapy] Not available or no root ({e}), falling back to ping sweep")
        import platform
        is_windows = platform.system() == "Windows"

        # Fallback: ping sweep
        net = ipaddress.ip_network(network_cidr, strict=False)
        hosts = list(net.hosts())
        log(f"[ping] Sweeping {len(hosts[:254])} hosts...")

        for host in hosts[:254]:
            ip = str(host)
            if is_windows:
                cmd = ["ping", "-n", "1", "-w", "500", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            try:
                ret = subprocess.run(cmd, capture_output=True, timeout=3)
                if ret.returncode == 0:
                    results.append({"ip": ip, "mac": "00:00:00:00:00:00"})
            except Exception:
                pass

        log(f"[ping] {len(results)} host(s) responded")

        # Read ARP cache to get MACs
        try:
            if is_windows:
                arp_out = subprocess.run(["arp", "-a"], capture_output=True, text=True)
                for line in arp_out.stdout.splitlines():
                    parts = line.split()
                    # Windows arp -a: "  192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic"
                    if len(parts) >= 2:
                        ip_candidate = parts[0].strip()
                        mac_candidate = parts[1].strip().replace("-", ":").upper()
                        for r in results:
                            if r["ip"] == ip_candidate and len(mac_candidate) == 17:
                                r["mac"] = mac_candidate
            else:
                arp_out = subprocess.run(["arp", "-n"], capture_output=True, text=True)
                for line in arp_out.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] != "(incomplete)":
                        for r in results:
                            if r["ip"] == parts[0]:
                                r["mac"] = parts[2].upper()
        except Exception:
            pass
    return results


def run_scan(custom_target=None):
    """Full scan pipeline — runs in background thread."""
    global scan_state, known_devices

    scan_state["running"] = True
    scan_state["progress"] = 0
    scan_state["scan_log"] = []
    scan_state["devices"] = []

    def log(msg):
        ts = datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        scan_state["scan_log"].append(entry)
        print(entry)

    try:
        # Step 1: resolve target network
        log("Detecting network configuration...")
        scan_state["progress"] = 5

        gw, iface = get_default_gateway_and_iface()

        if custom_target:
            # User supplied a target — normalise it
            target = custom_target.strip()
            # If bare IP (no slash), turn into /24
            if "/" not in target:
                target = target + "/24"
            try:
                net = ipaddress.ip_network(target, strict=False)
                cidr = str(net)
                log(f"Using user-specified target: {cidr}")
            except ValueError as ve:
                log(f"Invalid IP/CIDR '{target}': {ve}")
                scan_state["running"] = False
                return
        else:
            cidr = get_local_ip_and_subnet(iface) if iface else None
            if not cidr:
                cidr = "192.168.1.0/24"
                log(f"Could not detect subnet; defaulting to {cidr}")
            else:
                log(f"Gateway: {gw}  Interface: {iface}  Subnet: {cidr}")

        scan_state["progress"] = 15

        # Step 2: ARP scan
        log("Starting ARP scan...")
        arp_hosts = arp_scan(cidr, log_fn=log)
        scan_state["progress"] = 50

        # Step 3: enrich each host
        log(f"Enriching {len(arp_hosts)} device(s)...")
        devices = []
        total = len(arp_hosts)

        for i, host in enumerate(arp_hosts):
            ip = host["ip"]
            mac = host["mac"]
            log(f"  → {ip} ({mac})")

            vendor = lookup_vendor(mac)
            hostname = get_hostname(ip)
            ports = get_open_ports(ip)
            dev_type = guess_device_type(vendor, ports, hostname)
            is_known = mac in known_devices
            is_gateway = (ip == gw)

            port_list = [
                {"port": p, "service": PORT_SERVICES.get(p, str(p))}
                for p in ports
            ]

            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname or ip,
                "type": dev_type,
                "ports": port_list,
                "is_known": is_known,
                "is_gateway": is_gateway,
                "flagged": not is_known,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
            })

            pct = 50 + int((i + 1) / max(total, 1) * 45)
            scan_state["progress"] = pct

        # Sort: gateway first, then by IP
        devices.sort(key=lambda d: (
            0 if d["is_gateway"] else 1,
            list(map(int, d["ip"].split(".")))
        ))

        scan_state["devices"] = devices
        scan_state["last_scan"] = datetime.now().isoformat()
        scan_state["history"].append({
            "timestamp": datetime.now().isoformat(),
            "count": len(devices),
        })
        # Keep last 20 scans
        scan_state["history"] = scan_state["history"][-20:]
        scan_state["progress"] = 100
        log(f"Scan complete. {len(devices)} device(s) found.")

    except Exception as e:
        log(f"ERROR: {e}")
        import traceback
        log(traceback.format_exc())
    finally:
        scan_state["running"] = False


# ─── Flask Routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    if scan_state["running"]:
        return jsonify({"error": "Scan already running"}), 409
    data = request.get_json(silent=True) or {}
    custom_target = data.get("target", "").strip() or None
    thread = threading.Thread(target=run_scan, args=(custom_target,), daemon=True)
    thread.start()
    return jsonify({"status": "started", "target": custom_target})

@app.route("/api/status")
def api_status():
    return jsonify({
        "running": scan_state["running"],
        "progress": scan_state["progress"],
        "last_scan": scan_state["last_scan"],
        "device_count": len(scan_state["devices"]),
        "log": scan_state["scan_log"][-20:],
    })

@app.route("/api/devices")
def api_devices():
    return jsonify(scan_state["devices"])

@app.route("/api/history")
def api_history():
    return jsonify(scan_state["history"])

@app.route("/api/detect-network")
def api_detect_network():
    """Auto-detect the local network CIDR the machine is currently on."""
    try:
        gw, iface = get_default_gateway_and_iface()
        cidr = get_local_ip_and_subnet(iface) if iface else get_local_ip_and_subnet(None)
        if cidr:
            net = ipaddress.ip_network(cidr, strict=False)
            return jsonify({
                "cidr": str(net),
                "gateway": gw,
                "interface": iface,
                "ok": True,
            })
        return jsonify({"ok": False, "error": "Could not detect network"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/mark_known", methods=["POST"])
def api_mark_known():
    global known_devices
    data = request.get_json()
    mac = data.get("mac", "").upper()
    if mac:
        known_devices.add(mac)
        save_known_devices(known_devices)
        # update live state
        for d in scan_state["devices"]:
            if d["mac"] == mac:
                d["is_known"] = True
                d["flagged"] = False
    return jsonify({"ok": True})

@app.route("/api/mark_unknown", methods=["POST"])
def api_mark_unknown():
    global known_devices
    data = request.get_json()
    mac = data.get("mac", "").upper()
    if mac in known_devices:
        known_devices.discard(mac)
        save_known_devices(known_devices)
        for d in scan_state["devices"]:
            if d["mac"] == mac:
                d["is_known"] = False
                d["flagged"] = True
    return jsonify({"ok": True})


if __name__ == "__main__":
    print("=" * 60)
    print("  NetScanner — Home Network Device Scanner")
    print("  Open http://localhost:5000 in your browser")
    print("  TIP: Run as root/sudo for full ARP scanning")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)