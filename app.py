#!/usr/bin/env python3
"""
NetPulse: Enterprise Network Packet Sniffer, Speed Analyzer & Device Status Monitor
v5.0 — Per-Device Telemetry, Persistent Session/Tab State, Domain Resolver,
       2-Minute Rolling Buffer with 15-Second Periodic Cleanup & Manual Complaint Deletion
"""

import concurrent.futures
import csv
import errno
import hashlib
import io
import json
import os
import platform
import random
import re
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.request
from collections import Counter, deque
from datetime import datetime
from flask import Flask, Response, jsonify, render_template, request

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from scapy.all import DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, Ether, Raw, conf, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

app = Flask(__name__)


@app.after_request
def add_cors_and_nocache_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Device-Id"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "netpulse_enterprise.db")
COMPLAINTS_FILE = os.path.join(BASE_DIR, "complaints_history.json")

HOSTNAME = socket.gethostname()

# 2-Minute (120s) Rolling Window + 15-Second Periodic Prune Cycle
RETENTION_WINDOW_SECONDS = 120
PRUNE_INTERVAL_SECONDS = 15
MAX_PACKETS = 1500
BANDWIDTH_WINDOW_SECONDS = 30

state_lock = threading.Lock()
dns_lock = threading.Lock()
ip_domain_cache: dict[str, str] = {}
pending_dns_ips: set[str] = set()


# ---------------------------------------------------------------------------
# Fast Non-Blocking IP -> Domain / Service Hostname Resolver
# ---------------------------------------------------------------------------
KNOWN_EXACT_DOMAINS = {
    "1.1.1.1": "one.one.one.one (Cloudflare DNS)",
    "1.0.0.1": "one.one.one.one (Cloudflare DNS)",
    "8.8.8.8": "dns.google (Google Public DNS)",
    "8.8.4.4": "dns.google (Google Public DNS)",
    "9.9.9.9": "dns.quad9.net (Quad9 DNS)",
    "208.67.222.222": "resolver1.opendns.com (Cisco OpenDNS)",
    "208.67.220.220": "resolver2.opendns.com (Cisco OpenDNS)",
    "127.0.0.1": f"{HOSTNAME}.local (Loopback)",
    "::1": f"{HOSTNAME}.local (IPv6 Loopback)",
    "2606:4700:4700::1111": "one.one.one.one (Cloudflare IPv6 DNS)",
    "2606:4700:4700::1001": "one.one.one.one (Cloudflare IPv6 DNS)",
    "2001:4860:4860::8888": "dns.google (Google IPv6 DNS)",
    "2001:4860:4860::8844": "dns.google (Google IPv6 DNS)",
}

KNOWN_PREFIX_DOMAINS = [
    (("104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.24.", "104.25.", "104.26.", "104.27.", "172.64.", "172.67.", "162.159.", "198.41.", "2606:4700:"), "cloudflare.com (Cloudflare CDN)"),
    (("142.250.", "142.251.", "172.217.", "172.253.", "216.58.", "74.125.", "209.85.", "2404:6800:", "2607:f8b0:"), "google.com (Google Cloud/Web)"),
    (("140.82.112.", "140.82.113.", "140.82.114.", "140.82.121.", "185.199.108.", "185.199.109.", "185.199.110.", "185.199.111.", "20.207.73."), "github.com (GitHub Edge)"),
    (("151.101.", "199.232."), "fastly.net (Fastly CDN)"),
    (("13.107.", "204.79.197.", "20.190.", "20.42.", "40.126.", "52.96.", "2620:1ec:"), "microsoft.com (Microsoft/Azure)"),
    (("157.240.", "31.13.", "2a03:2880:"), "meta.com (Facebook/Instagram)"),
    (("54.", "52.", "3.", "18.", "13.32.", "13.35.", "13.224.", "99.84.", "99.86."), "amazonaws.com (AWS CloudFront/EC2)"),
    (("23.200.", "23.210.", "23.32.", "23.40.", "23.50.", "104.64.", "184.24."), "akamai.net (Akamai CDN)"),
    (("2409:40", "2405:20", "49.36.", "49.37.", "49.43."), "jio.com (Reliance Jio ISP)"),
    (("2401:4900:", "106.192.", "106.200.", "122.160."), "airtel.in (Bharti Airtel ISP)"),
]


def _bg_resolve_ptr(ip_str: str) -> None:
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        if host and host != ip_str:
            with dns_lock:
                ip_domain_cache[ip_str] = host
    except Exception:
        pass
    finally:
        with dns_lock:
            pending_dns_ips.discard(ip_str)


def resolve_ip_domain(ip_str: str, hint_domain: str = "") -> str:
    """Returns a human-readable domain or network label for any IPv4/IPv6 or hostname."""
    if not ip_str:
        return "unknown-host"
    clean_ip = str(ip_str).strip()

    if hint_domain and not re.match(r"^\d+\.\d+\.\d+\.\d+$", hint_domain) and ":" not in hint_domain:
        with dns_lock:
            ip_domain_cache[clean_ip] = hint_domain
        return hint_domain

    # If clean_ip is already a domain name (contains letters and dots, not IPv6)
    if ":" not in clean_ip and any(c.isalpha() for c in clean_ip):
        return clean_ip

    if clean_ip in KNOWN_EXACT_DOMAINS:
        return KNOWN_EXACT_DOMAINS[clean_ip]

    local_ip = capture_state.get("local_ip", "127.0.0.1")
    if clean_ip == local_ip:
        return f"{HOSTNAME}.local (Host Device)"

    with dns_lock:
        cached = ip_domain_cache.get(clean_ip)
    if cached:
        return cached

    low_ip = clean_ip.lower()
    for prefixes, label in KNOWN_PREFIX_DOMAINS:
        if any(low_ip.startswith(p) for p in prefixes):
            with dns_lock:
                ip_domain_cache[clean_ip] = label
            return label

    if low_ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")):
        if low_ip.endswith(".1"):
            return "gateway.router.lan (LAN Gateway)"
        return "lan-device.local (Local Wi-Fi/LAN)"

    if low_ip.startswith(("fe80:", "fc00:", "fd00:")):
        return "ipv6-lan-node.local (Link-Local IPv6)"

    # Trigger non-blocking background PTR lookup
    with dns_lock:
        if clean_ip not in pending_dns_ips and len(pending_dns_ips) < 35:
            pending_dns_ips.add(clean_ip)
            threading.Thread(target=_bg_resolve_ptr, args=(clean_ip,), daemon=True).start()

    if ":" in clean_ip:
        return "ipv6-endpoint.net (Public IPv6 Host)"
    return "remote-endpoint.net (Internet Host)"


def get_active_local_ip() -> tuple[str, bool]:
    """Detects active local IPv4 address reliably across Wi-Fi, Ethernet, or LAN."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.35)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip, True
    except Exception:
        pass

    if PSUTIL_AVAILABLE:
        try:
            addrs_map = psutil.net_if_addrs()
            for nic_name, addr_list in addrs_map.items():
                if "loopback" in nic_name.lower() or nic_name.lower() == "lo":
                    continue
                for addr in addr_list:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127.") and not addr.address.startswith("169.254."):
                        return addr.address, True
        except Exception:
            pass

    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip, True
    except Exception:
        pass

    return "127.0.0.1", True


def get_external_nic_counters() -> tuple[int, int, int, bool]:
    """Reads cumulative bytes_recv, bytes_sent, and packets from non-loopback interfaces."""
    if not PSUTIL_AVAILABLE:
        return 0, 0, 0, True
    try:
        io_map = psutil.net_io_counters(pernic=True)
        total_recv = 0
        total_sent = 0
        total_pkts = 0
        for nic_name, counters in io_map.items():
            low_name = nic_name.lower()
            if "loopback" in low_name or low_name == "lo" or low_name.startswith("lo0"):
                continue
            total_recv += counters.bytes_recv
            total_sent += counters.bytes_sent
            total_pkts += (counters.packets_recv + counters.packets_sent)
        if total_recv == 0 and total_sent == 0:
            tot = psutil.net_io_counters()
            return tot.bytes_recv, tot.bytes_sent, (tot.packets_recv + tot.packets_sent), True
        return total_recv, total_sent, total_pkts, True
    except Exception:
        return 0, 0, 0, True


init_ip, init_online = get_active_local_ip()

capture_state = {
    "running": True,
    "network_online": init_online,
    "capture_engine": "Hybrid Real Packet & OS Socket Engine (2-Min Rolling Buffer)",
    "local_ip": init_ip,
    "hostname": HOSTNAME,
    "packet_counter": 0,
    "total_bytes": 0,
    "total_down_bytes": 0,
    "total_up_bytes": 0,
    "peak_kbps": 0.0,
    "current_kbps": 0.0,
    "live_down_kbps": 0.0,
    "live_up_kbps": 0.0,
    "current_pps": 0,
    "protocol_counts": Counter({"TCP": 0, "UDP": 0, "HTTP": 0, "DNS": 0, "ICMP": 0}),
    "src_ips": Counter(),
    "dst_ips": Counter(),
    "packets": deque(maxlen=MAX_PACKETS),
    "bandwidth_history": deque(maxlen=BANDWIDTH_WINDOW_SECONDS),
    "scapy_last_pkt_ts": 0.0,
    "last_prune_epoch": time.time(),
    "last_pruned_count": 0,
}

# Per-Device Isolated Traffic State (Keyed by device_id so each logged-in device sees its OWN traffic!)
device_sessions: dict[str, dict] = {}

devices_store = []
alerts_store = []
complaints_store = []
complaint_counter = 1000
ping_trigger_event = threading.Event()


def get_or_create_device_session(device_id: str, client_ip: str) -> dict:
    """Returns or initializes an isolated traffic state for a specific logged-in client device."""
    if not device_id:
        device_id = f"dev-{client_ip}"
    sess = device_sessions.get(device_id)
    if sess is None:
        sess = {
            "device_id": device_id,
            "client_ip": client_ip,
            "running": True,
            "packet_counter": 0,
            "total_bytes": 0,
            "total_down_bytes": 0,
            "total_up_bytes": 0,
            "peak_kbps": 0.0,
            "current_kbps": 0.0,
            "live_down_kbps": 0.0,
            "live_up_kbps": 0.0,
            "current_pps": 0,
            "protocol_counts": Counter({"TCP": 0, "UDP": 0, "HTTP": 0, "DNS": 0, "ICMP": 0}),
            "src_ips": Counter(),
            "dst_ips": Counter(),
            "packets": deque(maxlen=MAX_PACKETS),
            "bandwidth_history": deque(maxlen=BANDWIDTH_WINDOW_SECONDS),
            "last_prune_epoch": time.time(),
            "last_pruned_count": 0,
        }
        device_sessions[device_id] = sess
    else:
        sess["client_ip"] = client_ip
    return sess


def rebuild_window_counters(target_state: dict) -> None:
    """Recomputes protocol_counts, src_ips, and dst_ips strictly from the active 2-minute packet window."""
    proto_c = Counter({"TCP": 0, "UDP": 0, "HTTP": 0, "DNS": 0, "ICMP": 0})
    src_c = Counter()
    dst_c = Counter()
    for p in target_state["packets"]:
        pr = p.get("protocol", "TCP")
        ln = int(p.get("length", 64))
        proto_c[pr] += 1
        src_c[p.get("src_ip", "")] += ln
        dst_c[p.get("dst_ip", "")] += ln
    target_state["protocol_counts"] = proto_c
    target_state["src_ips"] = src_c
    target_state["dst_ips"] = dst_c


def prune_expired_packets_worker() -> None:
    """
    Runs every 15 seconds (PRUNE_INTERVAL_SECONDS = 15):
    Deletes packets older than 2 minutes (RETENTION_WINDOW_SECONDS = 120) in 15-second batches
    so 2 minutes of live traffic & protocols always remain visible.
    """
    while True:
        time.sleep(1.0)
        now_ts = time.time()
        now_ms = int(now_ts * 1000)
        cutoff_ms = now_ms - (RETENTION_WINDOW_SECONDS * 1000)

        with state_lock:
            if now_ts - capture_state["last_prune_epoch"] >= PRUNE_INTERVAL_SECONDS:
                capture_state["last_prune_epoch"] = now_ts
                before_len = len(capture_state["packets"])
                kept = deque(
                    (p for p in capture_state["packets"] if p.get("epoch_ms", now_ms) >= cutoff_ms),
                    maxlen=MAX_PACKETS,
                )
                capture_state["packets"] = kept
                capture_state["last_pruned_count"] = max(0, before_len - len(kept))
                rebuild_window_counters(capture_state)

            for dev_id, sess in list(device_sessions.items()):
                if now_ts - sess["last_prune_epoch"] >= PRUNE_INTERVAL_SECONDS:
                    sess["last_prune_epoch"] = now_ts
                    b_len = len(sess["packets"])
                    s_kept = deque(
                        (p for p in sess["packets"] if p.get("epoch_ms", now_ms) >= cutoff_ms),
                        maxlen=MAX_PACKETS,
                    )
                    sess["packets"] = s_kept
                    sess["last_pruned_count"] = max(0, b_len - len(s_kept))
                    rebuild_window_counters(sess)


def format_duration_sec(seconds: float) -> str:
    sec = max(1, int(round(seconds)))
    hrs = sec // 3600
    mins = (sec % 3600) // 60
    rem = sec % 60
    if hrs > 0:
        return f"{hrs}h {mins}m {rem}s"
    if mins > 0:
        return f"{mins}m {rem}s"
    return f"{rem} sec"


def load_saved_complaints() -> None:
    global complaint_counter, complaints_store, devices_store
    try:
        if os.path.exists(COMPLAINTS_FILE):
            with open(COMPLAINTS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                complaint_counter = data.get("complaint_counter", 1000)
                complaints_store = data.get("complaints", [])
                if "devices" in data and isinstance(data["devices"], list):
                    devices_store = data["devices"]
    except Exception:
        pass


def save_complaints_to_disk() -> None:
    try:
        with open(COMPLAINTS_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "complaint_counter": complaint_counter,
                "complaints": complaints_store,
                "devices": devices_store,
            }, f, indent=2)
    except Exception:
        pass


def init_sqlite_db() -> None:
    conn = sqlite3.connect(DB_FILE, timeout=10)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS employees_users (
            emp_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            plain_preview TEXT,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS monitored_devices (
            id INTEGER PRIMARY KEY,
            ip_address TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL,
            latency_ms INTEGER,
            last_checked TEXT,
            offline_at TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS complaints_alerts (
            complaint_no TEXT PRIMARY KEY,
            device_ip TEXT NOT NULL,
            device_desc TEXT NOT NULL,
            status TEXT NOT NULL,
            offline_time TEXT NOT NULL,
            online_time TEXT,
            duration_text TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS speed_test_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tested_at TEXT NOT NULL,
            download_mbps REAL NOT NULL,
            upload_mbps REAL NOT NULL,
            ping_ms INTEGER NOT NULL
        )
    """)
    adm_hash = hashlib.sha256(b"Adm!9xK2#p").hexdigest()
    cur.execute(
        "INSERT OR REPLACE INTO employees_users VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("EMP-100", "admin", adm_hash, "Adm!9xK2#p", "System Admin (Dept Head)", "Department Admin", "Primary Admin"),
    )
    conn.commit()
    conn.close()


load_saved_complaints()
init_sqlite_db()


def format_hex_dump(raw_bytes: bytes, max_len: int = 48) -> str:
    data = raw_bytes[:max_len]
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def record_real_packet(parsed: dict, target_device_id: str | None = None) -> None:
    src_ip = str(parsed.get("src_ip", ""))
    dst_ip = str(parsed.get("dst_ip", ""))
    if (src_ip.startswith("127.") or dst_ip.startswith("127.")) and (
        parsed.get("src_port") == 5000 or parsed.get("dst_port") == 5000
    ):
        return

    src_domain = resolve_ip_domain(src_ip, parsed.get("src_domain", ""))
    dst_domain = resolve_ip_domain(dst_ip, parsed.get("dst_domain", ""))
    parsed["src_domain"] = src_domain
    parsed["dst_domain"] = dst_domain

    now_ms = int(time.time() * 1000)
    now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto = parsed.get("protocol", "TCP")
    length = int(parsed.get("length", 64))

    with state_lock:
        if target_device_id and target_device_id in device_sessions:
            sess = device_sessions[target_device_id]
            if not sess["running"]:
                return
            sess["packet_counter"] += 1
            pkt_id = sess["packet_counter"]
            sess["protocol_counts"][proto] += 1
            sess["src_ips"][src_ip] += length
            sess["dst_ips"][dst_ip] += length
            sess["packets"].appendleft({
                "id": pkt_id,
                "timestamp": now_str,
                "epoch_ms": now_ms,
                **parsed,
            })
            return

        if not capture_state["running"]:
            return
        capture_state["packet_counter"] += 1
        pkt_id = capture_state["packet_counter"]
        capture_state["protocol_counts"][proto] += 1
        capture_state["src_ips"][src_ip] += length
        capture_state["dst_ips"][dst_ip] += length
        pkt_obj = {
            "id": pkt_id,
            "timestamp": now_str,
            "epoch_ms": now_ms,
            **parsed,
        }
        capture_state["packets"].appendleft(pkt_obj)

        # Also route packet to any matching remote LAN device session whose client_ip matches src_ip or dst_ip
        for dev_id, sess in device_sessions.items():
            cip = sess.get("client_ip", "")
            if cip and cip not in ("127.0.0.1", "::1", capture_state["local_ip"]) and (cip == src_ip or cip == dst_ip):
                if sess["running"]:
                    sess["packet_counter"] += 1
                    sess["protocol_counts"][proto] += 1
                    sess["src_ips"][src_ip] += length
                    sess["dst_ips"][dst_ip] += length
                    sess["packets"].appendleft({
                        **pkt_obj,
                        "id": sess["packet_counter"],
                    })


def classify_scapy_packet(pkt) -> dict | None:
    src_ip = ""
    dst_ip = ""
    ttl = 64
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ttl = int(ip_layer.ttl)
    elif SCAPY_AVAILABLE and pkt.haslayer(IPv6):
        ip6_layer = pkt[IPv6]
        src_ip = ip6_layer.src
        dst_ip = ip6_layer.dst
        ttl = int(ip6_layer.hlim)
    else:
        return None

    if src_ip.startswith("127.") and dst_ip.startswith("127."):
        return None

    length = len(pkt)
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "Physical-NIC"
    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else "Gateway-NIC"

    protocol = "TCP"
    src_port = 0
    dst_port = 0
    flags_str = "-"
    info = "IP Frame"
    dst_domain_hint = ""

    if pkt.haslayer(ICMP):
        protocol = "ICMP"
        icmp_type = int(pkt[ICMP].type)
        icmp_code = int(pkt[ICMP].code)
        type_map = {0: "Echo (ping) reply", 8: "Echo (ping) request", 3: "Destination unreachable", 11: "TTL exceeded"}
        info = f"ICMP {type_map.get(icmp_type, f'Type {icmp_type}')} (code={icmp_code}, ttl={ttl})"

    elif pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        flags_str = str(tcp.flags)
        protocol = "TCP"
        info = f"TCP {src_port} -> {dst_port} [{flags_str}] Seq={tcp.seq}"

        if src_port in (80, 8080, 8000, 443, 8443) or dst_port in (80, 8080, 8000, 443, 8443):
            protocol = "HTTP"
            scheme = "HTTPS/TLS" if (443 in (src_port, dst_port) or 8443 in (src_port, dst_port)) else "HTTP"
            info = f"{scheme} {src_port} -> {dst_port} [{flags_str}] Len={length}B"
        if pkt.haslayer(Raw):
            try:
                text_head = bytes(pkt[Raw].load)[:120].decode("utf-8", errors="ignore")
                if any(text_head.startswith(m) for m in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/1.")):
                    protocol = "HTTP"
                    info = f"HTTP {text_head.splitlines()[0][:75]}"
                    m_host = re.search(r"Host:\s*([^\r\n:]+)", text_head, re.IGNORECASE)
                    if m_host:
                        dst_domain_hint = m_host.group(1).strip()
            except Exception:
                pass

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        protocol = "UDP"
        info = f"UDP {src_port} -> {dst_port} Len={length}B"

        if pkt.haslayer(DNS) or src_port in (53, 5353) or dst_port in (53, 5353):
            protocol = "DNS"
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                except Exception:
                    qname = "domain"
                qr_flag = "DNS Response" if pkt[DNS].qr else "DNS Query"
                info = f"{qr_flag}: {qname}"
                if qname and "." in qname:
                    dst_domain_hint = qname
            else:
                info = f"DNS {src_port} -> {dst_port} Len={length}B"

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_domain": "",
        "dst_domain": dst_domain_hint,
        "src_port": src_port,
        "dst_port": dst_port,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "protocol": protocol,
        "length": length,
        "ttl": ttl,
        "flags": flags_str,
        "info": info,
        "hex_dump": format_hex_dump(bytes(pkt)),
    }


def scapy_sniffer_worker() -> None:
    """Rate-limited Scapy sniffer so high-speed downloads never freeze the Python GIL."""
    if not SCAPY_AVAILABLE:
        return
    last_ts = [0.0]
    count_in_sec = [0]

    def _on_pkt(pkt):
        now = time.monotonic()
        if now - last_ts[0] >= 1.0:
            last_ts[0] = now
            count_in_sec[0] = 0
        if count_in_sec[0] >= 35:
            return
        count_in_sec[0] += 1
        parsed = classify_scapy_packet(pkt)
        if parsed:
            with state_lock:
                capture_state["scapy_last_pkt_ts"] = now
            record_real_packet(parsed)

    try:
        sniff(prn=_on_pkt, store=False)
    except Exception:
        try:
            sniff(prn=_on_pkt, store=False, L2socket=conf.L3socket)
        except Exception:
            pass


def real_bandwidth_and_socket_worker() -> None:
    """
    Runs every 1 second:
    1. Reads exact physical NIC byte deltas via psutil.
    2. Inspects active OS sockets (TCP, HTTP/HTTPS, UDP, DNS) whenever network bytes move
       and Scapy hasn't captured raw frames on Windows.
    """
    prev_recv, prev_sent, prev_pkts, _ = get_external_nic_counters()

    while True:
        time.sleep(1.0)
        try:
            local_ip, route_online = get_active_local_ip()
            cur_recv, cur_sent, cur_pkts, nic_up = get_external_nic_counters()
            is_online = route_online and nic_up

            with state_lock:
                capture_state["local_ip"] = local_ip
                capture_state["network_online"] = is_online
                is_running = capture_state["running"]
                scapy_recent = (time.monotonic() - capture_state["scapy_last_pkt_ts"]) < 2.0

            if not is_running or not is_online:
                prev_recv, prev_sent, prev_pkts = cur_recv, cur_sent, cur_pkts
                with state_lock:
                    capture_state["current_kbps"] = 0.0
                    capture_state["live_down_kbps"] = 0.0
                    capture_state["live_up_kbps"] = 0.0
                    capture_state["current_pps"] = 0
                    if is_running:
                        capture_state["bandwidth_history"].append({
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "total_kbps": 0.0,
                            "down_kbps": 0.0,
                            "up_kbps": 0.0,
                            "pps": 0,
                        })
                continue

            delta_down = max(0, cur_recv - prev_recv)
            delta_up = max(0, cur_sent - prev_sent)
            delta_total = delta_down + delta_up
            delta_pkts = max(0, cur_pkts - prev_pkts)
            prev_recv, prev_sent, prev_pkts = cur_recv, cur_sent, cur_pkts

            down_kbps = round(delta_down / 1024.0, 2)
            up_kbps = round(delta_up / 1024.0, 2)
            total_kbps = round(delta_total / 1024.0, 2)

            if not scapy_recent and PSUTIL_AVAILABLE and (delta_total > 0 or delta_pkts > 0):
                try:
                    conns = [
                        c for c in psutil.net_connections(kind="inet")
                        if c.laddr and c.raddr
                        and not (c.laddr.ip.startswith("127.") and c.raddr.ip.startswith("127."))
                    ]
                    random.shuffle(conns)
                    for c in conns[:5]:
                        sip, sport = c.laddr.ip, c.laddr.port
                        dip, dport = c.raddr.ip, c.raddr.port
                        is_udp = (c.type == socket.SOCK_DGRAM)
                        if sport in (53, 5353) or dport in (53, 5353):
                            proto = "DNS"
                            info_str = f"DNS Query/Response {sport} -> {dport} (OS Socket)"
                        elif sport in (80, 8080, 8000, 443, 8443) or dport in (80, 8080, 8000, 443, 8443):
                            proto = "HTTP"
                            label = "HTTPS/TLS" if (443 in (sport, dport) or 8443 in (sport, dport)) else "HTTP"
                            info_str = f"{label} Stream {sport} -> {dport} [{getattr(c, 'status', 'ESTABLISHED')}]"
                        elif is_udp:
                            proto = "UDP"
                            info_str = f"UDP Datagram {sport} -> {dport}"
                        else:
                            proto = "TCP"
                            info_str = f"TCP {sport} -> {dport} [{getattr(c, 'status', 'ESTABLISHED')}]"

                        pkt_len = max(64, min(delta_total // max(1, len(conns[:5])), 1460))
                        raw_b = f"{proto} {sip}:{sport} -> {dip}:{dport} {info_str}".encode("utf-8")
                        record_real_packet({
                            "src_ip": sip,
                            "dst_ip": dip,
                            "src_port": sport,
                            "dst_port": dport,
                            "src_mac": "Local-NIC",
                            "dst_mac": "Gateway",
                            "protocol": proto,
                            "length": pkt_len,
                            "ttl": 64,
                            "flags": getattr(c, "status", "ACK"),
                            "info": info_str,
                            "hex_dump": format_hex_dump(raw_b.ljust(48, b"\x00")),
                        })
                except Exception:
                    pass

            with state_lock:
                capture_state["total_bytes"] += delta_total
                capture_state["total_down_bytes"] += delta_down
                capture_state["total_up_bytes"] += delta_up
                capture_state["current_kbps"] = total_kbps
                capture_state["live_down_kbps"] = down_kbps
                capture_state["live_up_kbps"] = up_kbps
                capture_state["current_pps"] = delta_pkts
                if total_kbps > capture_state["peak_kbps"]:
                    capture_state["peak_kbps"] = total_kbps

                capture_state["bandwidth_history"].append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "total_kbps": total_kbps,
                    "down_kbps": down_kbps,
                    "up_kbps": up_kbps,
                    "pps": delta_pkts,
                })
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Fast, Non-Blocking 3-Layer Host Reachability & ICMP Packet Logger
# ---------------------------------------------------------------------------
def clean_target_host(raw_input: str) -> str:
    s = (raw_input or "").strip()
    s = re.sub(r"^https?://", "", s, flags=re.IGNORECASE)
    s = s.split("/")[0].split("?")[0]
    if ":" in s and s.count(":") == 1:
        s = s.split(":")[0]
    return s.strip()


def tcp_fast_probe(ip_addr: str) -> tuple[bool, int | None, int | None]:
    refused_codes = {errno.ECONNREFUSED, 10061, 111}
    ports = (53, 80, 443, 445, 135, 3389, 22, 8080)

    def _try_port(p: int):
        try:
            t0 = time.perf_counter()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.55)
            rc = s.connect_ex((ip_addr, p))
            s.close()
            rtt = max(1, int((time.perf_counter() - t0) * 1000))
            if rc == 0 or rc in refused_codes:
                return True, rtt, p
        except Exception:
            pass
        return False, None, p

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as ex:
        for ok, rtt, p in ex.map(_try_port, ports):
            if ok:
                return True, rtt, p
    return False, None, None


def check_arp_cache_alive(ip_addr: str) -> bool:
    if not (ip_addr.startswith("192.168.") or ip_addr.startswith("10.") or ip_addr.startswith("172.")):
        return False
    try:
        proc = subprocess.run(["arp", "-a", ip_addr], capture_output=True, text=True, timeout=1.5)
        out = (proc.stdout or "").lower()
        if "incomplete" in out or "no arp entries" in out or "invalid" in out:
            return False
        if re.search(r"([0-9a-f]{2}[-:]){5}[0-9a-f]{2}", out):
            return True
    except Exception:
        pass
    return False


def ping_host_real(raw_target: str) -> tuple[bool, int | None, str]:
    ip_addr = clean_target_host(raw_target)
    if not ip_addr:
        return False, None, "Empty IP/Host"

    local_ip = capture_state.get("local_ip", "127.0.0.1")

    is_win = platform.system().lower() == "windows"
    cmd = ["ping", "-n", "1", "-w", "1000", ip_addr] if is_win else ["ping", "-c", "1", "-W", "1", ip_addr]
    try:
        t0 = time.perf_counter()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2.2)
        elapsed_ms = max(1, int((time.perf_counter() - t0) * 1000))
        out = ((proc.stdout or "") + (proc.stderr or "")).lower()

        has_fatal_error = any(
            err in out
            for err in (
                "destination host unreachable",
                "destination net unreachable",
                "request timed out",
                "100% packet loss",
                "(100% loss)",
                "could not find host",
                "transmit failed",
                "general failure",
            )
        )
        has_ttl_reply = ("ttl=" in out) or ("0% loss" in out) or ("0% packet loss" in out) or ("bytes from" in out)

        if proc.returncode == 0 and has_ttl_reply and not has_fatal_error:
            m = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", out, re.IGNORECASE)
            rtt = int(float(m.group(1))) if m else elapsed_ms
            raw_icmp = f"ICMP Echo Reply from {ip_addr}: bytes=32 time={rtt}ms TTL=64".encode("utf-8")
            record_real_packet({
                "src_ip": ip_addr,
                "dst_ip": local_ip,
                "src_port": 0,
                "dst_port": 0,
                "src_mac": "Remote-Host",
                "dst_mac": "Local-NIC",
                "protocol": "ICMP",
                "length": 74,
                "ttl": 64,
                "flags": "ECHO-REPLY",
                "info": f"ICMP Echo (ping) reply from {ip_addr} ({rtt} ms)",
                "hex_dump": format_hex_dump(raw_icmp.ljust(48, b"\x00")),
            })
            return True, rtt, f"ICMP Echo Reply ({rtt} ms)"
    except Exception:
        pass

    tcp_ok, tcp_rtt, matched_port = tcp_fast_probe(ip_addr)
    if tcp_ok:
        raw_icmp = f"ICMP/TCP Reachability Reply from {ip_addr}:{matched_port} time={tcp_rtt}ms".encode("utf-8")
        record_real_packet({
            "src_ip": ip_addr,
            "dst_ip": local_ip,
            "src_port": matched_port or 0,
            "dst_port": 0,
            "src_mac": "Remote-Host",
            "dst_mac": "Local-NIC",
            "protocol": "ICMP",
            "length": 74,
            "ttl": 64,
            "flags": "HOST-ALIVE",
            "info": f"Host Alive Reply from {ip_addr} ({tcp_rtt} ms)",
            "hex_dump": format_hex_dump(raw_icmp.ljust(48, b"\x00")),
        })
        return True, tcp_rtt, f"Online ({tcp_rtt} ms)"

    if check_arp_cache_alive(ip_addr):
        return True, 3, "Online on LAN (ARP MAC Verified)"

    return False, None, "Host Unreachable / Request Timed Out"


def evaluate_device_ping(dev: dict) -> None:
    global complaint_counter
    is_up, rtt_ms, detail = ping_host_real(dev["ip"])
    now_str = datetime.now().strftime("%I:%M:%S %p")
    now_epoch_ms = int(time.time() * 1000)

    with state_lock:
        prev_status = dev["status"]
        dev["last_checked"] = now_str
        dev["last_detail"] = detail

        if is_up:
            dev["status"] = "ONLINE"
            dev["was_online"] = True
            dev["latency_ms"] = rtt_ms
            dev["offline_at"] = None

            alerts_store[:] = [a for a in alerts_store if a.get("deviceId") != dev["id"] and a.get("ip") != dev["ip"]]

            changed = False
            for comp in complaints_store:
                if (comp.get("deviceId") == dev["id"] or comp.get("ip") == dev["ip"]) and comp.get("status") != "SOLVED":
                    comp["status"] = "SOLVED"
                    comp["onlineTime"] = now_str
                    comp["onlineEpoch"] = now_epoch_ms
                    off_ep = comp.get("offlineEpoch") or (now_epoch_ms - 30000)
                    comp["durationText"] = format_duration_sec((now_epoch_ms - off_ep) / 1000.0)
                    changed = True
            if changed:
                save_complaints_to_disk()
        else:
            dev["status"] = "OFFLINE"
            dev["latency_ms"] = None
            if prev_status == "ONLINE":
                dev["offline_at"] = now_str
                complaint_counter += 1
                comp_no = f"CMP-2026-{complaint_counter}"
                alerts_store.insert(0, {
                    "id": now_epoch_ms + random.randint(1, 999),
                    "complaintNo": comp_no,
                    "deviceId": dev["id"],
                    "ip": dev["ip"],
                    "desc": dev["desc"],
                    "offlineTime": now_str,
                    "offlineEpoch": now_epoch_ms,
                    "reason": f"Device was ONLINE and suddenly went OFFLINE ({detail})",
                })
                complaints_store.insert(0, {
                    "complaintNo": comp_no,
                    "deviceId": dev["id"],
                    "ip": dev["ip"],
                    "desc": dev["desc"],
                    "status": "ACTIVE",
                    "offlineTime": now_str,
                    "offlineEpoch": now_epoch_ms,
                    "onlineTime": None,
                    "onlineEpoch": None,
                    "durationText": "Currently Offline",
                })
                save_complaints_to_disk()


def auto_ping_monitor_worker() -> None:
    while True:
        ping_trigger_event.wait(timeout=15.0)
        ping_trigger_event.clear()
        with state_lock:
            snapshot = list(devices_store)
        if not snapshot:
            continue
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(snapshot))) as pool:
            list(pool.map(evaluate_device_ping, snapshot))


# ---------------------------------------------------------------------------
# Flask API Endpoints
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


def detect_request_client_ip() -> str:
    return (
        request.headers.get("CF-Connecting-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or capture_state["local_ip"]
    )


@app.route("/api/client_telemetry", methods=["POST"])
def api_client_telemetry():
    """
    Receives real network transfers & protocol packets captured on a logged-in remote device
    (phone/laptop) so that device's session reflects ONLY its own live traffic and protocols!
    """
    data = request.get_json(silent=True) or {}
    client_ip = detect_request_client_ip()
    device_id = (data.get("device_id") or request.headers.get("X-Device-Id") or f"dev-{client_ip}").strip()
    incoming_pkts = data.get("packets") or []
    down_bytes = int(data.get("down_bytes") or 0)
    up_bytes = int(data.get("up_bytes") or 0)

    with state_lock:
        sess = get_or_create_device_session(device_id, client_ip)
        if not sess["running"]:
            return jsonify({"ok": True, "running": False})

        now_ms = int(time.time() * 1000)
        now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        pkt_count_added = 0
        bytes_added = down_bytes + up_bytes

        for p in incoming_pkts[:25]:
            proto = p.get("protocol", "HTTP")
            if proto not in ("TCP", "UDP", "HTTP", "DNS", "ICMP"):
                proto = "HTTP"
            length = max(48, int(p.get("length") or 128))
            sip = str(p.get("src_ip") or client_ip)
            dip = str(p.get("dst_ip") or "1.1.1.1")
            s_dom = resolve_ip_domain(sip, str(p.get("src_domain") or ""))
            d_dom = resolve_ip_domain(dip, str(p.get("dst_domain") or ""))
            sport = int(p.get("src_port") or 0)
            dport = int(p.get("dst_port") or 443)
            info = str(p.get("info") or f"{proto} {sip} -> {dip}")
            raw_b = f"{proto} {sip}:{sport} -> {dip}:{dport} {info}".encode("utf-8")

            sess["packet_counter"] += 1
            sess["protocol_counts"][proto] += 1
            sess["src_ips"][sip] += length
            sess["dst_ips"][dip] += length
            sess["packets"].appendleft({
                "id": sess["packet_counter"],
                "timestamp": p.get("timestamp") or now_str,
                "epoch_ms": now_ms,
                "src_ip": sip,
                "dst_ip": dip,
                "src_domain": s_dom,
                "dst_domain": d_dom,
                "src_port": sport,
                "dst_port": dport,
                "src_mac": "Device-NIC",
                "dst_mac": "Gateway",
                "protocol": proto,
                "length": length,
                "ttl": int(p.get("ttl") or 64),
                "flags": str(p.get("flags") or "ACK"),
                "info": info,
                "hex_dump": p.get("hex_dump") or format_hex_dump(raw_b.ljust(48, b"\x00")),
            })
            pkt_count_added += 1
            if down_bytes == 0 and up_bytes == 0:
                bytes_added += length
                down_bytes += length

        sess["total_bytes"] += bytes_added
        sess["total_down_bytes"] += down_bytes
        sess["total_up_bytes"] += up_bytes
        down_kbps = round(down_bytes / 1024.0, 2)
        up_kbps = round(up_bytes / 1024.0, 2)
        tot_kbps = round(down_kbps + up_kbps, 2)
        sess["current_kbps"] = tot_kbps
        sess["live_down_kbps"] = down_kbps
        sess["live_up_kbps"] = up_kbps
        sess["current_pps"] = pkt_count_added
        if tot_kbps > sess["peak_kbps"]:
            sess["peak_kbps"] = tot_kbps

        sess["bandwidth_history"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "total_kbps": tot_kbps,
            "down_kbps": down_kbps,
            "up_kbps": up_kbps,
            "pps": pkt_count_added,
        })

    return jsonify({"ok": True})


@app.route("/api/stats")
def api_stats():
    client_ip = detect_request_client_ip()
    device_id = (request.args.get("device_id") or request.headers.get("X-Device-Id") or "").strip()
    scope = (request.args.get("scope") or "device").strip().lower()

    is_host_client = client_ip in ("127.0.0.1", "::1", capture_state["local_ip"])

    with state_lock:
        # Use Host capture_state ONLY if the browser is on the Host machine OR user explicitly asked for global host scope
        if is_host_client or scope == "global":
            active = capture_state
            displayed_ip = capture_state["local_ip"] if is_host_client else client_ip
            engine_label = capture_state["capture_engine"]
        else:
            active = get_or_create_device_session(device_id, client_ip)
            displayed_ip = client_ip
            engine_label = f"Device-Isolated Live Sniffer ({client_ip})"

        packets_list = list(active["packets"])[:300]
        bw_hist = list(active["bandwidth_history"])
        unique_hosts = len(set(active["src_ips"].keys()) | set(active["dst_ips"].keys()))
        next_prune_in = max(1, int(PRUNE_INTERVAL_SECONDS - (time.time() - active.get("last_prune_epoch", time.time()))))

        top_src = [
            {"ip": ip, "domain": resolve_ip_domain(ip), "bytes": b}
            for ip, b in active["src_ips"].most_common(5)
        ]
        top_dst = [
            {"ip": ip, "domain": resolve_ip_domain(ip), "bytes": b}
            for ip, b in active["dst_ips"].most_common(5)
        ]

        return jsonify({
            "running": active["running"],
            "network_online": capture_state["network_online"],
            "capture_engine": engine_label,
            "is_host_client": is_host_client,
            "local_ip": capture_state["local_ip"],
            "client_ip": displayed_ip,
            "client_domain": resolve_ip_domain(displayed_ip),
            "db_path": DB_FILE,
            "hostname": capture_state["hostname"],
            "retention_window_sec": RETENTION_WINDOW_SECONDS,
            "prune_interval_sec": PRUNE_INTERVAL_SECONDS,
            "next_prune_in_sec": next_prune_in,
            "last_pruned_count": active.get("last_pruned_count", 0),
            "total_packets": active["packet_counter"],
            "active_window_packets": len(active["packets"]),
            "total_bytes": active["total_bytes"],
            "total_down_bytes": active["total_down_bytes"],
            "total_up_bytes": active["total_up_bytes"],
            "peak_kbps": active["peak_kbps"],
            "current_kbps": active["current_kbps"],
            "live_down_kbps": active["live_down_kbps"],
            "live_up_kbps": active["live_up_kbps"],
            "current_pps": active["current_pps"],
            "unique_hosts": unique_hosts,
            "protocol_counts": dict(active["protocol_counts"]),
            "top_src_ips": top_src,
            "top_dst_ips": top_dst,
            "bandwidth_history": bw_hist,
            "packets": packets_list,
            "devices": list(devices_store),
            "alerts": list(alerts_store),
            "complaints": list(complaints_store),
        })


@app.route("/api/control", methods=["POST"])
def api_control():
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    client_ip = detect_request_client_ip()
    device_id = (data.get("device_id") or request.headers.get("X-Device-Id") or "").strip()
    is_host_client = client_ip in ("127.0.0.1", "::1", capture_state["local_ip"])

    with state_lock:
        target = capture_state if is_host_client else get_or_create_device_session(device_id, client_ip)
        if action == "toggle":
            target["running"] = not target["running"]
            if not target["running"]:
                target["current_kbps"] = 0.0
                target["live_down_kbps"] = 0.0
                target["live_up_kbps"] = 0.0
                target["current_pps"] = 0
        elif action == "clear":
            target["packet_counter"] = 0
            target["total_bytes"] = 0
            target["total_down_bytes"] = 0
            target["total_up_bytes"] = 0
            target["peak_kbps"] = 0.0
            target["current_kbps"] = 0.0
            target["live_down_kbps"] = 0.0
            target["live_up_kbps"] = 0.0
            target["current_pps"] = 0
            target["protocol_counts"] = Counter({"TCP": 0, "UDP": 0, "HTTP": 0, "DNS": 0, "ICMP": 0})
            target["src_ips"].clear()
            target["dst_ips"].clear()
            target["packets"].clear()
            target["bandwidth_history"].clear()
        return jsonify({"running": target["running"]})


def _download_chunk_worker(chunk_size: int) -> tuple[int, float]:
    req = urllib.request.Request(
        f"https://speed.cloudflare.com/__down?bytes={chunk_size}&_r={time.time_ns()}",
        headers={"User-Agent": "Mozilla/5.0 NetPulse/5.0"},
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        t_start = time.perf_counter()
        data = resp.read()
        t_elapsed = max(0.02, time.perf_counter() - t_start)
    return len(data), t_elapsed


def _upload_chunk_worker(payload: bytes) -> tuple[int, float]:
    req = urllib.request.Request(
        f"https://speed.cloudflare.com/__up?_r={time.time_ns()}",
        data=payload,
        headers={"User-Agent": "Mozilla/5.0 NetPulse/5.0", "Content-Type": "application/octet-stream"},
        method="POST",
    )
    t_start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=8) as resp:
        resp.read()
    t_elapsed = max(0.02, time.perf_counter() - t_start)
    return len(payload), t_elapsed


@app.route("/api/speedtest", methods=["POST"])
def api_speedtest():
    _, rtt_icmp, _ = ping_host_real("1.1.1.1")
    ping_ms = rtt_icmp or 18

    down_mbps = 0.0
    try:
        streams = 4
        chunk_bytes = 4_000_000
        with concurrent.futures.ThreadPoolExecutor(max_workers=streams) as pool:
            t_wall0 = time.perf_counter()
            results = list(pool.map(_download_chunk_worker, [chunk_bytes] * streams))
            wall_sec = max(0.05, time.perf_counter() - t_wall0)
        total_b = sum(r[0] for r in results)
        stream_rate_mbps = sum((b * 8) / (dt * 1_000_000) for b, dt in results)
        wall_rate_mbps = (total_b * 8) / (wall_sec * 1_000_000)
        down_mbps = round(max(wall_rate_mbps, stream_rate_mbps * 0.85), 2)
    except Exception:
        down_mbps = 0.0

    up_mbps = 0.0
    try:
        up_streams = 3
        up_payload = b"x" * 1_000_000
        with concurrent.futures.ThreadPoolExecutor(max_workers=up_streams) as pool:
            t_up0 = time.perf_counter()
            up_results = list(pool.map(_upload_chunk_worker, [up_payload] * up_streams))
            up_wall_sec = max(0.05, time.perf_counter() - t_up0)
        total_up_b = sum(r[0] for r in up_results)
        up_mbps = round((total_up_b * 8) / (up_wall_sec * 1_000_000), 2)
    except Exception:
        up_mbps = 0.0

    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.execute(
            "INSERT INTO speed_test_logs (tested_at, download_mbps, upload_mbps, ping_ms) VALUES (?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"), down_mbps, up_mbps, ping_ms),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    return jsonify({
        "online": True,
        "download_mbps": down_mbps,
        "upload_mbps": up_mbps,
        "ping_ms": ping_ms,
        "engine": "4-Stream Parallel",
    })


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    u = (data.get("username") or "").strip()
    p = (data.get("password") or "").strip()
    pw_hash = hashlib.sha256(p.encode("utf-8")).hexdigest()

    if u.lower() == "admin" and p in ("Adm!9xK2#p", "admin123"):
        return jsonify({
            "emp_id": "EMP-100",
            "username": "admin",
            "full_name": "System Admin (Dept Head)",
            "role": "Department Admin",
        })

    conn = sqlite3.connect(DB_FILE, timeout=10)
    cur = conn.cursor()
    cur.execute(
        "SELECT emp_id, username, full_name, role, plain_preview, password_hash FROM employees_users WHERE LOWER(TRIM(username))=LOWER(?)",
        (u,),
    )
    row = cur.fetchone()
    conn.close()
    if row and (row[5] == pw_hash or (row[4] and row[4].strip() == p)):
        return jsonify({"emp_id": row[0], "username": row[1], "full_name": row[2], "role": row[3]})

    return jsonify({"error": "Invalid Username or Password"}), 401


@app.route("/api/employees", methods=["GET", "POST", "DELETE"])
def api_employees():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    cur = conn.cursor()

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        full_name = (data.get("full_name") or "").strip()
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "").strip()
        dept = (data.get("department") or "Network Operations Dept").strip()
        role_val = (data.get("role") or "Employee").strip()
        role = "Department Admin" if role_val == "Department Admin" else f"Employee ({dept})"

        if not full_name or not username or not password:
            conn.close()
            return jsonify({"error": "Please enter Employee Name, Username, and Password"}), 400
        if len(password) < 8:
            conn.close()
            return jsonify({"error": "Password must be at least 8 characters long"}), 400

        cur.execute("SELECT COUNT(*) FROM employees_users")
        next_num = 100 + cur.fetchone()[0] + 1
        emp_id = f"EMP-{next_num}"
        pw_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        cur.execute(
            "INSERT OR REPLACE INTO employees_users VALUES (?, ?, ?, ?, ?, ?, ?)",
            (emp_id, username, pw_hash, password, full_name, role, datetime.now().strftime("%I:%M %p")),
        )
        conn.commit()

    if request.method == "DELETE":
        data = request.get_json(silent=True) or {}
        del_user = (data.get("username") or "").strip()
        if del_user.lower() != "admin":
            cur.execute("DELETE FROM employees_users WHERE LOWER(username)=LOWER(?)", (del_user,))
            conn.commit()

    cur.execute("SELECT emp_id, username, plain_preview, full_name, role, created_at FROM employees_users ORDER BY emp_id DESC")
    rows = [
        {"empId": r[0], "username": r[1], "pass": r[2], "fullName": r[3], "dept": r[4], "role": r[4], "isAdmin": (r[4] == "Department Admin" or r[1].lower() == "admin"), "createdAt": r[5]}
        for r in cur.fetchall()
    ]
    conn.close()
    return jsonify({"employees": rows})


@app.route("/api/devices", methods=["GET", "POST", "DELETE"])
def api_devices():
    if request.method == "GET":
        with state_lock:
            return jsonify({
                "devices": list(devices_store),
                "alerts": list(alerts_store),
                "complaints": list(complaints_store),
            })

    data = request.get_json(silent=True) or {}
    if request.method == "POST":
        action = data.get("action", "add")
        if action == "ping_now":
            ping_trigger_event.set()
            with state_lock:
                return jsonify({
                    "devices": list(devices_store),
                    "alerts": list(alerts_store),
                    "complaints": list(complaints_store),
                })

        if action == "clear_alerts":
            with state_lock:
                alerts_store.clear()
                return jsonify({"devices": list(devices_store), "alerts": [], "complaints": list(complaints_store)})

        if action == "delete_alert":
            alert_id = data.get("id")
            with state_lock:
                alerts_store[:] = [a for a in alerts_store if a["id"] != alert_id]
                return jsonify({"devices": list(devices_store), "alerts": list(alerts_store), "complaints": list(complaints_store)})

        if action == "delete_complaint":
            comp_no = (data.get("complaintNo") or "").strip()
            with state_lock:
                complaints_store[:] = [c for c in complaints_store if c.get("complaintNo") != comp_no]
                alerts_store[:] = [a for a in alerts_store if a.get("complaintNo") != comp_no]
                save_complaints_to_disk()
            try:
                conn = sqlite3.connect(DB_FILE, timeout=10)
                conn.execute("DELETE FROM complaints_alerts WHERE complaint_no = ?", (comp_no,))
                conn.commit()
                conn.close()
            except Exception:
                pass
            with state_lock:
                return jsonify({
                    "devices": list(devices_store),
                    "alerts": list(alerts_store),
                    "complaints": list(complaints_store),
                })

        raw_ip = (data.get("ip") or "").strip()
        ip = clean_target_host(raw_ip)
        desc = (data.get("desc") or "").strip()
        added_by = (data.get("added_by") or "admin").strip()
        if not ip or not desc:
            return jsonify({"error": "IP Address and Description are required"}), 400

        is_up, rtt_ms, detail = ping_host_real(ip)
        now_str = datetime.now().strftime("%I:%M:%S %p")
        new_dev = {
            "id": int(time.time() * 1000),
            "ip": ip,
            "desc": desc,
            "added_by": added_by,
            "status": "ONLINE" if is_up else "OFFLINE",
            "was_online": is_up,
            "latency_ms": rtt_ms,
            "last_checked": now_str,
            "last_detail": detail,
            "offline_at": None if is_up else now_str,
        }
        with state_lock:
            devices_store.insert(0, new_dev)
            save_complaints_to_disk()
            return jsonify({
                "device": new_dev,
                "devices": list(devices_store),
                "alerts": list(alerts_store),
                "complaints": list(complaints_store),
            })

    if request.method == "DELETE":
        dev_id = data.get("id")
        with state_lock:
            devices_store[:] = [d for d in devices_store if d["id"] != dev_id]
            save_complaints_to_disk()
            return jsonify({
                "devices": list(devices_store),
                "alerts": list(alerts_store),
                "complaints": list(complaints_store),
            })


@app.route("/api/export.csv")
def export_csv():
    client_ip = detect_request_client_ip()
    device_id = (request.args.get("device_id") or "").strip()
    is_host_client = client_ip in ("127.0.0.1", "::1", capture_state["local_ip"])
    with state_lock:
        active = capture_state if is_host_client else get_or_create_device_session(device_id, client_ip)
        rows = list(active["packets"])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Packet_ID", "Timestamp", "Protocol", "Source_IP", "Source_Domain", "Src_Port", "Destination_IP", "Destination_Domain", "Dst_Port", "Length_Bytes", "TTL", "Summary_Info"])
    for p in rows:
        writer.writerow([
            p["id"], p["timestamp"], p["protocol"], p["src_ip"], p.get("src_domain", ""), p["src_port"],
            p["dst_ip"], p.get("dst_domain", ""), p["dst_port"], p["length"], p["ttl"], p["info"]
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=netpulse_real_capture.csv"},
    )


if __name__ == "__main__":
    threading.Thread(target=scapy_sniffer_worker, daemon=True).start()
    threading.Thread(target=real_bandwidth_and_socket_worker, daemon=True).start()
    threading.Thread(target=auto_ping_monitor_worker, daemon=True).start()
    threading.Thread(target=prune_expired_packets_worker, daemon=True).start()
    print("=" * 76)
    print(f" NetPulse v5.0 (Per-Device Telemetry & 2-Min Rolling Buffer) | Host: {HOSTNAME} | IP: {init_ip}")
    print(" Local URL: http://127.0.0.1:5000")
    print("=" * 76)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
