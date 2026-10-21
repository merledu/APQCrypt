"""
Makes a small SAMPLE capture (data/traffic.pcapng) WITHOUT Mininet, so you can test the
dashboard on Windows. It contains: ARP, ping, HTTPS to a bank-like name (SNI), HTTPS to a
normal name, HTTP login (POST + Authorization), plain HTTP GET, an SSH greeting,
DNS A and MX questions, NTP, and some plain TCP/UDP.

Run:  python make_sample_pcap.py
Then tick "Reuse last capture" in the dashboard and press Start.
This is TEST DATA ONLY. For real results use the Linux capture (Mininet).
"""
import os
import ssl
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, Raw, wrpcap, conf

conf.verb = 0
os.makedirs("data", exist_ok=True)
H1, H2 = "10.0.0.1", "10.0.0.2"
pk, t = [], [1000.0]


def add(p):
    p.time = t[0]
    t[0] += 0.01
    pk.append(p)


def tcp(sp, dp, flags, payload=b"", src=H1, dst=H2):
    p = Ether() / IP(src=src, dst=dst, flags="DF") / TCP(sport=sp, dport=dp, flags=flags, window=64240)
    if payload:
        p = p / Raw(payload)
    add(p)


def client_hello(name):
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


# ARP and ping
add(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=H1, pdst=H2))
add(Ether() / ARP(op=2, psrc=H2, pdst=H1, hwdst="00:00:00:00:00:01"))
for _ in range(3):
    add(Ether() / IP(src=H1, dst=H2) / ICMP() / Raw(b"x" * 20))

# HTTPS (port 8443) with a bank-like name, and a normal name
tcp(40001, 8443, "S"); tcp(8443, 40001, "SA", src=H2, dst=H1); tcp(40001, 8443, "A")
tcp(40001, 8443, "PA", client_hello("bank.example.com"))
tcp(8443, 40001, "PA", b"\x16\x03\x03" + b"a" * 60, src=H2, dst=H1)
tcp(40002, 8443, "S"); tcp(40002, 8443, "PA", client_hello("cdn.example.net"))

# HTTP (port 8000): login POST with Authorization, and a plain GET
tcp(40003, 8000, "S")
tcp(40003, 8000, "PA", b"POST /login HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abc\r\n\r\nuser=a")
tcp(40004, 8000, "PA", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")

# SSH greeting
tcp(40005, 22, "S")
tcp(22, 40005, "PA", b"SSH-2.0-OpenSSH_9.6\r\n", src=H2, dst=H1)


# DNS: A question and MX question
def dns(sport, qtype):
    q = bytes([1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 109, 97, 105, 108, 7, 101, 120, 97, 109, 112,
               108, 101, 3, 99, 111, 109, 0, 0, qtype, 0, 1])
    add(Ether() / IP(src=H1, dst=H2) / UDP(sport=sport, dport=53) / Raw(q))


dns(50001, 1)
dns(50002, 15)

# NTP, plain TCP, plain UDP
add(Ether() / IP(src=H1, dst=H2) / UDP(sport=50003, dport=123) / Raw(b"\x1b" + b"\0" * 47))
tcp(40006, 5555, "PA", b"hello world")
add(Ether() / IP(src=H1, dst=H2) / UDP(sport=50004, dport=9999) / Raw(b"ping"))

wrpcap("data/traffic.pcapng", pk)
print(f"Wrote data/traffic.pcapng with {len(pk)} packets")
