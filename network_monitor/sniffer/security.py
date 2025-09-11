from scapy.all import ARP, IP, TCP, UDP, DNS, DNSQR, Raw, ICMP
from collections import defaultdict
import time
from .socket_client import send_security_alert

TIME_WINDOW = 10 

# Strutture dati per accumulare traffico
traffic_stats = {
    "syn": defaultdict(list),      
    "rst": defaultdict(list),      
    "udp": defaultdict(list),      
    "dns": defaultdict(list),      
    "generic": defaultdict(list)   
}

arp_table = {}   
ping_count = {}  


def run_security_scan(pkt):
    detect_arp_spoof(pkt)
    detect_icmp(pkt)
    detect_syn_flood(pkt)
    detect_tcp_reset(pkt)
    detect_udp_amplification(pkt)
    detect_dns_tunneling(pkt)
    detect_ddos(pkt)

# --- ARP Spoofing ---
def detect_arp_spoof(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc

        if ip in arp_table and arp_table[ip] != mac:
            message = f"[ALERT] ARP Spoofing detected: {ip} -> {arp_table[ip]} e {mac}"
            send_security_alert("security_alert_listener", message)
        else:
            arp_table[ip] = mac


# --- ICMP Flood / Ping Scan ---
def detect_icmp(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt.haslayer(IP):  # echo request
        src = pkt[IP].src
        ping_count[src] = ping_count.get(src, 0) + 1

        if ping_count[src] > 10:
            message = f"[ALERT] ICMP scan: received too many pings from {src}"
            send_security_alert("security_alert_listener", message)


# --- SYN Flood ---
def detect_syn_flood(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt[TCP].flags == "S":
        src = pkt[IP].src
        now = time.time()

        traffic_stats["syn"][src].append(now)
        # tieni solo eventi recenti
        traffic_stats["syn"][src] = [t for t in traffic_stats["syn"][src] if now - t < TIME_WINDOW]

        if len(traffic_stats["syn"][src]) > 50:
            message = f"[ALERT] Suspect SYN flood from {src} ({len(traffic_stats['syn'][src])} SYN in {TIME_WINDOW}s)"
            send_security_alert("security_alert_listener", message)


# --- TCP Reset Attack ---
def detect_tcp_reset(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt[TCP].flags == "R":
        src = pkt[IP].src
        now = time.time()

        traffic_stats["rst"][src].append(now)
        traffic_stats["rst"][src] = [t for t in traffic_stats["rst"][src] if now - t < TIME_WINDOW]

        if len(traffic_stats["rst"][src]) > 20:
            message = f"[ALERT] Possible TCP Reset Attack from {src}"
            send_security_alert("security_alert_listener", message)


# --- UDP Amplification ---
def detect_udp_amplification(pkt):
    if pkt.haslayer(UDP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
        size = len(pkt[Raw].load)
        now = time.time()

        traffic_stats["udp"][(src, dst)].append((now, size))
        traffic_stats["udp"][(src, dst)] = [(t, s) for t, s in traffic_stats["udp"][(src, dst)] if now - t < TIME_WINDOW]

        # euristica: risposta molto più grande della richiesta
        if len(traffic_stats["udp"][(src, dst)]) > 2:
            sizes = [s for _, s in traffic_stats["udp"][(src, dst)]]
            if max(sizes) > 3 * min(sizes):
                message = f"[ALERT] Suspect UDP amplification between {src} -> {dst} (ratio {max(sizes)}/{min(sizes)})"
                send_security_alert("security_alert_listener", message)


# --- DNS Tunneling ---
def detect_dns_tunneling(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(IP):
        query = pkt[DNSQR].qname.decode("utf-8", errors="ignore")
        src = pkt[IP].src
        now = time.time()

        traffic_stats["dns"][src].append(now)
        traffic_stats["dns"][src] = [t for t in traffic_stats["dns"][src] if now - t < TIME_WINDOW]

        # euristiche di tunneling DNS
        if len(query) > 50 or query.count(".") > 5:
            message = f"[ALERT] Suspect DNS Tunneling from {src}, suspicious query: {query}"
            send_security_alert("security_alert_listener", message)

        if len(traffic_stats["dns"][src]) > 30:
            message = f"[ALERT] Suspect DNS Tunneling flood from {src} ({len(traffic_stats['dns'][src])} query in {TIME_WINDOW}s)"
            send_security_alert("security_alert_listener", message)


# --- DDoS Detection ---
def detect_ddos(pkt):
    if pkt.haslayer(IP):
        dst = pkt[IP].dst
        src = pkt[IP].src
        now = time.time()

        # Salvo timestamp + sorgente
        traffic_stats["generic"][dst].append((now, src))
        traffic_stats["generic"][dst] = [(t, s) for (t, s) in traffic_stats["generic"][dst] if now - t < TIME_WINDOW]

        # Conta sorgenti uniche
        unique_sources = {s for (_, s) in traffic_stats["generic"][dst]}

        if len(unique_sources) > 30:
            message = f"[ALERT] Suspect DDoS on {dst} from {len(unique_sources)} unique sources"
            send_security_alert("security_alert_listener", message)
