from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
from scapy.all import DNS, DNSQR, DNSRR
import json
import time
from .socket_client import send_packet_data

# --- Dati traffico ---
traffic = {}  # traffico totale per IP
traffic_proto = {}  # traffico per IP e protocollo
traffic_io = {}  # traffico in/out per host

# --- Funzione di analisi ---
def analyze(packet):
    info = {}
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        size = len(packet)

        # --- Protocollo dettagliato ---
        if proto == 6:  # TCP
            proto_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif proto == 17:  # UDP
            proto_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif proto == 1:  # ICMP
            proto_name = "ICMP"
            sport = dport = None
        else:
            proto_name = str(proto)
            sport = dport = None

        # --- Statistiche per IP e protocollo ---
        traffic[ip_src] = traffic.get(ip_src, 0) + size
        traffic_proto.setdefault(ip_src, {})
        traffic_proto[ip_src][proto_name] = traffic_proto[ip_src].get(proto_name, 0) + size

        # --- Traffico in/out per host ---
        traffic_io.setdefault(ip_src, {"out":0, "in":0})
        traffic_io.setdefault(ip_dst, {"out":0, "in":0})
        traffic_io[ip_src]["out"] += size
        traffic_io[ip_dst]["in"] += size

        info = {
            "src": ip_src,
            "dst": ip_dst,
            "sport": sport,
            "dport": dport,
            "proto": proto_name,
            "size": size
        }
    return info

def analyze_dns(packet):
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        # Query (richiesta)
        if dns_layer.qr == 0:
            query_name = dns_layer.qd.qname.decode()  # dominio richiesto
            print(f"DNS Query: {query_name}")
        # Risposta
        elif dns_layer.qr == 1:
            for i in range(dns_layer.ancount):
                answer = dns_layer.an[i].rrname.decode()
                ip = dns_layer.an[i].rdata
                print(f"DNS Response: {answer} → {ip}")



def analyze_network(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ttl = packet[IP].ttl
        proto = packet[IP].proto
        mac_src = packet[Ether].src if Ether in packet else None
        mac_dst = packet[Ether].dst if Ether in packet else None
        print(f"{ip_src}({mac_src}) → {ip_dst}({mac_dst}) | TTL={ttl} | Proto={proto}")



def analyze_transport(packet):
    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        size = len(packet)
        print(f"TCP {sport} → {dport} | Flags={flags} | Size={size}")
    elif UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        size = len(packet)
        print(f"UDP {sport} → {dport} | Size={size}")



def analyze_application(packet):
    if DNS in packet and packet[DNS].qr == 0:  # query DNS
        domain = packet[DNSQR].qname.decode()
        print(f"DNS query: {domain}")

traffic = {}

def update_stats(ip, size, direction):
    if ip not in traffic:
        traffic[ip] = {'in':0, 'out':0}
    traffic[ip][direction] += size

top_ips = sorted(traffic.items(), key=lambda x: x[1]['in']+x[1]['out'], reverse=True)[:5]

# --- Callback per ogni pacchetto ---
def packet_callback(packet):
    info = analyze(packet)
    if info:
        print(f"{info['src']}:{info['sport']} → {info['dst']}:{info['dport']} | "
              f"{info['proto']} | {info['size']} bytes")

        # --- Top 5 IP più trafficati ---
        top5 = sorted(traffic.items(), key=lambda x: x[1], reverse=True)[:5]
        print("Top 5 IP per traffico:", top5)

        # --- Invia dati alla dashboard ---
        if ws:
            try:
                ws.send(json.dumps({
                    "packet": info,
                    "top5": top5,
                    "traffic_io": traffic_io,
                    "traffic_proto": traffic_proto
                }))
            except Exception as e:
                print("Errore invio WebSocket:", e)
    if packet.haslayer(DNS):
        analyze_dns(packet)
    
    send_packet_data(info)

# --- Avvio sniffer ---
def start_sniffer():
    sniff(prn=packet_callback)



