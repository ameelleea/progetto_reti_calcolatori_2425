from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP
from scapy.all import DNS, DNSQR, DNSRR
import json
import time
from .socket_client import send_packet_data
from .lib.constants import proto_dict
from datetime import datetime

OUTPUT_FILE = "dns_log.json"

def save_to_json(entry):
    """Salva un dict con timestamp in un file JSON"""
    try:
        # se esiste già il file, carica i dati
        with open(OUTPUT_FILE, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # se non esiste o è vuoto, inizia da una lista vuota
        data = []

    # aggiunge un timestamp ISO
    entry_with_time = {
        "timestamp": datetime.now().isoformat(),
        **entry
    }

    # aggiungi il nuovo record
    data.append(entry_with_time)

    # riscrivi il file
    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

# --- Dati traffico ---
traffic = {}  # traffico totale per IP
traffic_proto = {}  # traffico per IP e protocollo
traffic_io = {}  # traffico in/out per host

# --- Funzioni di analisi ---
def analyze_network(packet):
    info = {}

    info["timestamp"] = datetime.now().isoformat()
    # --- Livello di rete ---
    if IP in packet:
        info["network_proto"] = "IP"
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ttl = packet[IP].ttl
        proto = packet[IP].proto
        proto_name = proto_dict[proto]
        size = len(packet)
        mac_src = packet[Ether].src if Ether in packet else None
        mac_dst = packet[Ether].dst if Ether in packet else None
        info["src"] = ip_src
        info["dst"] = ip_dst
        info["size"] = size
        info["proto_name"] = proto_name
        info["mac_src"] = mac_src
        info["mac_dst"] = mac_dst
        info["ttl"] = ttl
        
            # --- ARP ---
    if ARP in packet:
        info["network_proto"] = "ARP"
        arp_layer = packet[ARP]
        info["arp_op"] = "who-has" if arp_layer.op == 1 else "is-at"
        info["arp_psrc"] = arp_layer.psrc
        info["arp_pdst"] = arp_layer.pdst
        info["arp_hwsrc"] = arp_layer.hwsrc
        info["arp_hwdst"] = arp_layer.hwdst

    # --- ICMP ---
    if ICMP in packet:
        info["network_proto"] = "ARP"
        icmp_layer = packet[ICMP]
        info["icmp_type"] = icmp_layer.type
        info["icmp_code"] = icmp_layer.code
        info["icmp_size"] = len(packet)

    # --- Statistiche per IP e protocollo ---
    traffic[ip_src] = traffic.get(ip_src, 0) + size
    traffic_proto.setdefault(ip_src, {})
    traffic_proto[ip_src][proto_name] = traffic_proto[ip_src].get(proto_name, 0) + size

    # --- Traffico in/out per host ---
    traffic_io.setdefault(ip_src, {"out":0, "in":0})
    traffic_io.setdefault(ip_dst, {"out":0, "in":0})
    traffic_io[ip_src]["out"] += size
    traffic_io[ip_dst]["in"] += size

    # --- Livello di trasporto ---
    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        size = len(packet)
        info["sport"] = sport
        info["dport"] = dport
        info["flags"] = str(flags)
        info["size"] = size

    elif UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        size = len(packet)
        #print(f"UDP {sport} → {dport} | Size={size}")
        info["sport"] = sport
        info["dport"] = dport
        info["size"] = size

    # --- Livello applicazione ---
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        # Query (richiesta)
        if dns_layer.qr == 0:
            query_name = dns_layer.qd.qname.decode()  # dominio richiesto
            info["dnsquery"] = query_name
            info["dnsquerytype"] = "Query"
        # Risposta
        elif dns_layer.qr == 1:
            for i in range(dns_layer.ancount):
                answer = dns_layer.an[i].rrname.decode()
                info["dnsquery"] = answer
    save_to_json(info)
    return info

def update_stats(ip, size, direction):
    if ip not in traffic:
        traffic[ip] = {'in':0, 'out':0}
    traffic[ip][direction] += size

top_ips = sorted(traffic.items(), key=lambda x: x[1]['in']+x[1]['out'], reverse=True)[:5]

# --- Callback per ogni pacchetto ---
def packet_callback(packet):
    """info = analyze(packet)
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
    
    send_packet_data(info)"""
    print("Network data: ", analyze_network(packet))
    

# --- Avvio sniffer ---
def start_sniffer():
    sniff(prn=packet_callback)



