import time
from scapy.all import Ether, IP, TCP, UDP
from scapy.all import DNS
from datetime import datetime

from .socket_client import send_traffic_data
from .lib.constants import proto_dict
from .lib.config import get_local_ip

LOCAL_IP = get_local_ip()

# --- Dati traffico ---
traffic = {}  # traffico totale per IP
traffic_proto = {}  # traffico per IP e protocollo
traffic_io = {"out": {0: 0}, "in": {0: 0}}  # traffico in/out per host
top_ips = {}

# --- Funzioni di analisi ---
def process_ip_packet(packet, start_time):
    # --- Livello di rete ---
    # --- IP ---
    print(packet.summary())
    if IP in packet:
        info = {
            "timestamp": datetime.now().isoformat(),
            "network_proto": '',     
            "src": '', 
            "dst": '', 
            "size": '',     
            "proto_name": '',
            "mac_src": '', 
            "mac_dst": '',    
            "sport": '', 
            "dport": '', 
            "flags": '',
            "dnsquery": '', 
            "dnsquerytype": ''
        }
        info["network_proto"] = "IP"
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
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

        update_stats(ip_src, ip_dst, size, proto_name, start_time)

        # --- Livello di trasporto ---
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            size = len(packet)
            info["sport"] = sport
            info["dport"] = dport
            info["flags"] = str(flags)

        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            size = len(packet)
            #print(f"UDP {sport} → {dport} | Size={size}")
            info["sport"] = sport
            info["dport"] = dport

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

        send_traffic_data("packet_log_data", info)
        send_traffic_data("ip_log_data", top_ips)
        send_traffic_data("protocol_traffic_data", traffic_proto)
        send_traffic_data("io_traffic_data", traffic_io)

def update_stats(ip_src, ip_dst, size, proto_name, start_time):
    # --- Statistiche per IP e protocollo ---
    traffic[ip_src] = traffic.get(ip_src, 0) + size
    traffic_proto[proto_name] = traffic_proto.get(proto_name, 0) + size

    # --- Traffico in/out per host ---
    elapsed = time.time() - start_time

    if(ip_src == LOCAL_IP):
        lastkey = next(reversed(traffic_io["out"]))
        newsize = (traffic_io['out'][lastkey] + size)
        traffic_io["out"][elapsed] = newsize
    elif(ip_dst == LOCAL_IP):
        lastkey = next(reversed(traffic_io["in"]))
        newsize = (traffic_io['in'][lastkey] + size)
        traffic_io["in"][elapsed] = newsize
    else:
        print("Direction unkown.")

    global top_ips
    top_ips = dict(sorted(traffic.items(), key=lambda x: x[1], reverse=True)[:5])





