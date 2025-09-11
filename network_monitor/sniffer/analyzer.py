import time
from scapy.all import Ether, IP, TCP, UDP, DNS
import socket 
from datetime import datetime

from .socket_client import send_traffic_data
from .lib.constants import proto_dict
from .lib.config import get_local_ip

LOCAL_IP = get_local_ip()

buffer = []

# --- Dati traffico ---
traffic = {}  # traffico totale per IP
traffic_proto = {}  # traffico per IP e protocollo
traffic_io = {"out": {0: 0}, "in": {0: 0}}  # traffico in/out per host
top_ips = {}

# --- Trova tutti gli IP locali ---
def get_local_ips():
    local_ips = set()
    
    hostname = socket.gethostname()
    
    try:
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        for ip in ip_list:
            local_ips.add(ip)
    except socket.gaierror:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass

    return local_ips

local_ips = get_local_ips()

# --- Funzioni di analisi ---
def process_ip_packet(packet, start_time):
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
            info["sport"] = sport
            info["dport"] = dport


        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            # Query (richiesta)
            if dns_layer.qr == 0:
                query_name = dns_layer.qd.qname.decode()
                info["dnsquery"] = query_name
                info["dnsquerytype"] = "Query"
            # Risposta
            elif dns_layer.qr == 1:
                for i in range(dns_layer.ancount):
                    answer = dns_layer.an[i].rrname.decode()
                    info["dnsquery"] = answer

        buffer.append(info)
        if len(buffer) >= 5:  # invia ogni 5 pacchetti
            send_traffic_data("packet_log_data", buffer)
            send_traffic_data("ip_log_data", top_ips)
            send_traffic_data("protocol_traffic_data", traffic_proto)
            send_traffic_data("io_traffic_data", traffic_io)
            buffer.clear()


def update_stats(ip_src, ip_dst, size, proto_name, start_time):
    # --- Statistiche per IP e protocollo ---
    traffic[ip_src] = traffic.get(ip_src, 0) + size
    traffic_proto[proto_name] = traffic_proto.get(proto_name, 0) + size

    # --- Traffico in/out per host ---
    elapsed = time.time() - start_time

    if ip_dst.startswith("224.") or ip_dst == "255.255.255.255":
        pass

    if ip_src in local_ips:
        # out
        lastkey = next(reversed(traffic_io["out"]))
        traffic_io["out"][elapsed] = traffic_io["out"][lastkey] + size

    elif ip_dst in local_ips:
        # in
        lastkey = next(reversed(traffic_io["in"]))
        traffic_io["in"][elapsed] = traffic_io["in"][lastkey] + size

    else:
        print(f"Direction unknown: {ip_src} -> {ip_dst}")
        pass

    global top_ips
    top_ips = dict(sorted(traffic.items(), key=lambda x: x[1], reverse=True)[:5])



