from scapy.all import IP, TCP, UDP

def analyze(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet.proto
        size = len(packet)
        print(f"{ip_src} → {ip_dst} | Proto: {proto} | Size: {size}")

traffic = {}

def update_traffic(ip, size):
    traffic[ip] = traffic.get(ip, 0) + size
