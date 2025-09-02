traffic = {}

def process_packet(packet):
    ip = packet[0][1].src if packet.haslayer("IP") else None
    size = len(packet)
    if ip:
        traffic[ip] = traffic.get(ip, 0) + size
