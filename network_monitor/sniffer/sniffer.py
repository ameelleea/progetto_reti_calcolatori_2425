from scapy.all import sniff
from .analyzer import process_ip_packet
from .security import run_security_scan
import time

start_time = 0

def packet_callback(pkt):
    try:
        process_ip_packet(pkt, start_time)
        run_security_scan(pkt)
    except Exception as e:
        print("Errore: sniffer line 12, ", e)

# --- Avvio sniffer ---
def start_sniffer():
    global start_time
    start_time = time.time()
    print("Sniffer avviato.")

    sniff(prn=packet_callback, store=False)

    print("Sniffer interrupt")



