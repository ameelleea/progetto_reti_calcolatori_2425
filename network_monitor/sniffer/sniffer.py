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
        print("[NetSniffer] ", e)

# --- Avvio sniffer ---
def start_sniffer(iface=None):
    global start_time
    start_time = time.time()
    print(f"[NetSniffer] Sniffer avviato su interfaccia {iface}.")

    sniff(prn=packet_callback, store=False, iface=iface)
    print("[NetSniffer] Sniffer interrupt")



