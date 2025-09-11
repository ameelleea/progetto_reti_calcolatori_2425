from .lib.config import config_host, config_port
from .socket_client import start_socket, close_socket
from .sniffer import start_sniffer
from scapy.all import conf
import argparse
import threading

def main():

    parser = argparse.ArgumentParser(description="Network Sniffer with Attack Detection")
    parser.add_argument("--iface", help="Interfaccia di rete da sniffare (default: interfaccia principale)", default=conf.iface)

    parser.add_argument("-H", "--host", help="The server's URL host")
    parser.add_argument("-p", "--port", help="The server's URL port")

    args = parser.parse_args()

    config_host(args.host)
    config_port(args.port)
    try:
        start_socket()
        start_sniffer(iface=args.iface)
        close_socket()
    except Exception as e:
        print(e)
        close_socket()

if __name__ == "__main__":
    main()