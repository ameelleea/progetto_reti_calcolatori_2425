from .lib.config import config_host, config_port
from .socket_client import start_socket
from .sniffer import start_sniffer
import argparse

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="The server's URL host")
    parser.add_argument("-p", "--port", help="The server's URL port")

    args = parser.parse_args()

    config_host(args.host)
    config_port(args.port)
    try:
        #start_socket()
        start_sniffer()
    except Exception as e:
        print(e)
    
    pass

if __name__ == "__main__":
    main()