import socket

HOST = 'localhost'
PORT = 3000

def config_host(host):
    HOST = host

def config_port(port):
    PORT = port

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0] 
    except Exception:
        ip = "127.0.0.1"  # fallback
    finally:
        s.close()
    return ip