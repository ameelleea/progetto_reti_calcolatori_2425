import socketio
import time
import sys
from .lib.config import HOST, PORT
from .lib.exceptions import ConnectionRefusedException

sio = socketio.Client()

# URL del server Node
SERVER_URL = f"http://{HOST}:{PORT}"  # usa il nome del servizio Docker

# Crea client socketio
sio = socketio.Client()

def connect_with_retry(max_retries=10, delay=2):
    """
    Tenta di connettersi al server Node con più retry.
    """
    for attempt in range(1, max_retries + 1):
        try:
            print(f"[SocketClient] Tentativo {attempt}/{max_retries} di connessione a {SERVER_URL}...")
            sio.connect(SERVER_URL)
            print("[SocketClient] Connessione riuscita")
            return True
        except Exception as e:
            print(f"[SocketClient] Connessione fallita: {e}")
            if attempt < max_retries:
                time.sleep(delay)
            else:
                print("[SocketClient] Errore: impossibile connettersi al server dopo più tentativi.")
                sys.exit(1)

def start_socket():
    connect_with_retry()


'''def start_socket():
    try:
        sio.connect(f'http://{HOST}:{PORT}')
    except Exception as e:
        raise ConnectionRefusedException
'''
def close_socket():
    try:
        sio.disconnect()
        print("[SocketClient] Disconnesso.")
    except Exception:
        pass

def send_traffic_data(dest, data):
    """
    dest: evento websocket al quale inviare i dati
    data: dict con le informazioni da inviare
    """
    sio.emit(dest, data)

def send_security_alert(dest, message):
    sio.emit(dest, message)

@sio.event
def connect():
    print("Connesso al server WebSocket!")

@sio.event
def disconnect():
    print("Disconnesso dal server.")

# Connessione al server Node
#sio.connect("http://localhost:3000")


