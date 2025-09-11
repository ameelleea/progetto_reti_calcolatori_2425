import socketio
import time
from datetime import datetime
import sys
from .lib.config import HOST, PORT

sio = socketio.Client()

# URL del server Node
SERVER_URL = f"http://{HOST}:{PORT}"

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

def close_socket():
    try:
        sio.disconnect()
        print("[SocketClient] Disconnesso.")
    except Exception:
        pass

def send_traffic_data(dest, data):
    sio.emit(dest, data)

def send_security_alert(dest, message):
    timestamp = datetime.now().isoformat()
    fullmessage = "[" + timestamp + "] " + message
    print(fullmessage)
    sio.emit(dest, fullmessage)

@sio.event
def connect():
    print("Connesso al server WebSocket!")

@sio.event
def disconnect():
    print("Disconnesso dal server.")



