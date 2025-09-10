import socketio
from .lib.config import HOST, PORT
from .lib.exceptions import ConnectionRefusedException

sio = socketio.Client()

def start_socket():
    try:
        sio.connect(f'http://{HOST}:{PORT}')
    except Exception as e:
        raise ConnectionRefusedException

def close_socket():
    sio.disconnect()

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


