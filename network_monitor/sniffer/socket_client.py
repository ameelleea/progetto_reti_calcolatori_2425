import socketio
from .lib.config import HOST, PORT
from .lib.exceptions import ConnectionRefusedException

sio = socketio.Client()

def start_socket():
    try:
        sio.connect(f'http://{HOST}:{PORT}')
    except Exception as e:
        raise ConnectionRefusedException

def send_packet_data(data):
    """
    data: dict con le informazioni da inviare
    """
    sio.emit('packet', data)
