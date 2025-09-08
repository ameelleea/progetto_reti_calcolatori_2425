class ConnectionRefusedException(Exception):
    def __init__(self, message="Connection refused: no server listening on port."):
        # chiama il costruttore della superclasse
        super().__init__(message)
        self.message = message

    def __str__(self):
        return f"[SocketError] {self.message}"
