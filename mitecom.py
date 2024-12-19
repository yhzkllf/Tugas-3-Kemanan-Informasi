import json

class PublicKeyRequest:
    def __init__(self, request_for: str, requested_by: str):
        self.request_for = request_for
        self.requested_by = requested_by
    
    def to_msg(self) -> dict:
        return {
            'request_for': self.request_for,
            'requested_by': self.requested_by
        }

class PublicKeyResponse:
    def __init__(self, type: str = "error", value: str = None, message: str = None):
        self.type = type
        self.value = value
        self.message = message
    
    def to_msg(self) -> dict:
        return {
            'type': self.type,
            'value': self.value,
            'message': self.message
        }

class HandshakeMessage:
    def __init__(self, id: str, nonce: bytes):
        self.id = id
        self.nonce = nonce

    def to_msg(self) -> dict:
        return {
            'id': self.id,
            'nonce': self.nonce.hex()
        }

def read_all(client, buf_size: int = 1024) -> bytes:
    data = b''
    while True:
        packet = client.recv(buf_size)
        data += packet
        if len(packet) < buf_size:
            break
    return data
