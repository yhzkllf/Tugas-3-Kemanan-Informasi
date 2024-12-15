import socket
import json
import os

from utils.mitecom import PublicKeyResponse, read_all
from utils.RSA import RSA

HOST = '127.0.0.1'
PORT = 12345

# Initialize the server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

PUBLIC_KEYS = {}

def load_public_keys():
    """Load public keys for all nodes except PKA from the keys directory."""
    base_dir = os.path.dirname(__file__)
    keys_dir = os.path.join(base_dir, "utils/pub_keys")

    for file_name in os.listdir(keys_dir):
        if file_name.endswith(".pem"):
            node_name = file_name.split(".")[0]
            # Skip PKA key as it is handled by RSA class
            if node_name != "pka":
                with open(os.path.join(keys_dir, file_name), "r") as key_file:
                    key = tuple(map(int, key_file.read().strip().split(",")))
                    PUBLIC_KEYS[node_name] = key

def process_request(client_socket):
    """Process incoming client requests and return the appropriate response."""
    request_data = read_all(client_socket).decode()
    response = PublicKeyResponse()

    try:
        request = json.loads(request_data)

        # Validate request fields
        if request['request_for'] not in PUBLIC_KEYS:
            response.type = "error"
            response.message = "The requested public key was not found."
        elif request['requested_by'] not in PUBLIC_KEYS:
            response.type = "error"
            response.message = "Unauthorized requester!"
        else:
            response.type = "success"
            response.value = PUBLIC_KEYS[request['request_for']]
    except json.JSONDecodeError:
        response.type = "error"
        response.message = "Invalid JSON in request."

    return json.dumps(response.to_msg())

if __name__ == "__main__":
    load_public_keys()
    rsa = RSA("pka")

    try:
        print("Public Key Authority server is running...")

        while True:
            client_socket, client_address = server.accept()

            try:
                # Handle the client's request
                response = process_request(client_socket)
                encrypted_response = rsa.encrypt(response, rsa.private_key)

                # Send encrypted response back to the client
                client_socket.sendall(json.dumps(encrypted_response).encode('utf-8'))
            finally:
                client_socket.close()
    except KeyboardInterrupt:
        print("Shutting down the server...")
    finally:
        server.close()
