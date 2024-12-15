import socket
import json
import os

from utils.mitecom import PublicKeyRequest, HandshakeMessage, read_all
from utils.RSA import RSA
from utils.DES import DES


PKA_ADDRESS = ('127.0.0.1', 12345)
RESPONDER_ADDRESS = ('127.0.0.1', 12346)

PUBLIC_KEYS = {}

rsa = RSA("initiator")

def load_pka_public_key():
    """Load the PKA's public key from a file."""
    base_dir = os.path.dirname(__file__)
    key_file = os.path.join(base_dir, "utils/pub_keys/pka.pem")
    with open(key_file, "r") as file:
        PUBLIC_KEYS["pka"] = tuple(map(int, file.read().strip().split(",")))

def fetch_responder_public_key():
    """Retrieve the responder's public key from the PKA."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(PKA_ADDRESS)

    request = PublicKeyRequest("responder", "initiator")
    client_socket.sendall(json.dumps(request.to_msg()).encode('utf-8'))

    response_data = read_all(client_socket)
    encrypted_response = json.loads(response_data)

    decrypted_response = rsa.decrypt(encrypted_response, PUBLIC_KEYS["pka"])
    response = json.loads(decrypted_response)

    if response['type'] == "error":
        print(f"Error: {response['message']}")
        success = False
    else:
        PUBLIC_KEYS["responder"] = response['value']
        success = True

    client_socket.close()
    return success

def perform_handshake(client_socket):
    """Perform a handshake to establish trust with the responder."""
    nonce_initiator = os.urandom(16)
    handshake_request = HandshakeMessage("initiator", nonce_initiator)

    encrypted_request = rsa.encrypt(json.dumps(handshake_request.to_msg()), PUBLIC_KEYS["responder"])
    client_socket.sendall(json.dumps(encrypted_request).encode('utf-8'))

    response_data = read_all(client_socket)
    encrypted_response = json.loads(response_data)

    decrypted_response = rsa.decrypt(encrypted_response)
    response = json.loads(decrypted_response)

    combined_nonce = bytes.fromhex(response['nonce'])

    if nonce_initiator in combined_nonce:
        nonce_responder = combined_nonce[:16]
        handshake_response = HandshakeMessage("initiator", nonce_responder)
        encrypted_response = rsa.encrypt(json.dumps(handshake_response.to_msg()), PUBLIC_KEYS["responder"])
        client_socket.sendall(json.dumps(encrypted_response).encode('utf-8'))
        return True
    else:
        print(f"Nonce mismatch: {nonce_initiator} not found in {combined_nonce}")
        return False

def generate_des_key():
    """Generate a random 64-bit DES key."""
    return os.urandom(4).hex()

def send_des_key_to_responder(new_key, client_socket):
    """Encrypt and send a new DES key to the responder."""
    try:
        encrypted_with_private_key = rsa.encrypt(new_key, rsa.private_key)
        doubly_encrypted_key = rsa.encrypt(encrypted_with_private_key, PUBLIC_KEYS["responder"])
        client_socket.sendall(doubly_encrypted_key.encode('utf-8'))
    except Exception as e:
        print(f"Failed to send DES key: {e}")

def start_publisher():
    """Start the communication process as the initiator."""
    print("Publisher starting...")
    des_cipher = None
    message_counter = 0

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(RESPONDER_ADDRESS)

        if perform_handshake(client_socket):
            print("Handshake successful!")

            while True:
                if message_counter % 5 == 0:
                    new_des_key = generate_des_key()
                    des_cipher = DES(new_des_key)
                    send_des_key_to_responder(new_des_key, client_socket)
                    print(f"New DES key sent: {new_des_key}")
                else:
                    message = input("Enter a message to send (or type 'exit' to quit): ")
                    if message.lower() == 'exit':
                        print("Terminating connection...")
                        break

                    encrypted_message = des_cipher.encrypt(message)
                    client_socket.sendall(encrypted_message.encode('utf-8'))
                    print(f"Encrypted message sent: {encrypted_message}")

                message_counter += 1
    except Exception as e:
        print(f"Error during publishing: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    load_pka_public_key()
    if fetch_responder_public_key():
        start_publisher()
