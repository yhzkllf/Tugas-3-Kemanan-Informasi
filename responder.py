import socket
import json
import os

from utils.mitecom import PublicKeyRequest, HandshakeMessage, read_all
from utils.RSA import RSA
from utils.DES import DES

PKA_HOST = '127.0.0.1'
PKA_PORT = 12345

RESPONDER_HOST = '127.0.0.1'
RESPONDER_PORT = 12346

PUBLIC_KEYS = {}

rsa = RSA("responder")

def load_pka_public_key():
    """Load the public key of the PKA node."""
    key_path = os.path.join(os.path.dirname(__file__), "utils/pub_keys/pka.pem")
    with open(key_path, "r") as key_file:
        PUBLIC_KEYS["pka"] = tuple(map(int, key_file.read().strip().split(",")))

def retrieve_initiator_public_key():
    """Fetch the public key of the initiator from the PKA."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((PKA_HOST, PKA_PORT))
    
    request = PublicKeyRequest("initiator", "responder")
    client.sendall(json.dumps(request.to_msg()).encode('utf-8'))

    response = read_all(client)
    ciphertext = json.loads(response)
    
    decrypted_response = rsa.decrypt(ciphertext, PUBLIC_KEYS["pka"])
    plaintext = json.loads(decrypted_response)

    if plaintext['type'] == "error":
        print(f"Error: {plaintext['message']}")
        client.close()
        return False

    PUBLIC_KEYS["initiator"] = plaintext['value']
    client.close()
    return True

def perform_handshake(client):
    """Handle the handshake process with the initiator."""
    data = read_all(client)
    ciphertext = json.loads(data)

    decrypted_data = rsa.decrypt(ciphertext)
    plaintext = json.loads(decrypted_data)

    initiator_id = plaintext['id']
    print(f"Received handshake from {initiator_id}")

    if not retrieve_initiator_public_key():
        print("Handshake failed: Unable to retrieve initiator's public key.")
        client.close()
        return False

    n2 = os.urandom(16)
    combined_nonce = n2 + bytes.fromhex(plaintext['nonce'])
    response = HandshakeMessage("responder", combined_nonce)

    encrypted_response = rsa.encrypt(json.dumps(response.to_msg()), PUBLIC_KEYS["initiator"])
    client.sendall(json.dumps(encrypted_response).encode('utf-8'))

    confirmation_data = read_all(client)
    confirmation_ciphertext = json.loads(confirmation_data)
    decrypted_confirmation = rsa.decrypt(confirmation_ciphertext)

    confirmation_plaintext = json.loads(decrypted_confirmation)
    nonce = bytes.fromhex(confirmation_plaintext['nonce'])

    if nonce != n2:
        print(f"Handshake failed: Nonce mismatch ({nonce} != {n2}).")
        client.close()
        return False

    print("Handshake successful!")
    return True

def update_des_key(data):
    """Decrypt and update the DES key."""
    decrypted_once = rsa.decrypt(data)
    decrypted_key = rsa.decrypt(decrypted_once, PUBLIC_KEYS["initiator"])
    return decrypted_key

def start_responder():
    """Start the responder server to handle connections and communication."""
    print("Starting responder...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((RESPONDER_HOST, RESPONDER_PORT))
    server.listen(5)

    counter = 0
    des = None
    handshake_completed = False

    try:
        client, _ = server.accept()

        while True:
            if not handshake_completed:
                handshake_completed = perform_handshake(client)

            if handshake_completed:
                data = read_all(client).decode()

                if counter % 5 == 0:
                    new_key = update_des_key(data)
                    des = DES(new_key)
                    print(f"Updated DES Key: {new_key}")
                elif des is not None:
                    decrypted_message = des.decrypt(data)
                    print(f"Ciphertext: {data}")
                    print(f"Decrypted Message: {decrypted_message}")
                else:
                    print("DES key is not initialized yet.")

                counter += 1
            else:
                print("Handshake failed. Closing connection.")
                client.close()
                break
    except KeyboardInterrupt:
        print("Shutting down responder...")
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    load_pka_public_key()
    start_responder()
