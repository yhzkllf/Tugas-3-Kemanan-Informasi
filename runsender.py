import socket
import logging
from algoritmaDES import algoritmaDES

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = '127.0.0.1'
PORT = 12345

def encrypt_and_send_message(message: str, DES, connection):
    try:
        encrypted_message = DES.encrypt(message)
        connection.sendall(encrypted_message.encode())
        logging.info(f"Sent Encrypted Message: {encrypted_message}")
    except Exception as e:
        logging.error(f"Failed to encrypt or send message: {e}")

def start_sender(host=HOST, port=PORT):
    DES = algoritmaDES()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((host, port))
            logging.info(f"Connected to server at {host}:{port}")

            while True:
                message = input("Enter message to send (type 'exit' to quit): ").strip()
                if not message:
                    logging.warning("Message is empty. Please enter a valid message.")
                    continue

                if message.lower() == 'exit':
                    logging.info("Exiting...")
                    break

                encrypt_and_send_message(message, DES, client_socket)
        except ConnectionRefusedError:
            logging.error(f"Connection refused by the server at {host}:{port}")
        except ConnectionError as e:
            logging.error(f"Connection error: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
        finally:
            logging.info("Closing the connection...")

if __name__ == "__main__":
    start_sender()
``` ### 1. `generate_keys.py`
- Add error handling for file operations.
- Ensure that the public and private key directories exist before saving keys.
- Improve the prime generation function to avoid generating the same prime twice.

```python
import random
from sympy import isprime, mod_inverse
import os

NODES = ["initiator", "responder", "pka"]

def generate_prime_candidate(length):
    p = 0
    while not isprime(p):
        p = random.getrandbits(length)
    return p

def generate_keypair(bits):
    p = generate_prime_candidate(bits // 2)
    q = generate_prime_candidate(bits // 2)
    
    # Ensure p and q are different
    while p == q:
        q = generate_prime_candidate(bits // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def save_keys(public_key, private_key, node):
    script_dir = os.path.dirname(__file__)
    public_key_path = os.path.join(script_dir, f"pub_keys/{node}.pem")
    private_key_path = os.path.join(script_dir, f"priv_keys/{node}.pem")
    
    # Ensure directories exist
    os.makedirs(os.path.dirname(public_key_path), exist_ok=True)
    os.makedirs(os.path.dirname(private_key_path), exist_ok=True)

    try:
        with open(public_key_path, "w") as f:
            f.write(f"{public_key[0]},{public_key[1]}")
        
        with open(private_key_path, "w") as f:
            f.write(f"{private_key[0]},{private_key[1]}")
    except IOError as e:
        print(f"Error saving keys for {node}: {e}")

if __name__ == "__main__":
    bits = 1024

    for node in NODES:
        public_key, private_key = generate_keypair(bits)
        save_keys(public_key, private_key, node)
        print(f"Generated keys for {node}")
