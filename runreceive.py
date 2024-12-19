import socket
import logging
from algoritmaDES import algoritmaDES

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = '0.0.0.0'
PORT = 12345

def handle_client_connection(conn, DES):
    try:
        addr = conn.getpeername()
        logging.info(f"Connected by {addr}")

        while True:
            logging.info("Waiting for message...")
            data = conn.recv(1024)
            if not data:
                logging.info("Client disconnected.")
                break
            
            ciphertext = data.decode ().strip()
            logging.info(f"Cipher Text: {ciphertext}")
            
            try:
                plaintext = DES.decrypt(ciphertext)
                logging.info(f"Plain Text: {plaintext}")
            except Exception as e:
                logging.error(f"Failed to decrypt message: {e}")
                conn.sendall(b"Error: Failed to decrypt message.")
    except Exception as e:
        logging.error(f"An error occurred with the client connection: {e}")

def start_receiver(host=HOST, port=PORT):
    DES = algoritmaDES()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            server_socket.bind((host, port))
            server_socket.listen()
            logging.info(f"Server listening on {host}:{port}")

            while True:
                conn, addr = server_socket.accept()
                logging.info(f"Accepted connection from {addr}")
                handle_client_connection(conn, DES)
        except KeyboardInterrupt:
            logging.info("Shutting down server...")
        except Exception as e:
            logging.error(f"Server error: {e}")
        finally:
            logging.info("Server closed.")

if __name__ == "__main__":
    start_receiver()
