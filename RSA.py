import os

class RSA:
    def __init__(self, node):
        """
        Initialize the RSA instance with a node identifier.
        Automatically reads the associated public and private keys.
        """
        self.node = node
        self.read_keys()

    def read_keys(self):
        """
        Reads public and private keys from files associated with the node.
        """
        base_dir = os.path.dirname(__file__)

        public_key_path = os.path.join(base_dir, f"pub_keys/{self.node}.pem")
        with open(public_key_path, "r") as file:
            self.public_key = tuple(map(int, file.read().split(",")))

        private_key_path = os.path.join(base_dir, f"priv_keys/{self.node}.pem")
        with open(private_key_path, "r") as file:
            self.private_key = tuple(map(int, file.read().split(",")))

    def encrypt(self, plaintext, key=None):
        """
        Encrypts plaintext using the specified key or the instance's public key.

        Args:
            plaintext (str): The text to be encrypted.
            key (tuple, optional): The (e, n) key pair for encryption. Defaults to the public key.

        Returns:
            str: The ciphertext as a space-separated string of integers.
        """
        e, n = key if key else self.public_key
        cipher = [pow(ord(char), e, n) for char in plaintext]
        return ' '.join(map(str, cipher))

    def decrypt(self, ciphertext, key=None):
        """
        Decrypts ciphertext using the specified key or the instance's private key.

        Args:
            ciphertext (str): The ciphertext as a space-separated string of integers.
            key (tuple, optional): The (d, n) key pair for decryption. Defaults to the private key.

        Returns:
            str: The decrypted plaintext.
        """
        d, n = key if key else self.private_key
        cipher = list(map(int, ciphertext.split()))
        return ''.join(chr(pow(char, d, n)) for char in cipher)

if __name__ == "__main__":
    # Create an RSA instance for the "initiator" node
    rsa = RSA("initiator")

    # Example plaintext message
    plaintext = "Hello, World!"

    # Encrypt the plaintext message
    ciphertext = rsa.encrypt(plaintext)
    print("Plain Text:", plaintext)
    print("Cipher Text:", ciphertext)

    # Decrypt the ciphertext back to the original message
    decrypted_message = rsa.decrypt(ciphertext)
    print("Decrypted Message:", decrypted_message)
