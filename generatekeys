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
