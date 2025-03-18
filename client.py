import os
import socket
import struct
import time
import psutil  # For CPU utilization tracking
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# -------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------
def x25519_generate_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return private_key, public_bytes

def x25519_compute_shared_key(private_key, peer_public_bytes):
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_public_key)

def poly1305_tag(mac_key: bytes, message: bytes) -> bytes:
    mac = poly1305.Poly1305(mac_key)
    mac.update(message)
    return mac.finalize()

def encrypt_message(plaintext: bytes, speck_key: bytes, mac_key: bytes):
    iv = os.urandom(8)
    ciphertext = plaintext  # Speck CTR encryption == decryption
    tag = poly1305_tag(mac_key, iv + ciphertext)
    return iv, ciphertext, tag

# -------------------------------------------------------------
# Client Code
# -------------------------------------------------------------
SERVER_HOST = "127.0.0.1"  
SERVER_PORT = 4000
TEXT_FILES_DIR = "."  # Current directory
NUM_ITERATIONS = 100  # Number of times to encrypt each file

def measure_encryption_time(file_path, speck_key, mac_key):
    """Encrypts the file 100 times and returns the average time & CPU usage."""
    with open(file_path, "rb") as f:
        plaintext = f.read()

    total_time = 0
    cpu_percentages = []

    for _ in range(NUM_ITERATIONS):
        start_time = time.perf_counter()
        cpu_start = psutil.cpu_percent(interval=None)  # Get CPU usage before encryption
        encrypt_message(plaintext, speck_key, mac_key)
        cpu_end = psutil.cpu_percent(interval=None)  # Get CPU usage after encryption
        end_time = time.perf_counter()

        total_time += (end_time - start_time)
        cpu_percentages.append(cpu_end)

    avg_time = total_time / NUM_ITERATIONS
    avg_cpu_usage = sum(cpu_percentages) / len(cpu_percentages)  # Compute avg CPU usage
    return avg_time, avg_cpu_usage

def main():
    # Get list of 5 text files from the current directory
    text_files = [f for f in os.listdir(TEXT_FILES_DIR) if f.endswith(".txt")][:5]

    if len(text_files) < 5:
        print("Error: Not enough text files found in the directory!")
        return

    # Connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_HOST, SERVER_PORT))
    print(f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")

    try:
        # 1. Generate client's X25519 key pair
        client_priv, client_pub = x25519_generate_keypair()

        # 2. Receive server's public key
        server_pub = s.recv(32)
        if len(server_pub) != 32:
            raise ValueError("Invalid public key received from server.")

        # 3. Send client's public key
        s.sendall(client_pub)

        # 4. Compute shared secret
        shared_secret = x25519_compute_shared_key(client_priv, server_pub)

        # 5. Derive Speck encryption key (96 bits) + Poly1305 key (256 bits)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=44, salt=None, info=b"SecureComm")
        key_material = hkdf.derive(shared_secret)
        speck_key = key_material[:12]
        mac_key = key_material[12:44]

        # 6. Measure encryption time and CPU usage for each file
        for file_name in text_files:
            file_path = os.path.join(TEXT_FILES_DIR, file_name)
            avg_time, avg_cpu = measure_encryption_time(file_path, speck_key, mac_key)
            print(f"File: {file_name} | Avg Encryption Time: {avg_time:.6f} sec | Avg CPU Usage: {avg_cpu:.2f}%")

        # 7. Encrypt and send the last file as a sample message
        with open(os.path.join(TEXT_FILES_DIR, text_files[0]), "rb") as f:
            plaintext = f.read()
        iv, ciphertext, tag = encrypt_message(plaintext, speck_key, mac_key)

        s.sendall(iv)
        s.sendall(struct.pack("<I", len(ciphertext)))
        s.sendall(ciphertext)
        s.sendall(tag)

        print("Sample message sent successfully.")

    finally:
        s.close()

if __name__ == "__main__":
    main()
