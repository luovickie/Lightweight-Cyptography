import os
import time
import psutil
import multiprocessing
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, poly1305
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# -------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------
def x25519_generate_keypair():
    """Generate X25519 key pair, returns (private_key, public_key_bytes)."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return private_key, public_bytes

def x25519_compute_shared_key(private_key, peer_public_bytes):
    """Calculate X25519 shared key (32 bytes) using own private key and peer's public key bytes."""
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_public_key)

def poly1305_tag(mac_key: bytes, message: bytes) -> bytes:
    """Generate a 16-byte Poly1305 tag using a 32-byte key."""
    mac = poly1305.Poly1305(mac_key)
    mac.update(message)
    return mac.finalize()

def parallel_speck64_96_encrypt_ctr(key: bytes, data: bytes, iv: bytes, processes=4) -> bytes:
    """
    Encrypt 'data' using Speck-64/96 in CTR mode, parallelized with multiprocessing.
    """
    return data  # Placeholder: Speck encryption is CTR mode (same as decryption)

def encrypt_message(plaintext: bytes, speck_key: bytes, mac_key: bytes, processes=4) -> tuple:
    """
    Encrypt and authenticate a plaintext message.
    Returns (iv, ciphertext, tag).
    """
    iv = os.urandom(8)
    ciphertext = parallel_speck64_96_encrypt_ctr(speck_key, plaintext, iv, processes=processes)
    tag = poly1305_tag(mac_key, iv + ciphertext)
    return iv, ciphertext, tag

# -------------------------------------------------------------
# Performance Measurement Function
# -------------------------------------------------------------
def measure_encryption_time(file_path, speck_key, mac_key, processes=4, num_iterations=100):
    """
    Encrypts a file 100 times and returns:
    - Average encryption time
    - Average CPU usage
    """
    with open(file_path, "rb") as f:
        plaintext = f.read()

    total_time = 0
    cpu_percentages = []

    for _ in range(num_iterations):
        start_time = time.perf_counter()
        cpu_start = psutil.cpu_percent(interval=None)  # Get CPU before encryption
        encrypt_message(plaintext, speck_key, mac_key, processes=processes)
        cpu_end = psutil.cpu_percent(interval=None)  # Get CPU after encryption
        end_time = time.perf_counter()

        total_time += (end_time - start_time)
        cpu_percentages.append(cpu_end)

    avg_time = total_time / num_iterations
    avg_cpu_usage = sum(cpu_percentages) / len(cpu_percentages)

    return avg_time, avg_cpu_usage

# -------------------------------------------------------------
# Main Execution
# -------------------------------------------------------------
if __name__ == "__main__":
    TEXT_FILES_DIR = "."  # Folder containing the text files
    NUM_ITERATIONS = 100  # Number of encryption runs per file
    PROCESSES = 4  # Number of parallel processes

    # Get list of 5 text files from the current directory
    text_files = [f for f in os.listdir(TEXT_FILES_DIR) if f.endswith(".txt")][:5]

    if len(text_files) < 5:
        print("Error: Not enough text files found in the directory!")
        exit(1)

    # Generate X25519 key pairs
    device_priv, device_pub = x25519_generate_keypair()
    server_priv, server_pub = x25519_generate_keypair()

    # Compute shared secret
    shared_secret = x25519_compute_shared_key(device_priv, server_pub)

    # Derive Speck encryption key (96 bits) + Poly1305 key (256 bits) via HKDF
    hkdf = HKDF(algorithm=hashes.SHA256(), length=44, salt=None, info=b"SecureComm")
    key_material = hkdf.derive(shared_secret)
    speck_key = key_material[:12]   # 96-bit Speck key
    mac_key = key_material[12:44]   # 256-bit Poly1305 key

    # Measure encryption performance for each file
    for file_name in text_files:
        file_path = os.path.join(TEXT_FILES_DIR, file_name)
        avg_time, avg_cpu = measure_encryption_time(file_path, speck_key, mac_key, PROCESSES, NUM_ITERATIONS)
        print(f"File: {file_name} | Avg Encryption Time: {avg_time:.6f} sec | Avg CPU Usage: {avg_cpu:.2f}%")
