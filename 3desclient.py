import os
import socket
import struct
import time
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import psutil

def measure_encryption_time(file_path, key):
    """Encrypts the file 100 times and returns the average encryption time & CPU usage."""
    with open(file_path, "rb") as f:
        plaintext = f.read()

    total_time = 0
    cpu_percentages = []

    for _ in range(NUM_ITERATIONS):
        start_time = time.perf_counter()
        cpu_start = psutil.cpu_percent(interval=None)  # Get CPU usage before encryption
        encrypt_message(plaintext, key)
        cpu_end = psutil.cpu_percent(interval=None)  # Get CPU usage after encryption
        end_time = time.perf_counter()

        total_time += (end_time - start_time)
        cpu_percentages.append(cpu_end)

    avg_time = total_time / NUM_ITERATIONS
    avg_cpu_usage = sum(cpu_percentages) / len(cpu_percentages)  # Average CPU usage
    return avg_time, avg_cpu_usage


# -------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------
def encrypt_message(plaintext: bytes, key: bytes):
    """Encrypts a message using 3DES-CBC."""
    iv = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))
    return iv, ciphertext

# -------------------------------------------------------------
# Client Code
# -------------------------------------------------------------
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 4000
TEXT_FILES_DIR = "."  # Current directory
NUM_ITERATIONS = 100  # Encrypt each file 100 times

def main():
    text_files = [f for f in os.listdir(TEXT_FILES_DIR) if f.endswith(".txt")][:5]

    if len(text_files) < 5:
        print("Error: Not enough text files found in the directory!")
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_HOST, SERVER_PORT))
    print(f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")

    try:
        # Generate a 3DES key
        key = DES3.adjust_key_parity(get_random_bytes(24))

        # Send the key to the server
        s.sendall(key)

        # Measure encryption time for each file
        for file_name in text_files:
            file_path = os.path.join(TEXT_FILES_DIR, file_name)
            avg_time, avg_cpu = measure_encryption_time(file_path, key)
            print(f"File: {file_name} | Avg Encryption Time: {avg_time:.6f} sec | Avg CPU Usage: {avg_cpu:.2f}%")

        # Encrypt and send one file as a test message
        with open(os.path.join(TEXT_FILES_DIR, text_files[0]), "rb") as f:
            plaintext = f.read()
        iv, ciphertext = encrypt_message(plaintext, key)

        s.sendall(iv)
        s.sendall(struct.pack("<I", len(ciphertext)))
        s.sendall(ciphertext)

        print("Sample message sent successfully.")

    finally:
        s.close()

if __name__ == "__main__":
    main()
