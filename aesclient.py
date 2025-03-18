import os
import socket
import struct
import time
import psutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# -------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------
def encrypt_message(plaintext: bytes, key: bytes):
    """
    Encrypts a message using AES-CBC.
    Returns IV + encrypted data.
    """
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + encrypted_data

# -------------------------------------------------------------
# Client Code
# -------------------------------------------------------------
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 4000
TEXT_FILES_DIR = "."  # Current directory
NUM_ITERATIONS = 100  # Encrypt each file 100 times

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

def main():
    text_files = [f for f in os.listdir(TEXT_FILES_DIR) if f.endswith(".txt")][:5]

    if len(text_files) < 5:
        print("Error: Not enough text files found in the directory!")
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_HOST, SERVER_PORT))
    print(f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")

    try:
        # Generate an AES-256 key
        key = get_random_bytes(32)

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
        encrypted = encrypt_message(plaintext, key)

        s.sendall(struct.pack("<I", len(encrypted)))  # Send length as 4-byte integer
        s.sendall(encrypted)

        print("Sample message sent successfully.")

    finally:
        s.close()

if __name__ == "__main__":
    main()
