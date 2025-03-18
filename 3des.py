#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import os
import time
import psutil  # Import for CPU usage tracking

# -------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------
def encrypt_file(input_path, key):
    """Encrypt a file using 3DES in CBC mode."""
    iv = os.urandom(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    
    with open(input_path, 'rb') as f_in:
        data = f_in.read()
    
    encrypted_data = iv + cipher.encrypt(pad(data, DES3.block_size))
    return encrypted_data

def measure_encryption_time(file_path, key, num_iterations=100):
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
        encrypt_file(file_path, key)
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

    # Get list of 5 text files from the current directory
    text_files = [f for f in os.listdir(TEXT_FILES_DIR) if f.endswith(".txt")][:5]

    if len(text_files) < 5:
        print("Error: Not enough text files found in the directory!")
        exit(1)

    # Generate a valid 3DES key (24 bytes)
    key_3des = DES3.adjust_key_parity(os.urandom(24))

    # Measure encryption performance for each file
    for file_name in text_files:
        file_path = os.path.join(TEXT_FILES_DIR, file_name)
        avg_time, avg_cpu = measure_encryption_time(file_path, key_3des, NUM_ITERATIONS)
        print(f"File: {file_name} | Avg Encryption Time: {avg_time:.6f} sec | Avg CPU Usage: {avg_cpu:.2f}%")
