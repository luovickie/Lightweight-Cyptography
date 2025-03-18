from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import time
import psutil  # For CPU usage tracking

# -------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------
def encrypt_data(data, key):
    """
    Encrypts the given data using AES in CBC mode.
    The IV is generated randomly and prepended to the encrypted data.
    """
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data  # Return IV + encrypted data

def decrypt_data(encrypted, key):
    """
    Decrypts the data encrypted by encrypt_data.
    Assumes the IV is prepended to the encrypted data.
    """
    iv = encrypted[:AES.block_size]
    encrypted_data = encrypted[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(encrypted_data)
    data = unpad(padded_data, AES.block_size)
    return data

def measure_encryption_time(file_path, key, num_iterations=100):
    """
    Encrypts the file data 100 times and returns:
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
        encrypt_data(plaintext, key)
        cpu_end = psutil.cpu_percent(interval=None)  # Get CPU after encryption
        end_time = time.perf_counter()

        total_time += (end_time - start_time)
        cpu_percentages.append(cpu_end)

    avg_time = total_time / num_iterations
    avg_cpu_usage = sum(cpu_percentages) / len(cpu_percentages)  # Compute avg CPU usage

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

    # Generate a random AES-256 key (32 bytes)
    key = os.urandom(32)

    # Measure encryption performance for each file
    for file_name in text_files:
        file_path = os.path.join(TEXT_FILES_DIR, file_name)
        avg_time, avg_cpu = measure_encryption_time(file_path, key, NUM_ITERATIONS)
        print(f"File: {file_name} | Avg Encryption Time: {avg_time:.6f} sec | Avg CPU Usage: {avg_cpu:.2f}%")
