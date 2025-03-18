import os
import socket
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# -------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------
def decrypt_message(encrypted, key):
    """
    Decrypts the received data using AES-CBC.
    Assumes IV is prepended to the encrypted data.
    """
    iv = encrypted[:AES.block_size]
    encrypted_data = encrypted[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(encrypted_data)
    data = unpad(padded_data, AES.block_size)
    return data.decode('utf-8')

# -------------------------------------------------------------
# Server Code
# -------------------------------------------------------------
HOST = "0.0.0.0"
PORT = 4000

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    print(f"Server listening on {HOST}:{PORT}...")

    while True:
        client_conn, addr = server_sock.accept()
        print(f"Client connected from {addr}")

        try:
            # Receive key from client (32 bytes for AES-256)
            key = client_conn.recv(32)
            if len(key) != 32:
                raise ValueError("Invalid key received from client.")

            # Receive the encrypted data
            data_len = struct.unpack("<I", client_conn.recv(4))[0]  # Read 4-byte length
            encrypted = client_conn.recv(data_len)  # Read encrypted data

            # Decrypt and verify the message
            try:
                plaintext = decrypt_message(encrypted, key)
                print(f"Decrypted message: {plaintext}")
            except Exception as e:
                print(f"Decryption failed: {e}")

        except Exception as e:
            print(f"Server error: {e}")
        finally:
            client_conn.close()

if __name__ == "__main__":
    main()
