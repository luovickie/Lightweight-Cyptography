import os
import socket
import struct
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

# -------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------
def decrypt_message(iv: bytes, ciphertext: bytes, key: bytes):
    """Decrypts a message using 3DES-CBC."""
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return plaintext

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
            # Receive key from client (24 bytes for 3DES)
            key = client_conn.recv(24)
            if len(key) != 24:
                raise ValueError("Invalid key received from client.")

            # Receive the encrypted data
            iv = client_conn.recv(8)  # 8-byte IV
            cipher_len = struct.unpack("<I", client_conn.recv(4))[0]  # Read 4-byte length
            ciphertext = client_conn.recv(cipher_len)  # Read ciphertext

            # Decrypt and verify the message
            try:
                plaintext = decrypt_message(iv, ciphertext, key)
                print(f"Decrypted message: {plaintext.decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"Decryption failed: {e}")

        except Exception as e:
            print(f"Server error: {e}")
        finally:
            client_conn.close()

if __name__ == "__main__":
    main()
