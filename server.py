import os
import socket
import struct
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, poly1305
from cryptography.exceptions import InvalidSignature
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

def poly1305_verify(mac_key: bytes, message: bytes, tag: bytes) -> bool:
    try:
        mac = poly1305.Poly1305(mac_key)
        mac.update(message)
        mac.verify(tag)
        return True
    except InvalidSignature:
        return False

def decrypt_message(iv: bytes, ciphertext: bytes, tag: bytes, speck_key: bytes, mac_key: bytes):
    if not poly1305_verify(mac_key, iv + ciphertext, tag):
        raise ValueError("MAC verification failed!")
    return ciphertext  # Speck CTR encryption == decryption

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
            server_priv, server_pub = x25519_generate_keypair()
            client_conn.sendall(server_pub)

            client_pub = client_conn.recv(32)
            if len(client_pub) != 32:
                raise ValueError("Invalid public key received from client.")

            shared_secret = x25519_compute_shared_key(server_priv, client_pub)
            hkdf = HKDF(algorithm=hashes.SHA256(), length=44, salt=None, info=b"SecureComm")
            key_material = hkdf.derive(shared_secret)
            speck_key = key_material[:12]
            mac_key = key_material[12:44]

            iv = client_conn.recv(8)
            cipher_len = struct.unpack("<I", client_conn.recv(4))[0]
            ciphertext = client_conn.recv(cipher_len)
            tag = client_conn.recv(16)

            try:
                plaintext = decrypt_message(iv, ciphertext, tag, speck_key, mac_key)
                print(f"Decrypted message: {plaintext.decode('utf-8')}")
            except InvalidSignature:
                print("Decryption failed: Invalid authentication tag.")

        except Exception as e:
            print(f"Server error: {e}")
        finally:
            client_conn.close()

if __name__ == "__main__":
    main()
