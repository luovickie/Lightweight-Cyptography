import os
import socket
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, poly1305
from cryptography.exceptions import InvalidSignature

# ===============================
# X25519 Helpers
# ===============================
def x25519_generate_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return private_key, public_bytes

def x25519_compute_shared_key(private_key, peer_public_bytes):
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_public_key)

# ===============================
# Speck-64/96 Implementation
# ===============================
def speck64_96_key_schedule(key: int):
    word_size = 32
    mask = (1 << word_size) - 1
    rounds = 26
    k0 = key & mask
    k1 = (key >> 32) & mask
    k2 = (key >> 64) & mask
    round_keys = [k0]
    L = [k1, k2]
    alpha = 8
    beta = 3
    for i in range(rounds - 1):
        L_rot_r = ((L[i] >> alpha) | (L[i] << (word_size - alpha))) & mask
        new_L = (L_rot_r + round_keys[i]) & mask
        new_L ^= i
        K_rot_l = ((round_keys[i] << beta) | (round_keys[i] >> (word_size - beta))) & mask
        new_k = K_rot_l ^ new_L
        L.append(new_L)
        round_keys.append(new_k)
    return round_keys

def speck64_96_encrypt_block(x: int, y: int, round_keys):
    word_size = 32
    mask = (1 << word_size) - 1
    alpha = 8
    beta = 3
    for k in round_keys:
        x = ((x >> alpha) | (x << (word_size - alpha))) & mask
        x = (x + y) & mask
        x ^= k
        y = ((y << beta) | (y >> (word_size - beta))) & mask
        y ^= x
    return x, y

def speck64_96_encrypt_ctr(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    if len(key) != 12 or len(iv) != 8:
        raise ValueError("Key must be 96 bits, IV must be 64 bits.")
    key_int = int.from_bytes(key, 'little')
    round_keys = speck64_96_key_schedule(key_int)
    counter = int.from_bytes(iv, 'little')
    ciphertext = bytearray()
    for offset in range(0, len(plaintext), 8):
        block = plaintext[offset: offset+8]
        x = counter & 0xffffffff
        y = (counter >> 32) & 0xffffffff
        ks_x, ks_y = speck64_96_encrypt_block(x, y, round_keys)
        keystream = (ks_y << 32) | ks_x
        block_int = int.from_bytes(block.ljust(8, b'\x00'), 'little')
        cipher_int = block_int ^ keystream
        cipher_block = cipher_int.to_bytes(8, 'little')[:len(block)]
        ciphertext.extend(cipher_block)
        counter = (counter + 1) & 0xffffffffffffffff
    return bytes(ciphertext)

def speck64_96_decrypt_ctr(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    return speck64_96_encrypt_ctr(key, ciphertext, iv)

# ===============================
# Poly1305 Helpers
# ===============================
def poly1305_tag(mac_key: bytes, message: bytes) -> bytes:
    if len(mac_key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes.")
    m = poly1305.Poly1305(mac_key)
    m.update(message)
    return m.finalize()

def poly1305_verify(mac_key: bytes, message: bytes, tag: bytes) -> bool:
    try:
        m = poly1305.Poly1305(mac_key)
        m.update(message)
        m.verify(tag)
        return True
    except InvalidSignature:
        return False

# ===============================
# Combined Encrypt/Decrypt
# ===============================
def encrypt_message(plaintext: bytes, speck_key: bytes, mac_key: bytes) -> tuple:
    iv = os.urandom(8)
    ciphertext = speck64_96_encrypt_ctr(speck_key, plaintext, iv)
    tag = poly1305_tag(mac_key, iv + ciphertext)
    return (iv, ciphertext, tag)

def decrypt_message(iv: bytes, ciphertext: bytes, tag: bytes, speck_key: bytes, mac_key: bytes) -> bytes:
    if not poly1305_verify(mac_key, iv + ciphertext, tag):
        raise ValueError("Invalid MAC! Possible tampering.")
    return speck64_96_decrypt_ctr(speck_key, ciphertext, iv)

# ===============================
# Simple Server Code
# ===============================
HOST = '54.160.174.239'  # Bind to this specific IP
PORT = 4000              

def main():   
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    print(f"Server listening on {HOST}:{PORT}...")

    while True:
        client_conn, addr = server_sock.accept()
        print("Client connected from:", addr)
        try:
            # 1) Generate ephemeral X25519
            server_priv, server_pub = x25519_generate_keypair()

            # 2) Send server's pubkey (32 bytes) to client
            client_conn.sendall(server_pub)

            # 3) Receive client's public key (32 bytes)
            client_pub = client_conn.recv(32)
            if len(client_pub) != 32:
                raise ValueError("Didn't get 32-byte client public key.")

            # 4) Compute shared secret
            shared_secret = x25519_compute_shared_key(server_priv, client_pub)

            # 5) Derive Speck+Poly1305 keys via HKDF
            hkdf = HKDF(algorithm=hashes.SHA256(), length=44, salt=None, info=b"ULAE-IoT")
            key_material = hkdf.derive(shared_secret)
            speck_key = key_material[:12]
            mac_key   = key_material[12:]

            # 6) Receive (IV, ciph_len, ciphertext, tag)
            iv = client_conn.recv(8)
            if len(iv) != 8:
                raise ValueError("IV must be 8 bytes.")

            import struct
            ciph_len_bytes = client_conn.recv(4)
            ciph_len = struct.unpack("<I", ciph_len_bytes)[0]
            ciphertext = client_conn.recv(ciph_len)
            if len(ciphertext) != ciph_len:
                raise ValueError("Ciphertext length mismatch.")

            tag = client_conn.recv(16)
            if len(tag) != 16:
                raise ValueError("Poly1305 tag must be 16 bytes.")

            # 7) Decrypt & verify
            plaintext = decrypt_message(iv, ciphertext, tag, speck_key, mac_key)
            print("Server received plaintext:", plaintext.decode('utf-8', errors='ignore'))

        except Exception as e:
            print("Server error:", e)
        finally:
            client_conn.close()

if __name__ == "__main__":
    main()
