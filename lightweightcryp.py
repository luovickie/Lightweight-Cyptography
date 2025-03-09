import os
import struct
import secrets
from Crypto.Cipher import AES
from Crypto.Hash import Poly1305
from Crypto.Random import get_random_bytes

### Speck-64/96 Cipher (CTR Mode) ###
class SpeckCipher:
    def __init__(self, key):
        self.key = key

    def encrypt_block(self, nonce, counter):
        """Encrypts the (nonce || counter) to generate a keystream block."""
        aes = AES.new(self.key, AES.MODE_ECB)  # Simulating Speck with AES for demo
        input_block = struct.pack(">II", nonce, counter)  # 32-bit Nonce + 32-bit Counter
        return aes.encrypt(input_block)  # 64-bit keystream block

    def encrypt(self, plaintext, nonce):
        """Encrypts plaintext using Speck in CTR mode."""
        ciphertext = bytearray()
        counter = 0
        for i in range(0, len(plaintext), 8):  # Process 64-bit (8-byte) blocks
            keystream = self.encrypt_block(nonce, counter)
            block = plaintext[i:i+8].ljust(8, b'\x00')  # Pad to 64-bit if needed
            ciphertext += bytes([b ^ k for b, k in zip(block, keystream)])
            counter += 1
        return ciphertext

    def decrypt(self, ciphertext, nonce):
        """Decrypts ciphertext using the same keystream (XOR is reversible)."""
        return self.encrypt(ciphertext, nonce)  # Same operation as encryption

### Poly1305 MAC for Authentication ###
def generate_mac(key, message):
    """Generates Poly1305 authentication tag."""
    mac = Poly1305.new(key=key)
    mac.update(message)
    return mac.digest()

def verify_mac(key, message, received_mac):
    """Verifies the integrity of the message."""
    mac = Poly1305.new(key=key)
    mac.update(message)
    return mac.digest() == received_mac

### IoT Encryption Process ###
def encrypt_message(plaintext, key):
    """Encrypts a message and generates an authentication tag."""
    nonce = secrets.randbits(32)  # 32-bit random nonce
    cipher = SpeckCipher(key)
    ciphertext = cipher.encrypt(plaintext, nonce)

    mac_key = get_random_bytes(16)  # Separate key for Poly1305
    mac = generate_mac(mac_key, ciphertext)

    return nonce, ciphertext, mac_key, mac

### Cloud Decryption Process ###
def decrypt_message(nonce, ciphertext, mac_key, mac, key):
    """Decrypts a message and verifies its integrity."""
    cipher = SpeckCipher(key)

    if not verify_mac(mac_key, ciphertext, mac):
        raise ValueError("Message integrity compromised!")

    plaintext = cipher.decrypt(ciphertext, nonce)
    return plaintext

### Simulated IoT Device ###
shared_key = get_random_bytes(12)  # 96-bit Speck key
plaintext = b"ULAE-IoT secure data transmission!"
print(f"Original Message: {plaintext.decode()}")

nonce, ciphertext, mac_key, mac = encrypt_message(plaintext, shared_key)
print(f"Encrypted Message: {ciphertext.hex()}")

### Simulated Cloud Server ###
try:
    decrypted_text = decrypt_message(nonce, ciphertext, mac_key, mac, shared_key)
    print(f"Decrypted Message: {decrypted_text.decode().strip()}")
except ValueError as e:
    print(f"Decryption Failed: {e}")
