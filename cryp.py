from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, poly1305
from cryptography.exceptions import InvalidSignature
import os

# 1. X25519 Elliptic Curve Key Exchange
def x25519_generate_keypair():
    """Generate X25519 key pair, returns (private_key, public_key_bytes)."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return private_key, public_bytes

def x25519_compute_shared_key(private_key, peer_public_bytes):
    """Calculate X25519 shared key (32 bytes) using own private key and peer's public key bytes."""
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret  # Returns 32-byte shared key

# 2. Speck-64/96 Lightweight Encryption (CTR mode)
def speck64_96_key_schedule(key: int):
    """
    Generate the Speck 64/96 subkey sequence.
    Parameter key: 96-bit key (int type).
    Returns: A list of 26 32-bit subkeys.
    """
    # Speck64/96 parameters: 64-bit block size, 96-bit key
    word_size = 32
    mask = (1 << word_size) - 1
    rounds = 26
    # Split the 96-bit key into three 32-bit words (using little-endian)
    k0 = key & mask
    k1 = (key >> 32) & mask
    k2 = (key >> 64) & mask
    round_keys = [k0]
    L = [k1, k2]
    # Round function rotation constants
    alpha = 8  # Right rotation bits
    beta = 3   # Left rotation bits
    # Generate subkeys for each round
    for i in range(rounds - 1):
        # Right rotate L[i] by alpha bits and add the current subkey
        L_rot_r = ((L[i] >> alpha) | (L[i] << (word_size - alpha))) & mask
        new_L = (L_rot_r + round_keys[i]) & mask
        new_L ^= i  # XOR with round constant i
        # Left rotate current subkey by beta bits, XOR with new_L to get new subkey
        K_rot_l = ((round_keys[i] << beta) | (round_keys[i] >> (word_size - beta))) & mask
        new_round_key = K_rot_l ^ new_L
        L.append(new_L)
        round_keys.append(new_round_key)
    return round_keys

def speck64_96_encrypt_block(x: int, y: int, round_keys):
    """Encrypt a single 64-bit data block with Speck64/96 (x, y are 32-bit high and low halves)."""
    word_size = 32
    mask = (1 << word_size) - 1
    alpha = 8
    beta = 3
    # Apply Feistel round function for each round
    for k in round_keys:
        # Right rotate x by alpha, add y, then XOR with subkey k
        x = ((x >> alpha) | (x << (word_size - alpha))) & mask
        x = (x + y) & mask
        x ^= k
        # Left rotate y by beta, then XOR with new x
        y = ((y << beta) | (y >> (word_size - beta))) & mask
        y ^= x
    return x, y

def speck64_96_encrypt_ctr(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """
    Encrypt data using Speck64/96 in CTR mode.
    key: 12-byte key (96-bit).
    iv: 8-byte initialization vector (nonce).
    plaintext: Plain data.
    Returns ciphertext byte string, same length as plaintext.
    """
    if len(key) != 12 or len(iv) != 8:
        raise ValueError("Key must be 96 bits (12 bytes), IV must be 64 bits (8 bytes).")
    # Generate subkey sequence
    key_int = int.from_bytes(key, 'little')
    round_keys = speck64_96_key_schedule(key_int)
    # Treat IV as 64-bit counter (little-endian byte order)
    counter = int.from_bytes(iv, 'little')
    ciphertext = bytearray()
    for offset in range(0, len(plaintext), 8):
        block = plaintext[offset: offset+8]
        # Encrypt counter value with Speck to get keystream block
        x = counter & 0xFFFFFFFF
        y = (counter >> 32) & 0xFFFFFFFF
        ks_x, ks_y = speck64_96_encrypt_block(x, y, round_keys)
        keystream = (ks_y << 32) | ks_x  # 64-bit keystream
        # XOR plaintext block with keystream (blocks less than 8 bytes are padded with 0, then truncated)
        block_int = int.from_bytes(block.ljust(8, b'\x00'), 'little')
        cipher_int = block_int ^ keystream
        cipher_block = cipher_int.to_bytes(8, 'little')[:len(block)]
        ciphertext.extend(cipher_block)
        # Increment counter (modulo 2^64)
        counter = (counter + 1) & 0xFFFFFFFFFFFFFFFF
    return bytes(ciphertext)

def speck64_96_decrypt_ctr(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """Decrypt data using Speck64/96 CTR mode (same as encryption process)."""
    return speck64_96_encrypt_ctr(key, ciphertext, iv)

# 3. Poly1305 Message Authentication Code (MAC)
def poly1305_tag(mac_key: bytes, message: bytes) -> bytes:
    """Generate authentication tag (16 bytes) for a message using 32-byte Poly1305 key."""
    if len(mac_key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes.")
    mac = poly1305.Poly1305(mac_key)
    mac.update(message)
    return mac.finalize()

def poly1305_verify(mac_key: bytes, message: bytes, tag: bytes) -> bool:
    """Verify if the Poly1305 tag for the message is correct."""
    try:
        mac = poly1305.Poly1305(mac_key)
        mac.update(message)
        mac.verify(tag)  # Will throw an exception if verification fails
        return True
    except InvalidSignature:
        return False

# 4. Complete Encryption and Decryption Process
def encrypt_message(plaintext: bytes, speck_key: bytes, mac_key: bytes) -> tuple:
    """
    Encrypt and authenticate a plaintext message.
    Returns a tuple (iv, ciphertext, tag).
    """
    iv = os.urandom(8)  # Generate random 64-bit IV
    ciphertext = speck64_96_encrypt_ctr(speck_key, plaintext, iv)
    # Calculate Poly1305 tag (authenticate IV and ciphertext together to prevent tampering)
    tag = poly1305_tag(mac_key, iv + ciphertext)
    return iv, ciphertext, tag

def decrypt_message(iv: bytes, ciphertext: bytes, tag: bytes, speck_key: bytes, mac_key: bytes) -> bytes:
    """
    Verify tag and decrypt ciphertext.
    Will throw an exception if the tag is incorrect; otherwise returns the decrypted plaintext.
    """
    # Verify MAC tag before decryption
    if not poly1305_verify(mac_key, iv + ciphertext, tag):
        raise ValueError("MAC verification failed, data may have been tampered with!")
    plaintext = speck64_96_decrypt_ctr(speck_key, ciphertext, iv)
    return plaintext

# 5. Test Case: Simulate Device and Server Side
if __name__ == "__main__":
    # Device side generates X25519 key pair
    device_priv, device_pub = x25519_generate_keypair()
    # Server side generates X25519 key pair
    server_priv, server_pub = x25519_generate_keypair()
    # Exchange public keys and calculate shared key on each side
    device_shared = x25519_compute_shared_key(device_priv, server_pub)
    server_shared = x25519_compute_shared_key(server_priv, device_pub)
    assert device_shared == server_shared  # Verify shared keys match
    shared_secret = device_shared  # 32-byte shared key

    # Use HKDF to derive Speck encryption key (96 bits) and Poly1305 key (256 bits) from shared key
    hkdf = HKDF(algorithm=hashes.SHA256(), length=44, salt=None, info=b"ULAE-IoT")
    key_material = hkdf.derive(shared_secret)
    speck_key = key_material[:12]   # 96-bit Speck key
    mac_key = key_material[12:44]   # 256-bit Poly1305 key

    # Device side: Encrypt information to be sent
    plaintext = b"Hello, welcome to CSEN241 course!"
    iv, ciphertext, tag = encrypt_message(plaintext, speck_key, mac_key)

    # ======= Dividing line: The following simulates the receiving end =======
    # Server side: Received iv, ciphertext, tag, perform verification and decryption
    try:
        recovered_text = decrypt_message(iv, ciphertext, tag, speck_key, mac_key)
        print("Original plaintext:", plaintext)
        print("Ciphertext (hex):", ciphertext.hex())
        print("Decrypted plaintext:", recovered_text)
        print("Tag (hex):", tag.hex())
        if recovered_text == plaintext:
            print("Success: message decrypted and authenticated.")
    except ValueError as e:
        print("Decryption failed:", e)