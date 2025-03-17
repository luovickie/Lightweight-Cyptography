#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, poly1305
from cryptography.exceptions import InvalidSignature
import os
import time

# ========== 1. X25519 Elliptic Curve Key Exchange ==========

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

# ========== 2. Speck-64/96 (CTR) + Poly1305 ==========

def speck64_96_key_schedule(key: int):
    """
    Generate the Speck 64/96 subkey sequence.
    Parameter key: 96-bit key (int type).
    Returns: A list of 26 32-bit subkeys.
    """
    word_size = 32
    mask = (1 << word_size) - 1
    rounds = 26
    # Split the 96-bit key into three 32-bit words (little-endian)
    k0 = key & mask
    k1 = (key >> 32) & mask
    k2 = (key >> 64) & mask
    round_keys = [k0]
    L = [k1, k2]
    alpha = 8  # rotation bits
    beta = 3
    for i in range(rounds - 1):
        L_rot_r = ((L[i] >> alpha) | (L[i] << (word_size - alpha))) & mask
        new_L = (L_rot_r + round_keys[i]) & mask
        new_L ^= i
        K_rot_l = ((round_keys[i] << beta) | (round_keys[i] >> (word_size - beta))) & mask
        new_round_key = K_rot_l ^ new_L
        L.append(new_L)
        round_keys.append(new_round_key)
    return round_keys

def speck64_96_encrypt_block(x: int, y: int, round_keys):
    """Encrypt a single 64-bit block (x,y) for Speck64/96."""
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
    """
    Encrypt data using Speck64/96 in CTR mode.
    key: 12-byte key (96-bit).
    iv: 8-byte IV/counter (64-bit).
    plaintext: Plain data.
    """
    if len(key) != 12 or len(iv) != 8:
        raise ValueError("Key must be 96 bits (12 bytes) and IV must be 64 bits (8 bytes).")

    key_int = int.from_bytes(key, 'little')
    round_keys = speck64_96_key_schedule(key_int)

    # 64-bit counter from iv
    counter = int.from_bytes(iv, 'little')
    ciphertext = bytearray()

    for offset in range(0, len(plaintext), 8):
        block = plaintext[offset: offset+8]
        # Encrypt the counter to get keystream
        x = counter & 0xFFFFFFFF
        y = (counter >> 32) & 0xFFFFFFFF
        ks_x, ks_y = speck64_96_encrypt_block(x, y, round_keys)
        keystream = (ks_y << 32) | ks_x
        # XOR with plaintext block
        block_int = int.from_bytes(block.ljust(8, b'\x00'), 'little')
        cipher_int = block_int ^ keystream
        cipher_block = cipher_int.to_bytes(8, 'little')[:len(block)]
        ciphertext.extend(cipher_block)
        # Increment counter mod 2^64
        counter = (counter + 1) & 0xFFFFFFFFFFFFFFFF

    return bytes(ciphertext)

def speck64_96_decrypt_ctr(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """Decrypt data under Speck64/96 CTR (same as encryption)."""
    return speck64_96_encrypt_ctr(key, ciphertext, iv)

# ========== 3. Poly1305 MAC ==========

def poly1305_tag(mac_key: bytes, message: bytes) -> bytes:
    """Generate a 16-byte Poly1305 tag."""
    if len(mac_key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes (256 bits).")
    mac = poly1305.Poly1305(mac_key)
    mac.update(message)
    return mac.finalize()

def poly1305_verify(mac_key: bytes, message: bytes, tag: bytes) -> bool:
    """Verify a Poly1305 tag."""
    try:
        mac = poly1305.Poly1305(mac_key)
        mac.update(message)
        mac.verify(tag)
        return True
    except InvalidSignature:
        return False

# ========== 4. Single-pass Encrypt & Decrypt with Speck + Poly1305 ==========

def encrypt_message(plaintext: bytes, speck_key: bytes, mac_key: bytes) -> tuple:
    """Returns (iv, ciphertext, tag). Tag is computed over (iv + ciphertext)."""
    iv = os.urandom(8)  # 64-bit IV
    ciphertext = speck64_96_encrypt_ctr(speck_key, plaintext, iv)
    tag = poly1305_tag(mac_key, iv + ciphertext)
    return (iv, ciphertext, tag)

def decrypt_message(iv: bytes, ciphertext: bytes, tag: bytes,
                    speck_key: bytes, mac_key: bytes) -> bytes:
    """Verify tag over (iv + ciphertext), then decrypt if valid."""
    if not poly1305_verify(mac_key, iv + ciphertext, tag):
        raise ValueError("MAC verification failed, data may have been tampered!")
    return speck64_96_decrypt_ctr(speck_key, ciphertext, iv)

# ========== 5. File-level encryption and decryption functions ==========

def encrypt_file(input_path, output_path, keys):
    """
    Encrypt the given file and write to output_path.
    keys: (speck_key, mac_key) tuple.
    Output file format: [IV(8 bytes)] + [ciphertext(n bytes)] + [tag(16 bytes)]
    """
    speck_key, mac_key = keys
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        plaintext = f_in.read()
        iv, ciphertext, tag = encrypt_message(plaintext, speck_key, mac_key)
        # Write file: iv + ciphertext + tag
        f_out.write(iv)
        f_out.write(ciphertext)
        f_out.write(tag)

def decrypt_file(input_path, output_path, keys):
    """
    Decrypt the given file and output plaintext.
    File structure: [IV(8 bytes)] + [ciphertext(n bytes)] + [tag(16 bytes)]
    """
    speck_key, mac_key = keys
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        file_content = f_in.read()
        # Split iv, ciphertext, tag
        iv = file_content[:8]
        tag = file_content[-16:]
        ciphertext = file_content[8:-16]
        plaintext = decrypt_message(iv, ciphertext, tag, speck_key, mac_key)
        f_out.write(plaintext)

# ========== 6. Speed test, consistent output format with AES/3DES examples ==========

def speed_test(test_files, keys):
    """
    Performance test similar to AES/3DES version:
    - test_files: list of file names
    - keys: (speck_key, mac_key)
    Generate the same column fields as previous AES/3DES: filename, size_KB, enc_time, dec_time, enc_speed, dec_speed
    """
    # Assume all test files are in the "test" folder in the current script directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.join(base_dir, "test")

    enc_dir = os.path.join(test_dir, "encrypted")
    dec_dir = os.path.join(test_dir, "decrypted")
    os.makedirs(enc_dir, exist_ok=True)
    os.makedirs(dec_dir, exist_ok=True)

    results = []
    for file in test_files:
        orig_path = os.path.join(test_dir, file)
        if not os.path.exists(orig_path):
            print(f"⚠️ File {file} does not exist, skipped.")
            continue

        enc_path = os.path.join(enc_dir, f"enc_{file}")
        dec_path = os.path.join(dec_dir, f"dec_{file}")
        file_size = os.path.getsize(orig_path)

        # -- Encryption test (warm-up) --
        encrypt_file(orig_path, os.devnull, keys)  # No timing, just to "warm up cache"

        start = time.perf_counter()
        encrypt_file(orig_path, enc_path, keys)
        enc_time = max(time.perf_counter() - start, 1e-5)  # Avoid division by zero

        # -- Decryption test (force read ciphertext) --
        with open(enc_path, 'rb') as f:
            f.read()  # Let the system cache read in

        start = time.perf_counter()
        decrypt_file(enc_path, dec_path, keys)
        dec_time = max(time.perf_counter() - start, 1e-5)

        # -- Speed statistics --
        #   MB/s = (file size/bytes) / (1024*1024) / time(s)
        MAX_SPEED = 5000  # Artificial upper limit
        enc_speed = min((file_size / (1024**2)) / enc_time, MAX_SPEED)
        dec_speed = min((file_size / (1024**2)) / dec_time, MAX_SPEED)

        results.append({
            "filename": file,
            "size_KB": file_size / 1024,
            "enc_time": round(enc_time, 6),
            "dec_time": round(dec_time, 6),
            "enc_speed": round(enc_speed, 2),
            "dec_speed": round(dec_speed, 2)
        })

    return results

def print_results(results):
    """Print the results table in the same format as AES/3DES examples."""
    print("\n{:<20} {:<10} {:<12} {:<12} {:<12} {:<12}".format(
        "Filename", "Size(KB)", "Enc Time(s)", "Dec Time(s)", "Enc Speed(MB/s)", "Dec Speed(MB/s)"))
    print("-" * 80)
    for res in results:
        print("{:<20} {:<10.1f} {:<12.6f} {:<12.6f} {:<12} {:<12}".format(
            res["filename"],
            res["size_KB"],
            res["enc_time"],
            res["dec_time"],
            res["enc_speed"],
            res["dec_speed"]
        ))

# ========== 7. Main program: simulate X25519 key exchange + HKDF derivation + file testing ==========

if __name__ == "__main__":
    # -- (1) Simulate device/server performing an X25519 key exchange --
    device_priv, device_pub = x25519_generate_keypair()
    server_priv, server_pub = x25519_generate_keypair()
    device_shared = x25519_compute_shared_key(device_priv, server_pub)
    server_shared = x25519_compute_shared_key(server_priv, device_pub)
    assert device_shared == server_shared, "X25519 shared keys mismatch!"
    shared_secret = device_shared  # 32 bytes

    # -- (2) Use HKDF to derive keys for Speck-64/96 and Poly1305 --
    #     where speck_key = 96 bits, mac_key = 256 bits
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=44,  # 12 bytes(96 bits) + 32 bytes(256 bits) = 44
        salt=None,
        info=b"ULAE-IoT"
    )
    key_material = hkdf.derive(shared_secret)
    speck_key = key_material[:12]   # 96-bit key
    mac_key = key_material[12:44]   # 256-bit key
    scheme_keys = (speck_key, mac_key)

    # -- (3) Test file list (same as AES/3DES examples) --
    test_files = [
        "1kbtest.txt",
        "10kbtest.txt",
        "100kbtest.txt",
        "1mbtest.txt",
        "5mbtest.txt"
    ]

    # -- (4) Run speed tests and print results --
    test_results = speed_test(test_files, scheme_keys)
    print_results(test_results)