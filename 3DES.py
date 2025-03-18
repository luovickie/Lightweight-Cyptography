#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import os
import time

def encrypt_file(input_path, output_path, key):
    """Correct implementation of block encryption (3DES)"""
    # Block size for 3DES is 8 bytes
    iv = os.urandom(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(iv)
        buffer = b''
        # To maintain consistency with the AES scheme, we'll also use 16KB blocks; 3DES.block_size=8
        chunk_size = 1024 * DES3.block_size  # 8*1024=8192 bytes
        
        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                break
            buffer += chunk
            
            # Process complete blocks
            full_blocks = len(buffer) // DES3.block_size
            if full_blocks == 0:
                continue
                
            # Encrypt complete blocks and write
            blocks_to_encrypt = buffer[:full_blocks * DES3.block_size]
            encrypted_blocks = cipher.encrypt(blocks_to_encrypt)
            f_out.write(encrypted_blocks)
            
            # Keep remaining incomplete block
            buffer = buffer[full_blocks * DES3.block_size:]
        
        # Process the last incomplete block (pad + encrypt)
        padded_data = pad(buffer, DES3.block_size)
        final_encrypted = cipher.encrypt(padded_data)
        f_out.write(final_encrypted)

def decrypt_file(input_path, output_path, key):
    """Correct implementation of block decryption (3DES)"""
    with open(input_path, 'rb') as f_in:
        # Read the IV from the beginning
        iv = f_in.read(DES3.block_size)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        
        with open(output_path, 'wb') as f_out:
            buffer = b''
            chunk_size = 1024 * DES3.block_size
            
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                # Decrypt and put into buffer
                buffer += cipher.decrypt(chunk)
                
                # Same as the AES scheme, reserve the last block for unpad
                full_blocks = (len(buffer) - DES3.block_size) // DES3.block_size
                if full_blocks > 0:
                    # Write all complete blocks except the "last block"
                    blocks_to_write = buffer[:full_blocks * DES3.block_size]
                    f_out.write(blocks_to_write)
                    buffer = buffer[full_blocks * DES3.block_size:]
            
            # Perform unpad on the last reserved block
            decrypted_data = unpad(buffer, DES3.block_size)
            f_out.write(decrypted_data)

def speed_test(test_files, key):
    """Improved performance test function for 3DES"""
    # Consistent with the AES version, just using the same test directory/files
    base_dir = os.path.dirname(os.path.abspath(__file__))
    random_dir = os.path.join(base_dir, "test")  # In your example, the "test" directory is used
    
    os.makedirs(os.path.join(random_dir, "encrypted"), exist_ok=True)
    os.makedirs(os.path.join(random_dir, "decrypted"), exist_ok=True)

    results = []
    for file in test_files:
        orig_path = os.path.join(random_dir, file)
        if not os.path.exists(orig_path):
            print(f"⚠️ File {file} does not exist, skipped")
            continue

        enc_path = os.path.join(random_dir, "encrypted", f"enc_{file}")
        dec_path = os.path.join(random_dir, "decrypted", f"dec_{file}")
        file_size = os.path.getsize(orig_path)

        # Encryption test (warm up cache)
        _ = encrypt_file(orig_path, os.devnull, key)
        start = time.perf_counter()
        encrypt_file(orig_path, enc_path, key)
        enc_time = max(time.perf_counter() - start, 1e-5)  # Minimum 1 microsecond

        # Decryption test (force file loading)
        with open(enc_path, 'rb') as f:
            f.read()
        start = time.perf_counter()
        decrypt_file(enc_path, dec_path, key)
        dec_time = max(time.perf_counter() - start, 1e-5)

        # Calculate speed (limit to reasonable range)
        MAX_SPEED = 5000  # 5GB/s is a reasonable upper limit
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
    """Print results in the same format as the AES version"""
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

if __name__ == "__main__":
    # Generate 3DES key. 3DES typically uses 24-byte key length (including parity bits to ensure correct parity check)
    # PyCryptodome provides adjust_key_parity to correct the parity bits of the key, ensuring a valid 3DES key
    from Crypto.Util import Counter  # If needed, can be used for counter mode, not needed here
    key_3des = DES3.adjust_key_parity(os.urandom(24))

    # Same test file list as the AES example
    test_files = [
        "1kbtest.txt",
        "10kbtest.txt",
        "100kbtest.txt",
        "1mbtest.txt",
        "5mbtest.txt"
    ]
    
    # Run speed test for the 3DES scheme
    test_results = speed_test(test_files, key_3des)
    # Output results, format consistent with AES
    print_results(test_results)
