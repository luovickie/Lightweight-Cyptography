from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import time

def encrypt_file(input_path, output_path, key):
    """Correct implementation of block encryption"""
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(iv)
        buffer = b''
        chunk_size = 1024 * AES.block_size  # 16KB blocks
        
        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                break
            buffer += chunk
            
            # Process complete blocks
            full_blocks = len(buffer) // AES.block_size
            if full_blocks == 0:
                continue
                
            # Encrypt complete blocks and write
            blocks_to_encrypt = buffer[:full_blocks * AES.block_size]
            encrypted_blocks = cipher.encrypt(blocks_to_encrypt)
            f_out.write(encrypted_blocks)
            
            # Keep remaining incomplete block
            buffer = buffer[full_blocks * AES.block_size:]
        
        # Process the last incomplete block and pad
        padded_data = pad(buffer, AES.block_size)
        final_encrypted = cipher.encrypt(padded_data)
        f_out.write(final_encrypted)

def decrypt_file(input_path, output_path, key):
    """Correct implementation of block decryption"""
    with open(input_path, 'rb') as f_in:
        iv = f_in.read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        with open(output_path, 'wb') as f_out:
            buffer = b''
            chunk_size = 1024 * AES.block_size
            
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                buffer += cipher.decrypt(chunk)
                
                # Process complete blocks
                full_blocks = (len(buffer) - AES.block_size) // AES.block_size
                if full_blocks > 0:
                    # Write all complete blocks except the last one
                    blocks_to_write = buffer[:full_blocks * AES.block_size]
                    f_out.write(blocks_to_write)
                    buffer = buffer[full_blocks * AES.block_size:]
            
            # Process the last block and remove padding
            decrypted_data = unpad(buffer, AES.block_size)
            f_out.write(decrypted_data)

# Performance test function remains unchanged (need to add time precision handling)
def speed_test(test_files, key):
    """Improved performance test function"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    random_dir = os.path.join(base_dir, "test")
    
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

# Results printing function remains unchanged
def print_results(results):
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
    test_key = os.urandom(32)
    test_files = [
        "1kbtest.txt",
        "10kbtest.txt",
        "100kbtest.txt",
        "1mbtest.txt",
        "5mbtest.txt"
    ]
    
    test_results = speed_test(test_files, test_key)
    print_results(test_results)