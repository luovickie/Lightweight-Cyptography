#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import os
import time

def encrypt_file(input_path, output_path, key):
    """Correct implementation of block encryption (3DES)"""
    # 3DES 的分组大小为 8 字节
    iv = os.urandom(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(iv)
        buffer = b''
        # 为了与 AES 方案保持一致，这里也用 16KB 块；3DES.block_size=8
        chunk_size = 1024 * DES3.block_size  # 8*1024=8192 bytes
        
        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                break
            buffer += chunk
            
            # Process complete blocks (整分组)
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
        # 读取最前面的 IV
        iv = f_in.read(DES3.block_size)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        
        with open(output_path, 'wb') as f_out:
            buffer = b''
            chunk_size = 1024 * DES3.block_size
            
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                # 解密后放入 buffer
                buffer += cipher.decrypt(chunk)
                
                # 与 AES 方案相同，保留最后一个分组给 unpad
                full_blocks = (len(buffer) - DES3.block_size) // DES3.block_size
                if full_blocks > 0:
                    # 写出除“最后一个块”之外的所有完整块
                    blocks_to_write = buffer[:full_blocks * DES3.block_size]
                    f_out.write(blocks_to_write)
                    buffer = buffer[full_blocks * DES3.block_size:]
            
            # 对最后保留的一块执行 unpad
            decrypted_data = unpad(buffer, DES3.block_size)
            f_out.write(decrypted_data)

def speed_test(test_files, key):
    """Improved performance test function for 3DES"""
    # 这里与 AES 版本保持一致，只是使用同样的测试目录/文件
    base_dir = os.path.dirname(os.path.abspath(__file__))
    random_dir = os.path.join(base_dir, "test")  # 你示例中使用的是 "test" 目录
    
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
    # 生成3DES密钥。3DES通常使用24字节键长（含校验位需确保正确的奇偶校验）
    # PyCryptodome提供了adjust_key_parity来修正key的奇偶校验位，保证合法3DES密钥
    from Crypto.Util import Counter  # 如果需要，也可用于计数器模式，这里不需要
    key_3des = DES3.adjust_key_parity(os.urandom(24))

    # 与 AES 示例相同的测试文件列表
    test_files = [
        "1kbtest.txt",
        "10kbtest.txt",
        "100kbtest.txt",
        "1mbtest.txt",
        "5mbtest.txt"
    ]
    
    # 执行3DES方案的速度测试
    test_results = speed_test(test_files, key_3des)
    # 输出结果，格式与AES一致
    print_results(test_results)
