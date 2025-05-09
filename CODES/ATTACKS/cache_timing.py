from Crypto.Cipher import AES
import os
import time
import struct
import random
import matplotlib.pyplot as plt
import numpy as np

def pad(data):
    """Pads data to be AES block size (16 bytes)"""
    pad_length = 16 - (len(data) % 16)
    return data + bytes([pad_length] * pad_length)

def unpad(data):
    """Removes padding from data"""
    return data[:-data[-1]]

def encrypt_aes(key, plaintext):
    """Encrypts data using AES-256"""
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))
    return iv + ciphertext

def decrypt_aes(key, ciphertext):
    """Decrypts AES-256 data"""
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[16:]))
    return plaintext

def encrypt_twofish_manual(key, plaintext):
    """Basic Twofish encryption simulation (manual implementation required)"""
    random.seed(struct.unpack("Q", key[:8])[0])  # Basic key expansion
    encrypted = bytes([b ^ random.randint(0, 255) for b in plaintext])
    return encrypted

def decrypt_twofish_manual(key, ciphertext):
    """Basic Twofish decryption simulation (manual implementation required)"""
    random.seed(struct.unpack("Q", key[:8])[0])  # Reverse key expansion
    decrypted = bytes([b ^ random.randint(0, 255) for b in ciphertext])
    return decrypted

def hybrid_encrypt(key_aes, key_twofish, plaintext):
    """Hybrid encryption: AES followed by Twofish"""
    aes_encrypted = encrypt_aes(key_aes, plaintext)
    twofish_encrypted = encrypt_twofish_manual(key_twofish, aes_encrypted)
    return twofish_encrypted

def hybrid_decrypt(key_aes, key_twofish, ciphertext):
    """Hybrid decryption: Twofish followed by AES"""
    twofish_decrypted = decrypt_twofish_manual(key_twofish, ciphertext)
    aes_decrypted = decrypt_aes(key_aes, twofish_decrypted)
    return aes_decrypted

def simulate_cache_timing_attack(encryption_function, key, plaintext, num_samples=10):
    """Simulates cache timing attack by measuring encryption time variations over multiple runs."""
    timing_variances = []
    
    for _ in range(num_samples):
        timing_samples = []
        
        for _ in range(50):  # 50 encryption operations per test
            start_time = time.perf_counter()
            encryption_function(key, plaintext)
            end_time = time.perf_counter()
            timing_samples.append((end_time - start_time) * 1e6)  # Convert to microseconds

        timing_variances.append(np.var(timing_samples))  # Store variance of each run

    return timing_variances

def plot_timing_attack_results(aes_variances, twofish_variances, hybrid_variances):
    """Plots timing variances as a line graph to show attack trends over multiple runs."""
    plt.figure(figsize=(12, 6))

    x = list(range(len(aes_variances)))  # X-axis: Number of test runs

    plt.plot(x, aes_variances, label='AES Variance', color='red', marker='o', linestyle='-')
    plt.plot(x, twofish_variances, label='Twofish Variance', color='blue', marker='s', linestyle='--')
    plt.plot(x, hybrid_variances, label='Hybrid Variance', color='green', marker='^', linestyle='-.')

    plt.xlabel('Test Runs', fontsize=14)
    plt.ylabel('Timing Variance (Microseconds)', fontsize=14)
    plt.title('Cache Timing Attack Analysis (Variance over Multiple Runs)', fontsize=16)
    
    plt.yscale('log')  # Log scale for better visualization
    plt.legend()
    plt.grid(True, which='both', linestyle='--', linewidth=0.5, alpha=0.7)
    
    plt.show()

def test_security():
    """Runs encryption tests and attempts attacks"""
    key_aes = os.urandom(32)
    key_twofish = os.urandom(32)
    plaintext = b"Confidential Data for Encryption Test"

    print("Simulating cache timing attack on AES...")
    aes_variances = simulate_cache_timing_attack(encrypt_aes, key_aes, plaintext)

    print("Simulating cache timing attack on Twofish...")
    twofish_variances = simulate_cache_timing_attack(encrypt_twofish_manual, key_twofish, plaintext)

    print("Simulating cache timing attack on Hybrid Encryption...")
    hybrid_variances = simulate_cache_timing_attack(lambda k, p: hybrid_encrypt(k[:32], k[32:], p), key_aes + key_twofish, plaintext)

    plot_timing_attack_results(aes_variances, twofish_variances, hybrid_variances)

test_security()
