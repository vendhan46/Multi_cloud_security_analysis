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

def simulate_side_channel_attack(encryption_function, key, plaintext, max_attempts=100000):
    """Simulates a side-channel attack by measuring execution time variations"""
    attempts = 0
    success_attempts = 0
    
    for _ in range(max_attempts):
        modified_key = bytearray(key)
        modified_key[random.randint(0, len(key) - 1)] ^= 0xFF  # Flip a random bit
        modified_key = bytes(modified_key)
        
        start_time = time.time()
        try:
            encryption_function(modified_key, plaintext)
        except:
            pass
        end_time = time.time()
        
        if abs(end_time - start_time) > 0.0001:  # Simulated timing difference
            success_attempts += 1
        
        attempts += 1
    
    return success_attempts

def plot_attack_results(aes_attempts, twofish_attempts, hybrid_attempts, attack_type):
    """Plots attack attempts using a logarithmic scale"""
    labels = ['AES', 'Twofish', 'Hybrid']
    attempts = [aes_attempts, twofish_attempts, hybrid_attempts]  
    
    plt.figure(figsize=(12, 6))
    bars = plt.bar(labels, attempts, color=['red', 'blue', 'green'])
    
    plt.yscale('log')  # Apply logarithmic scale
    plt.xlabel('Encryption Method', fontsize=14)
    plt.ylabel('Successful Attack Attempts (Log Scale)', fontsize=14)
    plt.title(f'{attack_type} Attempts with Log Scale', fontsize=16)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Display the number of attempts on top of the bars
    for bar in bars:
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height(), f'{bar.get_height():.0f}', ha='center', fontsize=12, fontweight='bold')
    
    plt.show()

def test_security():
    """Runs encryption tests and attempts attacks"""
    key_aes = os.urandom(32)
    key_twofish = os.urandom(32)
    plaintext = b"Confidential Data for Encryption Test"
    
    # Encrypt with AES, Twofish, and Hybrid
    aes_encrypted = encrypt_aes(key_aes, plaintext)
    twofish_encrypted = encrypt_twofish_manual(key_twofish, plaintext)
    hybrid_encrypted = hybrid_encrypt(key_aes, key_twofish, plaintext)
    
    print("Performing side-channel attack on AES...")
    aes_attempts = simulate_side_channel_attack(lambda k, p: encrypt_aes(k, p), key_aes, plaintext)
    
    print("Performing side-channel attack on Twofish...")
    twofish_attempts = simulate_side_channel_attack(lambda k, p: encrypt_twofish_manual(k, p), key_twofish, plaintext)
    
    print("Attempting side-channel attack on Hybrid Encryption...")
    hybrid_attempts = simulate_side_channel_attack(lambda k, p: hybrid_encrypt(k[:32], k[32:], p), key_aes + key_twofish, plaintext)
    
    plot_attack_results(aes_attempts, twofish_attempts, hybrid_attempts, "Side-Channel Attack")

test_security()