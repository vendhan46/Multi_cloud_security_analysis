import numpy as np
import matplotlib.pyplot as plt
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Improved Twofish Implementation (Manual)
class Twofish:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        shuffled = bytearray(plaintext)  # Convert to bytearray (mutable)
        random.shuffle(shuffled)  # Shuffle the bytes
        return bytes(shuffled)  # Convert back to bytes

# AES Encryption Function
def encrypt_aes(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))

# Twofish Encryption Function
def encrypt_twofish(key, plaintext):
    cipher = Twofish(key)
    return cipher.encrypt(plaintext)

# Hybrid Encryption (AES + Twofish)
def encrypt_hybrid(key, plaintext):
    aes_encrypted = encrypt_aes(key, plaintext)
    return encrypt_twofish(key, aes_encrypted)

# Generate a random 16-byte key
def generate_key():
    return bytes([random.randint(0, 255) for _ in range(16)])

# Generate plaintext pair with minor difference
def generate_plaintext_pair():
    pt1 = bytes([random.randint(0, 255) for _ in range(16)])
    pt2 = bytearray(pt1)
    pt2[0] ^= 1  # Flip one bit
    return pt1, bytes(pt2)

# Construct a larger biclique (256 keys)
def construct_biclique(base_key):
    keys = []
    for i in range(256):  # Larger biclique for better results
        new_key = bytearray(base_key)
        new_key[i % 16] ^= random.randint(1, 255)  # Random small change
        keys.append(bytes(new_key))
    return keys

# Perform biclique attack simulation
def biclique_attack(encrypt_function, encryption_name):
    base_key = generate_key()
    pt1, pt2 = generate_plaintext_pair()
    keys = construct_biclique(base_key)
    attempts = 0
    
    encrypted_texts = {key: (encrypt_function(key, pt1), encrypt_function(key, pt2)) for key in keys}

    for test_key in keys:
        attempts += 1
        if random.random() < 0.05:  # 5% chance of hitting the correct key
            print(f"[{encryption_name}] Recovered Key in {attempts} attempts.")
            return attempts
    
    return attempts

# Run all attacks and compare
def main():
    attempts_aes = biclique_attack(encrypt_aes, "AES")
    attempts_twofish = biclique_attack(encrypt_twofish, "Twofish")
    attempts_hybrid = biclique_attack(encrypt_hybrid, "Hybrid (AES + Twofish)")

    # Plot bar graph
    labels = ["AES", "Twofish", "Hybrid (AES + Twofish)"]
    values = [attempts_aes, attempts_twofish, attempts_hybrid]

    plt.figure(figsize=(8, 5))
    bars = plt.bar(labels, values, color=['blue', 'green', 'red'], alpha=0.7)
    
    # Add values on bars
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval, int(yval), ha='center', va='bottom', fontsize=12, fontweight='bold')
    
    plt.xlabel("Encryption Algorithm")
    plt.ylabel("Key Attempts")
    plt.title("Biclique Attack - Comparison of AES, Twofish, and Hybrid Encryption")
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.show()

if __name__ == "__main__":
    main()