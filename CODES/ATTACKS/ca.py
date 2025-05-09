import time
import numpy as np
import matplotlib.pyplot as plt
from Crypto.Cipher import AES
from collections import defaultdict

# Simulate AES encryption with timing measurement
def encrypt_aes(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    start_time = time.perf_counter()  # Start time
    ciphertext = cipher.encrypt(plaintext)
    end_time = time.perf_counter()  # End time
    return ciphertext, end_time - start_time  # Return ciphertext and encryption time

# Generate random AES key and plaintexts
key = b'Sixteen byte key'  # 16-byte AES key
plaintexts = [bytes([i] * 16) for i in range(256)]  # 256 different plaintexts

# Measure encryption times
timing_data = []
for pt in plaintexts:
    _, time_taken = encrypt_aes(key, pt)
    timing_data.append((pt[0], time_taken))  # Store first byte and encryption time

# Group timing results by key byte candidate
timing_dict = defaultdict(list)
for byte, time_taken in timing_data:
    timing_dict[byte].append(time_taken)

# Compute the average timing for each key byte candidate
avg_times = {byte: np.mean(times) for byte, times in timing_dict.items()}

# Sort key byte candidates by increasing encryption time
sorted_bytes = sorted(avg_times, key=avg_times.get)

# Plot results
plt.figure(figsize=(12, 6))
plt.bar(sorted_bytes, [avg_times[b] for b in sorted_bytes], color='blue', alpha=0.7)

# Labels and title
plt.xlabel("Key Byte Candidates (Sorted by Timing)")
plt.ylabel("Average Encryption Time (seconds)")
plt.title("AES Cache Timing Attack - Key Byte Timing Analysis")
plt.xticks(rotation=90)

# Show the graph
plt.show()
