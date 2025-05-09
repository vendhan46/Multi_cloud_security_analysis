import os
import time
import threading
import hashlib
import boto3
import matplotlib.pyplot as plt
from google.cloud import storage
from Crypto.Cipher import AES
from botocore.exceptions import NoCredentialsError
from queue import Queue
from tabulate import tabulate

# Google Cloud Credentials
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "C:/Users/VENDHAN V/Downloads/fluent-outpost-450805-k9-7756a633eab8.json"

# AWS Credentials
AWS_ACCESS_KEY_ID = "your-aws-access-key-id"
AWS_SECRET_ACCESS_KEY = "your-aws-secret-access-key"
AWS_REGION = "region"

# Wasabi Credentials
WASABI_ACCESS_KEY_ID = "your-wasabi-key-id"
WASABI_SECRET_ACCESS_KEY = "your-wasabi-secret-access-key"
WASABI_ENDPOINT = "your-wasabi-endpoint"

result_queue = Queue()

# Simulated Twofish decryption (placeholder)
class Twofish:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()

    def decrypt(self, ciphertext):
        # Placeholder: return data as-is (replace with real Twofish decryption later)
        return ciphertext

def generate_aes_key(passphrase):
    return hashlib.sha256(passphrase.encode()).digest()

def unpad(data):
    return data[:-data[-1]]

def hybrid_decrypt(data, passphrase):
    """Decrypt using Twofish, then AES."""
    # Step 1: Decrypt with Twofish
    tf = Twofish(passphrase)
    intermediate_data = tf.decrypt(data)

    # Step 2: Extract IV and AES decrypt
    iv = intermediate_data[:16]
    aes_cipher = AES.new(generate_aes_key(passphrase), AES.MODE_CBC, iv)
    decrypted = aes_cipher.decrypt(intermediate_data[16:])
    return unpad(decrypted)

def analyze_performance(cloud_name, download_time, file_size):
    return {
        "Cloud": cloud_name,
        "Download Time": download_time,
        "Download Speed": file_size / download_time if download_time > 0 else 0
    }

def download_and_decrypt(cloud, download_func, encrypted_path, decrypted_path, original_text_path):
    try:
        start_time = time.time()
        download_func(encrypted_path)
        download_time = time.time() - start_time
        file_size = os.path.getsize(encrypted_path) / (1024 * 1024)

        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = hybrid_decrypt(encrypted_data, "SecurePassphrase")

        # Save decrypted data to file (binary format)
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)

        # Attempt to decode decrypted data as UTF-8 and save it as a text file
        try:
            decoded_data = decrypted_data.decode('utf-8')
            with open(original_text_path, 'w', encoding='utf-8') as f:
                f.write(decoded_data)
            print(f"Decrypted text written to {original_text_path}.")

        except UnicodeDecodeError:
            # If decoding fails, save raw binary data
            with open(original_text_path, 'wb') as f:
                f.write(decrypted_data)
            print(f"Decrypted binary data written to {original_text_path}.")

        result = analyze_performance(cloud, download_time, file_size)
        result_queue.put(result)

    except Exception as e:
        print(f"Error in {cloud} download: {e}")

def download_google_cloud_file(output_file):
    client = storage.Client()
    bucket = client.bucket("mycloudshield-bucket")
    blob = bucket.blob("encrypted_document.enc")
    blob.download_to_filename(output_file)

def download_aws_file(output_file):
    client = boto3.client('s3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
    client.download_file("my-cloudshield", "encrypted_document.enc", output_file)

def download_wasabi_file(output_file):
    client = boto3.client('s3',
        endpoint_url=WASABI_ENDPOINT,
        aws_access_key_id=WASABI_ACCESS_KEY_ID,
        aws_secret_access_key=WASABI_SECRET_ACCESS_KEY
    )
    client.download_file("cloudshield", "encrypted_document.enc", output_file)

def plot_graphs(results):
    clouds = [r["Cloud"] for r in results]
    times = [r["Download Time"] for r in results]
    speeds = [r["Download Speed"] for r in results]

    plt.figure(figsize=(12, 6))

    plt.subplot(1, 2, 1)
    plt.plot(clouds, times, 'bo-')
    for i, val in enumerate(times):
        plt.text(i, val, f"{val:.6f}s", ha='center', va='bottom')
    plt.title("Download Time")
    plt.ylabel("Time (s)")

    plt.subplot(1, 2, 2)
    plt.plot(clouds, speeds, 'go-')
    for i, val in enumerate(speeds):
        plt.text(i, val, f"{val:.6f} MB/s", ha='center', va='bottom')
    plt.title("Download Speed")
    plt.ylabel("Speed (MB/s)")

    plt.tight_layout()
    plt.show()

def display_table(results):
    print("\nDownload Performance:\n")
    headers = ["Cloud", "Download Time", "Download Speed"]
    rows = [[r["Cloud"], f"{r['Download Time']:.6f} s", f"{r['Download Speed']:.6f} MB/s"] for r in results]
    print(tabulate(rows, headers=headers, tablefmt="grid"))

def main():
    threads = [
        threading.Thread(target=download_and_decrypt, args=("Google Cloud", download_google_cloud_file, "google.enc", "google_decrypted.txt", "google_original.txt")),
        threading.Thread(target=download_and_decrypt, args=("AWS", download_aws_file, "aws.enc", "aws_decrypted.txt", "aws_original.txt")),
        threading.Thread(target=download_and_decrypt, args=("Wasabi", download_wasabi_file, "wasabi.enc", "wasabi_decrypted.txt", "wasabi_original.txt"))
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    results = [result_queue.get() for _ in range(result_queue.qsize())]
    plot_graphs(results)
    display_table(results)

if __name__ == "__main__":
    main()
