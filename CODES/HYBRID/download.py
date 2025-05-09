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

# Queue for thread-safe communication
result_queue = Queue()

def generate_aes_key(passphrase):
    """Generate AES-256 key from passphrase using SHA-256."""
    return hashlib.sha256(passphrase.encode()).digest()

def unpad(data):
    """Remove padding from decrypted data."""
    return data[:-data[-1]]

def aes_decrypt(key, ciphertext):
    """Decrypt data using AES-256 in CBC mode."""
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[16:]))

def analyze_performance(cloud_name, download_time, file_size):
    """Analyzes performance of download."""
    download_speed = file_size / download_time if download_time > 0 else 0
    return {
        "Cloud": cloud_name,
        "Download Time": download_time,
        "Download Speed": download_speed,
    }

def download_google_cloud():
    """Download and decrypt file from Google Cloud."""
    storage_client = storage.Client()
    bucket_name = "mycloudshield-bucket"
    source_blob_name = "encrypted_document.enc"
    encrypted_file_path = "downloaded_google.enc"
    decrypted_file_path = "decrypted_GoogleCloud.txt"

    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(source_blob_name)

    start_time = time.time()
    blob.download_to_filename(encrypted_file_path)
    download_time = time.time() - start_time
    file_size = os.path.getsize(encrypted_file_path) / (1024 * 1024)  # MB

    key_aes = generate_aes_key("SecurePassphrase")
    with open(encrypted_file_path, 'rb') as enc_file:
        decrypted_data = aes_decrypt(key_aes, enc_file.read())

    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)

    result = analyze_performance("Google Cloud", download_time, file_size)
    result_queue.put(result)

def download_aws():
    """Download and decrypt file from AWS."""
    s3_client = boto3.client(
        's3', aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=AWS_REGION
    )
    bucket_name = "my-cloudshield"
    source_blob_name = "encrypted_document.enc"
    encrypted_file_path = "downloaded_aws.enc"
    decrypted_file_path = "decrypted_AWS.txt"

    start_time = time.time()
    s3_client.download_file(bucket_name, source_blob_name, encrypted_file_path)
    download_time = time.time() - start_time
    file_size = os.path.getsize(encrypted_file_path) / (1024 * 1024)  # MB

    key_aes = generate_aes_key("SecurePassphrase")
    with open(encrypted_file_path, 'rb') as enc_file:
        decrypted_data = aes_decrypt(key_aes, enc_file.read())

    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)

    result = analyze_performance("AWS", download_time, file_size)
    result_queue.put(result)

def download_wasabi():
    """Download and decrypt file from Wasabi."""
    s3_client = boto3.client(
        's3', endpoint_url=WASABI_ENDPOINT,
        aws_access_key_id=WASABI_ACCESS_KEY_ID,
        aws_secret_access_key=WASABI_SECRET_ACCESS_KEY
    )
    bucket_name = "cloudshield"
    source_blob_name = "encrypted_document.enc"
    encrypted_file_path = "downloaded_wasabi.enc"
    decrypted_file_path = "decrypted_Wasabi.txt"

    try:
        start_time = time.time()
        s3_client.download_file(bucket_name, source_blob_name, encrypted_file_path)
        download_time = time.time() - start_time
        file_size = os.path.getsize(encrypted_file_path) / (1024 * 1024)  # MB

        key_aes = generate_aes_key("SecurePassphrase")
        with open(encrypted_file_path, 'rb') as enc_file:
            decrypted_data = aes_decrypt(key_aes, enc_file.read())

        with open(decrypted_file_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)

        result = analyze_performance("Wasabi", download_time, file_size)
        result_queue.put(result)
    except NoCredentialsError:
        print("Wasabi credentials not available.")

def plot_graphs(results):
    """Plots download time and speed graphs."""
    clouds = [res['Cloud'] for res in results]
    download_times = [res['Download Time'] for res in results]
    download_speeds = [res['Download Speed'] for res in results]

    plt.figure(figsize=(12, 6))

    # Download Time Graph
    plt.subplot(1, 2, 1)
    plt.plot(clouds, download_times, marker='o', linestyle='-', color='b')
    for i, txt in enumerate(download_times):
        plt.annotate(f"{txt:.2f}s", (clouds[i], download_times[i]), textcoords="offset points", xytext=(0,5), ha='center')
    plt.xlabel("Clouds")
    plt.ylabel("Download Time (s)")
    plt.title("Download Time Comparison")

    # Download Speed Graph
    plt.subplot(1, 2, 2)
    plt.plot(clouds, download_speeds, marker='o', linestyle='-', color='g')
    for i, txt in enumerate(download_speeds):
        plt.annotate(f"{txt:.6f} MB/s", (clouds[i], download_speeds[i]), textcoords="offset points", xytext=(0,5), ha='center')
    plt.xlabel("Clouds")
    plt.ylabel("Download Speed (MB/s)")
    plt.title("Download Speed Comparison")

    plt.tight_layout()
    plt.show()

def display_table(results):
    """Displays a tabulated summary of download performance."""
    headers = ["Cloud", "Download Time", "Download Speed"]
    table_data = [
        [res["Cloud"], f"{res['Download Time']:.2f} s", f"{res['Download Speed']:.6f} MB/s"]
        for res in results
    ]

    print("\nDownload Performance:\n")
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

def main():
    threads = [
        threading.Thread(target=download_google_cloud),
        threading.Thread(target=download_aws),
        threading.Thread(target=download_wasabi)
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    results = [result_queue.get() for _ in range(result_queue.qsize())]
    plot_graphs(results)
    display_table(results)

if __name__ == "__main__":
    main()
