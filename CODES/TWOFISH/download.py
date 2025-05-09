import os
import time
import threading
import hashlib
import boto3
import matplotlib.pyplot as plt
from google.cloud import storage
from botocore.exceptions import NoCredentialsError
from queue import Queue

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

# Twofish Decryption (Manually Implemented)
class Twofish:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()

    def decrypt(self, ciphertext):
        return ciphertext  # Placeholder for actual Twofish decryption logic

def analyze_security(cloud_name, download_time, file_size):
    """Analyzes security and performance of download."""
    download_speed = file_size / download_time if download_time > 0 else 0
    security_scores = {
        "Vulnerability to Attacks": 10 if cloud_name in ["Google Cloud", "AWS"] else 5,
        "Regulatory Compliance": 15 if cloud_name in ["Google Cloud", "AWS"] else 5,
        "Access Control": 15 if cloud_name in ["Google Cloud", "AWS"] else 5,
    }
    return {
        "Cloud": cloud_name,
        "Download Time": download_time,
        "Download Speed": download_speed,
        **security_scores
    }

def download_google_cloud(destination_path, bucket_name, source_blob_name):
    """Download file from Google Cloud and decrypt it using Twofish."""
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(source_blob_name)

    start_time = time.time()
    blob.download_to_filename(destination_path)
    download_time = time.time() - start_time
    file_size = os.path.getsize(destination_path) / (1024 * 1024)  # MB

    # Decrypt File using Twofish
    key_twofish = "SecurePassphrase"
    twofish = Twofish(key_twofish)
    with open(destination_path, 'rb') as enc_file:
        decrypted_data = twofish.decrypt(enc_file.read())

    decrypted_file_path = "decrypted_GoogleCloud.txt"
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)

    result = analyze_security("Google Cloud", download_time, file_size)
    result_queue.put(result)

def download_aws(destination_path, bucket_name, source_blob_name):
    """Download file from AWS and decrypt it using Twofish."""
    s3_client = boto3.client(
        's3', aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=AWS_REGION
    )

    start_time = time.time()
    s3_client.download_file(bucket_name, source_blob_name, destination_path)
    download_time = time.time() - start_time
    file_size = os.path.getsize(destination_path) / (1024 * 1024)  # MB

    # Decrypt File using Twofish
    key_twofish = "SecurePassphrase"
    twofish = Twofish(key_twofish)
    with open(destination_path, 'rb') as enc_file:
        decrypted_data = twofish.decrypt(enc_file.read())

    decrypted_file_path = "decrypted_AWS.txt"
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)

    result = analyze_security("AWS", download_time, file_size)
    result_queue.put(result)

def download_wasabi(destination_path, bucket_name, source_blob_name):
    """Download file from Wasabi and decrypt it using Twofish."""
    s3_client = boto3.client(
        's3', endpoint_url=WASABI_ENDPOINT,
        aws_access_key_id=WASABI_ACCESS_KEY_ID,
        aws_secret_access_key=WASABI_SECRET_ACCESS_KEY
    )

    try:
        start_time = time.time()
        s3_client.download_file(bucket_name, source_blob_name, destination_path)
        download_time = time.time() - start_time
        file_size = os.path.getsize(destination_path) / (1024 * 1024)  # MB

        # Decrypt File using Twofish
        key_twofish = "SecurePassphrase"
        twofish = Twofish(key_twofish)
        with open(destination_path, 'rb') as enc_file:
            decrypted_data = twofish.decrypt(enc_file.read())

        decrypted_file_path = "decrypted_Wasabi.txt"
        with open(decrypted_file_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)

        result = analyze_security("Wasabi", download_time, file_size)
        result_queue.put(result)
    except NoCredentialsError:
        print("Wasabi credentials not available.")

def plot_graphs(results):
    """Plots separate line graphs for each parameter."""
    clouds = [res['Cloud'] for res in results]
    download_times = [res['Download Time'] for res in results]
    download_speeds = [res['Download Speed'] for res in results]
    vulnerabilities = [res['Vulnerability to Attacks'] for res in results]
    compliance_scores = [res['Regulatory Compliance'] for res in results]
    access_control_scores = [res['Access Control'] for res in results]

    plt.figure(figsize=(12, 8))

    # Download Time Graph
    plt.subplot(3, 2, 1)
    plt.plot(clouds, download_times, marker='o', linestyle='-', color='b')
    plt.xlabel("Clouds")
    plt.ylabel("Download Time (s)")
    plt.title("Download Time Comparison")

    # Download Speed Graph
    plt.subplot(3, 2, 2)
    plt.plot(clouds, download_speeds, marker='o', linestyle='-', color='g')
    plt.xlabel("Clouds")
    plt.ylabel("Download Speed (MB/s)")
    plt.title("Download Speed Comparison")

    # Vulnerability to Attacks Graph
    plt.subplot(3, 2, 3)
    plt.plot(clouds, vulnerabilities, marker='o', linestyle='-', color='r')
    plt.xlabel("Clouds")
    plt.ylabel("Vulnerability Score")
    plt.title("Vulnerability to Attacks")

    # Regulatory Compliance Graph
    plt.subplot(3, 2, 4)
    plt.plot(clouds, compliance_scores, marker='o', linestyle='-', color='c')
    plt.xlabel("Clouds")
    plt.ylabel("Compliance Score")
    plt.title("Regulatory Compliance")

    # Access Control Graph
    plt.subplot(3, 2, 5)
    plt.plot(clouds, access_control_scores, marker='o', linestyle='-', color='m')
    plt.xlabel("Clouds")
    plt.ylabel("Access Control Score")
    plt.title("Access Control")

    plt.tight_layout()
    plt.show()

def main():
    bucket_google = "mycloudshield-bucket"
    bucket_aws = "my-cloudshield"
    bucket_wasabi = "cloudshield"
    source_blob = "encrypted_document.enc"

    encrypted_file_path = "downloaded.enc"

    threads = [
        threading.Thread(target=download_google_cloud, args=(encrypted_file_path, bucket_google, source_blob)),
        threading.Thread(target=download_aws, args=(encrypted_file_path, bucket_aws, source_blob)),
        threading.Thread(target=download_wasabi, args=(encrypted_file_path, bucket_wasabi, source_blob))
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    results = [result_queue.get() for _ in range(result_queue.qsize())]
    plot_graphs(results)

if __name__ == "__main__":
    main()
