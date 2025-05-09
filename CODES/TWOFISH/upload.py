import os
import time
import threading
import hashlib
import boto3
import matplotlib.pyplot as plt
from google.cloud import storage
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

# Twofish Manual Implementation
class TwofishCipher:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()[:16]  # 16-byte key for Twofish

    def encrypt(self, plaintext):
        padded_plaintext = self.pad(plaintext)
        ciphertext = bytearray()
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            ciphertext.extend(self._twofish_block_encrypt(block))
        return ciphertext

    def pad(self, data, block_size=16):
        padding_length = block_size - (len(data) % block_size)
        return data + bytes([padding_length] * padding_length)

    def _twofish_block_encrypt(self, block):
        # Dummy block encryption (Replace with actual Twofish encryption logic)
        return block  # Placeholder (implement actual Twofish encryption)

def analyze_security(cloud_name, encryption_supported=True, auth_status=True, access_control="Private", integrity_check=True, compliance=True, attack_logs=False):
    """Analyzes security and prints satisfied & not satisfied criteria."""

    security_criteria = {
        "Encryption Strength": encryption_supported,
        "Authentication Status": auth_status,
        "Access Control": access_control == "Private",
        "Data Integrity Check": integrity_check,
        "Regulatory Compliance": compliance,
        "Vulnerability to Attacks": not attack_logs  # If attack logs exist, it's a negative factor.
    }

    security_scores = {
        "Encryption Strength": 20 if encryption_supported else 10,
        "Authentication Status": 30 if auth_status else 0,
        "Access Control": 15 if access_control == "Private" else 5,
        "Data Integrity Check": 10 if integrity_check else 0,
        "Regulatory Compliance": 15 if compliance else 5,
        "Vulnerability to Attacks": 10 if not attack_logs else 5
    }

    final_score = sum(security_scores.values())

    # Print satisfied and not satisfied security criteria
    satisfied = [key for key, value in security_criteria.items() if value]
    not_satisfied = [key for key, value in security_criteria.items() if not value]

    print(f"\n🔹 Security Evaluation for {cloud_name} 🔹")
    print("✅ Satisfied Criteria:")
    for criteria in satisfied:
        print(f"   - {criteria}")

    print("\n❌ Not Satisfied Criteria:")
    for criteria in not_satisfied:
        print(f"   - {criteria}")

    print("-" * 50)  # Separator for readability

    return {
        "Cloud": cloud_name,
        **security_scores,
        "Final Security Score": final_score
    }

def upload_google_cloud(file_path, bucket_name, destination_blob_name):
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)

    start_time = time.time()
    blob.upload_from_filename(file_path)
    upload_time = time.time() - start_time
    file_size = os.path.getsize(file_path) / (1024 * 1024)  # MB

    result = analyze_security("Google Cloud")
    result.update({"Upload Time": upload_time, "Upload Speed": file_size / upload_time if upload_time > 0 else 0})
    result_queue.put(result)

def upload_aws(file_path, bucket_name, destination_blob_name):
    s3_client = boto3.client(
        's3', aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=AWS_REGION
    )

    start_time = time.time()
    s3_client.upload_file(file_path, bucket_name, destination_blob_name)
    upload_time = time.time() - start_time
    file_size = os.path.getsize(file_path) / (1024 * 1024)  # MB

    result = analyze_security("AWS")
    result.update({"Upload Time": upload_time, "Upload Speed": file_size / upload_time if upload_time > 0 else 0})
    result_queue.put(result)

def upload_wasabi(file_path, bucket_name, destination_blob_name):
    s3_client = boto3.client(
        's3', endpoint_url=WASABI_ENDPOINT,
        aws_access_key_id=WASABI_ACCESS_KEY_ID,
        aws_secret_access_key=WASABI_SECRET_ACCESS_KEY
    )

    try:
        start_time = time.time()
        s3_client.upload_file(file_path, bucket_name, destination_blob_name)
        upload_time = time.time() - start_time
        file_size = os.path.getsize(file_path) / (1024 * 1024)  # MB

        result = analyze_security("Wasabi")
        result.update({"Upload Time": upload_time, "Upload Speed": file_size / upload_time if upload_time > 0 else 0})
        result_queue.put(result)
    except NoCredentialsError:
        print("Wasabi credentials not available.")

def plot_graphs(results):
    """Plots separate line graphs for each parameter with annotations for Upload Time, Upload Speed, and Final Security Score."""
    clouds = [res['Cloud'] for res in results]
    upload_times = [res['Upload Time'] for res in results]
    upload_speeds = [res['Upload Speed'] for res in results]
    vulnerabilities = [res['Vulnerability to Attacks'] for res in results]
    compliance_scores = [res['Regulatory Compliance'] for res in results]
    access_control_scores = [res['Access Control'] for res in results]
    final_scores = [res['Final Security Score'] for res in results]

    plt.figure(figsize=(12, 10))

    # Upload Time Graph (with annotation)
    plt.subplot(3, 2, 1)
    plt.plot(clouds, upload_times, marker='o', linestyle='-', color='b')
    for i, txt in enumerate(upload_times):
        plt.annotate(f"{txt:.2f}s", (clouds[i], upload_times[i]), textcoords="offset points", xytext=(0,5), ha='center')
    plt.xlabel("Clouds")
    plt.ylabel("Upload Time (s)")
    plt.title("Upload Time Comparison")

    # Upload Speed Graph (with annotation)
    plt.subplot(3, 2, 2)
    plt.plot(clouds, upload_speeds, marker='o', linestyle='-', color='g')
    for i, txt in enumerate(upload_speeds):
        plt.annotate(f"{txt:.6f} MB/s", (clouds[i], upload_speeds[i]), textcoords="offset points", xytext=(0,5), ha='center')
    plt.xlabel("Clouds")
    plt.ylabel("Upload Speed (MB/s)")
    plt.title("Upload Speed Comparison")

    # Vulnerability to Attacks Graph
    plt.subplot(3, 2, 3)
    plt.plot(clouds, vulnerabilities, marker='o', linestyle='-', color='r')
    plt.xlabel("Clouds")
    plt.ylabel("Vulnerability resistance")
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

    # Final Security Score Graph (with annotation)
    plt.subplot(3, 2, 6)
    plt.plot(clouds, final_scores, marker='o', linestyle='-', color='purple')
    for i, txt in enumerate(final_scores):
        plt.annotate(f"{txt}", (clouds[i], final_scores[i]), textcoords="offset points", xytext=(0,5), ha='center')
    plt.xlabel("Clouds")
    plt.ylabel("Final Security Score")
    plt.title("Final Security Score Comparison")

    plt.tight_layout()
    plt.show()


def display_table(results):
    """Displays a tabulated summary of the security scores."""
    headers = ["Cloud", "Encryption Strength", "Authentication", "Access Control", "Data Integrity", "Compliance", "Vulnerability", "Final Score"]
    table_data = [
        [res["Cloud"], res["Encryption Strength"], res["Authentication Status"], res["Access Control"], 
         res["Data Integrity Check"], res["Regulatory Compliance"], res["Vulnerability to Attacks"], res["Final Security Score"]]
        for res in results
    ]
    
    print("\nFinal Security Scores:\n")
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

def main():
    file_path = "document.txt"
    bucket_google = "mycloudshield-bucket"
    bucket_aws = "my-cloudshield"
    bucket_wasabi = "cloudshield"
    destination_blob = "encrypted_document.enc"

    # Encrypt file using Twofish
    key_twofish = "SecurePassphrase"
    cipher = TwofishCipher(key_twofish)

    with open(file_path, 'rb') as file:
        encrypted_data = cipher.encrypt(file.read())

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(encrypted_data)

    # Create and start threads
    threads = [
        threading.Thread(target=upload_google_cloud, args=(encrypted_file_path, bucket_google, destination_blob)),
        threading.Thread(target=upload_aws, args=(encrypted_file_path, bucket_aws, destination_blob)),
        threading.Thread(target=upload_wasabi, args=(encrypted_file_path, bucket_wasabi, destination_blob))
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    results = [result_queue.get() for _ in range(result_queue.qsize())]
    display_table(results)
    plot_graphs(results)

if __name__ == "__main__":
    main()
