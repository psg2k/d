import socket
import ssl
from cryptography.fernet import Fernet
import os

HOST = "127.0.0.1"
PORT = 65431

# Generate AES key
key = Fernet.generate_key()
fernet = Fernet(key)

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain(certfile="client.crt", keyfile="client.key")
context.load_verify_locations("ca.crt")
context.check_hostname = False
context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")

# Read the text file
input_file = "input.txt"
try:
    with open(input_file, "rb") as f:
        file_data = f.read()
except FileNotFoundError:
    print(f"Error: {input_file} not found.")
    exit(1)

# Encrypt the file data
encrypted_data = fernet.encrypt(file_data)

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print(f"[*] Connected securely with mTLS to {HOST}:{PORT}")
        print(f"[*] Cipher: {ssock.cipher()}")

        # Send the AES key
        ssock.sendall(key)
        print("[*] Sent AES key")

        # Send the encrypted file size
        file_size = len(encrypted_data)
        ssock.sendall(file_size.to_bytes(8, byteorder='big'))
        print(f"[*] Sent file size: {file_size} bytes")

        # Send the encrypted file data
        ssock.sendall(encrypted_data)
        print(f"[*] Sent encrypted file: {input_file}")

        # Wait for server acknowledgment
        ack = ssock.recv(1024).decode().strip()
        print(f"[Server]: {ack}")

        if ack.lower() == "file received and decrypted":
            print("[*] File transfer successful.")
        else:
            print("[*] File transfer failed.")