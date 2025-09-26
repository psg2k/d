import socket
import ssl
from cryptography.fernet import Fernet

HOST = "127.0.0.1"
PORT = 65431

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations("ca.crt")
context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"[*] Secure mTLS server listening on {HOST}:{PORT}")

    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()
        print(f"[+] Connection from {addr}")
        print(f"[*] Cipher: {conn.cipher()}")

        # Receive the AES key
        key = conn.recv(128)  # Fernet keys are typically 44 bytes
        fernet = Fernet(key)
        print("[*] Received AES key")

        # Receive the file size
        file_size_bytes = conn.recv(8)
        file_size = int.from_bytes(file_size_bytes, byteorder='big')
        print(f"[*] Received file size: {file_size} bytes")

        # Receive the encrypted file data
        encrypted_data = b""
        while len(encrypted_data) < file_size:
            data = conn.recv(1024)
            if not data:
                break
            encrypted_data += data
        print("[*] Received encrypted file")

        # Decrypt the file data
        try:
            decrypted_data = fernet.decrypt(encrypted_data)
            # Save the decrypted file
            output_file = "received_output.txt"
            with open(output_file, "wb") as f:
                f.write(decrypted_data)
            print(f"[*] Decrypted file saved as: {output_file}")
            conn.sendall(b"File received and decrypted")
        except Exception as e:
            print(f"[*] Decryption failed: {e}")
            conn.sendall(b"File decryption failed")

        conn.close()
        print("[*] Connection closed.")