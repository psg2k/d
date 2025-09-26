import socket
import ssl
import json

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

        while True:
            data = conn.recv(4096)
            if not data:
                break

            # decode JSON string into Python list
            matrix_json = data.decode().strip()
            if matrix_json.lower() == "exit":
                print("[*] Client requested to end session.")
                break

            try:
                matrix = json.loads(matrix_json)
                print("[Server] Received matrix:")
                for row in matrix:
                    print(row)
                print()
            except json.JSONDecodeError:
                print("[Server] Could not decode matrix JSON.")

        conn.close()
        print("[*] Connection closed.")