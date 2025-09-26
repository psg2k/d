import socket
import ssl
import json
import random

HOST = "127.0.0.1"
PORT = 65431

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain(certfile="client.crt", keyfile="client.key")
context.load_verify_locations("ca.crt")
context.check_hostname = False
context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")

def generate_random_matrix(rows=3, cols=3):
    return [[random.randint(0, 99) for _ in range(cols)] for _ in range(rows)]

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print(f"[*] Connected securely with mTLS to {HOST}:{PORT}")

        while True:
            cmd = input("[Client > ] Press Enter to send random matrix or type 'exit': ").strip()
            if cmd.lower() in ("exit", "quit"):
                ssock.sendall(b"exit\n")
                print("[*] Client ending session.")
                break

            # generate matrix
            matrix = generate_random_matrix(3, 3)
            print("[Client] Generated matrix:")
            for row in matrix:
                print(row)

            # serialize to JSON and send
            matrix_json = json.dumps(matrix) + "\n"
            ssock.sendall(matrix_json.encode())
            print("[*]Matrix sent.")