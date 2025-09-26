import socket, ssl, hashlib, json

HOST = "127.0.0.1"
PORT = 9999

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain(certfile="client.crt", keyfile="client.key")
context.load_verify_locations("ca.crt")
context.check_hostname = False
context.set_ciphers("AES256-GCM-SHA384")

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        # Build 2x2 matrix
        matrix = []
        r, c = 2, 2
        for i in range(r):
            row = input(f"Enter row {i+1} values (space separated): ").split()
            row = [int(x) for x in row]
            matrix.append(row)

        print("Matrix is:", matrix)

        # Hash + wrap in JSON
        matrix_json = json.dumps(matrix)
        hashed = hashlib.sha256(matrix_json.encode()).hexdigest()
        payload = json.dumps({"hash": hashed, "matrix": matrix}).encode()

        ssock.sendall(payload)

        data = ssock.recv(1024)
        print("Server said:", data.decode().strip())
