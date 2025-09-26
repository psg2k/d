import socket, ssl, hashlib, json

HOST = "127.0.0.1"
PORT = 9999

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations("ca.crt")
context.set_ciphers("AES256-GCM-SHA384")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print("Server listening...")

    conn, addr = sock.accept()
    print("Connection from", addr)

    with context.wrap_socket(conn, server_side=True) as ssock:
        data = ssock.recv(4096).decode()
        obj = json.loads(data)

        hashed = obj["hash"]
        matrix = obj["matrix"]

        print("Received matrix:", matrix)

        # Verify hash
        if hashlib.sha256(json.dumps(matrix).encode()).hexdigest() == hashed:
            print("Hash OK ")
            ssock.sendall(b"yes")
        else:
            print("Hash mismatch ")
            ssock.sendall(b"no")

    print("Connection closed")

