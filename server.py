from crypto_util import encrypt, decrypt

from dh import make_keypair, shared_secret
from keys import derive_key

import socket
import threading
import base64


def send_msg(sock, data):
    """Send one framed, base64-encoded message (binary-safe once AES is added)."""
    sock.sendall(base64.b64encode(data) + b"\n")


def recv_msg(reader):
    """Read one framed message. Returns raw bytes, or None if the peer closed."""
    line = reader.readline()
    if not line:                 # empty read => connection closed by peer
        return None
    return base64.b64decode(line.strip())


def handle_client(client_socket, client_address):
    reader = client_socket.makefile('rb')

    A = int.from_bytes(recv_msg(reader), "big")
    b, B = make_keypair()
    send_msg(client_socket, B.to_bytes(256, "big"))
    K = derive_key(shared_secret(b, A))
    print("Key fingerprint:", K.hex()[:16])

    try:
        while True:
            # Receive message from the client
            data = recv_msg(reader)
            if data is None:                      # client closed abruptly
                print(f"Client {client_address} disconnected.")
                break

            message = decrypt(K, data).decode('utf-8')

            # If client sends "bye", close the connection
            if message == "nikl":
                print(f"Client {client_address} left the chat.")
                break

            print("Client:", message)

            # Send a response back to the client
            response = input("You (Server): ")
            out = ("Server: " + response).encode('utf-8')

            send_msg(client_socket, encrypt(K, out))
    finally:
        reader.close()
        client_socket.close()


def main():
    print("\n\t>>>>>>>>>> XYZ University Chat Server <<<<<<<<<<\n\n")
    # create the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # allow quick restarts during testing (avoids "Address already in use")
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # bind to the specified IP and port
    server_socket.bind(('', 8080))
    server_socket.listen(5)
    print("Server listening on port 8080. Waiting for connections...\n")

    try:
        while True:
            # accept incoming connections
            client_socket, client_address = server_socket.accept()
            print("Connected:", client_address)
            # threading works on every OS (unlike os.fork, which is Unix-only)
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
