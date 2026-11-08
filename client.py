import threading

from crypto_util import encrypt, decrypt

from dh import make_keypair, shared_secret
from keys import derive_key

import socket
import base64


def send_msg(sock, data):
    """Send one framed, base64-encoded message.

    Base64 + newline framing keeps binary data intact once AES is added:
    raw ciphertext is usually NOT valid UTF-8, and a TCP stream has no
    message boundaries. Base64 output is ASCII and never contains '\\n',
    so one line == one message.
    """
    sock.sendall(base64.b64encode(data) + b"\n")


def recv_msg(reader):
    """Read one framed message. Returns raw bytes, or None if the peer closed."""
    line = reader.readline()
    if not line:                 # empty read => connection closed by peer
        return None
    return base64.b64decode(line.strip())


def create_socket():
    # create the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # setup an address
    server_address = ('localhost', 8080)
    sock.connect(server_address)
    return sock

def receiver(reader, K):
       # Runs in the background and prints anything the server sends
       while True:
           line = recv_msg(reader)
           if line is None:
               print("\nServer closed the connection.")
               break
           print("\n" + decrypt(K, line).decode('utf-8'))
           print("You (Client): ", end="", flush=True)


def main():
    print("\n\t>>>>>>>>>> XYZ University Chat Client <<<<<<<<<<\n\n")
    # Create socket and connect to the server
    sock = create_socket()
    reader = sock.makefile('rb')     # buffered reader => no fixed-size recv truncation

    a, A = make_keypair()
    send_msg(sock, A.to_bytes(256, "big"))
    B = int.from_bytes(recv_msg(reader), "big")
    K = derive_key(shared_secret(a, B))
    
    while True:
       choice = input("(1) login  (2) register: ").strip()
       cmd = "login" if choice == "1" else "register"
       user = input("Username: ").strip()
       pw = input("Password: ")
       send_msg(sock, encrypt(K, f"{cmd}|{user}|{pw}".encode('utf-8')))
       reply = recv_msg(reader)
       if reply is None:
           print("Server closed the connection.")
           reader.close()
           sock.close()
           raise SystemExit
       if decrypt(K, reply) == b"ok":
           print("Logged in as", user)
           break
       print("Login failed. Try again.")

    try:
       threading.Thread(target=receiver, args=(reader, K), daemon=True).start()
       while True:
           message = input("You (Client): ")
           send_msg(sock, encrypt(K, message.encode('utf-8')))
           if message == "bye":
               print("You disconnected from the chat.")
               break
    finally:
        # Close the socket after communication
        reader.close()
        sock.close()


if __name__ == "__main__":
    main()
