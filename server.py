from auth import register, verify_login

from crypto_util import encrypt, decrypt

from dh import make_keypair, shared_secret
from keys import derive_key

import socket
import threading
import base64


online = {}
online_lock = threading.Lock()


send_lock = threading.Lock()  # one writer per socket at a time

def safe_send(sock, key, text):
       with send_lock:
           send_msg(sock, encrypt(key, text.encode('utf-8')))

def route(sender, target, text):
       with online_lock:
           entry = online.get(target)
       if entry is None:
           return f"error|{target} is offline"
       target_sock, target_key = entry
       safe_send(target_sock, target_key, f"from:{sender}|{text}")
       return "ok"

def send_msg(sock, data):
    """Send one framed, base64-encoded message (binary-safe once AES is added)."""
    sock.sendall(base64.b64encode(data) + b"\n")


def recv_msg(reader):
    """Read one framed message. Returns raw bytes, or None if the peer closed."""
    line = reader.readline()
    if not line:                 # empty read => connection closed by peer
        return None
    return base64.b64decode(line.strip())
    
def do_auth(reader, client_socket, K):
       # Up to 3 tries. Returns the username on success, None on failure.
       for _ in range(3):
           data = recv_msg(reader)
           if data is None:
               return None
           parts = decrypt(K, data).decode('utf-8').split('|', 2)
           if len(parts) != 3:
               send_msg(client_socket, encrypt(K, b"fail"))
               continue
           cmd, user, pw = parts
           if cmd == "register":
               ok = register(user, pw)
           elif cmd == "login":
               ok = verify_login(user, pw)
           else:
               ok = False
           if ok:
       	   	with online_lock:
           		if user in online:
               			send_msg(client_socket, encrypt(K, b"fail"))
               			continue
           		online[user] = (client_socket, K)
       	   	send_msg(client_socket, encrypt(K, b"ok"))
       	   	return user
           send_msg(client_socket, encrypt(K, b"fail"))
       return None


def handle_client(client_socket, client_address):
       reader = client_socket.makefile('rb')
       user = None
       try:
           # DH handshake (Step 10)
           A = int.from_bytes(recv_msg(reader), "big")
           b, B = make_keypair()
           send_msg(client_socket, B.to_bytes(256, "big"))
           K = derive_key(shared_secret(b, A))

           # Login or register (Step 14)
           user = do_auth(reader, client_socket, K)
           if user is None:
               print(f"Client {client_address} failed login.")
               return

           # Chat loop
           while True:
               data = recv_msg(reader)
               if data is None:
                   print(f"{user} disconnected.")
                   break
               message = decrypt(K, data).decode('utf-8')
               if message == "bye":
                   print(f"{user} left the chat.")
                   break
               if message.startswith("to:") and "|" in message:
                   target, text = message[3:].split("|", 1)
                   result = route(user, target, text)
                   print(f"{user} -> {target}: {result}")
                   safe_send(client_socket, K, result)
               else:
                   safe_send(client_socket, K, "error|use to:<user>|<text>")
       finally:
           if user is not None:
               with online_lock:
                   online.pop(user, None)
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
