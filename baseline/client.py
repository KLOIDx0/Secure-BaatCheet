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


def main():
    print("\n\t>>>>>>>>>> XYZ University Chat Client <<<<<<<<<<\n\n")
    # Create socket and connect to the server
    sock = create_socket()
    reader = sock.makefile('rb')     # buffered reader => no fixed-size recv truncation

    # ---- TODO (CLO3): Diffie-Hellman key exchange here to derive shared key K_ab ----

    try:
        while True:
            # Get user input
            message = input("You (Client): ")
            data = message.encode('utf-8')

            # ---- TODO (CLO3): AES-encrypt `data` with K_ab before sending ----
            send_msg(sock, data)

            # If the client sends "bye", terminate the chat
            if message == "bye":
                print("You disconnected from the chat.")
                break

            # Receive response from server
            reply = recv_msg(reader)
            if reply is None:
                print("Server closed the connection.")
                break

            # ---- TODO (CLO3): AES-decrypt `reply` with K_ab after receiving ----
            print(reply.decode('utf-8'))
    finally:
        # Close the socket after communication
        reader.close()
        sock.close()


if __name__ == "__main__":
    main()
