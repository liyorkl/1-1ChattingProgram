import select
import socket
import sys
import signal
import argparse
import threading
import ssl

from utils import *

SERVER_HOST = "localhost"

stop_thread = False


# Using custom hashing as python hashing is random on runtime
def custom_hash(string):
    new_hash = 7
    for c in string:
        new_hash = new_hash * 31 + ord(c)
    return new_hash


# when we retrieve data we also what to check it against it's hash to ensure that data was not tampered with
def receive_and_check_hash(client):
    message_hash = receive(client)
    message = receive(client)
    if message_hash != custom_hash(message):
        # If its not the same prompt will be displayed to the server
        print(
            f"Suspicous activity: Hash not match!\n{message_hash}\n{custom_hash(message)}"
        )
    return message


# we only send data with it's hash
def send_with_hash(client, data):
    send(client, custom_hash(data))
    send(client, data)


def get_and_send(client):
    while not stop_thread:
        data = sys.stdin.readline().strip()
        if data:
            send_with_hash(client.sock, data)


class ChatClient:
    """A command line chat client using select"""

    def __init__(self, port, host=SERVER_HOST):
        self.connected = False
        self.host = host
        self.port = port
        self.signed_in = False

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.context.load_cert_chain(certfile="cert2.pem", keyfile="cert2.pem")
        self.context.load_verify_locations("cert2.pem")
        self.context.set_ciphers(
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA256"
        )

        # Initial prompt
        self.prompt = f" > "

        # Connect to server at port
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock = self.context.wrap_socket(self.sock, server_hostname=host)

            self.sock.connect((host, self.port))
            print(f"Now connected to chat server@ port {self.port}")
            self.connected = True

            # # Send my name...
            # send(self.sock, 'NAME: ' + self.name)
            # data = receive(self.sock)

            # # Contains client address, set it
            # addr = data.split('CLIENT: ')[1]
            # self.prompt = '[' + '@'.join((self.name, addr)) + ']> '

            threading.Thread(target=get_and_send, args=(self,)).start()

        except socket.error as e:
            print(f"Failed to connect to chat server @ port {self.port}")
            sys.exit(1)

    def cleanup(self):
        """Close the connection and wait for the thread to terminate."""
        self.sock.close()

    def run(self):
        """Chat client main loop"""
        while self.connected:
            try:
                if self.signed_in:
                    sys.stdout.write(self.prompt)
                    sys.stdout.flush()

                # Wait for input from stdin and socket
                # readable, writeable, exceptional = select.select([0, self.sock], [], [])
                readable, writeable, exceptional = select.select([self.sock], [], [])

                for sock in readable:
                    # if sock == 0:
                    #     data = sys.stdin.readline().strip()
                    #     if data:
                    #         send(self.sock, data)
                    if sock == self.sock:
                        data = receive_and_check_hash(self.sock)
                        if not data:
                            print("Server is shutting down.")
                            self.connected = False
                            break
                        else:
                            if not self.signed_in:
                                if data == "[Server]>Logged in Successfully":
                                    sys.stdout.write(data + "\n")
                                    sys.stdout.flush()
                                    self.signed_in = True
                                    data = receive_and_check_hash(self.sock)
                                    # Contains client address, set it
                                    name_addr = data.split(":")
                                    self.prompt = self.prompt = "me: "
                                    continue
                                sys.stdout.write(data)
                                sys.stdout.flush()
                                continue
                            sys.stdout.write(data + "\n")
                            sys.stdout.flush()

            except KeyboardInterrupt:
                print(" Client interrupted. " "")
                stop_thread = True
                self.cleanup()
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", action="store", dest="port", type=int, required=True)
    given_args = parser.parse_args()

    port = given_args.port

    client = ChatClient(port=port)
    client.run()
