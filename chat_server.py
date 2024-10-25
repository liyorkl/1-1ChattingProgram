import functools
import select
import socket
import sys
import signal
import argparse
import ssl
import os
import sqlite3
import threading
from utils import *

current_directory = os.curdir


def create_connection(path):
    connection = None
    try:
        connection = sqlite3.connect(path)
        print("Connection to SQLite DB successful")
    except sqlite3.Error as e:
        print(f"The error '{e}' occurred")
    return connection


def execute_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
        print("Query executed successfully")
    except sqlite3.Error as e:
        print(f"The error '{e}' occurred")


def retrieval_query(connection, query):
    cursor = connection.cursor()
    result = None
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        print(f"Found: {result}")
        return result
    except sqlite3.Error as e:
        print(f"The error '{e}' occurred")


def register(connection, username, password):
    add_user = f"""
        INSERT INTO
            users (username, password)
        VALUES
            ('{username}', '{password}');
        """
    # probably should add error catching for dup names, but we will ignore for now
    execute_query(connection, add_user)


def register_prompt(client, connection):
    send(client, "[Server]>Registration\n[Server]>Username: ")
    username = receive(client).lower()
    send(client, "[Server]>Password: ")
    password = receive(client)
    register(connection, username, password)
    send(client, "[Server]>Successfully Registered!\n")


def login(client, connection, username, password):
    find_users_password = f"""
    SELECT
        password
    FROM
        users
    WHERE
        users.username = '{username}'
    """
    passwords = retrieval_query(connection, find_users_password)
    if len(passwords) == 0:
        send(client, "[Server]>User not Found, please restart!\n")
        return False, username
    if password == passwords[0][0]:
        send(client, "[Server]>Logged in Successfully")
        return True, username
    send(client, "[Server]>Could not login, please restart!\n")
    return False, username


def login_prompt(client, connection):
    send(client, "[Server]>Login\n[Server]>Username: ")
    username = receive(client).lower()
    send(client, "[Server]>Password: ")
    password = receive(client)
    return login(client, connection, username, password)


def register_and_login(client, db_connection):
    ## Figure how to incoporate this a little later need to login to the server first
    signed_in = False
    username = ""

    login_input = ["login", "1", "l"]
    register_input = ["register", "2", "r"]
    valid_input = login_input + register_input

    send(
        client, "[Server]>Please select whether to login(1 or l) or register(2 or r): "
    )
    option = receive(client)
    while option not in valid_input:
        send(client, "[Server]>Option was invalid please try again!")
        send(
            client,
            "[Server]>Please select whether to login(1 or l) or register(2 or r): ",
        )
        option = receive(client)
    if option in login_input:
        signed_in, username = login_prompt(client, db_connection)
    if option in register_input:
        register_prompt(client, db_connection)

    while not signed_in:
        send(
            client,
            "[Server]>Please select whether to login(1 or l) or register(2 or r): ",
        )
        option = receive(client)
        while option not in valid_input:
            send(client, "[Server]>Option was invalid please try again!")
            send(
                client,
                "[Server]>Please select whether to login(1 or l) or register(2 or r): ",
            )
            option = receive(client)
        if option in login_input:
            signed_in, username = login_prompt(client, db_connection)
        if option in register_input:
            register_prompt(client, db_connection)

    return signed_in, username


def synchronized(function):
    lock = threading.Lock()

    @functools.wraps(function)
    def wrapper(self, *args, **kwargs):
        with lock:
            return function(self, *args, **kwargs)

    return wrapper


SERVER_HOST = "localhost"


class ChatServer(object):
    """An example chat server using select"""

    def __init__(self, port, backlog=5):
        self.timeout = None
        self.clients = 0
        self.clientmap = {}
        self.outputs = []  # list output sockets

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.context.load_cert_chain(certfile="cert.pem", keyfile="cert.pem")
        self.context.load_verify_locations("cert.pem")
        self.context.set_ciphers("AES128-SHA")

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((SERVER_HOST, port))
        self.server.listen(backlog)
        self.server = self.context.wrap_socket(self.server, server_side=True)

        # Catch keyboard interrupts
        signal.signal(signal.SIGINT, self.sighandler)

        self.database_path = os.path.join(
            current_directory, "database", "serverData.sqlite"
        )
        self.db_connection = create_connection(self.database_path)

        create_users_table = """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            );
            """
        execute_query(self.db_connection, create_users_table)

        print(f"Server listening to port: {port} ...")

    @synchronized
    def add_client(self, client, address, username):
        # Compute client name and send back
        self.clients += 1
        send(client, f"{username}:{str(address[0])}")
        self.inputs.append(client)

        self.clientmap[client] = (address, username)
        # Send joining information to other clients
        msg = f"\n(Connected: New client ({self.clients}) from {self.get_client_name(client)})"
        for output in self.outputs:
            send(output, msg)
        self.outputs.append(client)
        self.timeout = None

    def handle_register_and_login(self, client, address):
        ## login/register code
        signed_in = False

        new_db_connection = create_connection(self.database_path)

        while not signed_in:
            signed_in, username = register_and_login(client, new_db_connection)

        self.add_client(client, address, username)

    def sighandler(self, signum, frame):
        """Clean up client outputs"""
        print("Shutting down server...")

        # Close existing client sockets
        for output in self.outputs:
            output.close()

        self.server.close()

    def get_client_name(self, client):
        """Return the name of the client"""
        info = self.clientmap[client]
        host, name = info[0][0], info[1]
        return name

    def run(self):
        # inputs = [self.server, sys.stdin]
        self.inputs = [self.server]
        self.outputs = []
        running = True
        while running:
            try:
                readable, writeable, exceptional = select.select(
                    self.inputs, self.outputs, [], self.timeout
                )
            except select.error as e:
                break

            for sock in readable:
                sys.stdout.flush()
                if sock == self.server:
                    # handle the server socket
                    client, address = self.server.accept()

                    print(
                        f"Chat server: got connection {client.fileno()} from {address}"
                    )

                    self.timeout = 1
                    threading.Thread(
                        target=self.handle_register_and_login, args=(client, address)
                    ).start()

                else:
                    # handle all other sockets
                    try:
                        data = receive(sock)
                        if data:
                            # Send as new client's message...
                            msg = f"\n{self.get_client_name(sock)}: {data}"

                            # Send data to all except ourself
                            for output in self.outputs:
                                if output != sock:
                                    send(output, msg)
                        else:
                            print(f"Chat server: {sock.fileno()} hung up")
                            self.clients -= 1
                            sock.close()
                            self.inputs.remove(sock)
                            self.outputs.remove(sock)

                            # Sending client leaving information to others
                            msg = f"\n(Now hung up: Client from {self.get_client_name(sock)})"

                            for output in self.outputs:
                                send(output, msg)
                    except socket.error as e:
                        # Remove
                        self.inputs.remove(sock)
                        self.outputs.remove(sock)

        self.server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Socket Server Example with Select")
    parser.add_argument("--port", action="store", dest="port", type=int, required=True)
    given_args = parser.parse_args()
    port = given_args.port

    server = ChatServer(port)
    server.run()
