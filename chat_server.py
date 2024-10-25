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


# Using custom hashing as python hashing is random on runtime
def custom_hash(string):
    new_hash = 7
    for c in string:
        new_hash = new_hash * 31 + ord(c)
    return new_hash


# when we retrieve data we also what to check it against it's hash to ensure that data was not tampered with
def retrieve_and_check_hash(client):
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


# creates a connection for sqlite to a database
def create_connection(path):
    connection = None
    try:
        connection = sqlite3.connect(path)
        print("Connected to database")
    except sqlite3.Error as e:
        print(f"The error '{e}' occurred")
    return connection


# executes a non retrival query
def execute_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
        print("Query executed successfully")
    except sqlite3.Error as e:
        print(f"The error '{e}' occurred")


# executes a retrieval query and returns the matches
def retrieval_query(connection, query):
    cursor = connection.cursor()
    result = None
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        print("Query executed successfully")
        print(f"Found: {result}")
        return result
    except sqlite3.Error as e:
        print(f"The error '{e}' occurred")


# Registers a user by adding its username and corresponding hashed password
def register(connection, username, password):

    # First check if there exists a the exact same username
    find_username = f"""
    SELECT
        username
    FROM
        users
    WHERE
        users.username = '{username}'
    """
    if retrieval_query(connection, find_username):
        # if so dont add another entry
        return False

    add_user = f"""
        INSERT INTO
            users (username, password)
        VALUES
            ('{username}', '{custom_hash(password)}');
        """
    execute_query(connection, add_user)
    return True


# Prompt for user to register an account
def register_prompt(client, connection):
    send_with_hash(client, "[Server]>Registration\n[Server]>Username: ")
    username = retrieve_and_check_hash(client).lower()
    send_with_hash(client, "[Server]>Password: ")
    password = retrieve_and_check_hash(client)
    if register(connection, username, password):
        send_with_hash(client, "[Server]>Successfully Registered!\n")
    else:
        send_with_hash(client, "[Server]>Name already exists, please restart!\n")


# checks if the hash of the password entered is the same as what is stored
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
        send_with_hash(client, "[Server]>User not Found, please restart!\n")
        return False, username
    if str(custom_hash(password)) == passwords[0][0]:
        send_with_hash(client, "[Server]>Logged in Successfully")
        return True, username
    send_with_hash(client, "[Server]>Could not login, please restart!\n")
    return False, username


# Prompt for user to login
def login_prompt(client, connection):
    send_with_hash(client, "[Server]>Login\n[Server]>Username: ")
    username = retrieve_and_check_hash(client).lower()
    send_with_hash(client, "[Server]>Password: ")
    password = retrieve_and_check_hash(client)
    return login(client, connection, username, password)


# function that allows handles pre login information
def register_and_login(client, db_connection):
    signed_in = False
    username = ""

    login_input = ["login", "1", "l"]
    register_input = ["register", "2", "r"]
    valid_input = login_input + register_input

    send_with_hash(
        client, "[Server]>Please select whether to login(1 or l) or register(2 or r): "
    )
    option = retrieve_and_check_hash(client)
    while option not in valid_input:
        send_with_hash(client, "[Server]>Option was invalid please try again!")
        send_with_hash(
            client,
            "[Server]>Please select whether to login(1 or l) or register(2 or r): ",
        )
        option = retrieve_and_check_hash(client)
    if option in login_input:
        signed_in, username = login_prompt(client, db_connection)
    if option in register_input:
        register_prompt(client, db_connection)

    while not signed_in:
        send_with_hash(
            client,
            "[Server]>Please select whether to login(1 or l) or register(2 or r): ",
        )
        option = retrieve_and_check_hash(client)
        while option not in valid_input:
            send_with_hash(client, "[Server]>Option was invalid please try again!")
            send_with_hash(
                client,
                "[Server]>Please select whether to login(1 or l) or register(2 or r): ",
            )
            option = retrieve_and_check_hash(client)
        if option in login_input:
            signed_in, username = login_prompt(client, db_connection)
        if option in register_input:
            register_prompt(client, db_connection)

    return signed_in, username


# synchronization wrapper to allow for concurrent users logging in
def synchronized(function):
    lock = threading.Lock()

    @functools.wraps(function)
    def wrapper(self, *args, **kwargs):
        with lock:
            return function(self, *args, **kwargs)

    return wrapper


SERVER_HOST = "localhost"


# Class example
class ChatServer(object):
    """An example chat server using select"""

    def __init__(self, port, backlog=5):
        self.timeout = None  # help with new clients issue
        self.clients = 0
        self.clientmap = {}
        self.outputs = []

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.context.load_cert_chain(certfile="cert1.pem", keyfile="cert1.pem")
        self.context.load_verify_locations("cert1.pem")
        # includes stronger and more ciphers
        self.context.set_ciphers(
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA256"
        )

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((SERVER_HOST, port))
        self.server.listen(backlog)
        self.server = self.context.wrap_socket(self.server, server_side=True)

        # Catch keyboard interrupts
        signal.signal(signal.SIGINT, self.sighandler)

        # path for database with user's hashed passwords
        self.database_path = os.path.join(current_directory, "serverData.sqlite")

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

    # Annotation used for concurrent users logging in.
    @synchronized
    def add_client(self, client, address, username):
        # Compute client name and send back
        self.clients += 1
        send_with_hash(client, f"{username}:{str(address[0])}")
        self.inputs.append(client)

        self.clientmap[client] = (address, username)
        # Send joining information to other clients
        msg = f"\n(Connected: New client ({self.clients}) from {self.get_client_name(client)})"
        for output in self.outputs:
            send_with_hash(output, msg)
        self.outputs.append(client)
        # reset timout to not refresh
        self.timeout = None

    ## login/register code to allow parallelisation and not block main thread
    def handle_register_and_login(self, client, address):
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
                    self.inputs, self.outputs, [], 1
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

                    # set time out so that we don't get stuck waiting when creating multiple clients
                    self.timeout = 1

                    # use a thread to handle multiple users signing in and still be able to process information
                    threading.Thread(
                        target=self.handle_register_and_login, args=(client, address)
                    ).start()

                else:
                    # handle all other sockets
                    try:
                        data = retrieve_and_check_hash(client)
                        if data:
                            # Send as new client's message...
                            msg = f"\n{self.get_client_name(sock)}: {data}"

                            # Send data to all except ourself
                            for output in self.outputs:
                                if output != sock:
                                    send_with_hash(output, msg)
                        else:
                            print(f"Chat server: {sock.fileno()} hung up")
                            self.clients -= 1
                            sock.close()
                            self.inputs.remove(sock)
                            self.outputs.remove(sock)

                            # Sending client leaving information to others
                            msg = f"\n(Now hung up: Client from {self.get_client_name(sock)})"

                            for output in self.outputs:
                                send_with_hash(output, msg)
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
