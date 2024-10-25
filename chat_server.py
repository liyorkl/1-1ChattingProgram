import select
import socket
import sys
import signal
import argparse
import ssl
import os
import sqlite3

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


def register_prompt(connection):
    print("Registration")
    username = input("Username: ").lower()
    password = input("Password: ")
    register(connection, username, password)
    print("Successfully Registered!\n")


def login(connection, username, password):
    global name
    find_users_password = f"""
    SELECT
        password
    FROM
        users
    WHERE
        users.username = '{username}'
    """
    passwords = retrieval_query(connection, find_users_password)
    if password == passwords[0][0]:
        print("Logged in Successfully")
        name = username
        return True
    print("Could not login, please restart!\n")
    return False


def login_prompt(connection):
    print("Login")
    username = input("Username: ").lower()
    password = input("Password: ")
    return login(connection, username, password)


SERVER_HOST = 'localhost'


class ChatServer(object):
    """ An example chat server using select """

    def __init__(self, port, backlog=5):
        self.clients = 0
        self.clientmap = {}
        self.outputs = []  # list output sockets

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.context.load_cert_chain(certfile="cert.pem", keyfile="cert.pem")
        self.context.load_verify_locations('cert.pem')
        self.context.set_ciphers('AES128-SHA')

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((SERVER_HOST, port))
        self.server.listen(backlog)
        # Catch keyboard interrupts
        signal.signal(signal.SIGINT, self.sighandler)

        database_path = os.path.join(current_directory, "database", "serverData.sqlite")
        db_connection = create_connection(database_path)

        create_users_table = """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            );
            """
        execute_query(db_connection, create_users_table)

        print(f'Server listening to port: {port} ...')

    def sighandler(self, signum, frame):
        """ Clean up client outputs"""
        print('Shutting down server...')

        # Close existing client sockets
        for output in self.outputs:
            output.close()

        self.server.close()

    def get_client_name(self, client):
        """ Return the name of the client """
        info = self.clientmap[client]
        host, name = info[0][0], info[1]
        return '@'.join((name, host))

    def run(self):
        # inputs = [self.server, sys.stdin]
        inputs = [self.server]
        self.outputs = []
        running = True
        while running:
            try:
                readable, writeable, exceptional = select.select(
                    inputs, self.outputs, [])
            except select.error as e:
                break

            for sock in readable:
                sys.stdout.flush()
                if sock == self.server:
                    # handle the server socket
                    client, address = self.server.accept()
                    print(
                        f'Chat server: got connection {client.fileno()} from {address}')
                    # Read the login name
                    cname = receive(client).split('NAME: ')[1]

                    # Compute client name and send back
                    self.clients += 1
                    send(client, f'CLIENT: {str(address[0])}')
                    inputs.append(client)

                    self.clientmap[client] = (address, cname)
                    # Send joining information to other clients
                    msg = f'\n(Connected: New client ({self.clients}) from {self.get_client_name(client)})'
                    for output in self.outputs:
                        send(output, msg)
                    self.outputs.append(client)

                # elif sock == sys.stdin:
                #     # didn't test sys.stdin on windows system
                #     # handle standard input
                #     cmd = sys.stdin.readline().strip()
                #     if cmd == 'list':
                #         print(self.clientmap.values())
                #     elif cmd == 'quit':
                #         running = False
                else:
                    # handle all other sockets
                    try:
                        data = receive(sock)
                        if data:
                            # Send as new client's message...
                            msg = f'\n#[{self.get_client_name(sock)}]>> {data}'

                            # Send data to all except ourself
                            for output in self.outputs:
                                if output != sock:
                                    send(output, msg)
                        else:
                            print(f'Chat server: {sock.fileno()} hung up')
                            self.clients -= 1
                            sock.close()
                            inputs.remove(sock)
                            self.outputs.remove(sock)

                            # Sending client leaving information to others
                            msg = f'\n(Now hung up: Client from {self.get_client_name(sock)})'

                            for output in self.outputs:
                                send(output, msg)
                    except socket.error as e:
                        # Remove
                        inputs.remove(sock)
                        self.outputs.remove(sock)
                        
        self.server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Socket Server Example with Select')
    parser.add_argument('--name', action="store", dest="name", required=True)
    parser.add_argument('--port', action="store",
                        dest="port", type=int, required=True)
    given_args = parser.parse_args()
    port = given_args.port
    name = given_args.name

    server = ChatServer(port)
    server.run()



## Figure how to incoporate this a little later need to login to the server first
signed_in = False

login_input = ["login", "1", "l"]
register_input = ["register", "2", "r"]
valid_input = login_input + register_input

print("Please select whether to login(1 or l) or register(2 or r):")
option = input("--> ")
while option not in valid_input:
    print("Option was invalid please try again!")
    print("Please select whether to login(1 or l) or register(2 or r):")
    option = input("--> ")
if option in login_input:
    signed_in = login_prompt(db_connection)
if option in register_input:
    register_prompt(db_connection)
last_option = option

while not signed_in:
    print("Please select whether to login(1 or l) or register(2 or r):")
    option = input("--> ")
    while option not in valid_input:
        print("Option was invalid please try again!")
        print("Please select whether to login(1 or l) or register(2 or r):")
        option = input("--> ")
    if option in login_input:
        signed_in = login_prompt(db_connection)
    if option in register_input:
        register_prompt(db_connection)