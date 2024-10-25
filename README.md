# 1-1 Chatting Program (Local machine)

Class Assignment! Simple local machine chatting program.

## Installation

There is no installation required as all libraries used are part of the python standard library.

## To use:

Before be get started we will need a terminal each for the server and each client that is going to be connected.

Make sure that the terminals are open to the directory with the python files.

Please run the server first!

### Server

To run the server please use in the command line

`python chat_server.py --port=9988`

`python` is dependent on how it's installed on your machine please follow the instructions there for this.

`--port=****` the port can be number, just ensure that client is using the same port as server

Once this is running please leave it open. There will be log messages in case there is a need to debug.

### Client

To run the client please use in the command line

`python chat_client.py --port=9988`

`python` is dependent on how it's installed on your machine please follow the instructions there for this.

`--port=****` the port can be number, just ensure that client is using the same port as server

Once you have this running follow the instructions to register an account, and then login to start messaging others connected to the server.

`username`s are case insensitive so `bob` is the same as `BoB`

## Limitations

There are no hard coded limits to message length.

There should also be no limit to the number of concurrent connections.

The same user can be signed in concurrently at the same time, could be useful to send messages to self, on same network but different devices.