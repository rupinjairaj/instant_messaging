# Instant Messaging System
A group project for CS 6349 Network Security

## Group Members
| Name | email ID |
|------|----------| 
| Kashif Hussain | kashif.hussain@utdallas.edu |
| Preetham Rao Gottumukula | preethamrao.gottumukula@utdallas.edu |
| Rupin Jairaj | rupin.jairaj@utdallas.edu |

## Instruction to run the program
- From the root of the project CD into: e2eeim/src
- Run make clean to start.

	```$ make clean```

- Compile the project:
	
	```$ make```

- Start the server:

	```$ make server hostName=localhost port=7000 clients=2```

	Note: `hostName` and `port` is the address the server is listening on. `client` represents the number of clients the server will support. This is so we can load up the required number of RSA public keys for clients.

- Start the client:

	```$ make client clientId=0 clientHostName=localhost clientPort=3000 serverHostName=localhost serverPort=7000```

- Follow the instruction on the screen to establish a p2p session and chat.
