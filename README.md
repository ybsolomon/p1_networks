## End-to-End Detection of Network Compression 
### Yordanos Solomon (ID: 20543571)
---
## Config File
To successfully run this program, you must populate a JSON file with the following parameters (***case-sensitive***) or the application **WILL NOT RUN CORRECTLY**:

```
- The Server’s IP Address
- The Client's IP Address
- Source Port Number for UDP
- Destination Port Number for UDP
- Destination Port Number for TCP Head SYN
- Destination Port Number for TCP Tail SYN
- Port Number for TCP
- The Size of the UDP Payload in the UDP Packet Train
- Inter-Measurement Time
- The Number of UDP Packets in the UDP Packet Train
- TTL for the UDP Packets (only required for standalone application)
```

## Server/Client Application
The server and client must be run on the machines that correspond to the IP addresses specified in the config file (server runs on server machine, client runs on client machine), otherwise the sockets will not bind.

### Server Setup:
To build and run the server side of the compression detection application, you must run `make server`, which is specified in the Makefile. Then to start the app, the only command line argument needed is the server's port number, which is found in the config file.
```
username@server$: make server
username@server$: ./server <port-number>
```
***The server must be running before starting the client in order for a connection to be established.***

### Client Setup:
To build and run the client side, you must run `make client`, which is specified in the Makefile. The only command line argument necessary to run the client is the path to the config file.

```
username@client$: make client
username@client$: ./client <path-to-config-file>
```

## Standalone Application
The standalone application must be run on the machine that corresponds to the client IP address specified in the config file, otherwise the sockets will not bind.

### Standalone Setup:
To build and run the standalone application, you must run `make standalone`, which is specified in the Makefile.  The standalone app must be run as the root user, but like the client, only requires the path to the config file as an argument.

```
username@client$: make standalone
username@client$: sudo ./standalone <path-to-config-file>
```

### Compilation Tip!
To compile the server/client and standalone applications at once, use `make all` on both machines.