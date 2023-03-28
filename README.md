## End-to-End Detection of Network Compression 
### Yordanos Solomon (ID: 20543571)
---
## Config File
To successfully run this program, you must populate a JSON file with the following parameters or the program **WILL NOT RUN**:

```
- The Server’s IP Address
- Source Port Number for UDP
- Destination Port Number for UDP
- Destination Port Number for TCP Head SYN, x
- Destination Port Number for TCP Tail SYN, y
- Port Number for TCP (Pre-/Post- Probing Phases)
- The Size of the UDP Payload in the UDP Packet Train, ℓ (default value: 1000B)
- Inter-Measurement Time, γ (default value: 15 seconds)
- The Number of UDP Packets in the UDP Packet Train, n (default value: 6000)
- TTL for the UDP Packets (default value: 255)
```

## Server/Client Application
### Server Command Line Arguments:
```
username@somewhere$: make server

username@somewhere$: ./server <port number from config file>
```

### Client Command Line Arguments:
```
username@somewhere$: make client

username@somewhere$: ./client <path to config file>
```

In order for this program to work, the server and client must be run on the machines that correspond to the IP addresses specified in the config file (i.e. server runs on server machine, client runs on client machine) or else the sockets will not bind.

## Standalone Application
### Command line arguments:
```
username@somewhere$ make standalone

username@somewhere$ sudo ./standalone <path to config file>
```

