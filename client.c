#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "util.h"
#include "cJSON/cJSON.h"

void cleanExit() {
    printf("\n");
    exit(0);
}

char *convert_to_binary(int num) { // this makes a big endian string representation of the int
    int c, k;
    char *num_str = malloc(32);

    for (c = 31; c >= 0; c--) {
        k = num >> c; // getting bit value

        if (k & 1)
            *(num_str + 31 - c) = '1';
        else
            *(num_str + 31 - c) = '0';
    }

    printf("num_str = %s\n", num_str);

    return num_str;
}

// ./client config.json
int main(int argc, char *argv[]) {
    signal(SIGTERM, cleanExit); // clean exits only
    signal(SIGINT, cleanExit);

    if (argc != 2) {
        printf("Usage: Please enter the path to the config file.");
        cleanExit();
    }

    char *file = readFile(argv[1]);
    if (file == 0) {
        perror("Couldn't read file, please try again later.");
        cleanExit();
    }

    // do some json parsing here
    cJSON *json = cJSON_Parse(file);
    cJSON *ip = cJSON_GetObjectItem(json, "The Server’s IP Address");
    cJSON *port = cJSON_GetObjectItem(json, "Port Number for TCP");

    int sock = socket(AF_INET, SOCK_STREAM, PF_UNSPEC);

    struct sockaddr_in sin;

    in_addr_t server_addr = inet_addr(ip->valuestring); 

    unsigned short server_port = cJSON_GetNumberValue(port);

    // int addr_len = sizeof(addr);
    printf("%d\n", server_port);

    memset(&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = server_addr; /* already in network order */ 
    sin.sin_port = htons(server_port);

    if (connect(sock, (struct sockaddr *) &sin, sizeof (sin))<0) {
        perror("Cannot connect to server");
        cleanExit();
    }

    // get config file info
    if (send_packets(file, strlen(file), sock) < 0) {
        perror("Could not send packets, please try again later.");
        cleanExit();
    }

    // the config file has been sent, time to send UDP packets

    int udp_sock = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);

    cJSON *dst = cJSON_GetObjectItem(json, "Destination Port Number for UDP");

    struct sockaddr_in udp_sin;
    int addr_len = sizeof(udp_sin);

    memset (&udp_sin, 0, sizeof (udp_sin));
    udp_sin.sin_family = AF_INET; 
    udp_sin.sin_addr.s_addr = htons(cJSON_GetNumberValue(dst)); 
    udp_sin.sin_port = INADDR_ANY;

    int optval = 1;
    if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) { // for port reuse after a bad exit
        perror("couldn’t reuse UDP address");
        abort(); 
    }

    // low entropy
    cJSON *payload_size = cJSON_GetObjectItem(json, "The Size of the UDP Payload in the UDP Packet Train");
    int payload = cJSON_GetNumberValue(payload_size);
    cJSON *train = cJSON_GetObjectItem(json, "The Number of UDP Packets in the UDP Packet Train");
    int train_len = cJSON_GetNumberValue(train);

    for (int i = 0; i < train_len; i++) {
        char *low = malloc(payload);
        char *num = convert_to_binary(i+1);

        strcpy(low, num);
        bzero((low + 32), cJSON_GetNumberValue(payload_size) - 32);
        int status = 0;
        if ((status = sendto(udp_sock, low, payload, 0, (struct sockaddr *) &udp_sin, addr_len)) < 0) {
            printf("status = %d\n", status);
            printf("udp packet #%d failed to send\n", i+1);
            perror("failed to send packet");
            abort();
        }
    }

    
    
    printf("Connected!\n");
}