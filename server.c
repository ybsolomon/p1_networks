#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include <time.h>

#include "cJSON/cJSON.h"
#include "util.h"

#define CONFIG 1024

void cleanExit() {
    printf("\n");
    exit(0);
}

int receive_udp(int sock, int port) {
    return 0;
}

char *get_config(int sock, int size) {
    char *file = malloc(size);

    if (receive_packets(file, size, sock) < 0) {
        perror("Something wen't wrong when retreiving config file, please try again later.");
        return -1;
    }

    return file;
}

int setup_tcp(int sock, int port) {
    struct sockaddr_in sin;

    memset (&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET; 
    sin.sin_addr.s_addr = INADDR_ANY; 
    sin.sin_port = htons(port);

    int optval = 1;
    if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) { // for port reuse after a bad exit
        perror ("couldn’t reuse TCP address");
        return -1;
    }

    if (bind(sock, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
        perror("Could not bind to given TCP address.");
        return -1;
    }

    if (listen(sock, 5) < 0) { 
        perror("error listening"); 
        return -1;
    }

    struct sockaddr_in addr;
    int client_sock, addr_len = sizeof(addr);

    client_sock = accept(sock, (struct sockaddr *) &addr, &addr_len); 
    printf("client_sock == null? %d\n", client_sock == 0);
    // printf("Connected.\n");
    if (client_sock < 0) {
        perror("error accepting connection");
        return -1;
    }

    return client_sock;
}

int setup_udp(int sock, cJSON *json, struct sockaddr_in *udp_sin) {
    cJSON *dst = cJSON_GetObjectItem(json, "Destination Port Number for UDP");

    memset(udp_sin, 0, sizeof (udp_sin));
    udp_sin->sin_family = AF_INET; 
    udp_sin->sin_addr.s_addr = INADDR_ANY; 
    udp_sin->sin_port = htons(cJSON_GetNumberValue(dst));

    printf("port = %d\n", udp_sin->sin_port);

    int optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) { // for port reuse after a bad exit
        perror("couldn’t reuse UDP address");
        return -1;
    }

    if (bind(sock, (struct sockaddr *) udp_sin, sizeof (*udp_sin)) < 0) {
        perror("Could not bind to given UDP address.");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    signal(SIGTERM, cleanExit); // clean exits only
    signal(SIGINT, cleanExit);

    if (argc != 2) {
        printf("Usage: Please enter ONLY a port number.\n");
        cleanExit();
    }

    int port = atoi(argv[1]);
    printf("Started server on port %d.\n", port);

    int sock = socket(AF_INET, SOCK_STREAM, PF_UNSPEC); // create server socket here

    int client_sock = setup_tcp(sock, port); // create client socket here
    if (client_sock < 0) {
        cleanExit(); 
    }

    char *config = get_config(client_sock, CONFIG); // get config file from client
    if (config < 0) {
        cleanExit();
    }

    int udp_sock = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC); // create server udp socket
    cJSON *json = cJSON_Parse(config);
    struct sockaddr_in udp_sin;

    if (setup_udp(udp_sock, json, &udp_sin) < 0) {
        cleanExit();
    }

    cJSON *train_len = cJSON_GetObjectItem(json, "The Number of UDP Packets in the UDP Packet Train");

    int payload_size = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "The Size of the UDP Payload in the UDP Packet Train"));
    int num_packets = cJSON_GetNumberValue(train_len);
    char *packet = malloc(payload_size);

    int rounds = 1; // change later, testing low entropy data sending
    while (rounds++ < 2) {
        printf("hello there\n");
        int addr_len = sizeof(udp_sin);
        int first = recvfrom(udp_sock, packet, payload_size, 0, (struct sockaddr *) &udp_sin, &addr_len);

        if (first < 0) {
            perror("Couldn't read first packet, aborting");
            cleanExit();
        }

        clock_t time = clock();

        for (int i = 1; i < num_packets; i++) {
            if (recvfrom(udp_sock, packet, payload_size, 0, (struct sockaddr *) &udp_sin, &addr_len) < 0) {
                printf("an error has occured with the UDP packet #%d\n", i + 1);
            }
        }

        time = clock() - time;
        printf("time to receive all %d %s entropy packets was %ld\n", num_packets, rounds == 1 ? "high" : "low", time);
    }

    printf("server done!\n");
}