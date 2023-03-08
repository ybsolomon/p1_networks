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

void cleanExit() {
    printf("\n");
    exit(0);
}

int receive_udp(int sock, int port) {
    return 0;
}

int main(int argc, char *argv[]) {
    signal(SIGTERM, cleanExit); // clean exits only
    signal(SIGINT, cleanExit);

    printf("hello there\n");
    printf("%d\n", argc);

    if (argc != 2) {
        printf("Usage: Please enter ONLY a port number.\n");
        abort();
    }

    printf("%d\n", atoi(argv[1]));
    int port = atoi(argv[1]);

    // create socket here
    int sock = socket(AF_INET, SOCK_STREAM, PF_UNSPEC);

    struct sockaddr_in sin;
    memset (&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET; 
    sin.sin_addr.s_addr = INADDR_ANY; 
    sin.sin_port = htons(port);

    int optval = 1;
    if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) { // for port reuse after a bad exit
        perror ("couldn’t reuse TCP address");
        abort(); 
    }

    if (bind(sock, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
        perror("Could not bind to given TCP address.");
        abort(); 
    }

    if (listen(sock, 5) < 0) { 
        perror("error listening"); 
        cleanExit();
    }

    struct sockaddr_in addr;
    int client_sock, addr_len = sizeof(addr);

    client_sock = accept(sock, (struct sockaddr *) &addr, &addr_len); 
    printf("client_sock == null? %d\n", client_sock == 0);
    // printf("Connected.\n");
    if (client_sock < 0) {
        perror("error accepting connection");
        cleanExit(); 
    }

    int size = 1024;
    char *file = malloc(size);
    int rv = 0;
    while ((rv = receive_packets(file, size, client_sock)) > 0) {
        size = strlen(file);
    }

    printf("file = %s\n", file);

    // config file has been transferred over, time for UDP train

    int udp_sock = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);

    cJSON *json = cJSON_Parse(file);
    cJSON *dst = cJSON_GetObjectItem(json, "Destination Port Number for UDP");
    cJSON *train_len = cJSON_GetObjectItem(json, "The Number of UDP Packets in the UDP Packet Train");

    struct sockaddr_in udp_sin;
    memset (&udp_sin, 0, sizeof (udp_sin));
    udp_sin.sin_family = AF_INET; 
    udp_sin.sin_addr.s_addr = INADDR_ANY; 
    udp_sin.sin_port = htons(cJSON_GetNumberValue(dst));

    if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) { // for port reuse after a bad exit
        perror("couldn’t reuse UDP address");
        abort(); 
    }

    if (bind(udp_sock, (struct sockaddr *) &udp_sin, sizeof (udp_sin)) < 0) {
        perror("Could not bind to given UDP address.");
        abort(); 
    }

    int payload_size = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "The Size of the UDP Payload in the UDP Packet Train"));
    int num_packets = cJSON_GetNumberValue(train_len);
    char *packet = malloc(payload_size);

    int rounds = 1; // change later, testing low entropy data sending
    while (rounds++ < 2) {
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