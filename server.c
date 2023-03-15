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
#define TIMEOUT 10

int timeout = 0;

void sig_handler(int errno) {
    timeout = 1;

    printf("timeout set to %d, starting next set of packets\n", timeout);
    // abort();

    alarm(TIMEOUT);
}

void cleanExit() {
    printf("\n");
    exit(0);
}

clock_t receive_udp(int sock, cJSON *json, struct sockaddr_in udp_sin) {

    int payload_size = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "The Size of the UDP Payload in the UDP Packet Train"));
    int train_len = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "The Number of UDP Packets in the UDP Packet Train"));
    char *packet = malloc(payload_size);

    int addr_len = sizeof(udp_sin);

    printf("starting recvfrom\n");

    clock_t time = clock();

    for (int i = 0, timeouts = 0; i < train_len && timeouts < 6; i++) {
        if (timeout != 0 || recvfrom(sock, packet, payload_size, 0, (struct sockaddr *) &udp_sin, &addr_len) < 0) {
            printf("timeouts = %d, an error has occured with the UDP packet #%d\n", timeouts++, i+1);
        }
    }

    time = clock() - time;

    return time;
}

char *get_config(int sock, int size) {
    char *file = malloc(size);

    if (receive_packets(file, size, sock) < 0) {
        perror("Something wen't wrong when retreiving config file, please try again later.");
        return (char *) -1;
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
    
    if (client_sock < 0) {
        perror("error accepting connection");
        return -1;
    }

    return client_sock;
}

int setup_udp(int sock, cJSON *json, struct sockaddr_in *udp_sin) {
    cJSON *dst = cJSON_GetObjectItem(json, "Destination Port Number for UDP");

    memset(udp_sin, 0, sizeof (*udp_sin));
    udp_sin->sin_family = AF_INET; 
    udp_sin->sin_addr.s_addr = INADDR_ANY; 
    udp_sin->sin_port = htons(cJSON_GetNumberValue(dst));

    printf("udp port = %d\n", udp_sin->sin_port);

    int optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) { // for port reuse after a bad exit
        perror("couldn’t reuse UDP address");
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv, sizeof (tv)) < 0) { // for port reuse after a bad exit
        perror("couldn’t set timeout value");
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
    signal(SIGALRM, sig_handler);

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

    int payload_size = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "The Size of the UDP Payload in the UDP Packet Train"));
    int train_len = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "The Number of UDP Packets in the UDP Packet Train"));
    char *packet = malloc(payload_size);

    alarm(TIMEOUT);

    printf("about to get low entropy packets\n");
    clock_t low_time = receive_udp(udp_sock, json, udp_sin); // first train of packets
    printf("time to receive all %d low entropy packets was %ld\n", train_len, low_time);

    sleep(cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Inter-Measurement Time")));

    timeout = 0;
    alarm(TIMEOUT);

    int wait = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Inter-Measurement Time"));
    printf("waiting %d seconds to receive packets\n", wait);
    sleep(wait);

    printf("about to get high entropy packets\n");
    clock_t high_time = receive_udp(udp_sock, json, udp_sin); // second train of packets
    printf("time to receive all %d high entropy packets was %ld\n", train_len, high_time);

    clock_t time_diff = high_time - low_time;

    printf("the time diff is %ld\n", time_diff);

    printf("server done!\n");
}