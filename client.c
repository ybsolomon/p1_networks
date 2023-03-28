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

struct packet_info {
  short packet_id;
  char *payload;
};

void cleanExit() {
    printf("\n");
    exit(0);
}

int send_udp(int train_len, int payload_len, int udp_sock, struct sockaddr_in udp_sin, char *data) {
    for (int i = 0; i < train_len; i++) {
        char buffer[payload_len];
        memcpy(buffer, &i, 2);

        if (data) {
            strncpy(buffer+2, data, payload_len-3);
        } else {
            bzero(buffer+2, payload_len-3);
        }
        
        buffer[payload_len-2] = '\0';

        int status = 0;
        if ((status = sendto(udp_sock, buffer, payload_len, 0, (struct sockaddr *) &udp_sin, sizeof(udp_sin))) < 0) {
            printf("status = %d\n", status);
            printf("udp packet #%d failed to send\n", i+1);
            perror("failed to send packet");
            return -1;
        }
        
        usleep(200);
    }

    return 0;
}

int setup_tcp_socket(int sock, struct sockaddr_in *sin, cJSON *json) {
    cJSON *ip = cJSON_GetObjectItem(json, "The Server's IP Address");
    cJSON *port = cJSON_GetObjectItem(json, "Port Number for TCP");

    in_addr_t server_addr = inet_addr(ip->valuestring); 
    unsigned short server_port = cJSON_GetNumberValue(port);

    memset(sin, 0, sizeof (*sin));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = server_addr; /* already in network order */ 
    sin->sin_port = htons(server_port);

    if (connect(sock, (struct sockaddr *) sin, sizeof (*sin))<0) {
        perror("Cannot connect to server");
        return -1;
    }

    return 0;
}

int setup_udp_socket(int udp_sock, struct sockaddr_in *udp_sin, cJSON *json) {
    struct sockaddr_in src_sin;

    memset (&src_sin, 0, sizeof (src_sin));
    src_sin.sin_family = AF_INET; 
    src_sin.sin_addr.s_addr = inet_addr(cJSON_GetObjectItem(json, "The Client's IP Address")->valuestring); 
    src_sin.sin_port = htons(cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Source Port Number for UDP")));

    if (bind(udp_sock, (struct sockaddr *) &src_sin, sizeof (src_sin)) < 0) {
        perror("Could not bind to given source UDP address.");
        return -1;
    }

    int addr_len = sizeof(&udp_sin);

    memset(udp_sin, 0, sizeof (&udp_sin));
    udp_sin->sin_family = AF_INET; 
    udp_sin->sin_addr.s_addr = inet_addr(cJSON_GetObjectItem(json, "The Server's IP Address")->valuestring);
    udp_sin->sin_port = htons(cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Destination Port Number for UDP")));

    int optval = 1;
    if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) { // for port reuse after a bad exit
        perror("couldn't reuse UDP address");
        abort(); 
    }

    return 0;
}

int main(int argc, char *argv[]) {
    signal(SIGTERM, cleanExit);
    signal(SIGINT, cleanExit);

    if (argc != 2) {
        printf("Usage: ./client <config file>");
        cleanExit();
    }

    char *file = readFile(argv[1]);
    if (file == 0) {
        perror("Couldn't read file, please try again later.");
        cleanExit();
    }

    int sock = socket(AF_INET, SOCK_STREAM, PF_UNSPEC);

    cJSON *json = cJSON_Parse(file);

    struct sockaddr_in sin;

    if (setup_tcp_socket(sock, &sin, json) < 0) {
        cleanExit();
    }

    if (send_packets(file, strlen(file), sock) < 0) {
        perror("Could not send packets, please try again later.");
        cleanExit();
    }
    close(sock);

    struct sockaddr_in udp_sin;
    int udp_sock = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);

    if (setup_udp_socket(udp_sock, &udp_sin, json) < 0) {
        return -1;
    }

    int payload_len = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "The Size of the UDP Payload in the UDP Packet Train"));
    int train_len = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "The Number of UDP Packets in the UDP Packet Train"));

    printf("sending low entropy chain now!\n");
    if (send_udp(train_len, payload_len, udp_sock, udp_sin, NULL) < 0) { // low entropy packets here
        cleanExit();
    }

    int wait = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Inter-Measurement Time"));

    printf("waiting %d seconds to send packets\n", wait);
    sleep(wait);
    printf("sending high entropy chain now!\n");

    char *data = readFile("h_entropy");
    if (data == 0){
        perror("Couldn't read entropy file, please try again later.");
        cleanExit();
    }

    if (send_udp(train_len, payload_len, udp_sock, udp_sin, data) < 0) { // low entropy packets here
        cleanExit();
    }

    sock = socket(AF_INET, SOCK_STREAM, PF_UNSPEC);

    if (setup_tcp_socket(sock, &sin, json) < 0) {
        cleanExit();
    }

    char *buf = malloc(128);

    if (receive_packets(buf, 128, sock) < 0) {
        cleanExit();
    }

    printf("\nResult: %s\n", buf + 5);

    free(buf);
    free(json);

    close(sock);
}