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

    printf("%d\n", server_port);

    memset(&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = server_addr; /* already in network order */ 
    sin.sin_port = htons(server_port);

    if (connect(sock, (struct sockaddr *) &sin, sizeof (sin))<0) {
        perror("Cannot connect to server");
        cleanExit();
    }

    // if (send_packets(file, strlen(file), sock) < 0) {
    //     perror("Could not send packets, please try again later.");
    //     cleanExit();
    // }

    printf("Connected!\n");
    // in_addr_t server_addr = *(in_addr_t *) host->h_addr_list[0];
}