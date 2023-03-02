#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>

#include "cJSON/cJSON.h"
#include "util.h"

void cleanExit() {
    printf("\n");
    exit(0);
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

    printf("%d\n", htons(port));

    int optval = 1;
    if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) { // for port reuse after a bad exit
        perror ("couldn’t reuse address");
        abort(); 
    }

    if (bind(sock, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
        perror("Could not bind to given address.");
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

    char *file = malloc(128);
    // int rv = 0;
    // while ((rv = receive_packets(file, 128, sock)) > 0) {
    //     perror("Could not recieve packets, please try again later.");
    //     cleanExit();
    // }

    // if (rv < 0) {
    //     perror("An error has occurred, please try again later.");
    //     cleanExit();
    // }

    printf("connecetd!");
}