#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/socket.h>

#include "util.h"

char *readFile(char *filename) {
    FILE *file = fopen(filename, "r+");
    int size = 128;
    char *contents = malloc(size);

    char *temp = malloc(128);

    while ((temp = fgets(temp, 128, file)) != 0) {
        if (strlen(contents) + strlen(temp) > size) {
            size *= 2;
            contents = realloc(contents, size);
        }

        strcat(contents, temp);
    }

    return contents == 0 ? 0 : contents;
}

int send_packets(char *buffer, int buffer_len, int sock) {
    int sent_bytes = send(sock, buffer, buffer_len, 0);

    if (sent_bytes < 0) {
        perror ("send() failed"); return 0;
    }
}

int receive_packets(char *buffer, int buffer_len, int sock) {
    int num_received = recv(sock, buffer, buffer_len, 0);

    if (num_received < 0) {
        perror ("recv() failed");
    } else if (num_received == 0) { /* sender has closed connection */ 
        return EOF;
    } else {
        return num_received; /* might not be a full record!*/
    }
}