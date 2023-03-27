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

struct packet_info {
  short packet_id;
  char *payload;
};

char *convert_to_binary(int num) { // this makes a big endian string representation of the int
    int c, k;
    char *num_str = malloc(32);

    for (c = 31; c >= 0; c--) {
        k = num >> c; // getting bit value

        if (k & 1) {
            *(num_str + 31 - c) = '1';
        } else {
            *(num_str + 31 - c) = '0';
        }
    }

    return num_str;
}

int send_udp(int train_len, int payload_size, int sock) {
    return 0;
}

int setup_socket(int sock, struct sockaddr_in *sin, cJSON *json) {
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

    int sock = socket(AF_INET, SOCK_STREAM, PF_UNSPEC);

    // do some json parsing here
    cJSON *json = cJSON_Parse(file);

    struct sockaddr_in sin;

    if (setup_socket(sock, &sin, json) < 0) {
        cleanExit();
    }

    // get config file info
    if (send_packets(file, strlen(file), sock) < 0) {
        perror("Could not send packets, please try again later.");
        cleanExit();
    }

    close(sock);
    // the config file has been sent, time to send UDP packets

    int udp_sock = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);

    cJSON *dst = cJSON_GetObjectItem(json, "Destination Port Number for UDP");
    cJSON *ip = cJSON_GetObjectItem(json, "The Server's IP Address");

    in_addr_t server_addr = inet_addr(ip->valuestring); 

    struct sockaddr_in udp_sin;
    int addr_len = sizeof(udp_sin);

    memset (&udp_sin, 0, sizeof (udp_sin));
    udp_sin.sin_family = AF_INET; 
    udp_sin.sin_addr.s_addr = server_addr; 
    udp_sin.sin_port = htons(cJSON_GetNumberValue(dst));

    printf("port = %f\n", cJSON_GetNumberValue(dst));

    int optval = 1;
    if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) { // for port reuse after a bad exit
        perror("couldn’t reuse UDP address");
        abort(); 
    }

    int ttl = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "TTL for the UDP Packets")); /* max = 255 */
	if (setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
		perror("couldn't set TTL for UDP packets");
		return -1;
	}

    // low entropy
    cJSON *payload_size = cJSON_GetObjectItem(json, "The Size of the UDP Payload in the UDP Packet Train");
    int payload = cJSON_GetNumberValue(payload_size);
    cJSON *train = cJSON_GetObjectItem(json, "The Number of UDP Packets in the UDP Packet Train");
    int train_len = cJSON_GetNumberValue(train);

    for (int i = 0; i < train_len; i++) { // LOW ENTROPY
        struct packet_info *info = malloc(sizeof(struct packet_info));
        info->packet_id = i;

        bzero((info + 2), cJSON_GetNumberValue(payload_size) - 2);
        int status = 0;
        if ((status = sendto(udp_sock, info, payload, 0, (struct sockaddr *) &udp_sin, sizeof(udp_sin))) < 0) {
            printf("status = %d\n", status);
            printf("udp packet #%d failed to send\n", i+1);
            perror("failed to send packet");
            abort();
        }

        usleep(200);
    }

    int wait = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Inter-Measurement Time"));

    printf("waiting %d seconds to send packets\n", wait);
    sleep(wait);
    printf("time to send! \n");


    char *data = readFile("h_entropy");
    if (data == 0){
        perror("Couldn't read entropy file, please try again later.");
        cleanExit();
    }

    for (int i = 0; i < train_len; i++) { // HIGH ENTROPY
        struct packet_info *info = malloc(sizeof(struct packet_info));
        info->packet_id = i;
        info->payload = malloc(payload-2);
        strncpy(info->payload, data, payload-2);
        
        int status = 0;
        if ((status = sendto(udp_sock, info, payload, 0, (struct sockaddr *) &udp_sin, sizeof(udp_sin))) < 0) {
            printf("status = %d\n", status);
            printf("udp packet #%d failed to send\n", i+1);
            perror("failed to send packet");
            abort();
        }
        usleep(200);
    }

    sock = socket(AF_INET, SOCK_STREAM, PF_UNSPEC);

    if (setup_socket(sock, &sin, json) < 0) {
        cleanExit();
    }

    char *buf = malloc(128);

    if (receive_packets(buf, 128, sock) < 0) {
        cleanExit();
    }

    printf("Result: %s\n", buf);

    free(buf);
    free(json);

    close(sock);
}