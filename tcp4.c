/*  Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Send an IPv4 TCP packet via raw socket.
// Stack fills out layer 2 (data link) information (MAC addresses) for us.
// Values set for SYN packet, no TCP options data.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <stdbool.h>

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_TCP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#define __FAVOR_BSD           // Use BSD format of tcp header
#include <netinet/tcp.h>      // struct tcphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq

#include <errno.h>            // errno, perror()
#include <time.h>

#include "cJSON/cJSON.h"
#include "util.h"

// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define TCP_HDRLEN 20         // TCP header length, excludes options data

// Function prototypes
uint16_t checksum (uint16_t *, int);
uint16_t tcp4_checksum(struct ip, struct tcphdr);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

int send_packet(char *filename, cJSON *json, int sd, bool head, struct sockaddr_in *sin) {
    int i, status, *ip_flags, *tcp_flags;
    char *src_ip, *dst_ip;
    struct ip iphdr;
    struct tcphdr tcphdr;
    uint8_t *packet;
    struct addrinfo *res;
    struct sockaddr_in *ipv4;
    void *tmp;

    // Allocate memory for various arrays.
    packet = allocate_ustrmem (IP_MAXPACKET);
    src_ip = allocate_strmem (INET_ADDRSTRLEN);
    dst_ip = allocate_strmem (INET_ADDRSTRLEN);
    ip_flags = allocate_intmem (4);
    tcp_flags = allocate_intmem (8);

    // Source IPv4 address: you need to fill this out
    strcpy(src_ip, cJSON_GetObjectItem(json, "The Client's IP Address")->valuestring);
    strcpy(dst_ip, cJSON_GetObjectItem(json, "The Server's IP Address")->valuestring);

    // IPv4 header

    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

    // Internet Protocol version (4 bits): IPv4
    iphdr.ip_v = 4;

    // Type of service (8 bits)
    iphdr.ip_tos = 0;

    // Total length of datagram (16 bits): IP header + TCP header
    iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN);

    // ID sequence number (16 bits): unused, since single datagram
    iphdr.ip_id = htons (0);

    // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

    // Zero (1 bit)
    ip_flags[0] = 0;

    // Do not fragment flag (1 bit)
    ip_flags[1] = 0;

    // More fragments following flag (1 bit)
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr.ip_off = htons ((ip_flags[0] << 15)
                        + (ip_flags[1] << 14)
                        + (ip_flags[2] << 13)
                        +  ip_flags[3]);

    // Time-to-Live (8 bits): default to maximum value
    iphdr.ip_ttl = 255;

    // Transport layer protocol (8 bits): 6 for TCP
    iphdr.ip_p = IPPROTO_TCP;

    // Source IPv4 address (32 bits)
    if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
        fprintf (stderr, "inet_pton() failed for source address.\nError message: %s", strerror (status));
        return (EXIT_FAILURE);
    }

    // Destination IPv4 address (32 bits)
    if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
        fprintf(stderr, "inet_pton() failed for destination address.\nError message: %s", strerror (status));
        return (EXIT_FAILURE);
    }

    // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    iphdr.ip_sum = 0;
    iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

    // TCP header

    // Source port number (16 bits)
    tcphdr.th_sport = htons(3001); // <-------- CHANGE THIS

    // Destination port number (16 bits)
    if (head) {
      tcphdr.th_dport = htons(cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Destination Port Number for TCP Head SYN"))); // <-------- CHANGE THIS
    } else {
      tcphdr.th_dport = htons(cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Destination Port Number for TCP Tail SYN"))); // <-------- CHANGE THIS
    }

    // Sequence number (32 bits)
    tcphdr.th_seq = htonl (0);

    // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
    tcphdr.th_ack = htonl (0);

    // Reserved (4 bits): should be 0
    tcphdr.th_x2 = 0;

    // Data offset (4 bits): size of TCP header in 32-bit words
    tcphdr.th_off = TCP_HDRLEN / 4;

    /* Flags (8 bits) */

    // FIN flag (1 bit)
    tcp_flags[0] = 0;

    // SYN flag (1 bit): set to 1
    tcp_flags[1] = 1;

    // RST flag (1 bit)
    tcp_flags[2] = 0;

    // PSH flag (1 bit)
    tcp_flags[3] = 0;

    // ACK flag (1 bit)
    tcp_flags[4] = 0;

    // URG flag (1 bit)
    tcp_flags[5] = 0;

    // ECE flag (1 bit)
    tcp_flags[6] = 0;

    // CWR flag (1 bit)
    tcp_flags[7] = 0;

    tcphdr.th_flags = 0;
    for (i=0; i<8; i++) {
      tcphdr.th_flags += (tcp_flags[i] << i);
    }

    // Window size (16 bits)
    tcphdr.th_win = htons (65535);

    // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
    tcphdr.th_urp = htons (0);

    // TCP checksum (16 bits)
    tcphdr.th_sum = tcp4_checksum(iphdr, tcphdr);

    // Prepare packet.
    // First part is an IPv4 header.
    memcpy(packet, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

    // Next part of packet is upper layer protocol header.
    memcpy((packet + IP4_HDRLEN), &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

    // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
    // For that, we need to specify a destination for the kernel in order for it
    // to decide where to send the raw datagram. We fill in a struct in_addr with
    // the desired destination IP address, and pass this structure to the sendto() function.
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = iphdr.ip_dst.s_addr;
    // sin->sin_port = 3001;

    // Send packet.
    if (sendto (sd, packet, IP4_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *) sin, sizeof (struct sockaddr)) < 0)  {
      perror ("sendto() failed");
      return (EXIT_FAILURE);
    }

    // Free allocated memory.
    free (packet);
    free (src_ip);
    free (dst_ip);
    free (ip_flags);
    free (tcp_flags);

    return (EXIT_SUCCESS);
}

struct packet_info {
  short packet_id;
  char *payload;
};


char *convert_to_binary(int num) { // this makes a big endian string representation of the int
  int c, k;
  short num_short = 0;
	char *num_str = malloc(32); // 2 bits here
	memset(num_str, 0, sizeof(*num_str));

  for (c = 15; c >= 0; c--) {
      k = num >> c; // getting bit value

      if (k & 1) {
          num_short |= 1UL << c;
          *num_str |= 1UL << c;
      }
  }

  return num_str;
}

int setup_udp_sock(int sock, cJSON *json, struct sockaddr_in *udp_sin) {
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
    tv.tv_sec = 15;
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

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum is not guaranteed to preclude collisions.
uint16_t checksum(uint16_t *addr, int len) {
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
      sum += *(addr++);
      count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
      sum += *(uint8_t *) addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
  }

  // Build IPv4 TCP pseudo-header and call checksum function.
uint16_t tcp4_checksum(struct ip iphdr, struct tcphdr tcphdr) {
    uint16_t svalue;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int chksumlen = 0;

    // ptr points to beginning of buffer buf
    ptr = &buf[0];

    // Copy source IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
    ptr += sizeof (iphdr.ip_src.s_addr);
    chksumlen += sizeof (iphdr.ip_src.s_addr);

    // Copy destination IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
    ptr += sizeof (iphdr.ip_dst.s_addr);
    chksumlen += sizeof (iphdr.ip_dst.s_addr);

    // Copy zero field to buf (8 bits)
    *ptr = 0; ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
    ptr += sizeof (iphdr.ip_p);
    chksumlen += sizeof (iphdr.ip_p);

    // Copy TCP length to buf (16 bits)
    svalue = htons (sizeof (tcphdr));
    memcpy (ptr, &svalue, sizeof (svalue));
    ptr += sizeof (svalue);
    chksumlen += sizeof (svalue);

    // Copy TCP source port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
    ptr += sizeof (tcphdr.th_sport);
    chksumlen += sizeof (tcphdr.th_sport);

    // Copy TCP destination port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
    ptr += sizeof (tcphdr.th_dport);
    chksumlen += sizeof (tcphdr.th_dport);

    // Copy sequence number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
    ptr += sizeof (tcphdr.th_seq);
    chksumlen += sizeof (tcphdr.th_seq);

    // Copy acknowledgement number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
    ptr += sizeof (tcphdr.th_ack);
    chksumlen += sizeof (tcphdr.th_ack);

    // Copy data offset to buf (4 bits) and
    // copy reserved bits to buf (4 bits)
    cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
    memcpy (ptr, &cvalue, sizeof (cvalue));
    ptr += sizeof (cvalue);
    chksumlen += sizeof (cvalue);

    // Copy TCP flags to buf (8 bits)
    memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
    ptr += sizeof (tcphdr.th_flags);
    chksumlen += sizeof (tcphdr.th_flags);

    // Copy TCP window size to buf (16 bits)
    memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
    ptr += sizeof (tcphdr.th_win);
    chksumlen += sizeof (tcphdr.th_win);

    // Copy TCP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    // Copy urgent pointer to buf (16 bits)
    memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
    ptr += sizeof (tcphdr.th_urp);
    chksumlen += sizeof (tcphdr.th_urp);

    return checksum ((uint16_t *) buf, chksumlen);
}

// Allocate memory for an array of chars.
char *allocate_strmem(int len) {
    void *tmp;

    if (len <= 0) {
      fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
      exit (EXIT_FAILURE);
    }

    tmp = (char *) malloc (len * sizeof (char));
    if (tmp != NULL) {
      memset (tmp, 0, len * sizeof (char));
      return (tmp);
    } else {
      fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
      exit (EXIT_FAILURE);
    }
}

// Allocate memory for an array of unsigned chars.
uint8_t *allocate_ustrmem(int len) {
    void *tmp;

    if (len <= 0) {
      fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
      exit (EXIT_FAILURE);
    }

    tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
    if (tmp != NULL) {
      memset (tmp, 0, len * sizeof (uint8_t));
      return (tmp);
    } else {
      fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
      exit (EXIT_FAILURE);
    }
}

// Allocate memory for an array of ints.
int *allocate_intmem(int len) {
    void *tmp;

    if (len <= 0) {
      fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
      exit (EXIT_FAILURE);
    }

    tmp = (int *) malloc (len * sizeof (int));
    if (tmp != NULL) {
      memset (tmp, 0, len * sizeof (int));
      return (tmp);
    } else {
      fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
      exit (EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
      printf("Usage: ./standalone <config file>");
      exit(-1);
    }

    char *filename = argv[1];
    char *file = readFile(filename); // getting file params
    if (file == 0) {
        perror("Couldn't read file, please try again later.");
        return -1;
    }

    cJSON *json = cJSON_Parse(file);

    int sock;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit (EXIT_FAILURE);
    }

    // Set flag so socket expects us to provide IPv4 header.
    int optval = 1;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof (optval)) < 0) {
        perror ("setsockopt() failed to set IP_HDRINCL");
        exit (EXIT_FAILURE);
    }

    struct sockaddr_in sin;

    if (send_packet(filename, json, sock, true, &sin) < 0) {
        return -1;
    }

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

    if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) { // for port reuse after a bad exit
        perror("couldn’t reuse UDP address");
        abort(); 
    }

    printf("send the udp packets here\n");
    cJSON *payload_size = cJSON_GetObjectItem(json, "The Size of the UDP Payload in the UDP Packet Train");
    int payload = cJSON_GetNumberValue(payload_size);
    cJSON *train = cJSON_GetObjectItem(json, "The Number of UDP Packets in the UDP Packet Train");
    int train_len = cJSON_GetNumberValue(train);

    for (int i = 0; i < train_len; i++) { // LOW ENTROPY

        struct packet_info *info = malloc(sizeof (struct packet_info));
        info->packet_id = i;

        char *low = malloc(payload);
        char *num = convert_to_binary(i+1);

        strcpy(low, num);
        bzero((low + 2), cJSON_GetNumberValue(payload_size) - 2);
        int status = 0;
        if ((status = sendto(udp_sock, info, payload, 0, (struct sockaddr *) &udp_sin, sizeof(udp_sin))) < 0) {
            printf("status = %d\n", status);
            printf("udp packet #%d failed to send\n", i+1);
            perror("failed to send packet");
            abort();
        }

        usleep(200);
    }

    if (send_packet(filename, json, sock, false, &sin) < 0) {
        return -1;
    }

    clock_t time;

    while (1) {
        char *packet = malloc(2048);

        if (recvfrom(sock, packet, 2048/*cJSON_GetNumberValue(payload_size)*/, 0, (struct sockaddr *) &sin, &addr_len) < 0) {
            printf("an error has occured while getting RST packet\n");
            return -1;
        }

        struct iphdr *iph = (struct iphdr *) packet;
        struct tcphdr *tcph = (struct tcphdr *) (packet + IP4_HDRLEN);

        if (tcph->th_dport == htons(3001)) {
          uint16_t flags = ntohs(tcph->th_flags);
          printf("%d\n", flags);
          if (tcph->th_flags & TH_RST) {
            printf("rst\n");
          }

          printf("packet = %d\n", (tcph->th_flags & (1 << 4)) >> 4);
          // printf("packet flags = %s\n", convert_to_binary(tcph->th_flags));
          time = clock();
          break;
        }
    }

    while (1) {
        char *packet = malloc(2048);

        if (recvfrom(sock, packet, 2048/*cJSON_GetNumberValue(payload_size)*/, 0, (struct sockaddr *) &sin, &addr_len) < 0) {
            printf("an error has occured while getting RST packet\n");
            return -1;
        }

        struct iphdr *iph = (struct iphdr *) packet;
        struct tcphdr *tcph = (struct tcphdr *) (packet + IP4_HDRLEN);

        if (tcph->th_dport == htons(3001)) {
          uint16_t flags = ntohs(tcph->th_flags);
          printf("%d\n", flags);
          if (tcph->th_flags & TH_RST) {
            printf("rst\n");
          }

          printf("packet = %d\n", (tcph->th_flags & (1 << 4)) >> 4);
          // printf("packet flags = %s\n", convert_to_binary(tcph->th_flags));
          time = clock() - time;
          break;
        }
    }
    

    printf("time diff = %ld\n", time);


    int wait = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Inter-Measurement Time"));

    printf("waiting %d seconds to send packets\n", wait);
    sleep(wait);
    printf("time to send! \n");


    char *data = readFile("h_entropy");
    if (data == 0){
        perror("Couldn't read entropy file, please try again later.");
        return -1;
    }

    // short num = 1200;

    clock_t time_2;

    if (send_packet(filename, json, sock, true, &sin) < 0) {
        return -1;
    }

    // printf("short = %s\n", (unsigned char *) num);

    for (int i = 0; i < train_len; i++) { // HIGH ENTROPY
        char *high = malloc(payload);
        char *num = convert_to_binary(i+1);

        strcpy(high, num);
        strncat(high, data, payload - 33);
        
        int status = 0;
        if ((status = sendto(udp_sock, high, payload, 0, (struct sockaddr *) &udp_sin, sizeof(udp_sin))) < 0) {
            printf("status = %d\n", status);
            printf("udp packet #%d failed to send\n", i+1);
            perror("failed to send packet");
            abort();
        }
        usleep(200);
    }

    if (send_packet(filename, json, sock, false, &sin) < 0) {
        return -1;
    }

    while (1) {
        char *packet = malloc(2048);

        if (recvfrom(sock, packet, 2048/*cJSON_GetNumberValue(payload_size)*/, 0, (struct sockaddr *) &sin, &addr_len) < 0) {
            printf("an error has occured while getting RST packet\n");
            return -1;
        }

        struct iphdr *iph = (struct iphdr *) packet;
        struct tcphdr *tcph = (struct tcphdr *) (packet + IP4_HDRLEN);

        if (tcph->th_dport == htons(3001)) {
          uint16_t flags = ntohs(tcph->th_flags);
          printf("%d\n", flags);
          if (tcph->th_flags & TH_RST) {
            printf("rst\n");
          }

          printf("packet = %d\n", (tcph->th_flags & (1 << 4)) >> 4);
          // printf("packet flags = %s\n", convert_to_binary(tcph->th_flags));
          time_2 = clock();
          break;
        }
    }

    while (1) {
        char *packet = malloc(2048);

        if (recvfrom(sock, packet, 2048/*cJSON_GetNumberValue(payload_size)*/, 0, (struct sockaddr *) &sin, &addr_len) < 0) {
            printf("an error has occured while getting RST packet\n");
            return -1;
        }

        struct iphdr *iph = (struct iphdr *) packet;
        struct tcphdr *tcph = (struct tcphdr *) (packet + IP4_HDRLEN);

        if (tcph->th_dport == htons(3001)) {
          uint16_t flags = ntohs(tcph->th_flags);
          printf("%d\n", flags);
          if (tcph->th_flags & TH_RST) {
            printf("rst\n");
          }

          printf("packet = %d\n", (tcph->th_flags & (1 << 4)) >> 4);
          // printf("packet flags = %s\n", convert_to_binary(tcph->th_flags));
          time_2 = clock() - time_2;
          break;
        }
    }

    printf("final diff = %d\n", abs(time - time_2));

    printf("AT THE END\n");
    close(sock);
}