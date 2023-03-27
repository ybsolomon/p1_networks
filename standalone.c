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
#include <sys/select.h>

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

struct packet_info {
  short packet_id;
  char *payload;
};

int send_packet(cJSON *json, int sd, bool head, struct sockaddr_in *sin) {
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
    tcphdr.th_sport = htons(cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Port Number for TCP"))); // <-------- CHANGE THIS

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
    memcpy((packet + IP4_HDRLEN), &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
	
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = iphdr.ip_dst.s_addr;

    if (sendto (sd, packet, IP4_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *) sin, sizeof (struct sockaddr)) < 0)  {
      perror ("sendto() failed");
      return (EXIT_FAILURE);
    }

    free (packet);
    free (src_ip);
    free (dst_ip);
    free (ip_flags);
    free (tcp_flags);

    return (EXIT_SUCCESS);
}

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

uint16_t checksum(uint16_t *addr, int len) {
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    while (count > 1) {
      sum += *(addr++);
      count -= 2;
    }

    if (count > 0) {
      sum += *(uint8_t *) addr;
    }
    
    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }

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

int send_recv(cJSON* json, int tcp_sock, int udp_sock, struct sockaddr_in sin, struct sockaddr_in udp_sin, char *data) {
	int train_len = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "The Number of UDP Packets in the UDP Packet Train"));
	int payload_len = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "The Size of the UDP Payload in the UDP Packet Train"));
	if (send_packet(json, tcp_sock, true, &sin) < 0) {
		return -1;
	}

	int rsts = 0;
	int maxfd, retval;
	int i = train_len - 1;
	int addr_len = sizeof(udp_sin);

	clock_t rst_times[2];
	char buffer[payload_len];
	fd_set readfds, writefds;

	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;

	while (rsts < 2) {
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_SET(tcp_sock, &readfds);
		FD_SET(udp_sock, &writefds);
		maxfd = (tcp_sock > udp_sock) ? tcp_sock : udp_sock;

		retval = select(maxfd + 1, &readfds, &writefds, NULL, &tv);

		if (retval == -1) {
			perror("select");
		} else if (retval == 0) {
			printf("Timeout\n");
		} else {
			if (FD_ISSET(tcp_sock, &readfds)) {
				if (recvfrom(tcp_sock, buffer, payload_len, 0, (struct sockaddr *) &sin, &addr_len) < 0) {
					printf("an error has occured while getting RST packet\n");
					return -1;
				}

				struct iphdr *iph = (struct iphdr *) buffer;
				struct tcphdr *tcph = (struct tcphdr *) (buffer + IP4_HDRLEN);

				if (tcph->th_dport == htons(cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Port Number for TCP")))) {
					if (tcph->th_flags & TH_RST) {
						printf("found rst\n");
						rst_times[rsts++] = clock();
					}
				}
			}

			if (i >= 0 && FD_ISSET(udp_sock, &writefds)) {
				struct packet_info *info = malloc(sizeof(struct packet_info));
				info->packet_id = i--;
				info->payload = malloc(payload_len-2);

				if (data) {
					strncpy(info->payload, data, payload_len-3);
				} else {
					bzero(info->payload, payload_len-3);
				}
				
				int status = 0;
				if ((status = sendto(udp_sock, info, payload_len, 0, (struct sockaddr *) &udp_sin, sizeof(udp_sin))) < 0) {
					printf("status = %d\n", status);
					printf("udp packet #%d failed to send\n", i+1);
					perror("failed to send packet");
					return -1;
				}
				
				usleep(200);
			} else if (i-- == -1) {
				if (send_packet(json, tcp_sock, false, &sin) < 0) {
					printf("couldn't send the final TCP packet\n");
					return -1;
				}
			}
		}
	}

  	return abs(rst_times[1] - rst_times[0]);
}

int main(int argc, char **argv) {
    if (argc < 2) {
      printf("Usage: sudo ./standalone <config file>");
      exit(-1);
    }

    char *filename = argv[1];
    char *file = readFile(filename); // getting file params
    if (file == 0) {
        perror("Couldn't read file, please try again later.");
        return -1;
    }

    cJSON *json = cJSON_Parse(file);

    int tcp_sock;
    if ((tcp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit (EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt (tcp_sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof (optval)) < 0) {
        perror ("setsockopt() failed to set IP_HDRINCL");
        exit (EXIT_FAILURE);
    }

    cJSON *dst = cJSON_GetObjectItem(json, "Destination Port Number for UDP");
    cJSON *ip = cJSON_GetObjectItem(json, "The Server's IP Address");

    struct sockaddr_in sin;

    int udp_sock = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);

    in_addr_t server_addr = inet_addr(ip->valuestring); 

    struct sockaddr_in udp_sin;
    int addr_len = sizeof(udp_sin);

    memset (&udp_sin, 0, sizeof (udp_sin));
    udp_sin.sin_family = AF_INET; 
    udp_sin.sin_addr.s_addr = server_addr; 
    udp_sin.sin_port = htons(cJSON_GetNumberValue(dst));

    printf("port = %f\n", cJSON_GetNumberValue(dst));

    if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) { // for port reuse after a bad exit
        perror("couldn't reuse UDP address");
        abort(); 
    }

	int ttl = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "TTL for the UDP Packets")); /* max = 255 */
	if (setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
		perror("couldn't set TTL for UDP packets");
		return -1;
	}

	int low_entropy;
	if ((low_entropy = send_recv(json, tcp_sock, udp_sock, sin, udp_sin, NULL)) < 0) {
		return -1;
	}

	printf("low entropy time = %.0fms\n", low_entropy / (double) CLOCKS_PER_SEC * 1000);

	char *data = readFile("h_entropy");
    if (data == 0){
        perror("Couldn't read entropy file, please try again later.");
        return -1;
    }

	int wait = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Inter-Measurement Time"));

    printf("waiting %d seconds\n", wait);
    sleep(wait);
    printf("sending high entropy packets! \n");

	int high_entropy;
	if ((high_entropy = send_recv(json, tcp_sock, udp_sock, sin, udp_sin, data)) < 0) {
		return -1;
	}

	printf("high entropy time = %.0fms\n", high_entropy / (double) CLOCKS_PER_SEC * 1000);

	int time_diff = high_entropy - low_entropy;
	char *stat = abs((double) time_diff / (double) CLOCKS_PER_SEC) > 0.1 ? "There is compression between these two ports!" : "No compression detected!";
	
	printf("%s\n", stat);
	
    close(tcp_sock);
	close(udp_sock);
}