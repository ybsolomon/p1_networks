#include <stdio.h>	//for printf
#include <string.h> //memset
#include <sys/socket.h>	//for socket ofcourse
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <stdbool.h> // for booleans

#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
#include <unistd.h> // sleep()

#include "util.h"
#include "cJSON/cJSON.h"

void cleanExit() {
    printf("\n");
    exit(0);
}

/* 
	96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr, int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
    
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;

		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

char *setup_syn_packet(cJSON *json, bool low, int sock) {
	int train_len = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "The Number of UDP Packets in the UDP Packet Train"));
	int payload_size = cJSON_GetNumberValue(cJSON_GetObjectItem(json, "The Size of the UDP Payload in the UDP Packet Train"));

	char *datagram = malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size);
	char *data; 
	char *pseudogram;

	struct pseudo_header psh; // for the checksum

    struct iphdr *iph = (struct iphdr *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));

	data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);

	cJSON *ip = cJSON_GetObjectItem(json, "The Server's IP Address");
    cJSON *port = cJSON_GetObjectItem(json, "Port Number for TCP");

	printf("the server's IP address = %s\n", ip->valuestring);

    in_addr_t server_addr = inet_addr(ip->valuestring); 
    unsigned short server_port = cJSON_GetNumberValue(port);

	struct sockaddr_in sin; 
	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	sin.sin_port = htons(server_port);
	
	sin.sin_addr.s_addr = server_addr;
	
	char *server_ip = cJSON_GetObjectItem(json, "The Server's IP Address")->valuestring;

	//some address resolution
	sin.sin_family = AF_INET;
	sin.sin_port = htons(cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Port Number for TCP")));
	sin.sin_addr.s_addr = inet_addr(server_ip);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
	iph->id = htonl (1);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr(server_ip);	//Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;

	tcph->source = htons(1234);
	tcph->dest = htons(80);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;	//tcp header size
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;

	psh.source_address = inet_addr(server_ip);
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data); // data should be empty since im not actually sending anything
	pseudogram = malloc(psize);

	memcpy(pseudogram, (char *) &psh, sizeof(struct pseudo_header)); // get pseudoheader for checksum
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data)); // add tcp header

	tcph->check = csum((unsigned short*) pseudogram , psize); // do the checksum and add it to the tcp header

	if (sendto (sock, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
		perror("sendto failed");
	} else {
		printf("Packet Send. Length : %d \n" , iph->tot_len);
	}

	return datagram;
}

int main(int argc, char** argv) {
    printf("hello\n");

    char *file = readFile(argv[1]); // getting file params
    if (file == 0) {
        perror("Couldn't read file, please try again later.");
        cleanExit();
    }

    cJSON *json = cJSON_Parse(file);

	
    int raw_sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (raw_sock < 0) {
		perror("something whent wrong");
		return -1;
	}

	int optval = 1;
	if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof (optval)) < 0) {
		perror("Couldnt set socket option");
		return -1;
	}

	

	char *syn_one = setup_syn_packet(json, cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Destination Port Number for TCP Head SYN")), raw_sock);
	// char *syn_two = setup_syn_packet(json, cJSON_GetNumberValue(cJSON_GetObjectItem(json, "Destination Port Number for TCP Tail SYN")), &sin, raw_sock);

	
}