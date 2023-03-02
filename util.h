#ifndef _UTIL_H_
#define _UTIL_H_

#include <stddef.h>
#include <sys/types.h>

char *readFile(char *filename);
int send_packets(char *buffer, int buffer_len, int sock);
int receive_packets(char *buffer, int buffer_len, int sock);

#endif