#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <netdb.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "control.h"

int new_packet(short type, char *packet)
{
	int id = (time(NULL) ^ (rand() * 1024*1024));

	*(short *)(packet + 0) = ntohs(0x9012);
	*(short *)(packet + 2) = ntohs(type);
	*(int *)(packet + 6) = ntohl(id);

	return 10;
}

int send_packet(int sockfd, int dest_ip, int dest_port, char *packet, int len)
{
	struct sockaddr_in addr;

	*(short *)(packet + 4) = ntohs(len);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	*(int*)&addr.sin_addr = htonl(dest_ip);
	addr.sin_port = htons(dest_port);
	if (sendto(sockfd, packet, len, 0, (void *) &addr, sizeof(addr)) < 0)
	{
		perror("sendto");
		return 0;
	}
	return 1;
}

int read_packet(int sockfd, char *packet)
{
	struct sockaddr_in addr;
	int alen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));
	return recvfrom(sockfd, packet, 1400, 0, (void *) &addr, &alen);
}

void dump_packet(char *packet, FILE *stream)
{
	if (htons(*(short *)(packet + 0)) != 0x9012)
	{
		fprintf(stream, "Invalid packet identifier %x\n", htons(*(short *)(packet + 0)));
		return;
	}
	fprintf(stream, "Control packet:\n");
	fprintf(stream, "	Type: %d\n", htons(*(short *)(packet + 2)));
	fprintf(stream, "	Length: %d\n", htons(*(short *)(packet + 4)));
	fprintf(stream, "	Identifier: %x\n", htonl(*(int *)(packet + 6)));
	fprintf(stream, "\n");
}


