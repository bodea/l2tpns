#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

#define PORT	39000

void sigalarm(int junk);
unsigned long long recv_count = 0;
unsigned long pps = 0;
unsigned long bytes = 0;
unsigned long dropped = 0, seq = 0;
unsigned port = PORT;

int main(int argc, char *argv[])
{
	int on = 1;
	struct sockaddr_in addr;
	int s;
	char *packet;

	while ((s = getopt(argc, argv, "?p:")) > 0)
	{
		switch (s)
		{
			case 'p' :
				port = atoi(optarg);
				break;
			case '?' :
				printf("Options:\n");
				printf("\t-p port to listen on\n");
				return(0);
				break;
		}
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (bind(s, (void *) &addr, sizeof(addr)) < 0)
	{
		perror("bind");
		return -1;
	}

	signal(SIGALRM, sigalarm);
	alarm(1);

	printf("Waiting on port %d\n", port);
	packet = (char *)malloc(65535);
	while (1)
	{
		struct sockaddr_in addr;
		int alen = sizeof(addr), l;
		unsigned int iseq;

		l = recvfrom(s, packet, 65535, 0, (void *) &addr, &alen);
		if (l < 0) continue;
		recv_count++;
		pps++;
		bytes += l;
		iseq =  *((unsigned int *)  packet);
		if (seq != iseq)
			dropped += (iseq - seq);
		seq = iseq + 1;

		sendto(s, packet, l, 0, (struct sockaddr *)&addr, alen);
	}

	free(packet);
}

void sigalarm(int junk)
{
	printf("Recv: %10llu %0.1fMbits/s (%lu pps) (%5ld dropped)\n", recv_count, (bytes / 1024.0 / 1024.0 * 8), pps, dropped);
	pps = bytes = 0;
	alarm(1);
}

