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

struct { char *command; int pkt_type; int params; } commands[] = {
	{ "load_plugin", PKT_LOAD_PLUGIN, 1 },
	{ "unload_plugin", PKT_UNLOAD_PLUGIN, 1 },
	{ "garden", PKT_GARDEN, 1 },
	{ "ungarden", PKT_UNGARDEN, 1 },
};

char *dest_host = NULL;
unsigned int dest_port = 1702;
int udpfd;

int main(int argc, char *argv[])
{
	int len = 0;
	int dest_ip = 0;
	int pkt_type = 0;
	char *packet = NULL;
	int i;

	setbuf(stdout, NULL);

	if (argc < 3)
	{
		printf("Usage: %s <host> <command> [args...]\n", argv[0]);
		return 1;
	}

	dest_host = strdup(argv[1]);

	{
		// Init socket
		int on = 1;
		struct sockaddr_in addr;

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(1703);
		udpfd = socket(AF_INET, SOCK_DGRAM, 17);
		setsockopt(udpfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		if (bind(udpfd, (void *) &addr, sizeof(addr)) < 0)
		{
			perror("bind");
			return(1);
		}
	}

	{
		struct hostent *h = gethostbyname(dest_host);
		if (h) dest_ip = ntohl(*(unsigned int *)h->h_addr);
		if (!dest_ip) dest_ip = ntohl(inet_addr(dest_host));
		if (!dest_ip)
		{
			printf("Can't resolve \"%s\"\n", dest_host);
			return 0;
		}
	}

	if (!(packet = calloc(1400, 1)))
	{
		perror("calloc");
		return(1);
	}

	srand(time(NULL));

	// Deal with command & params
	for (i = 0; i < (sizeof(commands) / sizeof(commands[0])); i++)
	{
		if (strcasecmp(commands[i].command, argv[2]) == 0)
		{
			int p;
			pkt_type = commands[i].pkt_type;
			len = new_packet(pkt_type, packet);
			if (argc < (commands[i].params + 3))
			{
				printf("Not enough parameters for %s\n", argv[2]);
				return 1;
			}
			for (p = 0; p < commands[i].params; p++)
			{
				strncpy((packet + len), argv[p + 3], 1400 - len);
				len += strlen(argv[p + 3]) + 1;
			}
			break;
		}
	}
	if (!pkt_type)
	{
		printf("Unknown command\n");
		return 1;
	}

	send_packet(udpfd, dest_ip, dest_port, packet, len);

	{
		int n;
		fd_set r;
		struct timeval timeout;

		FD_ZERO(&r);
		FD_SET(udpfd, &r);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		n = select(udpfd + 1, &r, 0, 0, &timeout);
		if (n <= 0)
		{
			printf("Timeout waiting for packet\n");
			return 0;
		}
	}
	if ((len = read_packet(udpfd, packet)))
	{
		printf("Received ");
		dump_packet(packet, stdout);
	}

	return 0;
}

