// L2TPNS Clustering Stuff
// $Id: cluster.c,v 1.1 2003-12-16 07:07:39 fred_nerk Exp $ #include <stdio.h> #include <sys/file.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include "cluster.h"

int cluster_sockfd = 0;
int cluster_server = 0;
uint32_t vip_address;
extern int debug;
void _log_hex(int level, const char *title, const char *data, int maxsize);
#define log_hex(a,b,c,d)
#ifndef log_hex
#define log_hex(a,b,c,d) do{if (a > debug) _log_hex(a,b,c,d);}while (0)
#endif

// Create a listening socket
int cluster_init(uint32_t bind_address, int server)
{
    struct sockaddr_in addr;

    vip_address = bind_address;
    cluster_server = !!server;

    cluster_sockfd = socket(AF_INET, SOCK_DGRAM, UDP);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cluster_server ? CLUSTERPORT : CLUSTERCLIENTPORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    setsockopt(cluster_sockfd, SOL_SOCKET, SO_REUSEADDR, &addr, sizeof(addr));
    if (bind(cluster_sockfd, (void *) &addr, sizeof(addr)) < 0)
    {
	perror("bind");
	exit(-1);
    }

    return cluster_sockfd;
}

int cluster_send_message(unsigned long ip_address, uint32_t vip, char type, void *data, int datalen)
{
    size_t l = 1 + sizeof(uint32_t) + datalen;
    char *buf = NULL;
    struct sockaddr_in addr = {0};

    if (!cluster_sockfd) return -1;
    if (!ip_address) return 0;

    buf = calloc(l, 1);
    *(uint32_t *)(buf) = htonl(vip);
    *(char *)(buf+sizeof(uint32_t)) = type;

    if (data && datalen > 0)
	memcpy((char *)(buf + sizeof(uint32_t) + 1), data, datalen);

    addr.sin_addr.s_addr = ip_address;
    addr.sin_port = htons(cluster_server ? CLUSTERCLIENTPORT : CLUSTERPORT);
    addr.sin_family = AF_INET;

    log_hex(4, "Cluster send", buf, l);

    if (sendto(cluster_sockfd, buf, l, MSG_NOSIGNAL, (void *) &addr, sizeof(addr)) < 0)
    {
	perror("sendto");
	free(buf);
	return -1;
    }
    free(buf);

    return 0;
}
