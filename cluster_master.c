// L2TPNS Cluster Master
// $Id: cluster_master.c,v 1.3 2004-05-24 04:12:34 fred_nerk Exp $

#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <malloc.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include "cluster.h"
#include "ll.h"
#include "util.h"
#include "config.h"

#define L2TPNS		BINDIR "/l2tpns"

typedef struct
{
    char *hostname;
    unsigned long last_message;
    uint32_t ip_address;
    uint32_t slave_address;
    int remove_from_cluster;
    int down;
    int tunnel_len;
    int session_len;
    pid_t pid;

    int num_tunnels;
    char *tunnels[1000];
    int num_sessions;
    char *sessions[13000];
} slave;

uint32_t master_address;
linked_list *slaves;
extern int cluster_sockfd;
int debug = 4;

int processmsg(char *buf, int l, struct sockaddr_in *src_addr);
int handle_hello(char *buf, int l, struct sockaddr_in *src_addr, uint32_t addr);
int handle_tunnel(char *buf, int l, uint32_t addr);
int handle_session(char *buf, int l, uint32_t addr);
int handle_ping(char *buf, int l, uint32_t addr);
int handle_goodbye(char *buf, int l, uint32_t addr);
int backup_up(slave *s);
int backup_down(slave *s);
int return_state(slave *s);
slave *find_slave(uint32_t address);
#define log _log
void _log(int level, const char *format, ...) __attribute__((format (printf, 2, 3)));
void log_hex(int level, const char *title, const char *data, int maxsize);

/* Catch our forked processes exiting */
void sigchild_handler(int signal)
{
    int status;
    int pid;

    pid = wait(&status);
    /* TODO: catch errors and respawn? */
}

int main(int argc, char *argv[])
{
    slave *s;
    char buf[4096];
    struct timeval to;

    if (argc != 2) {
	log(0, "Usage: %s <address>\n", argv[0]);
	exit(-1);
    }

    master_address = inet_addr(argv[1]);
    if (master_address == INADDR_NONE) {
	log(0, "Invalid ip %s\n", argv[1]);
	exit(-1);
    }

    cluster_init(master_address, 1);
    slaves = ll_init();

    signal(SIGCHLD, sigchild_handler);

    log(0, "Cluster Manager $Id: cluster_master.c,v 1.3 2004-05-24 04:12:34 fred_nerk Exp $ starting\n");

    to.tv_sec = 1;
    to.tv_usec = 0;
    while (1)
    {
	fd_set r;
	int n;

	FD_ZERO(&r);
	FD_SET(cluster_sockfd, &r);
	n = select(cluster_sockfd + 1, &r, 0, 0, &to);
	if (n < 0)
	{
	    if (errno != EINTR)
	    {
		perror("select");
		exit(-1);
	    }
	    continue;
	}
	else if (n)
	{
	    struct sockaddr_in addr;
	    int alen = sizeof(addr);

	    memset(buf, 0, sizeof(buf));
	    if (FD_ISSET(cluster_sockfd, &r))
		processmsg(buf, recvfrom(cluster_sockfd, buf, sizeof(buf), MSG_WAITALL, (void *) &addr, &alen), &addr);
	    continue;
	}

	// Handle slaves timing out
	{
	    time_t now = time(NULL);
	    ll_reset(slaves);
	    while ((s = ll_next(slaves)))
	    {
		if (s->down) continue;
		if (s->last_message < (now - TIMEOUT))
		{
		    log(4, "Slave \"%s\" s->last_message is %lu (timeout is %lu)\n", s->hostname, s->last_message, (now - TIMEOUT));
		    if (s->remove_from_cluster)
		    {
			// Remove them from the cluster
			ll_delete(slaves, s);
			if (s->hostname) free(s->hostname);
			free(s);
			ll_reset(slaves);
			continue;
		    }
		    backup_up(s);
		}
	    }
	}

	to.tv_sec = 1;
	to.tv_usec = 0;
    }

    return 0;
}

int processmsg(char *buf, int l, struct sockaddr_in *src_addr)
{
    slave *s;
    char mtype;
    uint32_t addr;

    log_hex(4, "Received", buf, l);
    if (!buf || l <= sizeof(uint32_t)) return 0;

    addr = ntohl(*(uint32_t*)buf);
    buf += sizeof(uint32_t);
    l -= sizeof(uint32_t);

    mtype = *buf; buf++; l--;

    if (mtype != C_GOODBYE && (s = find_slave(addr)) && s->down)
    {
	char *hostname;
	hostname = calloc(l + 1, 1);
	memcpy(hostname, buf, l);
	log(1, "Slave \"%s\" (for %s) has come back.\n", hostname, inet_toa(s->ip_address));
	backup_down(s);
	free(hostname);
    }

    switch (mtype)
    {
	case C_HELLO:
	    handle_hello(buf, l, src_addr, addr);
	    break;
	case C_PING:
	    if (!find_slave(addr))
		handle_hello(buf, l, src_addr, addr);
	    else
		handle_ping(buf, l, addr);
	    break;
	case C_TUNNEL:
	    if (!find_slave(addr)) handle_hello((char *)(buf + 1), *(char *)buf, src_addr, addr);
	    handle_tunnel(buf, l, addr);
	    break;
	case C_SESSION:
	    if (!find_slave(addr)) handle_hello((char *)(buf + 1), *(char *)buf, src_addr, addr);
	    handle_session(buf, l, addr);
	    break;
	case C_GOODBYE:
	    if (!find_slave(addr)) break;
	    handle_goodbye(buf, l, addr);
	    break;
    }
    return mtype;
}

int handle_hello(char *buf, int l, struct sockaddr_in *src_addr, uint32_t addr)
{
    slave *s;
    char *hostname;

    hostname = calloc(l + 1, 1);
    memcpy(hostname, buf, l);

    // Is this a slave we have state information for?
    if ((s = find_slave(addr)))
    {
	if (src_addr->sin_addr.s_addr == master_address)
	{
	    log(1, "Got hello from \"%s\", local backup for %s.\n", hostname, inet_toa(s->ip_address));
	}
	else if (s->down)
	{
	    log(1, "Slave \"%s\" (for %s) has come back.\n", hostname, inet_toa(s->ip_address));
	    backup_down(s);
	}
	else
	{
	    log(1, "Slave \"%s\" said hello and we didn't know it was down.\n", s->hostname);
	}

	/* Reset the hostname if needed */
	free(s->hostname);
	s->hostname = hostname;
    } else {
	// No state information, it's a new slave
	s = calloc(sizeof(slave), 1);
	s->ip_address = addr;
	ll_push(slaves, s);
	s->hostname = hostname;
	log(1, "New slave added to cluster \"%s\"\n", s->hostname);
    }

    s->slave_address = src_addr->sin_addr.s_addr;

    // Send state information back
    return_state(s);

    s->last_message = time(NULL);

    return 0;
}

int handle_tunnel(char *buf, int l, uint32_t addr)
{
    int tid;
    slave *s;
    if (!(s = find_slave(addr)))
    {
	log(0, "handle_tunnel() called with no valid slave\n");
	return 0;
    }
    s->last_message = time(NULL);

    // Skip hostname
    tid = *(char *)buf;
    buf += (tid + 1);
    l -= (tid + 1);

    // Grab tunnel ID
    tid = *(int *)buf;
    buf += sizeof(int);
    l -= sizeof(int);

    log(3, "Received tunnel %d from \"%s\" (%d bytes long)\n", tid, s->hostname, l);

    // Allocate memory for it if it's not already
    if (!s->tunnels[tid])
    {
	s->tunnels[tid] = malloc(l);
	s->num_tunnels++;
	s->tunnel_len = l;
    }

    memcpy(s->tunnels[tid], buf, l);
    return l;
}

int handle_session(char *buf, int l, uint32_t addr)
{
    slave *s;
    int sid;
    char hostname[4096] = {0};
    if (!(s = find_slave(addr)))
    {
	log(0, "handle_session() called with no valid slave\n");
	return 0;
    }
    s->last_message = time(NULL);

    // Skip hostname
    sid = *(char *)buf;
    memcpy(hostname, (char *)(buf + 1), sid);
    buf += (sid + 1);
    l -= (sid + 1);
    log(0, "Hostname is %s\n", hostname);

    // Grab session ID
    sid = *(int *)buf;
    buf += sizeof(int);
    l -= sizeof(int);

    log(3, "Received session %d from \"%s\" (%d bytes long)\n", sid, s->hostname, l);

    // Allocate memory for it if it's not already
    if (!s->sessions[sid])
    {
	s->sessions[sid] = malloc(l);
	s->num_sessions++;
	s->session_len = l;
    }

    memcpy(s->sessions[sid], buf, l);
    return l;
}

int handle_ping(char *buf, int l, uint32_t addr)
{
    slave *s;
    if (!(s = find_slave(addr)))
    {
	log(0, "handle_ping() called with no valid slave\n");
	return 0;
    }
    s->last_message = time(NULL);

    return 0;
}

int return_state(slave *s)
{
    char *packet;
    int i;
    int num_tunnels = 0, num_sessions = 0;
    int pktlen;

    log(3, "Sending state information to \"%s\"\n", s->hostname);

    for (i = 0; i < 1000; i++)
	if (s->tunnels[i]) num_tunnels++;

    for (i = 0; i < 13000; i++)
	if (s->sessions[i]) num_sessions++;

    if (!num_sessions && !num_tunnels) return 0;

    packet = calloc(IL * 4, 1);
    *(int *)(packet + IL * 0) = num_tunnels;
    *(int *)(packet + IL * 1) = num_sessions;
    *(int *)(packet + IL * 2) = s->tunnel_len;
    *(int *)(packet + IL * 3) = s->session_len;
    cluster_send_message(s->slave_address, s->ip_address, C_HELLO_RESPONSE, packet, IL * 4);
    free(packet);

    // Send tunnels one-by-one, in order
    log(0, "Sending %d tunnels of %d bytes each\n", num_tunnels, s->tunnel_len);
    pktlen = s->tunnel_len + sizeof(int);
    packet = malloc(pktlen);
    for (i = 0; i < 1000; i++)
    {
	if (s->tunnels[i])
	{
	    *(int *)packet = i;
	    memcpy((char *)(packet + sizeof(int)), s->tunnels[i], s->tunnel_len);
	    log(0, "Sending tunnel %d\n", i);
	    cluster_send_message(s->slave_address, s->ip_address, C_TUNNEL, packet, pktlen);
	}
    }
    free(packet);

    // Send sessions one-by-one, in order
    log(0, "Sending %d sessions of %d bytes each\n", num_sessions, s->session_len);
    pktlen = s->session_len + sizeof(int);
    packet = malloc(pktlen);
    for (i = 0; i < 13000; i++)
    {
	if (s->sessions[i])
	{
	    *(int *)packet = i;
	    memcpy((char *)(packet + sizeof(int)), s->sessions[i], s->session_len);
	    log(0, "Sending session %d\n", i);
	    cluster_send_message(s->slave_address, s->ip_address, C_SESSION, packet, pktlen);
	}
    }
    free(packet);

    return 0;
}

slave *find_slave(uint32_t address)
{
    slave *s;

    ll_reset(slaves);
    while ((s = ll_next(slaves)))
    {
	if (s->ip_address == address)
	{
	    return s;
	}
    }
    return NULL;
}

void _log(int level, const char *format, ...)
{
	va_list ap;
	if (debug < level) return;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
}

void log_hex(int level, const char *title, const char *data, int maxsize)
{
	unsigned int i, j;
	unsigned const char *d = (unsigned const char *)data;

	if (debug < level) return;
	log(level, "%s (%d bytes):\n", title, maxsize);
	setvbuf(stderr, NULL, _IOFBF, 16384);
	for (i = 0; i < maxsize; )
	{
		fprintf(stderr, "%4X: ", i);
		for (j = i; j < maxsize && j < (i + 16); j++)
		{
			fprintf(stderr, "%02X ", d[j]);
			if (j == i + 7)
				fputs(": ", stderr);
		}

		for (; j < i + 16; j++)
		{
			fputs("   ", stderr);
			if (j == i + 7)
				fputs(": ", stderr);
		}

		fputs("  ", stderr);
		for (j = i; j < maxsize && j < (i + 16); j++)
		{
			if (d[j] >= 0x20 && d[j] < 0x7f && d[j] != 0x20)
				fputc(d[j], stderr);
			else
				fputc('.', stderr);

			if (j == i + 7)
				fputs("  ", stderr);
		}

		i = j;
		fputs("\n", stderr);
	}
	fflush(stderr);
	setbuf(stderr, NULL);
}

int backup_up(slave *s)
{
    log(2, "Becoming backup for \"%s\" (%s).\n", s->hostname, inet_toa(s->ip_address));
    s->pid = fork();
    if (!s->pid)
    {
	if (execl(L2TPNS, L2TPNS, "-a", inet_toa(s->ip_address), NULL) < 0)
	    log(0, "Error execing backup " L2TPNS ": %s\n", strerror(errno));
	exit(0);
    }
    s->down = 1;
    return 0;
}

int backup_down(slave *s)
{
    log(2, "Not being backup for \"%s\" (%s) anymore.\n", s->hostname, inet_toa(s->ip_address));
    s->down = 0;
    if (s->pid) {
	kill(s->pid, SIGTERM);
	sleep(2);
	kill(s->pid, SIGKILL);
    }
    return 0;
}

int handle_goodbye(char *buf, int l, uint32_t addr)
{
    int i;
    slave *s;

    // Is this a slave we have state information for?
    if ((s = find_slave(addr)))
    {
        log(0, "Received goodbye for slave %s\n", s->hostname);
	ll_delete(slaves, s);
	for (i = 0; i < s->num_tunnels; i++)
	    if (s->tunnels[i]) free(s->tunnels[i]);
	for (i = 0; i < s->num_sessions; i++)
	    if (s->sessions[i]) free(s->sessions[i]);
	if (s->hostname) free(s->hostname);
	free(s);
    }

    return 0;
}

