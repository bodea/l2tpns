// L2TPNS Cluster Master
// $Id: cluster_slave.c,v 1.1.1.1 2003-12-16 07:07:39 fred_nerk Exp $

#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <malloc.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "l2tpns.h"
#include "cluster.h"
#include "ll.h"
#include "util.h"

extern int cluster_sockfd;
extern tunnelt *tunnel;
extern sessiont *session;
extern uint32_t cluster_address;
extern char hostname[1000];
extern int debug;
extern ippoolt *ip_address_pool;
extern uint32_t vip_address;
extern tunnelidt tunnelfree;
extern sessionidt sessionfree;

int handle_tunnel(char *buf, int l);
int handle_session(char *buf, int l);
int handle_hello_response(char *buf, int l);

int processcluster(char *buf, int l)
{
    char mtype;
    uint32_t addr;

    log_hex(4, "Cluster receive", buf, l);
    if (!buf || l <= sizeof(uint32_t)) return 0;

    addr = ntohl(*(uint32_t*)buf);
    buf += sizeof(uint32_t);
    l -= sizeof(uint32_t);

    if (addr != vip_address)
    {
	log(0, 0, 0, 0, "Received cluster message for VIP %s, which isn't ours\n", inet_toa(addr));
    }

    mtype = *buf; buf++; l--;

    switch (mtype)
    {
	case C_HELLO:
	    break;
	case C_HELLO_RESPONSE:
	    handle_hello_response(buf, l);
	    break;
	case C_PING:
	    break;
	case C_TUNNEL:
	    handle_tunnel(buf, l);
	    break;
	case C_SESSION:
	    handle_session(buf, l);
	    break;
    }
    return mtype;

    return 0;
}

int handle_tunnel(char *buf, int l)
{
    int t;

    t = *(int *)buf;
    log(1, 0, 0, t, "Receiving tunnel %d from cluster master (%d bytes)\n", t, l);
    buf += sizeof(int); l -= sizeof(int);

    if (t > MAXTUNNEL)
    {
	log(0, 0, 0, t, "Cluster master tried to send tunnel %d, which is bigger than MAXTUNNEL (%d)\n", t, MAXTUNNEL);
	return 0;
    }

    if (l != sizeof(tunnelt))
    {
	log(1, 0, 0, t, "Discarding bogus tunnel message (%d bytes instead of %d).\n", l, sizeof(tunnelt));
	return 0;
    }

    if (t > 1)
    {
	tunnel[t-1].next = tunnel[t].next;
    }

    if (tunnelfree == t)
    {
	tunnelfree = tunnel[t].next;
    }

    memcpy(&tunnel[t], buf, l);
    log(3, 0, 0, t, "Cluster master sent tunnel for %s\n", tunnel[t].hostname);

    tunnel[t].controlc = 0;
    tunnel[t].controls = NULL;
    tunnel[t].controle = NULL;
    return 0;
}

int handle_session(char *buf, int l)
{
    int s;

    s = *(int *)buf;
    log(1, 0, s, 0, "Receiving session %d from cluster master (%d bytes)\n", s, l);
    buf += sizeof(int); l -= sizeof(int);

    if (s > MAXSESSION)
    {
	log(0, 0, s, 0, "Cluster master tried to send session %d, which is bigger than MAXSESSION (%d)\n", s, MAXSESSION);
	return 0;
    }

    if (l != sizeof(sessiont))
    {
	log(1, 0, s, 0, "Discarding short session message (%d bytes instead of %d).\n", l, sizeof(sessiont));
	return 0;
    }

    if (s > 1)
    {
	session[s-1].next = session[s].next;
    }

    if (sessionfree == s)
    {
	sessionfree = session[s].next;
    }

    memcpy(&session[s], buf, l);
    session[s].tbf = 0;
    session[s].throttle = 0;
    if (session[s].opened)
    {
	log(2, 0, s, session[s].tunnel, "Cluster master sent active session for user %s\n", session[s].user);
	sessionsetup(session[s].tunnel, s, 0);
	if (session[s].ip && session[s].ip != 0xFFFFFFFE)
	{
	    int x;
	    for (x = 0; x < MAXIPPOOL && ip_address_pool[x].address; x++)
	    {
		if (ip_address_pool[x].address == session[s].ip)
		{
		    ip_address_pool[x].assigned = 1;
		    break;
		}
	    }
	}
    }
    return 0;
}

int handle_hello_response(char *buf, int l)
{
    int numtunnels, numsessions;

    /* The cluster master has downed the address, so send another garp */
    send_garp(vip_address);

    if (!l) return 0;

    if (l < (4 * IL))
    {
	log(1, 0, 0, 0, "Cluster master sent invalid hello response: %d bytes instead of %d\n", l, (4 * IL));
	return 0;
    }
    numtunnels = *(int *)(buf + IL * 0);
    numsessions = *(int *)(buf + IL * 1);
    if (numtunnels == 0 && numsessions == 0)
    {
	log(2, 0, 0, 0, "Cluster master has no state information for us.\n");
	return 0;
    }
    log(2, 0, 0, 0, "The cluster master will send %d tunnels and %d sessions.\n", numtunnels, numsessions);
    return 0;
}

int cluster_send_session(int s)
{
	char *packet;
	int len = 0;

	if (!cluster_sockfd) return 1;

	packet = malloc(4096);

	// Hostname
	len = strlen(hostname);
	*(char *)packet = len;
	memcpy((char *)(packet + 1), hostname, len);
	len++;

	// Session ID
	*(int *)(packet + len) = s;
	len += sizeof(int);

	// Session data
	memcpy((char *)(packet + len), &session[s], sizeof(sessiont));
	len += sizeof(sessiont);

	cluster_send_message(cluster_address, vip_address, C_SESSION, packet, len);
	free(packet);

	return 1;
}

int cluster_send_tunnel(int t)
{
	char *packet;
	int len = 0;

	packet = malloc(4096);

	// Hostname
	len = strlen(hostname);
	*(char *)packet = len;
	memcpy((char *)(packet + 1), hostname, len);
	len++;

	// Tunnel ID
	*(int *)(packet + len) = t;
	len += sizeof(int);

	// Tunnel data
	memcpy((char *)(packet + len), &tunnel[t], sizeof(tunnelt));
	len += sizeof(tunnelt);

	cluster_send_message(cluster_address, vip_address, C_TUNNEL, packet, len);
	free(packet);

	return 1;
}

