// L2TPNS Rate Limiting Stuff
// $Id: rl.c,v 1.1 2003-12-16 07:07:39 fred_nerk Exp $

#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include "l2tpns.h"

extern char *radiussecret;
extern radiust *radius;
extern sessiont *session;
extern ipt radiusserver[MAXRADSERVER]; // radius servers
extern u32 sessionid;
extern u8 radiusfree;
extern int radfd;
extern u8 numradiusservers;
extern char debug;
extern char *tapdevice;
extern tbft *filter_buckets;

#define DEVICE "tun0"

unsigned long rl_rate = 0;
int next_tbf = 1;

void init_rl()
{
#ifdef TC_TBF
    system("tc qdisc del dev " DEVICE " root");
    system("tc qdisc add dev " DEVICE " root handle 1: cbq avpkt 10000 bandwidth 100mbit");
    system("tc filter del dev " DEVICE " protocol ip pref 1 fw");
    system("iptables -t mangle -N throttle 2>&1 > /dev/null");
    system("iptables -t mangle -F throttle");
    system("iptables -t mangle -A l2tpns -j throttle");
#endif
#ifdef TC_HTB
    char *commands[] = {
	"tc qdisc add dev " DEVICE " root handle 1: htb default 1",
	"tc class add dev " DEVICE " parent 1: classid 1:1 htb rate 100mbit burst 300k",
	"tc filter del dev " DEVICE " protocol ip pref 1 fw",
	"iptables -t mangle -N throttle 2>&1 > /dev/null",
	"iptables -t mangle -F throttle",
	"iptables -t mangle -A l2tpns -j throttle",
	NULL
    };
    int i;

    if (!rl_rate) return;

    log(2, 0, 0, 0, "Initializing HTB\n");
    for (i = 0; commands[i] && *commands[i]; i++)
    {
	log(3, 0, 0, 0, "Running \"%s\"\n", commands[i]);
	system(commands[i]);
    }
    log(2, 0, 0, 0, "Done initializing HTB\n");
#endif
}

u16 rl_create_tbf()
{
    u16 t;
    char cmd[2048];
    if (!rl_rate) return 0;

    if (next_tbf >= MAXSESSION) return 0;
    t = next_tbf++;
    snprintf(filter_buckets[t].handle, 9, "1:%d0", t);

#ifdef TC_TBF
    log(2, 0, 0, 0, "Creating new tbf %s\n", filter_buckets[t].handle);
    snprintf(cmd, 2048, "tc class add dev " DEVICE " parent 1: classid 1:%d cbq bandwidth 100Mbit rate 100Mbit "
	    "weight 1 prio 8 allot 1514 cell 8 maxburst 20 avpkt 1000 bounded isolated",
	    t);
    log(3, 0, 0, 0, "%s\n", cmd);
    system(cmd);

    snprintf(cmd, 2048, "tc qdisc add dev " DEVICE " parent 1:%d handle %s tbf rate %dkbit buffer 1600 limit 3000",
	    t, filter_buckets[t].handle, rl_rate);
    log(3, 0, 0, 0, "%s\n", cmd);
    system(cmd);

    snprintf(cmd, 2048, "tc filter add dev " DEVICE " protocol ip parent 1:0 prio 1 handle %d fw flowid 1:%d",
	    t, t);
    log(3, 0, 0, 0, "%s\n", cmd);
    system(cmd);
#endif
#ifdef TC_HTB
    log(2, 0, 0, 0, "Creating new htb %s\n", filter_buckets[t].handle);
    snprintf(cmd, 2048, "tc class add dev " DEVICE " parent 1: classid %s htb rate %lukbit burst 15k",
	    filter_buckets[t].handle, rl_rate);
    log(3, 0, 0, 0, "%s\n", cmd);
    system(cmd);

    snprintf(cmd, 2048, "tc filter add dev " DEVICE " protocol ip parent 1:0 prio 1 handle %d fw flowid %s",
	    t, filter_buckets[t].handle);
    log(3, 0, 0, 0, "%s\n", cmd);
    system(cmd);
#endif

    next_tbf++;
    return t;
}

u16 rl_get_tbf()
{
    int i;
    if (!rl_rate) return 0;

    for (i = 1; i < MAXSESSION; i++)
    {
	if (!filter_buckets[i].in_use && *filter_buckets[i].handle)
	{
	    filter_buckets[i].in_use = 1;
	    log(2, 0, 0, 0, "Returning tbf %s\n", filter_buckets[i].handle);
	    return i;
	}
    }
    i = rl_create_tbf();
    if (i) filter_buckets[i].in_use = 1;
    return i;
}

void rl_done_tbf(u16 t)
{
    if (!t) return;
    if (!rl_rate) return;
    log(2, 0, 0, 0, "Freeing up TBF %s\n", filter_buckets[t].handle);
    filter_buckets[t].in_use = 0;
}

void rl_destroy_tbf(u16 t)
{
    char cmd[2048];
    if (!rl_rate) return;
    if (filter_buckets[t].in_use)
    {
	log(0, 0, 0, 0, "Trying to destroy an in-use TBF %s\n", filter_buckets[t].handle);
	return;
    }
#ifdef TC_TBF
    snprintf(cmd, 2048, "tc qdisc del dev " DEVICE " handle %s", filter_buckets[t].handle);
    system(cmd);
#endif
#ifdef TC_HTB
    snprintf(cmd, 2048, "tc qdisc del dev " DEVICE " handle %s", filter_buckets[t].handle);
    system(cmd);
#endif
    system("iptables -t mangle -D l2tpns -j throttle");
    system("iptables -t mangle -X throttle");
    memset(filter_buckets[t].handle, 0, sizeof(filter_buckets[t].handle));
}

