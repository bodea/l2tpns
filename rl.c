// L2TPNS Rate Limiting Stuff
// $Id: rl.c,v 1.2 2004-03-05 00:09:03 fred_nerk Exp $

#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include "l2tpns.h"

extern radiust *radius;
extern sessiont *session;
extern u32 sessionid;
extern int radfd;
extern tbft *filter_buckets;
extern struct configt *config;

#define DEVICE "tun0"

int next_tbf = 1;

void init_rl()
{
    char *commands[] = {
	"tc qdisc add dev " DEVICE " root handle 1: htb default 1",
	"tc class add dev " DEVICE " parent 1: classid 1:1 htb rate 100mbit burst 300k",
	"tc filter del dev " DEVICE " protocol ip pref 1 fw",
	"iptables -t mangle -N throttle 2>&1 >/dev/null",
	"iptables -t mangle -F throttle 2>&1 >/dev/null",
	"iptables -t mangle -A l2tpns -j throttle 2>&1 >/dev/null",
	NULL
    };
    int i;

    log(2, 0, 0, 0, "Initializing HTB\n");
    for (i = 0; commands[i] && *commands[i]; i++)
    {
	log(3, 0, 0, 0, "Running \"%s\"\n", commands[i]);
	system(commands[i]);
    }
    log(2, 0, 0, 0, "Done initializing HTB\n");
}

u16 rl_create_tbf()
{
    u16 t;
    char cmd[2048];
    if (!config->rl_rate) return 0;

    if (next_tbf >= MAXSESSION) return 0;
    t = next_tbf++;
    snprintf(filter_buckets[t].handle, 9, "1:%d0", t);

    log(2, 0, 0, 0, "Creating new htb %s\n", filter_buckets[t].handle);
    snprintf(cmd, 2048, "tc class add dev " DEVICE " parent 1: classid %s htb rate %lukbit burst 15k",
	    filter_buckets[t].handle, config->rl_rate);
    log(3, 0, 0, 0, "%s\n", cmd);
    system(cmd);

    snprintf(cmd, 2048, "tc filter add dev " DEVICE " protocol ip parent 1:0 prio 1 handle %d fw flowid %s",
	    t, filter_buckets[t].handle);
    log(3, 0, 0, 0, "%s\n", cmd);
    system(cmd);

    next_tbf++;
    return t;
}

u16 rl_get_tbf()
{
    int i;
    if (!config->rl_rate) return 0;

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
    if (!config->rl_rate) return;
    log(2, 0, 0, 0, "Freeing up HTB %s\n", filter_buckets[t].handle);
    filter_buckets[t].in_use = 0;
}

void rl_destroy_tbf(u16 t)
{
    char cmd[2048];
    if (!config->rl_rate) return;
    if (filter_buckets[t].in_use)
    {
	log(0, 0, 0, 0, "Trying to destroy an in-use HTB %s\n", filter_buckets[t].handle);
	return;
    }
    snprintf(cmd, 2048, "tc qdisc del dev " DEVICE " handle %s", filter_buckets[t].handle);
    system(cmd);
    system("iptables -t mangle -D l2tpns -j throttle 2>&1 >/dev/null");
    system("iptables -t mangle -X throttle 2>&1 >/dev/null");
    memset(filter_buckets[t].handle, 0, sizeof(filter_buckets[t].handle));
}

