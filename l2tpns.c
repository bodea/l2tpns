// L2TP Network Server
// Adrian Kennard 2002
// Copyright (c) 2003, 2004 Optus Internet Engineering
// Copyright (c) 2002 FireBrick (Andrews & Arnold Ltd / Watchfront Ltd) - GPL licenced
// vim: sw=8 ts=8

// FIXME immediately clear tunnels with vlan set when last session closes
// FIXME make outgoing packets work from PPPoE

char const *cvs_id_l2tpns = "$Id: l2tpns.c,v 1.28.2.3 2004-10-05 04:56:25 fred_nerk Exp $";

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#define SYSLOG_NAMES
#include <syslog.h>
#include <netinet/ether.h>
#include <malloc.h>
#include <math.h>
#include <net/route.h>
#include <sys/mman.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <linux/if.h>
#include <stddef.h>
#include <time.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <libcli.h>

#include "md5.h"
#include "l2tpns.h"
#include "cluster.h"
#include "plugin.h"
#include "ll.h"
#include "constants.h"
#include "control.h"
#include "util.h"
#include "tbf.h"

// Globals
struct configt *config = NULL;	// all configuration
int tunfd = -1;			// tun interface file handle. (network device)
int pcapfd = 0;			// tap interface file handle. (network device)
int udpfd = -1;			// UDP file handle
int controlfd = -1;		// Control signal handle
int snoopfd = -1;		// UDP file handle for sending out intercept data
int *radfds = NULL;		// RADIUS requests file handles
int ifrfd = -1;			// File descriptor for routing, etc
time_t basetime = 0;		// base clock
char *hostname = NULL;		// us.
int tunidx;			// ifr_ifindex of tun device
u32 sessionid = 0;		// session id for radius accounting
int syslog_log = 0;		// are we logging to syslog
FILE *log_stream = NULL;	// file handle for direct logging (i.e. direct into file, not via syslog).
extern int cluster_sockfd;	// Intra-cluster communications socket.
u32 last_id = 0;		// Last used PPP SID. Can I kill this?? -- mo
int clifd = 0;			// Socket listening for CLI connections.
tunnelidt vlan_tunnel_map[4096] = {0}; // Array of vlan -> tunnel id mappings
char *config_filename = CONFIGFILE;
char *ip_pool_file = IPPOOLFILE;

struct cli_session_actions *cli_session_actions = NULL;	// Pending session changes requested by CLI
struct cli_tunnel_actions *cli_tunnel_actions = NULL;	// Pending tunnel changes required by CLI

static void *ip_hash[256];	// Mapping from IP address to session structures.

u32 udp_tx = 0, udp_rx = 0, udp_rx_pkt = 0;	// Global traffic counters.
u32 eth_tx = 0, eth_rx = 0, eth_rx_pkt = 0;
u32 ip_pool_size = 1;		// Size of the pool of addresses used for dynamic address allocation.
time_t time_now = 0;		// Current time in seconds since epoch.
char time_now_string[64] = {0};	// Current time as a string.
char main_quit = 0;		// True if we're in the process of exiting.
char *_program_name = NULL;
linked_list *loaded_plugins;
linked_list *plugins[MAX_PLUGIN_TYPES];

#ifdef BGP
#include "bgp.h"
struct bgp_peer *bgp_peers = 0;
struct bgp_route_list *bgp_routes = 0;
int bgp_configured = 0;
#endif /* BGP */

#define membersize(STRUCT, MEMBER) sizeof(((STRUCT *)0)->MEMBER)
#define CONFIG(NAME, MEMBER, TYPE) { NAME, offsetof(struct configt, MEMBER), membersize(struct configt, MEMBER), TYPE }

struct config_descriptt config_values[] = {
	CONFIG("debug", debug, INT),
	CONFIG("log_file", log_filename, STRING),
	CONFIG("pid_file", pid_file, STRING),
	CONFIG("hostname", hostname, STRING),
	CONFIG("l2tp_secret", l2tpsecret, STRING),
	CONFIG("primary_dns", default_dns1, IP),
	CONFIG("secondary_dns", default_dns2, IP),
	CONFIG("save_state", save_state, BOOL),
	CONFIG("primary_radius", radiusserver[0], IP),
	CONFIG("secondary_radius", radiusserver[1], IP),
	CONFIG("primary_radius_port",radiusport[0], SHORT),
	CONFIG("secondary_radius_port",radiusport[1], SHORT),
	CONFIG("radius_accounting", radius_accounting, BOOL),
	CONFIG("radius_secret", radiussecret, STRING),
	CONFIG("bind_address", bind_address, IP),
	CONFIG("send_garp", send_garp, BOOL),
	CONFIG("throttle_speed", rl_rate, UNSIGNED_LONG),
	CONFIG("accounting_dir", accounting_dir, STRING),
	CONFIG("setuid", target_uid, INT),
	CONFIG("dump_speed", dump_speed, BOOL),
	CONFIG("cleanup_interval", cleanup_interval, INT),
	CONFIG("multi_read_count", multi_read_count, INT),
	CONFIG("scheduler_fifo", scheduler_fifo, BOOL),
	CONFIG("lock_pages", lock_pages, BOOL),
	CONFIG("icmp_rate", icmp_rate, INT),
	CONFIG("cluster_address", cluster_address, IP),
	CONFIG("cluster_interface", cluster_interface, STRING),
	CONFIG("cluster_hb_interval", cluster_hb_interval, INT),
	CONFIG("cluster_hb_timeout", cluster_hb_timeout, INT),
#ifdef BGP
	CONFIG("as_number", as_number, SHORT),
	CONFIG("bgp_peer1", bgp_peer[0], STRING),
	CONFIG("bgp_peer1_as", bgp_peer_as[0], SHORT),
	CONFIG("bgp_peer2", bgp_peer[1], STRING),
	CONFIG("bgp_peer2_as", bgp_peer_as[1], SHORT),
#endif /* BGP */
	CONFIG("mac_address", mac_address, MAC),
	CONFIG("pppoe_interface", pppoe_interface, STRING),
	{ NULL, 0, 0, 0 },
};

char *plugin_functions[] = {
	NULL,
	"plugin_pre_auth",
	"plugin_post_auth",
	"plugin_packet_rx",
	"plugin_packet_tx",
	"plugin_timer",
	"plugin_new_session",
	"plugin_kill_session",
	"plugin_control",
	"plugin_radius_response",
	"plugin_become_master",
	"plugin_new_session_master",
};

#define max_plugin_functions (sizeof(plugin_functions) / sizeof(char *))

tunnelt *tunnel = NULL;			// Array of tunnel structures.
sessiont *session = NULL;		// Array of session structures.
sessioncountt *sess_count = NULL;	// Array of partial per-session traffic counters.
radiust *radius = NULL;			// Array of radius structures.
ippoolt *ip_address_pool = NULL;	// Array of dynamic IP addresses.
controlt *controlfree = 0;
struct Tstats *_statistics = NULL;
#ifdef RINGBUFFER
struct Tringbuffer *ringbuffer = NULL;
#endif

void sigalrm_handler(int);
void sighup_handler(int);
void sigterm_handler(int);
void sigquit_handler(int);
void sigchild_handler(int);
void read_config_file();
void read_state();
void dump_state();
void tunnel_clean();
tunnelidt new_tunnel();
void update_config();
int unhide_avp(u8 *avp, tunnelidt t, sessionidt s, u16 length);
sessionidt new_session(tunnelidt t);
tunnelidt vlan_to_tunnel(u16 vlan);

static void cache_ipmap(ipt ip, int s);
static void uncache_ipmap(ipt ip);

// return internal time (10ths since process startup)
clockt now(void)
{
	struct timeval t;
	gettimeofday(&t, 0);
	return (t.tv_sec - basetime) * 10 + t.tv_usec / 100000 + 1;
}

// work out a retry time based on try number
// This is a straight bounded exponential backoff.
// Maximum re-try time is 32 seconds. (2^5).
clockt backoff(u8 try)
{
	if (try > 5) try = 5;                  // max backoff
	return now() + 10 * (1 << try);
}


//
// Log a debug message.
//
void _log(int level, ipt address, sessionidt s, tunnelidt t, const char *format, ...)
{
	static char message[65536] = {0};
	static char message2[65536] = {0};
	va_list ap;

#ifdef RINGBUFFER
	if (ringbuffer)
	{
		if (++ringbuffer->tail >= RINGBUFFER_SIZE)
			ringbuffer->tail = 0;
		if (ringbuffer->tail == ringbuffer->head)
			if (++ringbuffer->head >= RINGBUFFER_SIZE)
				ringbuffer->head = 0;

		ringbuffer->buffer[ringbuffer->tail].level = level;
		ringbuffer->buffer[ringbuffer->tail].address = address;
		ringbuffer->buffer[ringbuffer->tail].session = s;
		ringbuffer->buffer[ringbuffer->tail].tunnel = t;
		va_start(ap, format);
		vsnprintf(ringbuffer->buffer[ringbuffer->tail].message, 4095, format, ap);
		va_end(ap);
	}
#endif

	if (config->debug < level) return;

	va_start(ap, format);
	if (log_stream)
	{
		vsnprintf(message2, 65535, format, ap);
		snprintf(message, 65535, "%s %02d/%02d %s", time_now_string, t, s, message2);
		fprintf(log_stream, "%s", message);
	}
	else if (syslog_log)
	{
		vsnprintf(message2, 65535, format, ap);
		snprintf(message, 65535, "%02d/%02d %s", t, s, message2);
		syslog(level + 2, message); // We don't need LOG_EMERG or LOG_ALERT
	}
	va_end(ap);
}

void _log_hex(int level, ipt address, sessionidt s, tunnelidt t, const char *title, const char *data, int maxsize)
{
	int i, j;
	const u8 *d = (const u8 *)data;

	if (config->debug < level) return;

	// No support for log_hex to syslog
	if (log_stream)
	{
		log(level, address, s, t, "%s (%d bytes):\n", title, maxsize);
		setvbuf(log_stream, NULL, _IOFBF, 16384);

		for (i = 0; i < maxsize; )
		{
			fprintf(log_stream, "%4X: ", i);
			for (j = i; j < maxsize && j < (i + 16); j++)
			{
				fprintf(log_stream, "%02X ", d[j]);
				if (j == i + 7)
					fputs(": ", log_stream);
			}

			for (; j < i + 16; j++)
			{
				fputs("   ", log_stream);
				if (j == i + 7)
					fputs(": ", log_stream);
			}

			fputs("  ", log_stream);
			for (j = i; j < maxsize && j < (i + 16); j++)
			{
				if (d[j] >= 0x20 && d[j] < 0x7f && d[j] != 0x20)
					fputc(d[j], log_stream);
				else
					fputc('.', log_stream);

				if (j == i + 7)
					fputs("  ", log_stream);
			}

			i = j;
			fputs("\n", log_stream);
		}

		fflush(log_stream);
		setbuf(log_stream, NULL);
	}
}


// Add a route
//
// This adds it to the routing table, advertises it
// via iBGP if enabled, and stuffs it into the
// 'sessionbyip' cache.
//
// 'ip' and 'mask' must be in _host_ order.
//
void routeset(sessionidt s, ipt ip, ipt mask, ipt gw, u8 add)
{
	struct rtentry r;
	int i;

	if (!mask) mask = 0xffffffff;

	ip &= mask;		// Force the ip to be the first one in the route.

	memset(&r, 0, sizeof(r));
	r.rt_dev = config->tundevice;
	r.rt_dst.sa_family = AF_INET;
	*(u32 *) & (((struct sockaddr_in *) &r.rt_dst)->sin_addr.s_addr) = htonl(ip);
	r.rt_gateway.sa_family = AF_INET;
	*(u32 *) & (((struct sockaddr_in *) &r.rt_gateway)->sin_addr.s_addr) = htonl(gw);
	r.rt_genmask.sa_family = AF_INET;
	*(u32 *) & (((struct sockaddr_in *) &r.rt_genmask)->sin_addr.s_addr) = htonl(mask);
	r.rt_flags = (RTF_UP | RTF_STATIC);
	if (gw)
		r.rt_flags |= RTF_GATEWAY;
	else if (mask == 0xffffffff)
		r.rt_flags |= RTF_HOST;

	log(1, ip, 0, 0, "Route %s %u.%u.%u.%u/%u.%u.%u.%u %u.%u.%u.%u\n",
	    add ? "add" : "del",
	    ip   >> 24, ip   >> 16 & 0xff, ip   >> 8 & 0xff, ip   & 0xff,
	    mask >> 24, mask >> 16 & 0xff, mask >> 8 & 0xff, mask & 0xff,
	    gw   >> 24, gw   >> 16 & 0xff, gw   >> 8 & 0xff, gw   & 0xff);

	if (ioctl(ifrfd, add ? SIOCADDRT : SIOCDELRT, (void *) &r) < 0)
		log(0, 0, 0, 0, "routeset() error in ioctl: %s\n", strerror(errno));

#ifdef BGP
	if (add)
		bgp_add_route(htonl(ip), htonl(mask));
	else
		bgp_del_route(htonl(ip), htonl(mask));
#endif /* BGP */

		// Add/Remove the IPs to the 'sessionbyip' cache.
		// Note that we add the zero address in the case of 
		// a network route. Roll on CIDR.

		// Note that 's == 0' implies this is the address pool.
		// We still cache it here, because it will pre-fill
		// the malloc'ed tree.

	if (s)
	{
		if (!add)	// Are we deleting a route?
			s = 0;	// Caching the session as '0' is the same as uncaching.

		for (i = ip; (i&mask) == (ip&mask) ; ++i)
			cache_ipmap(i, s);
	}
}

//
// Set up TUN interface
void inittun(void)
{
	struct ifreq ifr;
	struct sockaddr_in sin = {0};
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;

	tunfd = open(TUNDEVICE, O_RDWR);
	if (tunfd < 0)
	{                          // fatal
		log(0, 0, 0, 0, "Can't open %s: %s\n", TUNDEVICE, strerror(errno));
		exit(1);
	}
	{
		int flags = fcntl(tunfd, F_GETFL, 0);
		fcntl(tunfd, F_SETFL, flags | O_NONBLOCK);
	}
	if (ioctl(tunfd, TUNSETIFF, (void *) &ifr) < 0)
	{
		log(0, 0, 0, 0, "Can't set tun interface: %s\n", strerror(errno));
		exit(1);
	}
	assert(strlen(ifr.ifr_name) < sizeof(config->tundevice));
	strncpy(config->tundevice, ifr.ifr_name, sizeof(config->tundevice) - 1);
	ifrfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = config->bind_address ? config->bind_address : 0x01010101; // 1.1.1.1
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));

	if (ioctl(ifrfd, SIOCSIFADDR, (void *) &ifr) < 0)
	{
		log(0, 0, 0, 0, "Error setting tun address: %s\n", strerror(errno));
		exit(1);
	}
	/* Bump up the qlen to deal with bursts from the network */
	ifr.ifr_qlen = 1000;
	if (ioctl(ifrfd, SIOCSIFTXQLEN, (void *) &ifr) < 0)
	{
		log(0, 0, 0, 0, "Error setting tun queue length: %s\n", strerror(errno));
		exit(1);
	}
	ifr.ifr_flags = IFF_UP;
	if (ioctl(ifrfd, SIOCSIFFLAGS, (void *) &ifr) < 0)
	{
		log(0, 0, 0, 0, "Error setting tun flags: %s\n", strerror(errno));
		exit(1);
	}
	if (ioctl(ifrfd, SIOCGIFINDEX, (void *) &ifr) < 0)
	{
		log(0, 0, 0, 0, "Error setting tun ifindex: %s\n", strerror(errno));
		exit(1);
	}
	tunidx = ifr.ifr_ifindex;
}

// Set up Ethernet interface
void initpcap(void)
{
	int fd;
	int ifindex;
	struct ifreq ifr;
	struct sockaddr_ll sll;

	if (!*config->pppoe_interface) return;

	fd = socket(PF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, config->pppoe_interface, sizeof(ifr.ifr_name) - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
	{
		log(0, 0, 0, 0, "Error getting %s hardware address: %s\n", config->pppoe_interface, strerror(errno));
		exit(-1);
	}
	printf("Hardware address is %s\n", ether_ntoa((struct ether_addr *)&ifr.ifr_hwaddr.sa_data));

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
	{
		log(0, 0, 0, 0, "Error getting %s index: %s\n", config->pppoe_interface, strerror(errno));
		exit(-1);
	}
	ifindex = ifr.ifr_ifindex;

        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);

	if ((pcapfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) <= 0)
	{
		log(0, 0, 0, 0, "Error creating %s socket: %s\n", config->pppoe_interface, strerror(errno));
		exit(-1);
	}

	{
		int flags = fcntl(pcapfd, F_GETFL, 0);
		fcntl(pcapfd, F_SETFL, flags | O_NONBLOCK);
	}

        if (bind(pcapfd, (struct sockaddr *)&sll, sizeof(sll)) == -1)
	{
		log(0, 0, 0, 0, "Error binding socket to %s: %s\n", config->pppoe_interface, strerror(errno));
                exit(-1);
        }

	/*
	log(2, 0, 0, 0, "Setting hardware address of %s to %s\n", ifr.ifr_name, ether_ntoa(&config->mac_address));

	memcpy(&ifr.ifr_hwaddr.sa_data, &config->mac_address, 6);
	if (ioctl(fd, SIOCSIFHWADDR, &ifr) < 0)
	{
		log(0, 0, 0, 0, "Error setting %s hardware address: %s\n", config->pppoe_interface, strerror(errno));
		exit(-1);
	}
	*/

	ifr.ifr_mtu = 1540;
	if (ioctl(fd, SIOCSIFMTU, &ifr) < 0)
	{
		log(0, 0, 0, 0, "Error setting %s MTU to %d: %s\n", config->pppoe_interface, ifr.ifr_mtu, strerror(errno));
	}

	// Bring interface up
	ifr.ifr_flags = IFF_UP | IFF_PROMISC;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
	{
		log(0, 0, 0, 0, "Error setting %s flags: %s\n", config->pppoe_interface, strerror(errno));
		exit( -1);
	}
}

// set up UDP port
void initudp(void)
{
	int on = 1;
	struct sockaddr_in addr;

	// Tunnel
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(L2TPPORT);
	addr.sin_addr.s_addr = config->bind_address;
	udpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	setsockopt(udpfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	{
		int flags = fcntl(udpfd, F_GETFL, 0);
		fcntl(udpfd, F_SETFL, flags | O_NONBLOCK);
	}
	if (bind(udpfd, (void *) &addr, sizeof(addr)) < 0)
	{
		log(0, 0, 0, 0, "Error in UDP bind: %s\n", strerror(errno));
		exit(1);
	}
	snoopfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	// Control
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(1702);
	controlfd = socket(AF_INET, SOCK_DGRAM, 17);
	setsockopt(controlfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (bind(controlfd, (void *) &addr, sizeof(addr)) < 0)
	{
		log(0, 0, 0, 0, "Error in control bind: %s\n", strerror(errno));
		exit(1);
	}
}

//
// Find session by IP, < 1 for not found
//
// Confusingly enough, this 'ip' must be
// in _network_ order. This being the common
// case when looking it up from IP packet headers.
//
// We actually use this cache for two things.
// #1. For used IP addresses, this maps to the
// session ID that it's used by.
// #2. For un-used IP addresses, this maps to the
// index into the pool table that contains that
// IP address.
//

int lookup_ipmap(ipt ip)
{
	u8 *a = (u8 *)&ip;
	char **d = (char **) ip_hash;
	int s;

	if (!(d = (char **) d[(size_t) *a++])) return 0;
	if (!(d = (char **) d[(size_t) *a++])) return 0;
	if (!(d = (char **) d[(size_t) *a++])) return 0;

	s = (ipt) d[(size_t) *a];
	return s;
}

sessionidt sessionbyip(ipt ip)
{
	int s = lookup_ipmap(ip);
	CSTAT(call_sessionbyip);

	if (s > 0 && s < MAXSESSION && session[s].tunnel)
		return s;
	return 0;
}

//
// Take an IP address in HOST byte order and
// add it to the sessionid by IP cache.
//
// (It's actually cached in network order)
//
static void cache_ipmap(ipt ip, int s)
{
	ipt nip = htonl(ip);		// MUST be in network order. I.e. MSB must in be ((char*)(&ip))[0]
	u8 *a = (u8 *) &nip;
	char **d = (char **) ip_hash;
	int i;

	for (i = 0; i < 3; i++)
	{
		if (!d[(size_t) a[i]])
		{
			if (!(d[(size_t) a[i]] = calloc(256, sizeof (void *))))
				return;
		}

		d = (char **) d[(size_t) a[i]];
	}

	d[(size_t) a[3]] = (char *)((int)s);

	if (s > 0)
		log(4, ip, s, session[s].tunnel, "Caching ip address %s\n", inet_toa(nip));
	else if (s == 0)
		log(4, ip, 0, 0, "Un-caching ip address %s\n", inet_toa(nip));
	// else a map to an ip pool index.
}

static void uncache_ipmap(ipt ip)
{
	cache_ipmap(ip, 0);	// Assign it to the NULL session.
}

//
// CLI list to dump current ipcache.
//
int cmd_show_ipcache(struct cli_def *cli, char *command, char **argv, int argc)
{
	char **d = (char **) ip_hash, **e, **f, **g;
	int i, j, k, l;
	int count = 0;

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_print(cli, "%7s %s", "Sess#", "IP Address");

	for (i = 0; i < 256; ++i)
	{
		if (!d[i])
			continue;
		e = (char**) d[i];
		for (j = 0; j < 256; ++j)
		{
			if (!e[j])
				continue;
			f = (char**) e[j];
			for (k = 0; k < 256; ++k)
			{
				if (!f[k])
					continue;
				g = (char**)f[k];
				for (l = 0; l < 256; ++l)
				{
					if (!g[l])
						continue;
					cli_print(cli, "%7d %d.%d.%d.%d", (int) g[l], i, j, k, l);
					++count;
				}
			}
		}
	}
	cli_print(cli, "%d entries in cache", count);
	return CLI_OK;
}


// Find session by username, 0 for not found
// walled garden users aren't authenticated, so the username is
// reasonably useless. Ignore them to avoid incorrect actions
//
// This is VERY inefficent. Don't call it often. :)
//
sessionidt sessionbyuser(char *username)
{
	int s;
	CSTAT(call_sessionbyuser);

	for (s = 1; s < MAXSESSION ; ++s)
	{
		if (session[s].walled_garden)
			continue;		// Skip walled garden users.

		if (!strncmp(session[s].user, username, 128))
			return s;

	}
	return 0;	// Not found.
}

void send_garp(ipt ip)
{
	int s;
	struct ifreq ifr;
	u8 mac[6];

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
	{
		log(0, 0, 0, 0, "Error creating socket for GARP: %s\n", strerror(errno));
		return;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "eth0", sizeof(ifr.ifr_name) - 1);
	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
	{
		log(0, 0, 0, 0, "Error getting eth0 hardware address for GARP: %s\n", strerror(errno));
		close(s);
		return;
	}
	memcpy(mac, &ifr.ifr_hwaddr.sa_data, 6*sizeof(char));
	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
	{
		log(0, 0, 0, 0, "Error getting eth0 interface index for GARP: %s\n", strerror(errno));
		close(s);
		return;
	}
	close(s);
	sendarp(ifr.ifr_ifindex, mac, ip);
}

// Find session by username, 0 for not found
sessiont *sessiontbysessionidt(sessionidt s)
{
	if (!s || s > MAXSESSION) return NULL;
	return &session[s];
}

sessionidt sessionidtbysessiont(sessiont *s)
{
	sessionidt val = s-session;
	if (s < session || val > MAXSESSION) return 0;
	return val;
}

// send a packet for a PPPoE user
void pppoesend(u8 *buf, u16 l, sessionidt s)
{
	tunnelidt t;
	char *rp, *ud;
	static char *response = NULL;

	if (!(t = session[s].tunnel))
	{
		log(0, 0, s, t, "pppoesend() called with session %d which has no tunnel\n", s);
		return;
	}

	log(4, 0, s, t, "pppoesend(%p, %u, %d)\n", buf, l, s);

	if (!response)
		response = (char *)malloc(1600);

	buf += 8;
	l -= 8;

	memcpy(response, &session[s].client_mac, 6);
	memcpy(response + 6, &config->mac_address, 6);

	if (tunnel[t].vlan > 1)
	{
		log(4, 0, s, t, "Sending a vlan packet\n");
		*(u16 *)(response + 12) = htons(ETH_P_8021Q);
		*(u16 *)(response + 14) = htons(tunnel[t].vlan) & htons(0xFFF);// VLAN ID
		*(u16 *)(response + 16) = htons(ETH_P_PPP_SES);
		*(u8 *)(response + 18) = 0x11;				// PPPoE ver 1 type 1
		*(u8 *)(response + 19) = 0;				// code
		rp = (response + 19);
		ud = (response + 24);
	}
	else
	{
		log(4, 0, s, t, "Sending a non-vlan packet\n");
		*(u16 *)(response + 12) = htons(ETH_P_PPP_SES);
		*(u8 *)(response + 14) = 0x11;				// PPPoE ver 1 type 1
		*(u8 *)(response + 15) = 0;				// code
		rp = (response + 15);
		ud = (response + 20);					// data starts here
	}
	*(u16 *)(rp + 1) = htons(s);
	memcpy(ud, buf, l);
	ud += l;
	*(u16 *)(rp + 3) = htons(l);
	log_hex(5, "Sending PPPoE packet", response, ud - response);
	if (write(pcapfd, response, ud - response) <= 0)
		log(0, 0, s, t, "Error writing %d bytes to pcapfd: %s\n", ud-response, strerror(errno));
	return;
}

// actually send a control message for a specific tunnel
void tunnelsend(u8 * buf, u16 l, tunnelidt t)
{
	struct sockaddr_in addr;

	CSTAT(call_tunnelsend);

	if (!t)
	{
		static int backtrace_count = 0;
		log(0, 0, 0, t, "tunnelsend called with 0 as tunnel id\n");
		STAT(tunnel_tx_errors);
		log_backtrace(backtrace_count, 5)
		return;
	}

	if (!tunnel[t].ip)
	{
		static int backtrace_count = 0;
		log(1, 0, 0, t, "Error sending data out tunnel: no remote endpoint (tunnel not set up)\n");
		log_backtrace(backtrace_count, 5)
		STAT(tunnel_tx_errors);
		return;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	*(u32 *) & addr.sin_addr = htonl(tunnel[t].ip);
	addr.sin_port = htons(tunnel[t].port);

	// sequence expected, if sequence in message
	if (*buf & 0x08) *(u16 *) (buf + ((*buf & 0x40) ? 10 : 8)) = htons(tunnel[t].nr);

	// If this is a control message, deal with retries
	if (*buf & 0x80)
	{
		tunnel[t].last = time_now; // control message sent
		tunnel[t].retry = backoff(tunnel[t].try); // when to resend
		if (tunnel[t].try > 1)
		{
			STAT(tunnel_retries);
			log(3, tunnel[t].ip, 0, t, "Control message resend try %d\n", tunnel[t].try);
		}
	}

	if (sendto(udpfd, buf, l, 0, (void *) &addr, sizeof(addr)) < 0)
	{
		log(0, tunnel[t].ip, ntohs((*(u16 *) (buf + 6))), t, "Error sending data out tunnel: %s (udpfd=%d, buf=%p, len=%d, dest=%s)\n",
				strerror(errno), udpfd, buf, l, inet_ntoa(addr.sin_addr));
		STAT(tunnel_tx_errors);
		return;
	}

	log_hex(5, "Send Tunnel Data", buf, l);
	STAT(tunnel_tx_packets);
	INC_STAT(tunnel_tx_bytes, l);
}

void returnpacket(u8 *buf, u16 l, sessionidt s, tunnelidt t)
{
	if (tunnel[t].vlan)
		pppoesend(buf, l + 1, s);
	else
		tunnelsend(buf, l, t);
}

//
// Tiny helper function to write data to
// the 'tun' device.
//
int tun_write(u8 * data, int size)
{
	return write(tunfd, data, size);
}

// process outgoing (to user) IP
//
void processipout(u8 * buf, int len)
{
	sessionidt s;
	sessiont *sp;
	tunnelidt t;
	ipt ip;

	char * data = buf;	// Keep a copy of the originals.
	int size = len;

	u8 b[MAXETHER + 20];

	CSTAT(call_processipout);

	if (len < MIN_IP_SIZE)
	{
		log(1, 0, 0, 0, "Short IP, %d bytes\n", len);
		STAT(tunnel_tx_errors);
		return;
	}
	if (len >= MAXETHER)
	{
		log(1, 0, 0, 0, "Oversize IP packet %d bytes\n", len);
		STAT(tunnel_tx_errors);
		return;
	}

	// Skip the tun header
	buf += 4;
	len -= 4;

	// Got an IP header now
	if (*(u8 *)(buf) >> 4 != 4)
	{
		log(1, 0, 0, 0, "IP: Don't understand anything except IPv4\n");
		return;
	}

	ip = *(u32 *)(buf + 16);
	if (!(s = sessionbyip(ip)))
	{
		// Is this a packet for a session that doesn't exist?
		static int rate = 0;	// Number of ICMP packets we've sent this second.
		static int last = 0;	// Last time we reset the ICMP packet counter 'rate'.

		if (last != time_now)
		{
			last = time_now;
			rate = 0;
		}

		if (rate++ < config->icmp_rate) // Only send a max of icmp_rate per second.
		{
			log(4, 0, 0, 0, "IP: Sending ICMP host unreachable to %s\n", inet_toa(*(u32 *)(buf + 12)));
			host_unreachable(*(u32 *)(buf + 12), *(u16 *)(buf + 4), ip, buf, (len < 64) ? 64 : len);
		}
		return;
	}
	t = session[s].tunnel;
	sp = &session[s];

	if (sp->tbf_out)
	{
		// Are we throttling this session?
		if (config->cluster_iam_master)
			tbf_queue_packet(sp->tbf_out, data, size);
		else
			master_throttle_packet(sp->tbf_out, data, size);
		return;
	}
	else if (sp->walled_garden && !config->cluster_iam_master)
	{
		// We are walled-gardening this
		master_garden_packet(s, data, size);
		return;
	}

	// Snooping this session, send it to intercept box
	if (sp->snoop_ip && sp->snoop_port)
		snoop_send_packet(buf, len, sp->snoop_ip, sp->snoop_port);

	if (0 && session[s].flags & SESSIONPPPOE)
	{
		log(5, session[s].ip, s, t, "Ethernet -> PPPoE (%d bytes)\n", len);

		// FIXME add on PPPoE header and write to pcapfd
	}
	else
	{
		// Add on L2TP header
		u8 *p = makeppp(b, sizeof(b), buf, len, t, s, PPPIP);
		log(5, session[s].ip, s, t, "Ethernet -> Tunnel (%d bytes)\n", len);

		if (!p)
		{
			log(3, session[s].ip, s, t, "failed to send packet in processipout.\n");
			return;
		}
		returnpacket(b, len + (p-b), s, t); // send it...
	}

	sp->cout += len; // byte count
	sp->total_cout += len; // byte count
	sp->pout++;
	udp_tx += len;
	sess_count[s].cout += len;	// To send to master..
}

//
// Helper routine for the TBF filters.
// Used to send queued data in to the user!
//
void send_ipout(sessionidt s, u8 *buf, int len)
{
	sessiont *sp;
	tunnelidt t;
	ipt ip;

	u8 b[MAXETHER + 20];

	if (len < 0 || len > MAXETHER)
	{
		log(1,0,0,0, "Odd size IP packet: %d bytes\n", len);
		return;
	}

	// Skip the tun header
	buf += 4;
	len -= 4;

	ip = *(u32 *)(buf + 16);

	if (!session[s].ip)
		return;
	t = session[s].tunnel;
	sp = &session[s];

	log(5, session[s].ip, s, t, "Ethernet -> Tunnel (%d bytes)\n", len);

	// Snooping this session.
	if (sp->snoop_ip && sp->snoop_port)
		snoop_send_packet(buf, len, sp->snoop_ip, sp->snoop_port);

	// Add on L2TP header
	{
		u8 *p = makeppp(b, sizeof(b),  buf, len, t, s, PPPIP);
		if (!p)
		{
			log(3, session[s].ip, s, t, "failed to send packet in send_ipout.\n");
			return;
		}
		returnpacket(b, len + (p-b), s, t); // send it...
	}
	sp->cout += len; // byte count
	sp->total_cout += len; // byte count
	sp->pout++;
	udp_tx += len;
	sess_count[s].cout += len;	// To send to master..
}

// add an AVP (16 bit)
void control16(controlt * c, u16 avp, u16 val, u8 m)
{
	u16 l = (m ? 0x8008 : 0x0008);
	*(u16 *) (c->buf + c->length + 0) = htons(l);
	*(u16 *) (c->buf + c->length + 2) = htons(0);
	*(u16 *) (c->buf + c->length + 4) = htons(avp);
	*(u16 *) (c->buf + c->length + 6) = htons(val);
	c->length += 8;
}

// add an AVP (32 bit)
void control32(controlt * c, u16 avp, u32 val, u8 m)
{
	u16 l = (m ? 0x800A : 0x000A);
	*(u16 *) (c->buf + c->length + 0) = htons(l);
	*(u16 *) (c->buf + c->length + 2) = htons(0);
	*(u16 *) (c->buf + c->length + 4) = htons(avp);
	*(u32 *) (c->buf + c->length + 6) = htonl(val);
	c->length += 10;
}

// add an AVP (32 bit)
void controls(controlt * c, u16 avp, char *val, u8 m)
{
	u16 l = ((m ? 0x8000 : 0) + strlen(val) + 6);
	*(u16 *) (c->buf + c->length + 0) = htons(l);
	*(u16 *) (c->buf + c->length + 2) = htons(0);
	*(u16 *) (c->buf + c->length + 4) = htons(avp);
	memcpy(c->buf + c->length + 6, val, strlen(val));
	c->length += 6 + strlen(val);
}

// add a binary AVP
void controlb(controlt * c, u16 avp, char *val, unsigned int len, u8 m)
{
	u16 l = ((m ? 0x8000 : 0) + len + 6);
	*(u16 *) (c->buf + c->length + 0) = htons(l);
	*(u16 *) (c->buf + c->length + 2) = htons(0);
	*(u16 *) (c->buf + c->length + 4) = htons(avp);
	memcpy(c->buf + c->length + 6, val, len);
	c->length += 6 + len;
}

// new control connection
controlt *controlnew(u16 mtype)
{
	controlt *c;
	if (!controlfree)
		c = malloc(sizeof(controlt));
	else
	{
		c = controlfree;
		controlfree = c->next;
	}
	assert(c);
	c->next = 0;
	*(u16 *) (c->buf + 0) = htons(0xC802); // flags/ver
	c->length = 12;
	control16(c, 0, mtype, 1);
	return c;
}

// send zero block if nothing is waiting
// (ZLB send).
void controlnull(tunnelidt t)
{
	u8 buf[12];
	if (tunnel[t].controlc)	// Messages queued; They will carry the ack.
		return;

	*(u16 *) (buf + 0) = htons(0xC802); // flags/ver
	*(u16 *) (buf + 2) = htons(12); // length
	*(u16 *) (buf + 4) = htons(tunnel[t].far); // tunnel
	*(u16 *) (buf + 6) = htons(0); // session
	*(u16 *) (buf + 8) = htons(tunnel[t].ns); // sequence
	*(u16 *) (buf + 10) = htons(tunnel[t].nr); // sequence
	tunnelsend(buf, 12, t);
}

// add a control message to a tunnel, and send if within window
void controladd(controlt * c, tunnelidt t, sessionidt s)
{
	*(u16 *) (c->buf + 2) = htons(c->length); // length
	*(u16 *) (c->buf + 4) = htons(tunnel[t].far); // tunnel
	*(u16 *) (c->buf + 6) = htons(s ? session[s].far : 0); // session
	*(u16 *) (c->buf + 8) = htons(tunnel[t].ns); // sequence
	tunnel[t].ns++;              // advance sequence
	// link in message in to queue
	if (tunnel[t].controlc)
		tunnel[t].controle->next = c;
	else
		tunnel[t].controls = c;
	tunnel[t].controle = c;
	tunnel[t].controlc++;
	// send now if space in window
	if (tunnel[t].controlc <= tunnel[t].window)
	{
		tunnel[t].try = 0;      // first send
		tunnelsend(c->buf, c->length, t);
	}
}

//
// Throttle or Unthrottle a session
//
// Throttle the data folling through a session
// to be no more than 'throttle' kbit/sec each way.
//
int throttle_session(sessionidt s, int throttle)
{
	if (!session[s].tunnel)
		return 0;	// No-one home.

	if (!*session[s].user)
	        return 0; // User not logged in

	if (throttle)
	{
		int rate_in = throttle & 0x0000FFFF;
		int rate_out = throttle >> 16;

		if (session[s].tbf_in || session[s].tbf_out)
		{
			if (throttle == session[s].throttle)
				return 1;

			// Currently throttled but the rate is changing.

			free_tbf(session[s].tbf_in);
			free_tbf(session[s].tbf_out);
		}

		if (rate_in) session[s].tbf_in = new_tbf(s, rate_in * 1024 / 4, rate_in * 1024 / 8, send_ipin);
		if (rate_out) session[s].tbf_out = new_tbf(s, rate_out * 1024 / 4, rate_out * 1024 / 8, send_ipout);

		if (throttle != session[s].throttle)
		{
			// Changed. Flood to slaves.
			session[s].throttle = throttle;
			cluster_send_session(s);
		}

		return 1;
	}

	// else Unthrottling.

	if (!session[s].tbf_in && !session[s].tbf_out && !session[s].throttle)
		return 0;

	free_tbf(session[s].tbf_in);
	session[s].tbf_in = 0;

	free_tbf(session[s].tbf_out);
	session[s].tbf_out = 0;

	if (throttle != session[s].throttle)
	{
		// Changed. Flood to slaves.
		session[s].throttle = throttle;
		cluster_send_session(s);
	}

	return 0;
}

// start tidy shutdown of session
void sessionshutdown(sessionidt s, char *reason)
{
	int dead = session[s].die;
	int walled_garden = session[s].walled_garden;

	CSTAT(call_sessionshutdown);

	if (!session[s].tunnel)
	{
		log(3, session[s].ip, s, session[s].tunnel, "Called sessionshutdown on a session with no tunnel.\n");
		return;                   // not a live session
	}

	if (!dead)
		log(2, 0, s, session[s].tunnel, "Shutting down session %d: %s\n", s, reason);

	session[s].die = now() + 150; // Clean up in 15 seconds

	{
		struct param_kill_session data = { &tunnel[session[s].tunnel], &session[s] };
		run_plugins(PLUGIN_KILL_SESSION, &data);
	}

	// RADIUS Stop message
	if (session[s].opened && !walled_garden && !dead && *session[s].user)
	{
		u16 r = session[s].radius;
		if (!r)
		{
			if (!(r = radiusnew(s)))
			{
				log(1, 0, s, session[s].tunnel, "No free RADIUS sessions for Stop message\n");
				STAT(radius_overflow);
			}
			else
			{
				int n;
				for (n = 0; n < 15; n++)
					radius[r].auth[n] = rand();
			}
		}
		if (r && radius[r].state != RADIUSSTOP)
			radiussend(r, RADIUSSTOP); // stop, if not already trying
	}

	if (session[s].ip)
	{
		// IP allocated, clear and unroute
		int r;
		for (r = 0; r < MAXROUTE && session[s].route[r].ip; r++)
		{
			routeset(s, session[s].route[r].ip, session[s].route[r].mask, session[s].ip, 0);
			session[s].route[r].ip = 0;
		}

		if (session[s].ip_pool_index == -1) // static ip
		{
			routeset(s, session[s].ip, 0, 0, 0);	// Delete route.
			session[s].ip = 0;
		}
		else
			free_ip_address(s);

		if (session[s].throttle)	// Unthrottle if throttled.
			throttle_session(s, 0);
	}
	{
		// Send CDN
		controlt *c = controlnew(14); // sending CDN
		control16(c, 1, 3, 1);    // result code (admin reasons - TBA make error, general error, add message
		control16(c, 14, s, 1);   // assigned session (our end)
		controladd(c, session[s].tunnel, s); // send the message
	}
	cluster_send_session(s);
}

void sendipcp(tunnelidt t, sessionidt s)
{
	u8 buf[MAXCONTROL];
	u16 r = session[s].radius;
	u8 *q;

	CSTAT(call_sendipcp);

	if (!r)
		r = radiusnew(s);

	if (radius[r].state != RADIUSIPCP)
	{
		radius[r].state = RADIUSIPCP;
		radius[r].try = 0;
	}

	radius[r].retry = backoff(radius[r].try++);
	if (radius[r].try > 10)
	{
		radiusclear(r, s);	// Clear radius session.
		sessionshutdown(s, "No reply on IPCP");
		return;
	}

	q = makeppp(buf,sizeof(buf), 0, 0, t, s, PPPIPCP);
	if (!q)
	{
		log(3, session[s].ip, s, t, "failed to send packet in sendipcp.\n");
		return;
	}

	*q = ConfigReq;
	q[1] = r << RADIUS_SHIFT;                    // ID, dont care, we only send one type of request
	*(u16 *) (q + 2) = htons(10);
	q[4] = 3;
	q[5] = 6;
	*(u32 *) (q + 6) = config->bind_address ? config->bind_address : my_address; // send my IP
	returnpacket(buf, 10 + (q - buf), s, t); // send it
	session[s].flags &= ~SF_IPCP_ACKED;	// Clear flag.
}

// kill a session now
void sessionkill(sessionidt s, char *reason)
{

	CSTAT(call_sessionkill);

	session[s].die = now();
	sessionshutdown(s, reason);  // close radius/routes, etc.
	if (session[s].radius)
		radiusclear(session[s].radius, s); // cant send clean accounting data, session is killed

	log(2, 0, s, session[s].tunnel, "Kill session %d (%s): %s\n", s, session[s].user, reason);

	throttle_session(s, 0);		// Force session to be un-throttle. Free'ing TBF structures.

	memset(&session[s], 0, sizeof(session[s]));
	session[s].tunnel = T_FREE;	// Mark it as free.
	session[s].next = sessionfree;
	sessionfree = s;
	cli_session_actions[s].action = 0;
	cluster_send_session(s);
}

// kill a tunnel now
void tunnelkill(tunnelidt t, char *reason)
{
	sessionidt s;
	controlt *c;

	CSTAT(call_tunnelkill);

	tunnel[t].state = TUNNELDIE;

	// free control messages
	while ((c = tunnel[t].controls))
	{
		controlt * n = c->next;
		tunnel[t].controls = n;
		tunnel[t].controlc--;
		c->next = controlfree;
		controlfree = c;
	}
	// kill sessions
	for (s = 1; s < MAXSESSION; s++)
		if (session[s].tunnel == t)
			sessionkill(s, reason);

	// free tunnel
	tunnelclear(t);
	log(1, 0, 0, t, "Kill tunnel %d: %s\n", t, reason);
	cli_tunnel_actions[s].action = 0;
	cluster_send_tunnel(t);
}

// shut down a tunnel cleanly
void tunnelshutdown(tunnelidt t, char *reason)
{
	sessionidt s;

	CSTAT(call_tunnelshutdown);

	if (!tunnel[t].last || !tunnel[t].far || tunnel[t].state == TUNNELFREE)
	{
		// never set up, can immediately kill
		tunnelkill(t, reason);
		return;
	}
	log(1, 0, 0, t, "Shutting down tunnel %d (%s)\n", t, reason);

	// close session
	for (s = 1; s < MAXSESSION; s++)
		if (session[s].tunnel == t)
			sessionkill(s, reason);

	tunnel[t].state = TUNNELDIE;
	tunnel[t].die = now() + 700; // Clean up in 70 seconds
	cluster_send_tunnel(t);
	// TBA - should we wait for sessions to stop?
	{                            // Send StopCCN
		controlt *c = controlnew(4); // sending StopCCN
		control16(c, 1, 1, 1);    // result code (admin reasons - TBA make error, general error, add message
		control16(c, 9, t, 1);    // assigned tunnel (our end)
		controladd(c, t, 0);      // send the message
	}
}

// read and process packet on tunnel (UDP)
void processudp(u8 *buf, int len, struct sockaddr_in *addr)
{
	char *chapresponse = NULL;
	u16 l = len, t = 0, s = 0, ns = 0, nr = 0;
	u8 *p = buf + 2;


	CSTAT(call_processudp);

	udp_rx += len;
	udp_rx_pkt++;
	log_hex(5, "UDP Data", buf, len);
	STAT(tunnel_rx_packets);
	INC_STAT(tunnel_rx_bytes, len);
	if (len < 6)
	{
		log(1, ntohl(addr->sin_addr.s_addr), 0, 0, "Short UDP, %d bytes\n", len);
		STAT(tunnel_rx_errors);
		return;
	}
	if ((buf[1] & 0x0F) != 2)
	{
		log(1, ntohl(addr->sin_addr.s_addr), 0, 0, "Bad L2TP ver %d\n", (buf[1] & 0x0F) != 2);
		STAT(tunnel_rx_errors);
		return;
	}
	if (*buf & 0x40)
	{                          // length
		l = ntohs(*(u16 *) p);
		p += 2;
	}
	t = ntohs(*(u16 *) p);
	p += 2;
	s = ntohs(*(u16 *) p);
	p += 2;
	if (s >= MAXSESSION)
	{
		log(1, ntohl(addr->sin_addr.s_addr), s, t, "Received UDP packet with invalid session ID\n");
		STAT(tunnel_rx_errors);
		return;
	}
	if (t >= MAXTUNNEL)
	{
		log(1, ntohl(addr->sin_addr.s_addr), s, t, "Received UDP packet with invalid tunnel ID\n");
		STAT(tunnel_rx_errors);
		return;
	}
	if (*buf & 0x08)
	{                          // ns/nr
		ns = ntohs(*(u16 *) p);
		p += 2;
		nr = ntohs(*(u16 *) p);
		p += 2;
	}
	if (*buf & 0x02)
	{                          // offset
		u16 o = ntohs(*(u16 *) p);
		p += o + 2;
	}
	if ((p - buf) > l)
	{
		log(1, ntohl(addr->sin_addr.s_addr), s, t, "Bad length %d>%d\n", (p - buf), l);
		STAT(tunnel_rx_errors);
		return;
	}
	l -= (p - buf);
	if (*buf & 0x80)
	{                          // control
		u16 message = 0xFFFF; // message type
		u8 fatal = 0;
		u8 mandatorymessage = 0;
		u8 chap = 0;      // if CHAP being used
		u16 asession = 0;  // assigned session
		u32 amagic = 0;    // magic number
		u8 aflags = 0;    // flags from last LCF
		u16 version = 0x0100; // protocol version (we handle 0.0 as well and send that back just in case)
		int requestchap = 0;	// do we request PAP instead of original CHAP request?
		char called[MAXTEL] = ""; // called number
		char calling[MAXTEL] = ""; // calling number

		if (!config->cluster_iam_master)
		{
			master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port);
			return;
		}

		if ((*buf & 0xCA) != 0xC8)
		{
			log(1, ntohl(addr->sin_addr.s_addr), s, t, "Bad control header %02X\n", *buf);
			STAT(tunnel_rx_errors);
			return;
		}
		log(3, ntohl(addr->sin_addr.s_addr), s, t, "Control message (%d bytes): (unacked %d) l-ns %d l-nr %d r-ns %d r-nr %d\n",
				l, tunnel[t].controlc, tunnel[t].ns, tunnel[t].nr, ns, nr);
		// if no tunnel specified, assign one
		if (!t)
		{
			int i;

				//
				// Is this a duplicate of the first packet? (SCCRQ)
				//
			for (i = 1; i <= config->cluster_highest_tunnelid ; ++i)
			{
				if (tunnel[i].state != TUNNELOPENING ||
					tunnel[i].ip != ntohl(*(ipt *) & addr->sin_addr) ||
					tunnel[i].port != ntohs(addr->sin_port) )
					continue;
				t = i;
				break;
			}
		}

		if (!t)
		{
			if (!(t = new_tunnel()))
			{
				log(1, ntohl(addr->sin_addr.s_addr), 0, 0, "No more tunnels\n");
				STAT(tunnel_overflow);
				return;
			}
			tunnelclear(t);
			tunnel[t].ip = ntohl(*(ipt *) & addr->sin_addr);
			tunnel[t].port = ntohs(addr->sin_port);
			tunnel[t].window = 4; // default window
			log(1, ntohl(addr->sin_addr.s_addr), 0, t, "   New tunnel from %u.%u.%u.%u/%u ID %d\n", tunnel[t].ip >> 24, tunnel[t].ip >> 16 & 255, tunnel[t].ip >> 8 & 255, tunnel[t].ip & 255, tunnel[t].port, t);
			STAT(tunnel_created);
		}

		// This is used to time out old tunnels
		tunnel[t].lastrec = time_now;

		// check sequence of this message
		{
			int skip = tunnel[t].window; // track how many in-window packets are still in queue
				// some to clear maybe?
			while (tunnel[t].controlc && (((tunnel[t].ns - tunnel[t].controlc) - nr) & 0x8000))
			{
				controlt *c = tunnel[t].controls;
				tunnel[t].controls = c->next;
				tunnel[t].controlc--;
				c->next = controlfree;
				controlfree = c;
				skip--;
				tunnel[t].try = 0; // we have progress
			}

				// If the 'ns' just received is not the 'nr' we're
				// expecting, just send an ack and drop it.
				//
				// if 'ns' is less, then we got a retransmitted packet.
				// if 'ns' is greater than missed a packet. Either way
				// we should ignore it.
			if (ns != tunnel[t].nr)
			{
				// is this the sequence we were expecting?
				log(1, ntohl(addr->sin_addr.s_addr), 0, t, "   Out of sequence tunnel %d, (%d is not the expected %d)\n", t, ns, tunnel[t].nr);
				STAT(tunnel_rx_errors);

				if (l)	// Is this not a ZLB?
					controlnull(t);
				return;
			}
			// receiver advance (do here so quoted correctly in any sends below)
			if (l) tunnel[t].nr = (ns + 1);
			if (skip < 0) skip = 0;
			if (skip < tunnel[t].controlc)
			{
				// some control packets can now be sent that were previous stuck out of window
				int tosend = tunnel[t].window - skip;
				controlt *c = tunnel[t].controls;
				while (c && skip)
				{
					c = c->next;
					skip--;
				}
				while (c && tosend)
				{
					tunnel[t].try = 0; // first send
					tunnelsend(c->buf, c->length, t);
					c = c->next;
					tosend--;
				}
			}
			if (!tunnel[t].controlc)
				tunnel[t].retry = 0; // caught up
		}
		if (l)
		{                     // if not a null message
			// process AVPs
			while (l && !(fatal & 0x80))
			{
				u16 n = (ntohs(*(u16 *) p) & 0x3FF);
				u8 *b = p;
				u8 flags = *p;
				u16 mtype;
				p += n;       // next
				if (l < n)
				{
					log(1, ntohl(addr->sin_addr.s_addr), s, t, "Invalid length in AVP\n");
					STAT(tunnel_rx_errors);
					fatal = flags;
					return;
				}
				l -= n;
				if (flags & 0x40)
				{
					// handle hidden AVPs
					if (!*config->l2tpsecret)
					{
						log(1, ntohl(addr->sin_addr.s_addr), s, t, "Hidden AVP requested, but no L2TP secret.\n");
						fatal = flags;
						continue;
					}
					if (!session[s].random_vector_length)
					{
						log(1, ntohl(addr->sin_addr.s_addr), s, t, "Hidden AVP requested, but no random vector.\n");
						fatal = flags;
						continue;
					}
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "Hidden AVP\n");
					// Unhide the AVP
					n = unhide_avp(b, t, s, n);
					if (n == 0)
					{
						fatal = flags;
						continue;
					}
				}
				if (*b & 0x3C)
				{
					log(1, ntohl(addr->sin_addr.s_addr), s, t, "Unrecognised AVP flags %02X\n", *b);
					fatal = flags;
					continue; // next
				}
				b += 2;
				if (*(u16 *) (b))
				{
					log(2, ntohl(addr->sin_addr.s_addr), s, t, "Unknown AVP vendor %d\n", ntohs(*(u16 *) (b)));
					fatal = flags;
					continue; // next
				}
				b += 2;
				mtype = ntohs(*(u16 *) (b));
				b += 2;
				n -= 6;

				log(4, ntohl(addr->sin_addr.s_addr), s, t, "   AVP %d (%s) len %d\n", mtype, avpnames[mtype], n);
				switch (mtype)
				{
				case 0:     // message type
					message = ntohs(*(u16 *) b);
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Message type = %d (%s)\n", *b,
							l2tp_message_types[message]);
					mandatorymessage = flags;
					break;
				case 1:     // result code
					{
						u16 rescode = ntohs(*(u16 *)(b));
						const char* resdesc = "(unknown)";
						if (message == 4)
						{ /* StopCCN */
							if (rescode <= MAX_STOPCCN_RESULT_CODE)
								resdesc = stopccn_result_codes[rescode];
						}
						else if (message == 14)
						{ /* CDN */
							if (rescode <= MAX_CDN_RESULT_CODE)
								resdesc = cdn_result_codes[rescode];
						}

						log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Result Code %d: %s\n",
							rescode, resdesc);
						if (n >= 4)
						{
							u16 errcode = ntohs(*(u16 *)(b + 2));
							const char* errdesc = "(unknown)";
							if (errcode <= MAX_ERROR_CODE)
								errdesc = error_codes[errcode];
							log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Error Code %d: %s\n",
								errcode, errdesc);
						}
						if (n > 4)
							log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Error String: %.*s\n",
								n-4, b+4);

						break;
					}
					break;
				case 2:     // protocol version
					{
						version = ntohs(*(u16 *) (b));
						log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Protocol version = %d\n", version);
						if (version && version != 0x0100)
						{   // allow 0.0 and 1.0
							log(1, ntohl(addr->sin_addr.s_addr), s, t, "   Bad protocol version %04X\n",
									version);
							fatal = flags;
							continue; // next
						}
					}
					break;
				case 3:     // framing capabilities
//					log(4, ntohl(addr->sin_addr.s_addr), s, t, "Framing capabilities\n");
					break;
				case 4:     // bearer capabilities
//					log(4, ntohl(addr->sin_addr.s_addr), s, t, "Bearer capabilities\n");
					break;
				case 5:		// tie breaker
					// We never open tunnels, so we don't care about tie breakers
//					log(4, ntohl(addr->sin_addr.s_addr), s, t, "Tie breaker\n");
					continue;
				case 6:     // firmware revision
//					log(4, ntohl(addr->sin_addr.s_addr), s, t, "Firmware revision\n");
					break;
				case 7:     // host name
					memset(tunnel[t].hostname, 0, 128);
					memcpy(tunnel[t].hostname, b, (n >= 127) ? 127 : n);
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Tunnel hostname = \"%s\"\n", tunnel[t].hostname);
					// TBA - to send to RADIUS
					break;
				case 8:     // vendor name
					memset(tunnel[t].vendor, 0, sizeof(tunnel[t].vendor));
					memcpy(tunnel[t].vendor, b, (n >= sizeof(tunnel[t].vendor) - 1) ? sizeof(tunnel[t].vendor) - 1 : n);
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Vendor name = \"%s\"\n", tunnel[t].vendor);
					break;
				case 9:     // assigned tunnel
					tunnel[t].far = ntohs(*(u16 *) (b));
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Remote tunnel id = %d\n", tunnel[t].far);
					break;
				case 10:    // rx window
					tunnel[t].window = ntohs(*(u16 *) (b));
					if (!tunnel[t].window)
						tunnel[t].window = 1; // window of 0 is silly
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   rx window = %d\n", tunnel[t].window);
					break;
				case 11:	// Challenge
					{
						log(4, ntohl(addr->sin_addr.s_addr), s, t, "   LAC requested CHAP authentication for tunnel\n");
						build_chap_response(b, 2, n, &chapresponse);
					}
					break;
				case 13:    // Response
					// Why did they send a response? We never challenge.
					log(2, ntohl(addr->sin_addr.s_addr), s, t, "   received unexpected challenge response\n");
				break;

				case 14:    // assigned session
					asession = session[s].far = ntohs(*(u16 *) (b));
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   assigned session = %d\n", asession);
					break;
				case 15:    // call serial number
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   call serial number = %d\n", ntohl(*(u32 *)b));
					break;
				case 18:    // bearer type
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   bearer type = %d\n", ntohl(*(u32 *)b));
					// TBA - for RADIUS
					break;
				case 19:    // framing type
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   framing type = %d\n", ntohl(*(u32 *)b));
					// TBA
					break;
				case 21:    // called number
					memset(called, 0, MAXTEL);
					memcpy(called, b, (n >= MAXTEL) ? (MAXTEL-1) : n);
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Called <%s>\n", called);
					break;
				case 22:    // calling number
					memset(calling, 0, MAXTEL);
					memcpy(calling, b, (n >= MAXTEL) ? (MAXTEL-1) : n);
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Calling <%s>\n", calling);
					break;
				case 23:    // subtype
					break;
				case 24:    // tx connect speed
					if (n == 4)
					{
						session[s].tx_connect_speed = ntohl(*(u32 *)b);
					}
					else
					{
						// AS5300s send connect speed as a string
						char tmp[30] = {0};
						memcpy(tmp, b, (n >= 30) ? 30 : n);
						session[s].tx_connect_speed = atol(tmp);
					}
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   TX connect speed <%u>\n",
							session[s].tx_connect_speed);
					break;
				case 38:    // rx connect speed
					if (n == 4)
					{
						session[s].rx_connect_speed = ntohl(*(u32 *)b);
					}
					else
					{
						// AS5300s send connect speed as a string
						char tmp[30] = {0};
						memcpy(tmp, b, (n >= 30) ? 30 : n);
						session[s].rx_connect_speed = atol(tmp);
					}
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   RX connect speed <%u>\n",
							session[s].rx_connect_speed);
					break;
				case 25:    // Physical Channel ID
					{
						u32 tmp = ntohl(*(u32 *)b);
						log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Physical Channel ID <%X>\n", tmp);
						break;
					}
				case 29:    // Proxy Authentication Type
					{
						u16 authtype = ntohs(*(u16 *)b);
						log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Proxy Auth Type %d (%s)\n",
							authtype, authtypes[authtype]);
						requestchap = (authtype == 2);
						break;
					}
				case 30:    // Proxy Authentication Name
					{
						char authname[64] = {0};
						memcpy(authname, b, (n > 63) ? 63 : n);
						log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Proxy Auth Name (%s)\n",
							authname);
						break;
					}
				case 31:    // Proxy Authentication Challenge
					{
						memcpy(radius[session[s].radius].auth, b, 16);
						log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Proxy Auth Challenge\n");
						break;
					}
				case 32:    // Proxy Authentication ID
					{
						u16 authid = ntohs(*(u16 *)(b));
						log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Proxy Auth ID (%d)\n",
							authid);
						if (session[s].radius)
							radius[session[s].radius].id = authid;
						break;
					}
				case 33:    // Proxy Authentication Response
					{
						char authresp[64] = {0};
						memcpy(authresp, b, (n > 63) ? 63 : n);
						log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Proxy Auth Response\n");
						break;
					}
				case 27:    // last send lcp
					{        // find magic number
						u8 *p = b, *e = p + n;
						while (p < e && p[1])
						{
							if (*p == 5 && p[1] == 6)
								amagic = ntohl(*(u32 *) (p + 2));
							else if (*p == 3 && p[1] == 5 && *(u16 *) (p + 2) == htons(PPPCHAP) && p[4] == 5)
								chap = 1;
							else if (*p == 7)
								aflags |= SESSIONPFC;
							else if (*p == 8)
								aflags |= SESSIONACFC;
							p += p[1];
						}

						{
							char tmp[500] = {0};
							tmp[0] = ConfigReq;
							memcpy((tmp + 1), b, n);
						}
					}
					break;
				case 28:    // last recv lcp confreq
					{
						char tmp[500] = {0};
						tmp[0] = ConfigReq;
						memcpy((tmp + 1), b, n);
						break;
					}
				case 26:    // Initial Received LCP CONFREQ
					{
						char tmp[500] = {0};
						tmp[0] = ConfigReq;
						memcpy((tmp + 1), b, n);
					}
					break;
				case 39:    // seq required - we control it as an LNS anyway...
					break;
				case 36:    // Random Vector
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Random Vector received. Enabled AVP Hiding.\n");
					memset(session[s].random_vector, 0, sizeof(session[s].random_vector));
					memcpy(session[s].random_vector, b, n);
					session[s].random_vector_length = n;
					break;
				default:
					log(2, ntohl(addr->sin_addr.s_addr), s, t, "   Unknown AVP type %d\n", mtype);
					fatal = flags;
					continue; // next
				}
			}
			// process message
			if (fatal & 0x80)
				tunnelshutdown(t, "Unknown Mandatory AVP");
			else
				switch (message)
				{
				case 1:       // SCCRQ - Start Control Connection Request
					{
						controlt *c = controlnew(2); // sending SCCRP
						control16(c, 2, version, 1); // protocol version
						control32(c, 3, 3, 1); // framing
						controls(c, 7, tunnel[t].hostname, 1); // host name (TBA)
						if (chapresponse) controlb(c, 13, chapresponse, 16, 1); // Challenge response
						control16(c, 9, t, 1); // assigned tunnel
						controladd(c, t, s); // send the resply
					}
					tunnel[t].state = TUNNELOPENING;
					break;
				case 2:       // SCCRP
					tunnel[t].state = TUNNELOPEN;
					break;
				case 3:       // SCCN
					tunnel[t].state = TUNNELOPEN;
					controlnull(t); // ack
					break;
				case 4:       // StopCCN
					controlnull(t); // ack
					tunnelshutdown(t, "Stopped"); // Shut down cleanly
					tunnelkill(t, "Stopped"); // Immediately force everything dead
					break;
				case 6:       // HELLO
					controlnull(t); // simply ACK
					break;
				case 7:       // OCRQ
					// TBA
					break;
				case 8:       // OCRO
					// TBA
					break;
				case 9:       // OCCN
					// TBA
					break;
				case 10:      // ICRQ
					if ((s = new_session(t)))
					{
						controlt *c;
						u16 r = session[s].radius;

						session[s].far = asession;

						c = controlnew(11); // sending ICRP
						log(3, ntohl(addr->sin_addr.s_addr), s, t, "New session (%d/%d)\n", tunnel[t].far, session[s].far);
						control16(c, 14, s, 1); // assigned session
						controladd(c, t, s); // send the reply

						strncpy(radius[r].calling, calling, sizeof(radius[r].calling) - 1);
						strncpy(session[s].called, called, sizeof(session[s].called) - 1);
						strncpy(session[s].calling, calling, sizeof(session[s].calling) - 1);
					}
					break;
				case 11:      // ICRP
					// TBA
					break;
				case 12:      // ICCN
					if (amagic == 0) amagic = time_now;
					session[s].magic = amagic; // set magic number
					session[s].l2tp_flags = aflags; // set flags received
					log(3, ntohl(addr->sin_addr.s_addr), s, t, "Magic %X Flags %X\n", amagic, aflags);
					controlnull(t); // ack
					// In CHAP state, request PAP instead
					if (requestchap)
						initlcp(t, s);
					break;
				case 14:      // CDN
					controlnull(t); // ack
					sessionshutdown(s, "Closed (Received CDN)");
					break;
				case 0xFFFF:
					log(1, ntohl(addr->sin_addr.s_addr), s, t, "Missing message type\n");
					break;
				default:
					STAT(tunnel_rx_errors);
					if (mandatorymessage & 0x80)
						tunnelshutdown(t, "Unknown message");
					else
						log(1, ntohl(addr->sin_addr.s_addr), s, t, "Unknown message type %d\n", message);
					break;
				}
			if (chapresponse) free(chapresponse);
			cluster_send_tunnel(t);
		}
		else
		{
			log(4, 0, s, t, "   Got a ZLB ack\n");
		}
	}
	else
	{
		if (s && !session[s].tunnel)	// Is something wrong??
		{
			if (!config->cluster_iam_master)
			{
				// Pass it off to the master to deal with..
				master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port);
				return;
			}

			log(1, ntohl(addr->sin_addr.s_addr), s, t, "UDP packet contains session %d "
					"but no session[%d].tunnel exists (LAC said"
					" tunnel = %d). Dropping packet.\n", s, s, t);
			STAT(tunnel_rx_errors);
			return;
		}

		if (session[s].die)
		{
			log(3, ntohl(addr->sin_addr.s_addr), s, t, "Session %d is closing. Don't process PPP packets\n", s);
			// I'm pretty sure this isn't right -- mo.
			// return;              // closing session, PPP not processed
		}
		processppp(s, t, buf, len, p, l, addr);
	}
}

void processppp(sessionidt s, tunnelidt t, u8 *buf, int len, u8 *p, int l, struct sockaddr_in *addr)
{
	u16 prot;

	log_hex(5, "Receive PPP Frame", p, l);
	if (l > 2 && p[0] == 0xFF && p[1] == 0x03)
	{
		// discard HDLC address header
		p += 2;
		l -= 2;
	}
	if (l < 2)
	{
		log(1, ntohl(addr->sin_addr.s_addr), s, t, "Short ppp length %d\n", l);
		STAT(tunnel_rx_errors);
		return;
	}
	if (*p & 1)
	{
		prot = *p++;
		l--;
	}
	else
	{
		prot = ntohs(*(u16 *) p);
		p += 2;
		l -= 2;
	}

	if (prot == PPPPAP)
	{
		session[s].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port); return; }
		processpap(t, s, p, l);
	}
	else if (prot == PPPCHAP)
	{
		session[s].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port); return; }
		processchap(t, s, p, l);
	}
	else if (prot == PPPLCP)
	{
		session[s].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port); return; }
		processlcp(t, s, p, l);
	}
	else if (prot == PPPIPCP)
	{
		session[s].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port); return; }
		processipcp(t, s, p, l);
	}
	else if (prot == PPPCCP)
	{
		session[s].last_packet = time_now;
		if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port); return; }
		processccp(t, s, p, l);
	}
	else if (prot == PPPIP)
	{
		if (!config->cluster_iam_master)
		{
			// We're a slave. Should we forward this packet to the master?

			// Is this a walled garden session, or something that needs it's
			// idle time updated??

			// Maintain the idle timeouts on the master. If this would
			// significantly reset the idletimeout, run it via the master
			// to refresh the master's idle timer.
			// Not sure this is ideal: It may re-order packets.

			if (session[s].walled_garden || (session[s].last_packet + (ECHO_TIMEOUT/2)) < time_now)
			{
				master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port);
				session[s].last_packet = time_now;
				return;
			}
			// fall through to processipin.
		} else
			session[s].last_packet = time_now;
		processipin(t, s, p, l);
	}
	else
	{
		STAT(tunnel_rx_errors);
		log(1, ntohl(addr->sin_addr.s_addr), s, t, "Unknown PPP protocol %04X\n", prot);
	}
}

// read and process packet on tun
void processtun(u8 *buf, int len)
{
	log_hex(5, "Receive TUN Data", buf, len);
	STAT(tun_rx_packets);
	INC_STAT(tun_rx_bytes, len);

	CSTAT(call_processtun);

	eth_rx_pkt++;
	eth_rx += len;
	if (len < 22)
	{
		log(1, 0, 0, 0, "Short tun packet %d bytes\n", len);
		STAT(tun_rx_errors);
		return;
	}

	if (*(u16 *) (buf + 2) == htons(PKTIP)) // IP
		processipout(buf, len);
	// Else discard.
}

// Read and process packet on pcap socket
// This will be packets from a PPPoE user
void processpcap(u8 *buf, int len)
{
	u16 vlan = 0;
	u16 type = 0;
	sessionidt s = 0;
	tunnelidt t = 0;
	u8 code;
	u16 l;
	u8 *p, *data = NULL;

	log_hex(5, "Receive Ethernet Data", buf, len);
	STAT(tap_rx_packets);
	INC_STAT(tap_rx_bytes, len);

	CSTAT(call_processpcap);

	eth_rx_pkt++;
	eth_rx += len;
	if (len < 22)
	{
		log(1, 0, 0, 0, "Short tap packet %d bytes\n", len);
		STAT(tap_rx_errors);
		return;
	}

	p = buf + 14;
	type = ntohs(*(u16 *)(buf + 12));
	if (type == ETH_P_8021Q)
	{
		vlan = ntohs(*(u16 *)(buf + 14) & htons(0xFFF));
		type = ntohs(*(u16 *)(buf + 16));
		p += 4;
		log(1, 0, 0, 0, "802.1Q encapsulated (vlan %d)..\n", vlan);
	}

	if (type != ETH_P_PPP_DISC && type != ETH_P_PPP_SES)
	{
		log(1, 0, 0, 0, "Ignoring ethernet type %04X\n", type);
		return;
	}

	// It's a PPPoE packet
	if (*(u8 *)(p) != 0x11)
	{
		log(3, 0, 0, 0, "Unknown PPPoE discovery version / type %02x\n", *(u8 *)(p));
		return;
	}
	code = *(u8 *)(p + 1);
	s = ntohs(*(u16 *)(p + 2));
	l = ntohs(*(u16 *)(p + 4));
	data = p + 6;

	if (vlan)
		t = vlan_to_tunnel(vlan);
	else
		t = vlan_to_tunnel(1);

	if (s && t && session[s].tunnel != t)
	{
		log(2, 0, s, t, "PPPoE Packet claiming to be from session %d, on tunnel %d, but should be tunnel %d\n",
			s, t, session[s].tunnel);
		return;
	}

	if (s && !memcmp(&session[s].client_mac, buf, 6))
	{
		log(2, 0, s, t, "Ignoring PAD packet claiming to be session %d, but wrong mac address\n", s);
		return;
	}

	tunnel[t].last = time_now;

	if (type == ETH_P_PPP_DISC)
	{
		char *service_name = NULL;
		u8 *rp = NULL, *ud = NULL;
		u16 rs = 0;
		u8 response[1500] = {0};

		if (vlan)
		{
			log(4, 0, s, t, "It's a vlan packet (vlan %d)\n", vlan & 0xFFF);
			*(u16 *)(response + 12) = htons(ETH_P_8021Q);
			*(u16 *)(response + 14) = htons(vlan) & htons(0xFFF);		// VLAN ID
			*(u16 *)(response + 16) = htons(ETH_P_PPP_DISC);
			*(u8 *)(response + 18) = 0x11;				// PPPoE ver 1 type 1
			*(u8 *)(response + 19) = 0;				// code
			rp = (response + 19);
			ud = (response + 24);
		}
		else
		{
			log(4, 0, s, t, "It's not a vlan packet\n");
			*(u16 *)(response + 12) = htons(ETH_P_PPP_DISC);
			*(u8 *)(response + 14) = 0x11;				// PPPoE ver 1 type 1
			*(u8 *)(response + 15) = 0;				// code
			rp = (response + 15);
			ud = (response + 20);					// data starts here
		}

		memcpy(response + 6, &config->mac_address, 6); // Source
		memcpy(response, buf + 6, 6);
		for (; l >= 4; )
		{
			u16 tag_type = ntohs(*(u16 *)(data));
			u16 tag_length = ntohs(*(u16 *)(data + 2));
			if (tag_length > (l - 4))
			{
				log(3, 0, s, t, "PAD packet contains tag %x longer than available packet data (%u)\n",
						tag_type, tag_length);
				return;
			}
			switch (tag_type)
			{
				case 0x0000:
					// End of list
					l = 0;
					log(3, 0, s, t, "	EOL\n");
					break;

				case 0x0101:
					// Service-Name
					if (tag_length) service_name = strndup(data + 4, tag_length);
					log(3, 0, s, t, "	Service-Name: %s\n", service_name);
					*(u16 *)(ud) = htons(tag_type);
					*(u16 *)(ud + 2) = htons(tag_length);
					memcpy(ud + 4, data + 4, tag_length);
					ud += 4 + tag_length;
					break;

				case 0x0102:
					// AC-Name
					if (tag_length)
						log(3, 0, s, t, "PAD packet contains AC-Name.. ignoring\n");
					break;

				case 0x0104:
					// AC-Cookie
					*(u16 *)(ud) = htons(tag_type);
					*(u16 *)(ud + 2) = htons(tag_length);
					memcpy(ud + 4, data + 4, tag_length);
					ud += 4 + tag_length;
					log(3, 0, s, t, "	AC-Cookie\n");
					break;

				case 0x0103:
					// Host-Uniq
					*(u16 *)(ud) = htons(tag_type);
					*(u16 *)(ud + 2) = htons(tag_length);
					memcpy(ud + 4, data + 4, tag_length);
					ud += 4 + tag_length;
					log(3, 0, s, t, "	Host-Uniq\n");
					break;

				case 0x0110:
					// Relay-Session-Id
					*(u16 *)(ud) = htons(tag_type);
					*(u16 *)(ud + 2) = htons(tag_length);
					memcpy(ud + 4, data + 4, tag_length);
					ud += 4 + tag_length;
					log(3, 0, s, t, "	Relay-Session-Id\n");
					break;

				case 0x0201:
					// Service-Name-Error
					if (tag_length)
					{
						char *err = strndup(data + 4, tag_length);
						log(3, 0, s, t, "PAD packet contains Service-Name-Error: %s\n", err);
						free(err);
					}
					else
					{
						log(3, 0, s, t, "PAD packet contains Service-Name-Error\n");
					}
					return;

				case 0x0202:
					// AC-System-Error
					if (tag_length)
					{
						char *err = strndup(data + 4, tag_length);
						log(3, 0, s, t, "PAD packet contains AC-System-Error: %s\n", err);
						free(err);
					}
					else
					{
						log(3, 0, s, t, "PAD packet contains AC-System-Error\n");
					}
					return;

				case 0x0203:
					// Generic Error
					if (tag_length)
					{
						char *err = strndup(data + 4, tag_length);
						log(3, 0, s, t, "PAD packet contains Generic-Error: %s\n", err);
						free(err);
					}
					else
					{
						log(3, 0, s, t, "PAD packet contains Generic-Error\n");
					}
					return;

				case 0x0105:
					// Vendor-Specific
					// Ignore
					break;

				default:
					log(3, 0, s, t, "PAD packet contains unknown tag type %x of length %u\n",
							tag_type, tag_length);
					break;
			}
			data += (tag_length + 4);
			l -= (tag_length + 4);
		}

		// Add AC-Name
		*(u16 *)(ud) = htons(0x102);
		*(u16 *)(ud + 2) = htons(strlen(hostname));
		memcpy(ud + 4, hostname, strlen(hostname));
		ud += 4 + strlen(hostname);

		log(3, 0, s, t, "	Code: %d\n", code);
		switch (code)
		{
			case 0x09:
				// PPPoE Active Discovery Initiation (PADI)
				if ((service_name && strcmp(service_name, "OptusNet") == 0) || !service_name)
				{
					log(3, 0, s, t, "	PADI - Sending PADO\n");
					*rp = 0x07; // PADO

					if (!service_name || !*service_name)
					{
						log(3, 0, s, t, "	Adding in service name\n");
						*(u16 *)(ud) = htons(0x0101);
						*(u16 *)(ud + 2) = htons(strlen("OptusNet"));
						memcpy(ud + 4, "OptusNet", strlen("OptusNet"));
						ud += 4 + strlen("OptusNet");
					}
				}
				else
				{
					log(3, 0, s, t, "Ignoring PADI request for service \"%s\"\n", service_name);
					free(service_name);
					return;
				}
				break;

			case 0x07:
				// PPPoE Active Discovery Offer (PADO)
				log(3, 0, s, t, "Ignoring PADO\n");
				break;

			case 0x19:
				// PPPoE Active Discovery Request (PADR)

				if (!config->cluster_iam_master)
				{
					master_forward_pppoe_packet(buf, len);
					return;
				}

				// Create a new session
				log(3, 0, s, t, "Creating new PPPoE session for pseudo-tunnel %d\n", t);
				*rp = 0x65; // PADS
				if (t && (s = new_session(t)))
				{
					rs = s;
					session[s].vlan = vlan;
					memcpy(&session[s].client_mac, buf + 6, 6);
					session[s].magic = rand();
					session[s].flags |= SESSIONPPPOE;
				}
				else
				{
					// Return AC-System-Error
					char *err = "No free sessions";
					rs = 0;
					*(u16 *)(ud) = htons(0x202);
					*(u16 *)(ud + 2) = htons(strlen(err));
					memcpy(ud + 4, err, strlen(err));
					ud += 4 + strlen(err);
				}

				break;

			case 0x65:
				// PPPoE Active Discovery Session-confirmation (PADS)
				log(3, 0, s, t, "Ignoring PADS\n");
				break;

			case 0xA7:
				// PPPoE Active Discovery Termination (PADT)
				// FIXME shutdown the session

				if (!config->cluster_iam_master)
				{
					master_forward_pppoe_packet(buf, len);
					return;
				}

				log(3, 0, s, t, "PADT.. shut down the session\n");
				sessionkill(s, "Remote end closed PPPoE connection");
				break;
		}
		if (*rp)
		{
			// Send a PAD response
			log(3, 0, s, t, "	Sending response type %d on vlan %d (%X)\n", *rp, vlan, htons(vlan & 0xFFF));
			*(u16 *)(rp + 1) = htons(rs);
			*(u16 *)(rp + 3) = htons(ud - rp - 5);
			write(pcapfd, response, ud - response);
			if (code == 0x19)
				initlcp(s, t);
		}
		if (service_name) free(service_name);
	}
	else if (type == ETH_P_PPP_SES)
	{
		// It's a PPPoE Session packet
		struct sockaddr_in addr = {0};
		processppp(s, t, buf, len, data, len - (data - buf), &addr);
	}
	else
	{
		log(5, 0, s, t, "Unknown ethernet protocol %04X on tap\n", type);
		return;
	}
}

//
// Maximum number of actions to complete.
// This is to avoid sending out too many packets
// at once.
#define MAX_ACTIONS 500

int regular_cleanups(void)
{
	static sessionidt s = 0;	// Next session to check for actions on.
	tunnelidt t;
	int count=0,i;
	u16 r;
	static clockt next_acct = 0;
	int a;

	log(3, 0, 0, 0, "Begin regular cleanup\n");

	for (r = 1; r < MAXRADIUS; r++)
	{
		if (!radius[r].state)
			continue;
		if (radius[r].retry)
		{
			if (radius[r].retry <= TIME)
				radiusretry(r);
		} else
			radius[r].retry = backoff(radius[r].try+1);	// Is this really needed? --mo
	}
	for (t = 1; t <= config->cluster_highest_tunnelid; t++)
	{
		// check for expired tunnels
		if (tunnel[t].die && tunnel[t].die <= TIME)
		{
			STAT(tunnel_timeout);
			tunnelkill(t, "Expired");
			continue;
		}
		// check for message resend
		if (tunnel[t].retry && tunnel[t].controlc && !tunnel[t].vlan)
		{
			// resend pending messages as timeout on reply
			if (tunnel[t].retry <= TIME)
			{
				controlt *c = tunnel[t].controls;
				u8 w = tunnel[t].window;
				tunnel[t].try++; // another try
				if (tunnel[t].try > 5)
					tunnelkill(t, "Timeout on control message"); // game over
				else
					while (c && w--)
					{
						tunnelsend(c->buf, c->length, t);
						c = c->next;
					}
			}
		}
		// Send hello
		if (tunnel[t].state == TUNNELOPEN && tunnel[t].lastrec < TIME + 600 && !tunnel[t].vlan)
		{
			controlt *c = controlnew(6); // sending HELLO
			controladd(c, t, 0); // send the message
			log(3, tunnel[t].ip, 0, t, "Sending HELLO message\n");
		}

		// Check for tunnel changes requested from the CLI
		if ((a = cli_tunnel_actions[t].action))
		{
			cli_tunnel_actions[t].action = 0;
			if (a & CLI_TUN_KILL)
			{
				log(2, tunnel[t].ip, 0, t, "Dropping tunnel by CLI\n");
				tunnelshutdown(t, "Requested by administrator");
			}
		}

	}

	count = 0;
	for (i = 1; i <= config->cluster_highest_sessionid; i++)
	{
		s++;
		if (s > config->cluster_highest_sessionid)
			s = 1;

		if (!session[s].tunnel)	// Session isn't in use
			continue;

		if (!session[s].die && session[s].ip && !(session[s].flags & SF_IPCP_ACKED))
		{
			// IPCP has not completed yet. Resend
			log(3, session[s].ip, s, session[s].tunnel, "No ACK for initial IPCP ConfigReq... resending\n");
			sendipcp(session[s].tunnel, s);
		}

		// check for expired sessions
		if (session[s].die && session[s].die <= TIME)
		{
			sessionkill(s, "Expired");
			if (++count >= MAX_ACTIONS) break;
			continue;
		}

		// Drop sessions who have not responded within IDLE_TIMEOUT seconds
		if (session[s].last_packet && (time_now - session[s].last_packet >= IDLE_TIMEOUT))
		{
			sessionkill(s, "No response to LCP ECHO requests");
			STAT(session_timeout);
			if (++count >= MAX_ACTIONS) break;
			continue;
		}

		// No data in IDLE_TIMEOUT seconds, send LCP ECHO
		if (session[s].user[0] && (time_now - session[s].last_packet >= ECHO_TIMEOUT))
		{
			u8 b[MAXCONTROL] = {0};

			u8 *q = makeppp(b, sizeof(b), 0, 0, session[s].tunnel, s, PPPLCP);
			if (!q)
			{
				log(3, session[s].ip, s, t, "failed to send ECHO packet.\n");
				continue;
			}

			*q = EchoReq;
			*(u8 *)(q + 1) = (time_now % 255); // ID
			*(u16 *)(q + 2) = htons(8); // Length
			*(u32 *)(q + 4) = 0; // Magic Number (not supported)

			log(4, session[s].ip, s, session[s].tunnel, "No data in %d seconds, sending LCP ECHO\n",
					(int)(time_now - session[s].last_packet));
			returnpacket(b, 24, s, session[s].tunnel); // send it
			if (++count >= MAX_ACTIONS) break;
		}

		// Check for actions requested from the CLI
		if ((a = cli_session_actions[s].action))
		{
			int send = 0;

			cli_session_actions[s].action = 0;
			if (a & CLI_SESS_KILL)
			{
				log(2, 0, s, session[s].tunnel, "Dropping session by CLI\n");
				sessionshutdown(s, "Requested by administrator");
				a = 0; // dead, no need to check for other actions
			}

			if (a & CLI_SESS_SNOOP)
			{
				log(2, 0, s, session[s].tunnel, "Snooping session by CLI (to %s:%d)\n",
				    inet_toa(cli_session_actions[s].snoop_ip), cli_session_actions[s].snoop_port);

				session[s].snoop_ip = cli_session_actions[s].snoop_ip;
				session[s].snoop_port = cli_session_actions[s].snoop_port;
				send++;
			}

			if (a & CLI_SESS_NOSNOOP)
			{
				log(2, 0, s, session[s].tunnel, "Unsnooping session by CLI\n");
				session[s].snoop_ip = 0;
				session[s].snoop_port = 0;
				send++;
			}

			if (a & CLI_SESS_THROTTLE)
			{
				log(2, 0, s, session[s].tunnel, "Throttling session by CLI (to %dkb/s up and %dkb/s down)\n",
				    cli_session_actions[s].throttle & 0xFFFF,
				    cli_session_actions[s].throttle >> 16);

				throttle_session(s, cli_session_actions[s].throttle);
			}

			if (a & CLI_SESS_NOTHROTTLE)
			{
				log(2, 0, s, session[s].tunnel, "Un-throttling session by CLI\n");
				throttle_session(s, 0);
			}

			if (send)
				cluster_send_session(s);

			if (++count >= MAX_ACTIONS) break;
		}
	}
	if (*config->accounting_dir && next_acct <= TIME)
	{
		// Dump accounting data
		next_acct = TIME + ACCT_TIME;
		dump_acct_info();
	}

	if (count >= MAX_ACTIONS)
		return 1;	// Didn't finish!

	log(3, 0, 0, 0, "End regular cleanup (%d actions), next in %d seconds\n", count, config->cleanup_interval);
	return 0;
}


//
// Are we in the middle of a tunnel update, or radius
// requests??
//
int still_busy(void)
{
	int i;
	static clockt last_talked = 0;
	static clockt start_busy_wait = 0;
	if (start_busy_wait == 0)
		start_busy_wait = TIME;

	for (i = config->cluster_highest_tunnelid ; i > 0 ; --i)
	{
		if (!tunnel[i].controlc)
			continue;

		if (tunnel[i].vlan)
			continue;

		if (last_talked != TIME)
		{
			log(2,0,0,0, "Tunnel %d still has un-acked control messages.\n", i);
			last_talked = TIME;
		}
		return 1;
	}

	// We stop waiting for radius after BUSY_WAIT_TIMEOUT 1/10th seconds
	if (abs(TIME - start_busy_wait) > BUSY_WAIT_TIMEOUT)
	{
		log(1, 0, 0, 0, "Giving up waiting for RADIUS to be empty. Shutting down anyway.\n");
		return 0;
	}

	for (i = 1; i < MAXRADIUS; i++)
	{
		if (radius[i].state == RADIUSNULL)
			continue;
	        if (radius[i].state == RADIUSWAIT)
			continue;

		if (last_talked != TIME)
		{
			log(2,0,0,0, "Radius session %d is still busy (sid %d)\n", i, radius[i].session);
			last_talked = TIME;
		}
		return 1;
	}

	return 0;
}

// main loop - gets packets on tun or udp and processes them
void mainloop(void)
{
	fd_set cr;
	int cn, i;
	u8 buf[65536];
	struct timeval to;
	clockt next_cluster_ping = 0;	// send initial ping immediately
	time_t next_clean = time_now + config->cleanup_interval;

	log(4, 0, 0, 0, "Beginning of main loop. udpfd=%d, tunfd=%d, cluster_sockfd=%d, controlfd=%d\n",
			udpfd, tunfd, cluster_sockfd, controlfd);

	FD_ZERO(&cr);
	FD_SET(udpfd, &cr);
	FD_SET(tunfd, &cr);
	if (pcapfd) FD_SET(pcapfd, &cr);
	FD_SET(controlfd, &cr);
	FD_SET(clifd, &cr);
	if (cluster_sockfd) FD_SET(cluster_sockfd, &cr);
	cn = udpfd;
	if (cn < tunfd) cn = tunfd;
	if (pcapfd && cn < pcapfd) cn = pcapfd;
	if (cn < controlfd) cn = controlfd;
	if (cn < clifd) cn = clifd;
	if (cn < cluster_sockfd) cn = cluster_sockfd;
	for (i = 0; i < config->num_radfds; i++)
	{
		if (!radfds[i]) continue;
		FD_SET(radfds[i], &cr);
		if (radfds[i] > cn)
			cn = radfds[i];
	}

	while (!main_quit || still_busy())
	{
		fd_set r;
		int n = cn;
#ifdef BGP
		fd_set w;
		int bgp_set[BGP_NUM_PEERS];
#endif /* BGP */

		if (config->reload_config)
		{
			// Update the config state based on config settings
			update_config();
		}

		memcpy(&r, &cr, sizeof(fd_set));
		to.tv_sec = 0;
		to.tv_usec = 100000; // 1/10th of a second.

#ifdef BGP
		FD_ZERO(&w);
		for (i = 0; i < BGP_NUM_PEERS; i++)
		{
			bgp_set[i] = bgp_select_state(&bgp_peers[i]);
			if (bgp_set[i] & 1)
			{
				FD_SET(bgp_peers[i].sock, &r);
				if (bgp_peers[i].sock > n)
					n = bgp_peers[i].sock;
			}

			if (bgp_set[i] & 2)
			{
				FD_SET(bgp_peers[i].sock, &w);
				if (bgp_peers[i].sock > n)
					n = bgp_peers[i].sock;
			}
		}

		n = select(n + 1, &r, &w, 0, &to);
#else /* BGP */
		n = select(n + 1, &r, 0, 0, &to);
#endif /* BGP */

		TIME = now();
		if (n < 0)
		{
			if (errno == EINTR)
				continue;

			log(0, 0, 0, 0, "Error returned from select(): %s\n", strerror(errno));
			main_quit++;
			break;
		}
		else if (n)
		{
			struct sockaddr_in addr;
			int alen = sizeof(addr);
			if (FD_ISSET(udpfd, &r))
			{
				int c, n;
				for (c = 0; c < config->multi_read_count; c++)
				{
					if ((n = recvfrom(udpfd, buf + 10, sizeof(buf) - 10, 0, (void *) &addr, &alen)) > 0)
						processudp(buf + 10, n, &addr);
					else
						break;
				}
			}
			if (FD_ISSET(tunfd, &r))
			{
				int c, n;
				for (c = 0; c < config->multi_read_count; c++)
				{
					if ((n = read(tunfd, buf, sizeof(buf))) > 0)
						processtun(buf, n);
					else
						break;
				}
			}
			if (pcapfd && FD_ISSET(pcapfd, &r))
			{
				int c, n;
				for (c = 0; c < config->multi_read_count; c++)
				{
					if ((n = read(pcapfd, buf, sizeof(buf))) > 0)
						processpcap(buf, n);
					else
						break;
				}
			}
			for (i = 0; i < config->num_radfds; i++)
				if (FD_ISSET(radfds[i], &r))
					processrad(buf, recv(radfds[i], buf, sizeof(buf), 0), i);
			if (FD_ISSET(cluster_sockfd, &r))
			{
				int size;
				size = recvfrom(cluster_sockfd, buf, sizeof(buf), MSG_WAITALL, (void *) &addr, &alen);
				processcluster(buf, size, addr.sin_addr.s_addr);
			}
			if (FD_ISSET(controlfd, &r))
				processcontrol(buf, recvfrom(controlfd, buf, sizeof(buf), MSG_WAITALL, (void *) &addr, &alen), &addr);
			if (FD_ISSET(clifd, &r))
			{
				struct sockaddr_in addr;
				int sockfd;
				int len = sizeof(addr);

				if ((sockfd = accept(clifd, (struct sockaddr *)&addr, &len)) <= 0)
				{
					log(0, 0, 0, 0, "accept error: %s\n", strerror(errno));
					continue;
				}
				else
				{
					cli_do(sockfd);
					close(sockfd);
				}
			}
		}

			// Runs on every machine (master and slaves).
		if (cluster_sockfd && next_cluster_ping <= TIME)
		{
			// Check to see which of the cluster is still alive..

			cluster_send_ping(basetime);	// Only does anything if we're a slave
			cluster_check_master();		// ditto.

			cluster_heartbeat();		// Only does anything if we're a master.
			cluster_check_slaves();		// ditto.

			master_update_counts();		// If we're a slave, send our byte counters to our master.

			if (config->cluster_iam_master && !config->cluster_iam_uptodate)
				next_cluster_ping = TIME + 1; // out-of-date slaves, do fast updates
			else
				next_cluster_ping = TIME + config->cluster_hb_interval;
		}

			// Run token bucket filtering queue..
			// Only run it every 1/10th of a second.
			// Runs on all machines both master and slave.
		{
			static clockt last_run = 0;
			if (last_run != TIME)
			{
				last_run = TIME;
				tbf_run_timer();
			}
		}

		/* Handle timeouts. Make sure that this gets run anyway, even if there was
		 * something to read, else under load this will never actually run....
		 *
		 */
		if (config->cluster_iam_master && next_clean <= time_now)
		{
			if (regular_cleanups())
			{
				// Did it finish?
				next_clean = time_now + 1 ;	// Didn't finish. Check quickly.
			}
			else
			{
				next_clean = time_now + config->cleanup_interval; // Did. Move to next interval.
			}
		}

#ifdef BGP
		for (i = 0; i < BGP_NUM_PEERS; i++)
		{
			bgp_process(&bgp_peers[i],
				bgp_set[i] ? FD_ISSET(bgp_peers[i].sock, &r) : 0,
				bgp_set[i] ? FD_ISSET(bgp_peers[i].sock, &w) : 0);
		}
#endif /* BGP */
	}

		// Are we the master and shutting down??
	if (config->cluster_iam_master)
		cluster_heartbeat(); // Flush any queued changes..

		// Ok. Notify everyone we're shutting down. If we're
		// the master, this will force an election.
	cluster_send_ping(0);

	//
	// Important!!! We MUST not process any packets past this point!
}

// Init data structures
void initdata(void)
{
	int i;
	char *p;

	if (!(_statistics = shared_malloc(sizeof(struct Tstats))))
	{
		fprintf(stderr, "Error doing malloc for _statistics: %s\n", strerror(errno));
		exit(1);
	}
	if (!(config = shared_malloc(sizeof(struct configt))))
	{
		fprintf(stderr, "Error doing malloc for configuration: %s\n", strerror(errno));
		exit(1);
	}
	memset(config, 0, sizeof(struct configt));
	time(&config->start_time);
	strncpy(config->config_file, config_filename, sizeof(config->config_file) - 1);
	if (!(tunnel = shared_malloc(sizeof(tunnelt) * MAXTUNNEL)))
	{
		fprintf(stderr, "Error doing malloc for tunnels: %s\n", strerror(errno));
		exit(1);
	}
	if (!(session = shared_malloc(sizeof(sessiont) * MAXSESSION)))
	{
		fprintf(stderr, "Error doing malloc for sessions: %s\n", strerror(errno));
		exit(1);
	}

	if (!(sess_count = shared_malloc(sizeof(sessioncountt) * MAXSESSION)))
	{
		fprintf(stderr, "Error doing malloc for sessions_count: %s\n", strerror(errno));
		exit(1);
	}

	if (!(radius = shared_malloc(sizeof(radiust) * MAXRADIUS)))
	{
		fprintf(stderr, "Error doing malloc for radius: %s\n", strerror(errno));
		exit(1);
	}

	if (!(ip_address_pool = shared_malloc(sizeof(ippoolt) * MAXIPPOOL)))
	{
		fprintf(stderr, "Error doing malloc for ip_address_pool: %s\n", strerror(errno));
		exit(1);
	}

#ifdef RINGBUFFER
	if (!(ringbuffer = shared_malloc(sizeof(struct Tringbuffer))))
	{
		fprintf(stderr, "Error doing malloc for ringbuffer: %s\n", strerror(errno));
		exit(1);
	}
	memset(ringbuffer, 0, sizeof(struct Tringbuffer));
#endif

	if (!(cli_session_actions = shared_malloc(sizeof(struct cli_session_actions) * MAXSESSION)))
	{
		fprintf(stderr, "Error doing malloc for cli session actions: %s\n", strerror(errno));
		exit(1);
	}
	memset(cli_session_actions, 0, sizeof(struct cli_session_actions) * MAXSESSION);

	if (!(cli_tunnel_actions = shared_malloc(sizeof(struct cli_tunnel_actions) * MAXSESSION)))
	{
		fprintf(stderr, "Error doing malloc for cli tunnel actions: %s\n", strerror(errno));
		exit(1);
	}
	memset(cli_tunnel_actions, 0, sizeof(struct cli_tunnel_actions) * MAXSESSION);

	memset(tunnel, 0, sizeof(tunnelt) * MAXTUNNEL);
	memset(session, 0, sizeof(sessiont) * MAXSESSION);
	memset(radius, 0, sizeof(radiust) * MAXRADIUS);
	memset(ip_address_pool, 0, sizeof(ippoolt) * MAXIPPOOL);

		// Put all the sessions on the free list marked as undefined.
	for (i = 1; i < MAXSESSION - 1; i++)
	{
		session[i].next = i + 1;
		session[i].tunnel = T_UNDEF;	// mark it as not filled in.
	}
	session[MAXSESSION - 1].next = 0;
	sessionfree = 1;

		// Mark all the tunnels as undefined (waiting to be filled in by a download).
	for (i = 1; i < MAXTUNNEL- 1; i++)
		tunnel[i].state = TUNNELUNDEF;	// mark it as not filled in.

	// Grab my hostname unless it's been specified
	gethostname(config->hostname, sizeof(config->hostname));
	if ((p = strchr(config->hostname, '.'))) *p = 0;
	hostname = config->hostname;

	_statistics->start_time = _statistics->last_reset = time(NULL);

#ifdef BGP
	if (!(bgp_peers = shared_malloc(sizeof(struct bgp_peer) * BGP_NUM_PEERS)))
	{
		fprintf(stderr, "Error doing malloc for bgp: %s\n", strerror(errno));
		exit(1);
	}
#endif /* BGP */
}

void initiptables(void)
{
	/* Flush the tables here so that we have a clean slate */

// Not needed. 'nat' is setup by garden.c
// mangle isn't used (as throttling is done by tbf inhouse).
}

int assign_ip_address(sessionidt s)
{
	u32 i;
	int best = -1;
	time_t best_time = time_now;
	char *u = session[s].user;
	char reuse = 0;


	CSTAT(call_assign_ip_address);

	for (i = 1; i < ip_pool_size; i++)
	{
		if (!ip_address_pool[i].address || ip_address_pool[i].assigned)
			continue;

		if (!session[s].walled_garden && ip_address_pool[i].user[0] && !strcmp(u, ip_address_pool[i].user))
		{
			best = i;
			reuse = 1;
			break;
		}

		if (ip_address_pool[i].last < best_time)
		{
			best = i;
			if (!(best_time = ip_address_pool[i].last))
				break; // never used, grab this one
		}
	}

	if (best < 0)
	{
		log(0, 0, s, session[s].tunnel, "assign_ip_address(): out of addresses\n");
		return 0;
	}

	session[s].ip = ip_address_pool[best].address;
	session[s].ip_pool_index = best;
	ip_address_pool[best].assigned = 1;
	ip_address_pool[best].last = time_now;
	ip_address_pool[best].session = s;
	if (session[s].walled_garden)
		/* Don't track addresses of users in walled garden (note: this
		   means that their address isn't "sticky" even if they get
		   un-gardened). */
		ip_address_pool[best].user[0] = 0;
	else
		strncpy(ip_address_pool[best].user, u, sizeof(ip_address_pool[best].user) - 1);

	STAT(ip_allocated);
	log(4, ip_address_pool[best].address, s, session[s].tunnel,
		"assign_ip_address(): %s ip address %d from pool\n", reuse ? "Reusing" : "Allocating", best);

	return 1;
}

void free_ip_address(sessionidt s)
{
	int i = session[s].ip_pool_index;

	if (!session[s].ip)
		return; // what the?

	if (i < 0)	// Is this actually part of the ip pool?
		i = 0;

	STAT(ip_freed);
	cache_ipmap(session[s].ip, -i);	// Change the mapping to point back to the ip pool index.
	session[s].ip = 0;
	ip_address_pool[i].assigned = 0;
	ip_address_pool[i].session = 0;
	ip_address_pool[i].last = time_now;


	CSTAT(call_free_ip_address);

}

//
// Fsck the address pool against the session table.
// Normally only called when we become a master.
//
// This isn't perfect: We aren't keep tracking of which
// users used to have an IP address.
//
void rebuild_address_pool(void)
{
	int i;

		//
		// Zero the IP pool allocation, and build
		// a map from IP address to pool index.
	for (i = 1; i < MAXIPPOOL; ++i)
	{
		ip_address_pool[i].assigned = 0;
		ip_address_pool[i].session = 0;
		if (!ip_address_pool[i].address)
			continue;

		cache_ipmap(ip_address_pool[i].address, -i);	// Map pool IP to pool index.
	}

	for (i = 0; i < MAXSESSION; ++i)
	{
		int ipid;
		if (!session[i].ip || !session[i].tunnel)
			continue;
		ipid = - lookup_ipmap(htonl(session[i].ip));

		if (session[i].ip_pool_index < 0)
		{
			// Not allocated out of the pool.
			if (ipid < 1)			// Not found in the pool either? good.
				continue;

			log(0, 0, i, 0, "Session %d has an IP address (%s) that was marked static, but is in the pool (%d)!\n",
				i, inet_toa(session[i].ip), ipid);

			// Fall through and process it as part of the pool.
		}


		if (ipid > MAXIPPOOL || ipid < 0)
		{
			log(0, 0, i, 0, "Session %d has a pool IP that's not found in the pool! (%d)\n", i, ipid);
			ipid = -1;
			session[i].ip_pool_index = ipid;
			continue;
		}

		ip_address_pool[ipid].assigned = 1;
		ip_address_pool[ipid].session = i;
		ip_address_pool[ipid].last = time_now;
		strncpy(ip_address_pool[ipid].user, session[i].user, sizeof(ip_address_pool[ipid].user) - 1);
		session[i].ip_pool_index = ipid;
		cache_ipmap(session[i].ip, i);	// Fix the ip map.
	}
}

//
// Fix the address pool to match a changed session.
// (usually when the master sends us an update).
void fix_address_pool(int sid)
{
	int ipid;

	ipid = session[sid].ip_pool_index;

	if (ipid > ip_pool_size)
		return;		// Ignore it. rebuild_address_pool will fix it up.

	if (ip_address_pool[ipid].address != session[sid].ip)
		return;		// Just ignore it. rebuild_address_pool will take care of it.

	ip_address_pool[ipid].assigned = 1;
	ip_address_pool[ipid].session = sid;
	ip_address_pool[ipid].last = time_now;
	strncpy(ip_address_pool[ipid].user, session[sid].user, sizeof(ip_address_pool[ipid].user) - 1);
}

//
// Add a block of addresses to the IP pool to hand out.
//
void add_to_ip_pool(u32 addr, u32 mask)
{
	int i;
	if (mask == 0)
		mask = 0xffffffff;	// Host route only.

	addr &= mask;

	if (ip_pool_size >= MAXIPPOOL)	// Pool is full!
		return ;

	for (i = addr ;(i & mask) == addr; ++i)
	{
		if ((i & 0xff) == 0 || (i&0xff) == 255)
			continue;	// Skip 0 and broadcast addresses.

		ip_address_pool[ip_pool_size].address = i;
		ip_address_pool[ip_pool_size].assigned = 0;
		++ip_pool_size;
		if (ip_pool_size >= MAXIPPOOL)
		{
			log(0,0,0,0, "Overflowed IP pool adding %s\n", inet_toa(htonl(addr)) );
			return;
		}
	}
}

// Initialize the IP address pool
void initippool()
{
	FILE *f;
	char *p;
	char buf[4096];
	memset(ip_address_pool, 0, sizeof(ip_address_pool));

	if (!(f = fopen(ip_pool_file, "r")))
	{
		log(0, 0, 0, 0, "Can't load pool file %s: %s\n", ip_pool_file, strerror(errno));
		exit(1);
	}

	while (ip_pool_size < MAXIPPOOL && fgets(buf, 4096, f))
	{
		char *pool = buf;
		buf[4095] = 0;	// Force it to be zero terminated/

		if (*buf == '#' || *buf == '\n')
			continue; // Skip comments / blank lines
		if ((p = (char *)strrchr(buf, '\n'))) *p = 0;
		if ((p = (char *)strchr(buf, ':')))
		{
			ipt src;
			*p = '\0';
			src = inet_addr(buf);
			if (src == INADDR_NONE)
			{
				log(0, 0, 0, 0, "Invalid address pool IP %s\n", buf);
				exit(1);
			}
			// This entry is for a specific IP only
			if (src != config->bind_address)
				continue;
			*p = ':';
			pool = p+1;
		}
		if ((p = (char *)strchr(pool, '/')))
		{
			// It's a range
			int numbits = 0;
			u32 start = 0, mask = 0;

			log(2, 0, 0, 0, "Adding IP address range %s\n", buf);
			*p++ = 0;
			if (!*p || !(numbits = atoi(p)))
			{
				log(0, 0, 0, 0, "Invalid pool range %s\n", buf);
				continue;
			}
			start = ntohl(inet_addr(pool));
			mask = (u32)(pow(2, numbits) - 1) << (32 - numbits);

			// Add a static route for this pool
			log(5, 0, 0, 0, "Adding route for address pool %s/%u\n", inet_toa(htonl(start)), 32 + mask);
			routeset(0, start, mask, 0, 1);

			add_to_ip_pool(start, mask);
		}
		else
		{
			// It's a single ip address
			add_to_ip_pool(inet_addr(pool), 0);
		}
	}
	fclose(f);
	log(1, 0, 0, 0, "IP address pool is %d addresses\n", ip_pool_size - 1);
}

void snoop_send_packet(char *packet, u16 size, ipt destination, u16 port)
{
	struct sockaddr_in snoop_addr = {0};
	if (!destination || !port || snoopfd <= 0 || size <= 0 || !packet)
		return;

	snoop_addr.sin_family = AF_INET;
	snoop_addr.sin_addr.s_addr = destination;
	snoop_addr.sin_port = ntohs(port);

	log(5, 0, 0, 0, "Snooping packet at %p (%d bytes) to %s:%d\n",
			packet, size, inet_toa(snoop_addr.sin_addr.s_addr), htons(snoop_addr.sin_port));
	if (sendto(snoopfd, packet, size, MSG_DONTWAIT | MSG_NOSIGNAL, (void *) &snoop_addr, sizeof(snoop_addr)) < 0)
		log(0, 0, 0, 0, "Error sending intercept packet: %s\n", strerror(errno));
	STAT(packets_snooped);
}

void dump_acct_info()
{
	char filename[1024];
	char timestr[64];
	time_t t = time(NULL);
	int i;
	FILE *f = NULL;


	CSTAT(call_dump_acct_info);

	strftime(timestr, 64, "%Y%m%d%H%M%S", localtime(&t));
	snprintf(filename, 1024, "%s/%s", config->accounting_dir, timestr);

	for (i = 0; i < MAXSESSION; i++)
	{
		if (!session[i].opened || !session[i].ip || (!session[i].cin && !session[i].cout) || !*session[i].user || session[i].walled_garden)
			continue;
		if (!f)
		{
			time_t now = time(NULL);
			if (!(f = fopen(filename, "w")))
			{
				log(0, 0, 0, 0, "Can't write accounting info to %s: %s\n", filename, strerror(errno));
				return ;
			}
			log(3, 0, 0, 0, "Dumping accounting information to %s\n", filename);
			fprintf(f, "# dslwatch.pl dump file V1.01\n"
			        "# host: %s\n"
			        "# time: %ld\n"
			        "# uptime: %ld\n"
			        "# format: username ip qos uptxoctets downrxoctets\n",
			        hostname,
			        now,
			        now - basetime);
		}

		log(4, 0, 0, 0, "Dumping accounting information for %s\n", session[i].user);
		fprintf(f, "%s %s %d %u %u\n",
		        session[i].user,		// username
		        inet_toa(htonl(session[i].ip)),	// ip
		        (session[i].throttle) ? 2 : 1,	// qos
		        (u32)session[i].cin,		// uptxoctets
		        (u32)session[i].cout);		// downrxoctets

		session[i].pin = session[i].cin = 0;
		session[i].pout = session[i].cout = 0;
	}

	if (f)
		fclose(f);
}

// Main program
int main(int argc, char *argv[])
{
	int o;
	int optdebug = 0;

	_program_name = strdup(argv[0]);

	time(&basetime);             // start clock
	srand(basetime);

	// scan args
	while ((o = getopt(argc, argv, "vc:h:i:?")) >= 0)
	{
		switch (o)
		{
			case 'd':
				// Double fork to detach from terminal
				if (fork()) exit(0);
				if (fork()) exit(0);
				break;
			case 'v':
				optdebug++;
				break;
			case 'h':
				snprintf(hostname, sizeof(hostname), "%s", optarg);
				break;
			case 'c':
				config_filename = strdup(optarg);
				break;
			case 'i':
				ip_pool_file = strdup(optarg);
				break;
			case '?':
			default:
				printf("Args are:\n"
				       "\t-d\t\tDetach from terminal\n"
				       "\t-c <file>\tConfig file\n"
				       "\t-h <hostname>\tForce hostname\n"
				       "\t-i <file>\tIP pool file\n"
				       "\t-v\t\tDebug\n");

				return (0);
				break;
		}
	}

	// Start the timer routine off
	time(&time_now);
	strftime(time_now_string, sizeof(time_now_string), "%Y-%m-%d %H:%M:%S", localtime(&time_now));
	signal(SIGALRM, sigalrm_handler);
	siginterrupt(SIGALRM, 0);

	initiptables();
	initplugins();
	initdata();

	config->debug = optdebug;

	init_tbf();
	init_cli();
	read_config_file();

	log(0, 0, 0, 0, "L2TPNS version " VERSION "\n");
	log(0, 0, 0, 0, "Copyright (c) 2003, 2004 Optus Internet Engineering\n");
	log(0, 0, 0, 0, "Copyright (c) 2002 FireBrick (Andrews & Arnold Ltd / Watchfront Ltd) - GPL licenced\n");
	{
		struct rlimit rlim;
		rlim.rlim_cur = RLIM_INFINITY;
		rlim.rlim_max = RLIM_INFINITY;
		// Remove the maximum core size
		if (setrlimit(RLIMIT_CORE, &rlim) < 0)
			log(0, 0, 0, 0, "Can't set ulimit: %s\n", strerror(errno));
		// Make core dumps go to /tmp
		chdir("/tmp");
	}

	if (config->scheduler_fifo)
	{
		int ret;
		struct sched_param params = {0};
		params.sched_priority = 1;

		if (get_nprocs() < 2)
		{
			log(0, 0, 0, 0, "Not using FIFO scheduler, there is only 1 processor in the system.\n");
			config->scheduler_fifo = 0;
		}
		else
		{
			if ((ret = sched_setscheduler(0, SCHED_FIFO, &params)) == 0)
			{
				log(1, 0, 0, 0, "Using FIFO scheduler. Say goodbye to any other processes running\n");
			}
			else
			{
				log(0, 0, 0, 0, "Error setting scheduler to FIFO: %s\n", strerror(errno));
				config->scheduler_fifo = 0;
			}
		}
	}

	/* Set up the cluster communications port. */
	if (cluster_init(config->bind_address) < 0)
		exit(1);

#ifdef BGP
	signal(SIGPIPE, SIG_IGN);
	bgp_setup(config->as_number);
	bgp_add_route(config->bind_address, 0xffffffff);
	if (*config->bgp_peer[0])
		bgp_start(&bgp_peers[0], config->bgp_peer[0],
		    config->bgp_peer_as[0], 0); /* 0 = routing disabled */

	if (*config->bgp_peer[1])
		bgp_start(&bgp_peers[1], config->bgp_peer[1],
		    config->bgp_peer_as[1], 0);
#endif /* BGP */

	inittun();
	log(1, 0, 0, 0, "Set up tun on interface %s\n", config->tundevice);
	if (*config->pppoe_interface)
	{
		if (config->mac_address.ether_addr_octet[0] + config->mac_address.ether_addr_octet[1]
			+ config->mac_address.ether_addr_octet[2] + config->mac_address.ether_addr_octet[3]
			+ config->mac_address.ether_addr_octet[4] + config->mac_address.ether_addr_octet[5])
			initpcap();
		log(1, 0, 0, 0, "Set up pcap on interface %s\n", config->pppoe_interface);
	}

	initudp();
	initrad();
	initippool();

	read_state();

	signal(SIGHUP, sighup_handler);
	signal(SIGTERM, sigterm_handler);
	signal(SIGINT, sigterm_handler);
	signal(SIGQUIT, sigquit_handler);
	signal(SIGCHLD, sigchild_handler);

	// Prevent us from getting paged out
	if (config->lock_pages)
	{
		if (!mlockall(MCL_CURRENT))
			log(1, 0, 0, 0, "Locking pages into memory\n");
		else
			log(0, 0, 0, 0, "Can't lock pages: %s\n", strerror(errno));
	}

	alarm(1);

	// Drop privileges here
	if (config->target_uid > 0 && geteuid() == 0)
		setuid(config->target_uid);

	mainloop();

#ifdef BGP
	/* try to shut BGP down cleanly; with luck the sockets will be
	   writable since we're out of the select */
	{
		int i;
		for (i = 0; i < BGP_NUM_PEERS; i++)
			if (bgp_peers[i].state == Established)
				bgp_stop(&bgp_peers[i]);
	}
#endif /* BGP */

	/* remove plugins (so cleanup code gets run) */
	plugins_done();

	// Remove the PID file if we wrote it
	if (config->wrote_pid && *config->pid_file == '/')
		unlink(config->pid_file);

	/* kill CLI children */
	signal(SIGTERM, SIG_IGN);
	kill(0, SIGTERM);
	return 0;
}

void sighup_handler(int junk)
{
	if (log_stream && log_stream != stderr)
	{
		fclose(log_stream);
		log_stream = NULL;
	}

	read_config_file();
}

void sigalrm_handler(int junk)
{
	// Log current traffic stats

	snprintf(config->bandwidth, sizeof(config->bandwidth),
		"UDP-ETH:%1.0f/%1.0f  ETH-UDP:%1.0f/%1.0f  TOTAL:%0.1f   IN:%u OUT:%u",
		(udp_rx / 1024.0 / 1024.0 * 8),
		(eth_tx / 1024.0 / 1024.0 * 8),
		(eth_rx / 1024.0 / 1024.0 * 8),
		(udp_tx / 1024.0 / 1024.0 * 8),
		((udp_tx + udp_rx + eth_tx + eth_rx) / 1024.0 / 1024.0 * 8),
		udp_rx_pkt, eth_rx_pkt);

	udp_tx = udp_rx = 0;
	udp_rx_pkt = eth_rx_pkt = 0;
	eth_tx = eth_rx = 0;

	if (config->dump_speed)
		printf("%s\n", config->bandwidth);

	// Update the internal time counter
	time(&time_now);
	strftime(time_now_string, sizeof(time_now_string), "%Y-%m-%d %H:%M:%S", localtime(&time_now));
	alarm(1);

	{
		// Run timer hooks
		struct param_timer p = { time_now };
		run_plugins(PLUGIN_TIMER, &p);
	}

}

void sigterm_handler(int junk)
{
	log(1, 0, 0, 0, "Shutting down cleanly\n");
	if (config->save_state)
		dump_state();

	main_quit++;
}

void sigquit_handler(int junk)
{
	int i;

	log(1, 0, 0, 0, "Shutting down without saving sessions\n");
	for (i = 1; i < MAXSESSION; i++)
	{
		if (session[i].opened)
			sessionkill(i, "L2TPNS Closing");
	}
	for (i = 1; i < MAXTUNNEL; i++)
	{
		if (tunnel[i].ip || tunnel[i].state)
			tunnelshutdown(i, "L2TPNS Closing");
	}

	main_quit++;
}

void sigchild_handler(int signal)
{
	while (waitpid(-1, NULL, WNOHANG) > 0)
	    ;
}

void read_state()
{
	struct stat sb;
	int i;
	ippoolt itmp;
	FILE *f;
	char magic[sizeof(DUMP_MAGIC) - 1];
	u32 buf[2];

	if (!config->save_state)
	{
		unlink(STATEFILE);
		return ;
	}

	if (stat(STATEFILE, &sb) < 0)
	{
		unlink(STATEFILE);
		return ;
	}

	if (sb.st_mtime < (time(NULL) - 60))
	{
		log(0, 0, 0, 0, "State file is too old to read, ignoring\n");
		unlink(STATEFILE);
		return ;
	}

	f = fopen(STATEFILE, "r");
	unlink(STATEFILE);

	if (!f)
	{
		log(0, 0, 0, 0, "Can't read state file: %s\n", strerror(errno));
		exit(1);
	}

	if (fread(magic, sizeof(magic), 1, f) != 1 || strncmp(magic, DUMP_MAGIC, sizeof(magic)))
	{
		log(0, 0, 0, 0, "Bad state file magic\n");
		exit(1);
	}

	log(1, 0, 0, 0, "Reading state information\n");
	if (fread(buf, sizeof(buf), 1, f) != 1 || buf[0] > MAXIPPOOL || buf[1] != sizeof(ippoolt))
	{
		log(0, 0, 0, 0, "Error/mismatch reading ip pool header from state file\n");
		exit(1);
	}

	if (buf[0] > ip_pool_size)
	{
		log(0, 0, 0, 0, "ip pool has shrunk!  state = %d, current = %d\n", buf[0], ip_pool_size);
		exit(1);
	}

	log(2, 0, 0, 0, "Loading %u ip addresses\n", buf[0]);
	for (i = 0; i < buf[0]; i++)
	{
		if (fread(&itmp, sizeof(itmp), 1, f) != 1)
		{
			log(0, 0, 0, 0, "Error reading ip %d from state file: %s\n", i, strerror(errno));
			exit(1);
		}

		if (itmp.address != ip_address_pool[i].address)
		{
			log(0, 0, 0, 0, "Mismatched ip %d from state file: pool may only be extended\n", i);
			exit(1);
		}

		memcpy(&ip_address_pool[i], &itmp, sizeof(itmp));
	}

	if (fread(buf, sizeof(buf), 1, f) != 1 || buf[0] != MAXTUNNEL || buf[1] != sizeof(tunnelt))
	{
		log(0, 0, 0, 0, "Error/mismatch reading tunnel header from state file\n");
		exit(1);
	}

	log(2, 0, 0, 0, "Loading %u tunnels\n", MAXTUNNEL);
	if (fread(tunnel, sizeof(tunnelt), MAXTUNNEL, f) != MAXTUNNEL)
	{
		log(0, 0, 0, 0, "Error reading tunnel data from state file\n");
		exit(1);
	}

	for (i = 0; i < MAXTUNNEL; i++)
	{
		tunnel[i].controlc = 0;
		tunnel[i].controls = NULL;
		tunnel[i].controle = NULL;
		if (*tunnel[i].hostname)
			log(3, 0, 0, 0, "Created tunnel for %s\n", tunnel[i].hostname);
	}

	if (fread(buf, sizeof(buf), 1, f) != 1 || buf[0] != MAXSESSION || buf[1] != sizeof(sessiont))
	{
		log(0, 0, 0, 0, "Error/mismatch reading session header from state file\n");
		exit(1);
	}

	log(2, 0, 0, 0, "Loading %u sessions\n", MAXSESSION);
	if (fread(session, sizeof(sessiont), MAXSESSION, f) != MAXSESSION)
	{
		log(0, 0, 0, 0, "Error reading session data from state file\n");
		exit(1);
	}

	for (i = 0; i < MAXSESSION; i++)
	{
		session[i].tbf_in = 0;
		session[i].tbf_out = 0;
		if (session[i].opened)
		{
			log(2, 0, i, 0, "Loaded active session for user %s\n", session[i].user);
			if (session[i].ip)
				sessionsetup(session[i].tunnel, i);
		}
	}

	fclose(f);
	log(0, 0, 0, 0, "Loaded saved state information\n");
}

void dump_state()
{
	FILE *f;
	u32 buf[2];

	if (!config->save_state)
		return;

	do
	{
		if (!(f = fopen(STATEFILE, "w")))
			break;

		log(1, 0, 0, 0, "Dumping state information\n");

		if (fwrite(DUMP_MAGIC, sizeof(DUMP_MAGIC) - 1, 1, f) != 1)
			break;

		log(2, 0, 0, 0, "Dumping %u ip addresses\n", ip_pool_size);
		buf[0] = ip_pool_size;
		buf[1] = sizeof(ippoolt);
		if (fwrite(buf, sizeof(buf), 1, f) != 1)
			break;
		if (fwrite(ip_address_pool, sizeof(ippoolt), ip_pool_size, f) != ip_pool_size)
			break;

		log(2, 0, 0, 0, "Dumping %u tunnels\n", MAXTUNNEL);
		buf[0] = MAXTUNNEL;
		buf[1] = sizeof(tunnelt);
		if (fwrite(buf, sizeof(buf), 1, f) != 1)
			break;
		if (fwrite(tunnel, sizeof(tunnelt), MAXTUNNEL, f) != MAXTUNNEL)
			break;

		log(2, 0, 0, 0, "Dumping %u sessions\n", MAXSESSION);
		buf[0] = MAXSESSION;
		buf[1] = sizeof(sessiont);
		if (fwrite(buf, sizeof(buf), 1, f) != 1)
			break;
		if (fwrite(session, sizeof(sessiont), MAXSESSION, f) != MAXSESSION)
			break;

		if (fclose(f) == 0)
			return ; // OK
	}
	while (0);

	log(0, 0, 0, 0, "Can't write state information: %s\n", strerror(errno));
	unlink(STATEFILE);
}

void build_chap_response(char *challenge, u8 id, u16 challenge_length, char **challenge_response)
{
	MD5_CTX ctx;
	*challenge_response = NULL;

	if (!*config->l2tpsecret)
	{
		log(0, 0, 0, 0, "LNS requested CHAP authentication, but no l2tp secret is defined\n");
		return;
	}

	log(4, 0, 0, 0, "   Building challenge response for CHAP request\n");

	*challenge_response = (char *)calloc(17, 1);

	MD5Init(&ctx);
	MD5Update(&ctx, &id, 1);
	MD5Update(&ctx, config->l2tpsecret, strlen(config->l2tpsecret));
	MD5Update(&ctx, challenge, challenge_length);
	MD5Final(*challenge_response, &ctx);

	return;
}

static int facility_value(char *name)
{
	int i;
	for (i = 0; facilitynames[i].c_name; i++)
	{
		if (strcmp(facilitynames[i].c_name, name) == 0)
			return facilitynames[i].c_val;
	}
	return 0;
}

void update_config()
{
	int i;
	static int timeout = 0;
	static int interval = 0;

	// Update logging
	closelog();
	syslog_log = 0;
	if (log_stream)
	{
		fclose(log_stream);
		log_stream = NULL;
	}
	if (*config->log_filename)
	{
		if (strstr(config->log_filename, "syslog:") == config->log_filename)
		{
			char *p = config->log_filename + 7;
			if (*p)
			{
				openlog("l2tpns", LOG_PID, facility_value(p));
				syslog_log = 1;
			}
		}
		else if (strchr(config->log_filename, '/') == config->log_filename)
		{
			if ((log_stream = fopen((char *)(config->log_filename), "a")))
			{
				fseek(log_stream, 0, SEEK_END);
				setbuf(log_stream, NULL);
			}
			else
			{
				log_stream = stderr;
				setbuf(log_stream, NULL);
			}
		}
	}
	else
	{
		log_stream = stderr;
		setbuf(log_stream, NULL);
	}


	// Update radius
	config->numradiusservers = 0;
	for (i = 0; i < MAXRADSERVER; i++)
		if (config->radiusserver[i])
		{
			config->numradiusservers++;
			// Set radius port: if not set, take the port from the
			// first radius server.  For the first radius server,
			// take the #defined default value from l2tpns.h

			// test twice, In case someone works with
			// a secondary radius server without defining
			// a primary one, this will work even then.
			if (i>0 && !config->radiusport[i])
				config->radiusport[i] = config->radiusport[i-1];
			if (!config->radiusport[i])
				config->radiusport[i] = RADPORT;
		}

	if (!config->numradiusservers)
	{
		log(0, 0, 0, 0, "No RADIUS servers defined!\n");
	}

	config->num_radfds = 2 << RADIUS_SHIFT;

	// Update plugins
	for (i = 0; i < MAXPLUGINS; i++)
	{
		if (strcmp(config->plugins[i], config->old_plugins[i]) == 0)
			continue;
		if (*config->plugins[i])
		{
			// Plugin added
			add_plugin(config->plugins[i]);
		}
		else if (*config->old_plugins[i])
		{
			// Plugin removed
			remove_plugin(config->old_plugins[i]);
		}
	}
	memcpy(config->old_plugins, config->plugins, sizeof(config->plugins));
	if (!config->cleanup_interval) config->cleanup_interval = 10;
	if (!config->multi_read_count) config->multi_read_count = 10;
	if (!config->cluster_address) config->cluster_address = inet_addr(DEFAULT_MCAST_ADDR);
	if (!*config->cluster_interface)
		strncpy(config->cluster_interface, DEFAULT_MCAST_INTERFACE, sizeof(config->cluster_interface) - 1);

	if (!config->cluster_hb_interval)
		config->cluster_hb_interval = PING_INTERVAL;	// Heartbeat every 0.5 seconds.

	if (!config->cluster_hb_timeout)
		config->cluster_hb_timeout = HB_TIMEOUT;	// 10 missed heartbeat triggers an election.

	if (interval != config->cluster_hb_interval || timeout != config->cluster_hb_timeout)
	{
		// Paranoia:  cluster_check_master() treats 2 x interval + 1 sec as
		// late, ensure we're sufficiently larger than that
		int t = 4 * config->cluster_hb_interval + 11;

		if (config->cluster_hb_timeout < t)
		{
			log(0,0,0,0, "Heartbeat timeout %d too low, adjusting to %d\n", config->cluster_hb_timeout, t);
			config->cluster_hb_timeout = t;
		}

		// Push timing changes to the slaves immediately if we're the master
		if (config->cluster_iam_master)
			cluster_heartbeat();

		interval = config->cluster_hb_interval;
		timeout = config->cluster_hb_timeout;
	}

	// Write PID file
	if (*config->pid_file == '/' && !config->wrote_pid)
	{
		FILE *f;
		if ((f = fopen(config->pid_file, "w")))
		{
			fprintf(f, "%d\n", getpid());
			fclose(f);
			config->wrote_pid = 1;
		}
		else
		{
			log(0, 0, 0, 0, "Can't write to PID file %s: %s\n", config->pid_file, strerror(errno));
		}
	}

	config->reload_config = 0;
}

void read_config_file()
{
	FILE *f;

	if (!config->config_file) return;
	if (!(f = fopen(config->config_file, "r")))
	{
		fprintf(stderr, "Can't open config file %s: %s\n", config->config_file, strerror(errno));
		return;
	}

	log(3, 0, 0, 0, "Reading config file %s\n", config->config_file);
	cli_do_file(f);
	log(3, 0, 0, 0, "Done reading config file\n");
	fclose(f);
	update_config();
}

int sessionsetup(tunnelidt t, sessionidt s)
{
	// A session now exists, set it up
	ipt ip;
	char *user;
	sessionidt i;
	int r;

	CSTAT(call_sessionsetup);

	log(3, session[s].ip, s, t, "Doing session setup for session\n");

	if (!session[s].ip || session[s].ip == 0xFFFFFFFE)
	{
		assign_ip_address(s);
		if (session[s].ip)
			log(3, 0, s, t, "   No IP allocated. Assigned %s from pool\n",
					inet_toa(htonl(session[s].ip)));
		else
		{
			log(0, 0, s, t, "   No IP allocated. The IP address pool is FULL!\n");
			sessionshutdown(s, "No IP addresses available");
			return 0;
		}
	}


	// Make sure this is right
	session[s].tunnel = t;

	// zap old sessions with same IP and/or username
	// Don't kill gardened sessions - doing so leads to a DoS
	// from someone who doesn't need to know the password
	{
		ip = session[s].ip;
		user = session[s].user;
		for (i = 1; i <= config->cluster_highest_sessionid; i++)
		{
			if (i == s) continue;
			if (ip == session[i].ip) sessionkill(i, "Duplicate IP address");
			if (!session[s].walled_garden && !session[i].walled_garden && strcasecmp(user, session[i].user) == 0)
				sessionkill(i, "Duplicate session for users");
		}
	}

		// Add the route for this session.
		//
		// Static IPs need to be routed. Anything else
		// is part of the IP address pool and is already routed,
		// it just needs to be added to the IP cache.
	if (session[s].ip_pool_index == -1) // static ip
		routeset(s, session[s].ip, 0, 0, 1);
	else
		cache_ipmap(session[s].ip, s);

	for (r = 0; r < MAXROUTE && session[s].route[r].ip; r++)
		routeset(s, session[s].route[r].ip, session[s].route[r].mask, session[s].ip, 1);

	if (!session[s].unique_id)
	{
		// did this session just finish radius?
		log(3, session[s].ip, s, t, "Sending initial IPCP to client\n");
		sendipcp(t, s);
		session[s].unique_id = ++last_id;
	}

	// Run the plugin's against this new session.
	{
		struct param_new_session data = { &tunnel[t], &session[s] };
		run_plugins(PLUGIN_NEW_SESSION, &data);
	}

	// Force throttling on or off (Actually : refresh the current throttling status)
	// This has the advantage of cleaning up after another throttled user who may have left
	// firewall rules lying around
	throttle_session(s, session[s].throttle);

	session[s].last_packet = time_now;

	{
		char *sessionip, *tunnelip;
		sessionip = strdup(inet_toa(htonl(session[s].ip)));
		tunnelip = strdup(inet_toa(htonl(tunnel[t].ip)));
		log(2, session[s].ip, s, t, "Login by %s at %s from %s (%s)\n",
				session[s].user, sessionip, tunnelip, tunnel[t].hostname);
		if (sessionip) free(sessionip);
		if (tunnelip) free(tunnelip);
	}

	cluster_send_session(s);	// Mark it as dirty, and needing to the flooded to the cluster.

	return 1;       // RADIUS OK and IP allocated, done...
}

//
// This session just got dropped on us by the master or something.
// Make sure our tables up up to date...
//
int load_session(sessionidt s, sessiont *new)
{
	int i;

		// Sanity checks.
	if (new->ip_pool_index >= MAXIPPOOL ||
		new->tunnel >= MAXTUNNEL)
	{
		log(0,0,s,0, "Strange session update received!\n");
			// FIXME! What to do here?
		return 0;
	}

		//
		// Ok. All sanity checks passed. Now we're committed to
		// loading the new session.
		//

	session[s].tunnel = new->tunnel; // For logging in cache_ipmap


	if (new->ip != session[s].ip)	// Changed ip. fix up hash tables.
	{
		if (session[s].ip)	// If there's an old one, remove it.
		{
			// Remove any routes if the IP has changed
			for (i = 0; i < MAXROUTE && session[s].route[i].ip; i++)
			{
				routeset(s, session[s].route[i].ip, session[s].route[i].mask, session[s].ip, 0);
				session[s].route[i].ip = 0;
			}

			if (session[s].ip_pool_index == -1) // static IP
				routeset(s, session[s].ip, 0, 0, 0);
			else		// It's part of the IP pool, remove it manually.
				uncache_ipmap(session[s].ip);
		}

		if (new->ip)
		{
			// If there's a new one, add it.
			if (new->ip_pool_index == -1)
				routeset(s, new->ip, 0, 0, 1);
			else
				cache_ipmap(new->ip, s);
		}
	}

	// Update routed networks
	for (i = 0; i < MAXROUTE && (session[s].route[i].ip || new->route[i].ip); i++)
	{
		if (new->route[i].ip == session[s].route[i].ip &&
		    new->route[i].mask == session[s].route[i].mask)
			continue;

		if (session[s].route[i].ip) // Remove the old one if it exists.
			routeset(s, session[s].route[i].ip, session[s].route[i].mask, session[s].ip, 0);

		if (new->route[i].ip)	// Add the new one if it exists.
			routeset(s, new->route[i].ip, new->route[i].mask, new->ip, 1);
	}

	if (new->tunnel && s > config->cluster_highest_sessionid)	// Maintain this in the slave. It's used
					// for walking the sessions to forward byte counts to the master.
		config->cluster_highest_sessionid = s;

	memcpy(&session[s], new, sizeof(session[s]));	// Copy over..

		// Do fixups into address pool.
	if (new->ip_pool_index != -1)
		fix_address_pool(s);

	return 1;
}

#ifdef RINGBUFFER
void ringbuffer_dump(FILE *stream)
{
	int i = ringbuffer->head;

	while (i != ringbuffer->tail)
	{
		if (*ringbuffer->buffer[i].message)
			fprintf(stream, "%d-%s", ringbuffer->buffer[i].level, ringbuffer->buffer[i].message);
		if (++i == ringbuffer->tail) break;
		if (i == RINGBUFFER_SIZE) i = 0;
	}
}
#endif

void initplugins()
{
	int i;

	loaded_plugins = ll_init();
	// Initialize the plugins to nothing
	for (i = 0; i < MAX_PLUGIN_TYPES; i++)
		plugins[i] = ll_init();
}

static void *open_plugin(char *plugin_name, int load)
{
	char path[256] = "";

	snprintf(path, 256, PLUGINDIR "/%s.so", plugin_name);
	log(2, 0, 0, 0, "%soading plugin from %s\n", load ? "L" : "Un-l", path);
	return dlopen(path, RTLD_NOW);
}

void add_plugin(char *plugin_name)
{
	static struct pluginfuncs funcs = {
		_log,
		_log_hex,
		inet_toa,
		sessionbyuser,
		sessiontbysessionidt,
		sessionidtbysessiont,
		sessionkill,
		radiusnew,
		radiussend,
	};

	void *p = open_plugin(plugin_name, 1);
	int (*initfunc)(struct pluginfuncs *);
	int i;

	if (!p)
	{
		log(1, 0, 0, 0, "   Plugin load failed: %s\n", dlerror());
		return;
	}

	if (ll_contains(loaded_plugins, p))
	{
		dlclose(p);
		return;
	}

	{
		int *v = dlsym(p, "__plugin_api_version");
		if (!v || *v != PLUGIN_API_VERSION)
		{
			log(1, 0, 0, 0, "   Plugin load failed: API version mismatch: %s\n", dlerror());
			dlclose(p);
			return;
		}
	}

	if ((initfunc = dlsym(p, "plugin_init")))
	{
		if (!initfunc(&funcs))
		{
			log(1, 0, 0, 0, "   Plugin load failed: plugin_init() returned FALSE: %s\n", dlerror());
			dlclose(p);
			return;
		}
	}

	ll_push(loaded_plugins, p);

	for (i = 0; i < max_plugin_functions; i++)
	{
		void *x;
		if (plugin_functions[i] && (x = dlsym(p, plugin_functions[i])))
		{
			log(3, 0, 0, 0, "   Supports function \"%s\"\n", plugin_functions[i]);
			ll_push(plugins[i], x);
		}
	}

	log(2, 0, 0, 0, "   Loaded plugin %s\n", plugin_name);
}

static void run_plugin_done(void *plugin)
{
	int (*donefunc)(void) = dlsym(plugin, "plugin_done");

	if (donefunc)
		donefunc();
}

void remove_plugin(char *plugin_name)
{
	void *p = open_plugin(plugin_name, 0);
	int i;

	if (!p)
		return;

	for (i = 0; i < max_plugin_functions; i++)
	{
		void *x;
		if (plugin_functions[i] && (x = dlsym(p, plugin_functions[i])))
			ll_delete(plugins[i], x);
	}

	if (ll_contains(loaded_plugins, p))
	{
		ll_delete(loaded_plugins, p);
		run_plugin_done(p);
	}

	dlclose(p);
	log(2, 0, 0, 0, "Removed plugin %s\n", plugin_name);
}

int run_plugins(int plugin_type, void *data)
{
	int (*func)(void *data);
	if (!plugins[plugin_type] || plugin_type > max_plugin_functions) return 1;

	ll_reset(plugins[plugin_type]);
	while ((func = ll_next(plugins[plugin_type])))
	{
		int rc;
		rc = func(data);
		if (rc == PLUGIN_RET_STOP) return 1;
		if (rc == PLUGIN_RET_ERROR) return 0;
	}
	return 1;
}

void plugins_done()
{
	void *p;

	ll_reset(loaded_plugins);
	while ((p = ll_next(loaded_plugins)))
		run_plugin_done(p);
}

void processcontrol(u8 * buf, int len, struct sockaddr_in *addr)
{
	char *resp;
	int l;
	struct param_control param = { buf, len, ntohl(addr->sin_addr.s_addr), ntohs(addr->sin_port), NULL, 0, 0 };


	if (log_stream && config->debug >= 4)
	{
		log(4, ntohl(addr->sin_addr.s_addr), 0, 0, "Received ");
		dump_packet(buf, log_stream);
	}

	resp = calloc(1400, 1);
	l = new_packet(PKT_RESP_ERROR, resp);
	*(int *)(resp + 6) = *(int *)(buf + 6);

	param.type = ntohs(*(short *)(buf + 2));
	param.id = ntohl(*(int *)(buf + 6));
	param.data_length = ntohs(*(short *)(buf + 4)) - 10;
	param.data = (param.data_length > 0) ? (char *)(buf + 10) : NULL;
	param.response = resp;
	param.response_length = l;

	run_plugins(PLUGIN_CONTROL, &param);

	if (param.send_response)
	{
		send_packet(controlfd, ntohl(addr->sin_addr.s_addr), ntohs(addr->sin_port), param.response, param.response_length);
		log(4, ntohl(addr->sin_addr.s_addr), 0, 0, "Sent Control packet response\n");
	}

	free(resp);
}

/*
 * HACK
 * Go through all of the tunnels and do some cleanups
 */
void tunnel_clean()
{
	int i;

	log(1, 0, 0, 0, "Cleaning tunnels array\n");

	for (i = 1; i < MAXTUNNEL; i++)
	{
		if (!tunnel[i].ip
				|| !*tunnel[i].hostname
				|| (tunnel[i].state == TUNNELDIE && tunnel[i].die >= time_now))
		{
			tunnelclear(i);
		}
	}
}

void tunnelclear(tunnelidt t)
{
	if (!t) return;
	memset(&tunnel[t], 0, sizeof(tunnel[t]));
	tunnel[t].state = TUNNELFREE;
}

tunnelidt new_tunnel()
{
	tunnelidt i;
	for (i = 1; i < MAXTUNNEL; i++)
	{
		if (tunnel[i].state == TUNNELFREE)
		{
			log(4, 0, 0, i, "Assigning tunnel ID %d\n", i);
			if (i > config->cluster_highest_tunnelid)
				config->cluster_highest_tunnelid = i;
			return i;
		}
	}
	log(0, 0, 0, 0, "Can't find a free tunnel! There shouldn't be this many in use!\n");
	return 0;
}

//
// We're becoming the master. Do any required setup..
//
// This is principally telling all the plugins that we're
// now a master, and telling them about all the sessions
// that are active too..
//
void become_master(void)
{
	int s, t;
	run_plugins(PLUGIN_BECOME_MASTER, NULL);

	for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
	{
		if (!session[s].tunnel) // Not an in-use session.
			continue;

		run_plugins(PLUGIN_NEW_SESSION_MASTER, &session[s]);
	}

	// Rebuild vlan -> tunnel mapping
	memset(vlan_tunnel_map, 0, sizeof(vlan_tunnel_map));
	for (t = 1; t < config->cluster_highest_tunnelid; t++)
	{
		if (tunnel[t].vlan)
			vlan_tunnel_map[tunnel[t].vlan] = t;
	}
}



int cmd_show_hist_idle(struct cli_def *cli, char *command, char **argv, int argc)
{
	int s, i;
	int count = 0;
	int buckets[64];

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	time(&time_now);
	for (i = 0; i < 64;++i) buckets[i] = 0;

	for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
	{
		int idle;
		if (!session[s].tunnel)
			continue;

		idle = time_now - session[s].last_packet;
		idle /= 5 ; // In multiples of 5 seconds.
		if (idle < 0)
			idle = 0;
		if (idle > 63)
			idle = 63;

		++count;
		++buckets[idle];
	}

	for (i = 0; i < 63; ++i)
	{
		cli_print(cli, "%3d seconds  : %7.2f%% (%6d)", i * 5, (double) buckets[i] * 100.0 / count , buckets[i]);
	}
	cli_print(cli, "lots of secs : %7.2f%% (%6d)", (double) buckets[63] * 100.0 / count , buckets[i]);
	cli_print(cli, "%d total sessions open.", count);
	return CLI_OK;
}

int cmd_show_hist_open(struct cli_def *cli, char *command, char **argv, int argc)
{
	int s, i;
	int count = 0;
	int buckets[64];

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	time(&time_now);
	for (i = 0; i < 64;++i) buckets[i] = 0;

	for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
	{
		int open = 0, d;
		if (!session[s].tunnel)
			continue;

		d = time_now - session[s].opened;
		if (d < 0)
			d = 0;
		while (d > 1 && open < 32)
		{
			++open;
			d >>= 1; // half.
		}
		++count;
		++buckets[open];
	}

	s = 1;
	for (i = 0; i  < 30; ++i)
	{
		cli_print(cli, " < %8d seconds : %7.2f%% (%6d)", s, (double) buckets[i] * 100.0 / count , buckets[i]);
		s <<= 1;
	}
	cli_print(cli, "%d total sessions open.", count);
	return CLI_OK;
}

/* Unhide an avp.
 *
 * This unencodes the AVP using the L2TP CHAP secret and the
 * previously stored random vector. It replaces the hidden data with
 * the cleartext data and returns the length of the cleartext data
 * (including the AVP "header" of 6 bytes).
 *
 * Based on code from rp-l2tpd by Roaring Penguin Software Inc.
 */
int unhide_avp(u8 *avp, tunnelidt t, sessionidt s, u16 length)
{
	MD5_CTX ctx;
	u8 *cursor;
	u8 digest[16];
	u8 working_vector[16];
	uint16_t hidden_length;
	u8 type[2];
	size_t done, todo;
	u8 *output;

	// Find the AVP type.
	type[0] = *(avp + 4);
	type[1] = *(avp + 5);

	// Line up with the hidden data
	cursor = output = avp + 6;

	// Compute initial pad
	MD5Init(&ctx);
	MD5Update(&ctx, type, 2);
	MD5Update(&ctx, config->l2tpsecret, strlen(config->l2tpsecret));
	MD5Update(&ctx, session[s].random_vector, session[s].random_vector_length);
	MD5Final(digest, &ctx);

	// Get hidden length
	hidden_length = ((uint16_t) (digest[0] ^ cursor[0])) * 256 + (uint16_t) (digest[1] ^ cursor[1]);

	// Keep these for later use
	working_vector[0] = *cursor;
	working_vector[1] = *(cursor + 1);
	cursor += 2;

	if (hidden_length > length - 8)
	{
		log(1, 0, s, t, "Hidden length %d too long in AVP of length %d\n", (int) hidden_length, (int) length);
		return 0;
	}

	/* Decrypt remainder */
	done = 2;
	todo = hidden_length;
	while (todo)
	{
		working_vector[done] = *cursor;
		*output = digest[done] ^ *cursor;
		++output;
		++cursor;
		--todo;
		++done;
		if (done == 16 && todo)
		{
			// Compute new digest
			done = 0;
			MD5Init(&ctx);
			MD5Update(&ctx, config->l2tpsecret, strlen(config->l2tpsecret));
			MD5Update(&ctx, &working_vector, 16);
			MD5Final(digest, &ctx);
		}
	}

	return hidden_length + 6;
}

sessionidt new_session(tunnelidt t)
{
	sessionidt s = 0;

	if (!sessionfree)
	{
		STAT(session_overflow);
	}
	else
	{
		u16 r;

		s = sessionfree;
		sessionfree = session[s].next;
		memset(&session[s], 0, sizeof(session[s]));

		if (s > config->cluster_highest_sessionid)
			config->cluster_highest_sessionid = s;

		// make a RADIUS session
		if (!(r = radiusnew(s)))
		{
			log(1, 0, s, t, "No free RADIUS sessions for session creation\n");
			sessionkill(s, "no free RADIUS sesions");
			return 0;
		}

		session[s].id = sessionid++;
		session[s].opened = time(NULL);
		session[s].tunnel = t;
		session[s].last_packet = time_now;
		{
			// Generate a random challenge
			int n;
			for (n = 0; n < 15; n++)
				radius[r].auth[n] = rand();
		}
		STAT(session_created);
	}
	return s;
}

// Locate a pseudo-tunnel from a vlan id
tunnelidt vlan_to_tunnel(u16 vlan)
{
	if (!vlan_tunnel_map[vlan])
	{
		tunnelidt t = 0;

		// If no tunnel exists, create a new one
		if (!(t = new_tunnel()))
		{
			log(0, 0, 0, 0, "Can't create a pesudo-tunnel for VLAN %u!\n", vlan);
			STAT(tunnel_overflow);
			return 0;
		}
		tunnelclear(t);
		log(1, 0, 0, t, "New pseudo-tunnel created for PPPoE VLAN %u\n", vlan);
		tunnel[t].vlan = vlan;
		tunnel[t].state = TUNNELOPEN;
		snprintf(tunnel[t].hostname, sizeof(tunnel[t].hostname), "PPPoE VLAN %d", vlan);
		STAT(tunnel_created);
		vlan_tunnel_map[vlan] = t;
	}
	return vlan_tunnel_map[vlan];
}

