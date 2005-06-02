// L2TP Network Server
// Adrian Kennard 2002
// Copyright (c) 2003, 2004, 2005 Optus Internet Engineering
// Copyright (c) 2002 FireBrick (Andrews & Arnold Ltd / Watchfront Ltd) - GPL licenced
// vim: sw=8 ts=8

char const *cvs_id_l2tpns = "$Id: l2tpns.c,v 1.107 2005-06-02 11:32:30 bodea Exp $";

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#define SYSLOG_NAMES
#include <syslog.h>
#include <malloc.h>
#include <math.h>
#include <net/route.h>
#include <sys/mman.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
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

#ifdef BGP
#include "bgp.h"
#endif /* BGP */

// Globals
configt *config = NULL;		// all configuration
int tunfd = -1;			// tun interface file handle. (network device)
int udpfd = -1;			// UDP file handle
int controlfd = -1;		// Control signal handle
int clifd = -1;			// Socket listening for CLI connections.
int snoopfd = -1;		// UDP file handle for sending out intercept data
int *radfds = NULL;		// RADIUS requests file handles
int ifrfd = -1;			// File descriptor for routing, etc
int ifr6fd = -1;		// File descriptor for IPv6 routing, etc
static int rand_fd = -1;	// Random data source
time_t basetime = 0;		// base clock
char hostname[1000] = "";	// us.
static int tunidx;		// ifr_ifindex of tun device
static int syslog_log = 0;	// are we logging to syslog
static FILE *log_stream = 0;	// file handle for direct logging (i.e. direct into file, not via syslog).
extern int cluster_sockfd;	// Intra-cluster communications socket.
uint32_t last_id = 0;		// Unique ID for radius accounting

struct cli_session_actions *cli_session_actions = NULL;	// Pending session changes requested by CLI
struct cli_tunnel_actions *cli_tunnel_actions = NULL;	// Pending tunnel changes required by CLI

static void *ip_hash[256];	// Mapping from IP address to session structures.
struct ipv6radix {
	int sess;
	struct ipv6radix *branch;
} ipv6_hash[256];		// Mapping from IPv6 address to session structures.

// Traffic counters.
static uint32_t udp_rx = 0, udp_rx_pkt = 0, udp_tx = 0;
static uint32_t eth_rx = 0, eth_rx_pkt = 0;
uint32_t eth_tx = 0;

static uint32_t ip_pool_size = 1;	// Size of the pool of addresses used for dynamic address allocation.
time_t time_now = 0;			// Current time in seconds since epoch.
static char time_now_string[64] = {0};	// Current time as a string.
char main_quit = 0;			// True if we're in the process of exiting.
linked_list *loaded_plugins;
linked_list *plugins[MAX_PLUGIN_TYPES];

#define membersize(STRUCT, MEMBER) sizeof(((STRUCT *)0)->MEMBER)
#define CONFIG(NAME, MEMBER, TYPE) { NAME, offsetof(configt, MEMBER), membersize(configt, MEMBER), TYPE }

config_descriptt config_values[] = {
	CONFIG("debug", debug, INT),
	CONFIG("log_file", log_filename, STRING),
	CONFIG("pid_file", pid_file, STRING),
	CONFIG("random_device", random_device, STRING),
	CONFIG("l2tp_secret", l2tpsecret, STRING),
	CONFIG("primary_dns", default_dns1, IPv4),
	CONFIG("secondary_dns", default_dns2, IPv4),
	CONFIG("primary_radius", radiusserver[0], IPv4),
	CONFIG("secondary_radius", radiusserver[1], IPv4),
	CONFIG("primary_radius_port", radiusport[0], SHORT),
	CONFIG("secondary_radius_port", radiusport[1], SHORT),
	CONFIG("radius_accounting", radius_accounting, BOOL),
	CONFIG("radius_interim", radius_interim, INT),
	CONFIG("radius_secret", radiussecret, STRING),
	CONFIG("radius_authtypes", radius_authtypes_s, STRING),
	CONFIG("allow_duplicate_users", allow_duplicate_users, BOOL),
	CONFIG("bind_address", bind_address, IPv4),
	CONFIG("peer_address", peer_address, IPv4),
	CONFIG("send_garp", send_garp, BOOL),
	CONFIG("throttle_speed", rl_rate, UNSIGNED_LONG),
	CONFIG("throttle_buckets", num_tbfs, INT),
	CONFIG("accounting_dir", accounting_dir, STRING),
	CONFIG("setuid", target_uid, INT),
	CONFIG("dump_speed", dump_speed, BOOL),
	CONFIG("multi_read_count", multi_read_count, INT),
	CONFIG("scheduler_fifo", scheduler_fifo, BOOL),
	CONFIG("lock_pages", lock_pages, BOOL),
	CONFIG("icmp_rate", icmp_rate, INT),
	CONFIG("packet_limit", max_packets, INT),
	CONFIG("cluster_address", cluster_address, IPv4),
	CONFIG("cluster_interface", cluster_interface, STRING),
	CONFIG("cluster_hb_interval", cluster_hb_interval, INT),
	CONFIG("cluster_hb_timeout", cluster_hb_timeout, INT),
 	CONFIG("cluster_master_min_adv", cluster_master_min_adv, INT),
	CONFIG("ipv6_prefix", ipv6_prefix, IPv6),
	{ NULL, 0, 0, 0 },
};

static char *plugin_functions[] = {
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

// Counters for shutdown sessions
static sessiont shut_acct[8192];
static sessionidt shut_acct_n = 0;

tunnelt *tunnel = NULL;			// Array of tunnel structures.
sessiont *session = NULL;		// Array of session structures.
sessionlocalt *sess_local = NULL;	// Array of local per-session counters.
radiust *radius = NULL;			// Array of radius structures.
ippoolt *ip_address_pool = NULL;	// Array of dynamic IP addresses.
ip_filtert *ip_filters = NULL;	// Array of named filters.
static controlt *controlfree = 0;
struct Tstats *_statistics = NULL;
#ifdef RINGBUFFER
struct Tringbuffer *ringbuffer = NULL;
#endif

static void cache_ipmap(in_addr_t ip, int s);
static void uncache_ipmap(in_addr_t ip);
static void cache_ipv6map(struct in6_addr ip, int prefixlen, int s);
static void free_ip_address(sessionidt s);
static void dump_acct_info(int all);
static void sighup_handler(int sig);
static void sigalrm_handler(int sig);
static void sigterm_handler(int sig);
static void sigquit_handler(int sig);
static void sigchild_handler(int sig);
static void build_chap_response(char *challenge, uint8_t id, uint16_t challenge_length, char **challenge_response);
static void update_config(void);
static void read_config_file(void);
static void initplugins(void);
static int add_plugin(char *plugin_name);
static int remove_plugin(char *plugin_name);
static void plugins_done(void);
static void processcontrol(uint8_t *buf, int len, struct sockaddr_in *addr, int alen);
static tunnelidt new_tunnel(void);
static void unhide_value(uint8_t *value, size_t len, uint16_t type, uint8_t *vector, size_t vec_len);

// on slaves, alow BGP to withdraw cleanly before exiting
#define QUIT_DELAY	5

// return internal time (10ths since process startup), set f if given
static clockt now(double *f)
{
	struct timeval t;
	gettimeofday(&t, 0);
	if (f) *f = t.tv_sec + t.tv_usec / 1000000.0;
	return (t.tv_sec - basetime) * 10 + t.tv_usec / 100000 + 1;
}

// work out a retry time based on try number
// This is a straight bounded exponential backoff.
// Maximum re-try time is 32 seconds. (2^5).
clockt backoff(uint8_t try)
{
	if (try > 5) try = 5;                  // max backoff
	return now(NULL) + 10 * (1 << try);
}


//
// Log a debug message.  Typically called via the LOG macro
//
void _log(int level, sessionidt s, tunnelidt t, const char *format, ...)
{
	static char message[65536] = {0};
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
		ringbuffer->buffer[ringbuffer->tail].session = s;
		ringbuffer->buffer[ringbuffer->tail].tunnel = t;
		va_start(ap, format);
		vsnprintf(ringbuffer->buffer[ringbuffer->tail].message, 4095, format, ap);
		va_end(ap);
	}
#endif

	if (config->debug < level) return;

	va_start(ap, format);
	vsnprintf(message, sizeof(message), format, ap);

	if (log_stream)
		fprintf(log_stream, "%s %02d/%02d %s", time_now_string, t, s, message);
	else if (syslog_log)
		syslog(level + 2, "%02d/%02d %s", t, s, message); // We don't need LOG_EMERG or LOG_ALERT

	va_end(ap);
}

void _log_hex(int level, const char *title, const char *data, int maxsize)
{
	int i, j;
	const uint8_t *d = (const uint8_t *) data;

	if (config->debug < level) return;

	// No support for _log_hex to syslog
	if (log_stream)
	{
		_log(level, 0, 0, "%s (%d bytes):\n", title, maxsize);
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

// update a counter, accumulating 2^32 wraps
void increment_counter(uint32_t *counter, uint32_t *wrap, uint32_t delta)
{
	uint32_t new = *counter + delta;
	if (new < *counter)
		(*wrap)++;

	*counter = new;
}

// initialise the random generator
static void initrandom(char *source)
{
	static char path[sizeof(config->random_device)] = "*undefined*";

	// reinitialise only if we are forced to do so or if the config has changed
	if (source && !strncmp(path, source, sizeof(path)))
		return;

	// close previous source, if any
	if (rand_fd >= 0) close(rand_fd);

	rand_fd = -1;

	if (source)
	{
		// register changes
		snprintf(path, sizeof(path), "%s", source);

		if (*path == '/')
		{
			rand_fd = open(path, O_RDONLY|O_NONBLOCK);
			if (rand_fd < 0)
				LOG(0, 0, 0, "Error opening the random device %s: %s\n",
					path, strerror(errno));
		}
	}

	// no source: seed prng
	{
		unsigned seed = time_now ^ getpid();
		LOG(4, 0, 0, "Seeding the pseudo random generator: %u\n", seed);
		srand(seed);
	}
}

// fill buffer with random data
void random_data(uint8_t *buf, int len)
{
	int n = 0;

	CSTAT(random_data);
	if (rand_fd >= 0)
	{
		n = read(rand_fd, buf, len);
		if (n >= len) return;
		if (n < 0)
		{
			if (errno != EAGAIN)
			{
				LOG(0, 0, 0, "Error reading from random source: %s\n",
					strerror(errno));

				// fall back to rand()
				initrandom(0);
			}

			n = 0;
		}
	}

	// append missing data
	while (n < len)
		// not using the low order bits from the prng stream
		buf[n++] = (rand() >> 4) & 0xff;
}

// Add a route
//
// This adds it to the routing table, advertises it
// via BGP if enabled, and stuffs it into the
// 'sessionbyip' cache.
//
// 'ip' and 'mask' must be in _host_ order.
//
static void routeset(sessionidt s, in_addr_t ip, in_addr_t mask, in_addr_t gw, int add)
{
	struct rtentry r;
	int i;

	if (!mask) mask = 0xffffffff;

	ip &= mask;		// Force the ip to be the first one in the route.

	memset(&r, 0, sizeof(r));
	r.rt_dev = config->tundevice;
	r.rt_dst.sa_family = AF_INET;
	*(uint32_t *) & (((struct sockaddr_in *) &r.rt_dst)->sin_addr.s_addr) = htonl(ip);
	r.rt_gateway.sa_family = AF_INET;
	*(uint32_t *) & (((struct sockaddr_in *) &r.rt_gateway)->sin_addr.s_addr) = htonl(gw);
	r.rt_genmask.sa_family = AF_INET;
	*(uint32_t *) & (((struct sockaddr_in *) &r.rt_genmask)->sin_addr.s_addr) = htonl(mask);
	r.rt_flags = (RTF_UP | RTF_STATIC);
	if (gw)
		r.rt_flags |= RTF_GATEWAY;
	else if (mask == 0xffffffff)
		r.rt_flags |= RTF_HOST;

	LOG(1, s, 0, "Route %s %s/%s%s%s\n", add ? "add" : "del",
	    fmtaddr(htonl(ip), 0), fmtaddr(htonl(mask), 1),
	    gw ? " via" : "", gw ? fmtaddr(htonl(gw), 2) : "");

	if (ioctl(ifrfd, add ? SIOCADDRT : SIOCDELRT, (void *) &r) < 0)
		LOG(0, 0, 0, "routeset() error in ioctl: %s\n", strerror(errno));

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

void route6set(sessionidt s, struct in6_addr ip, int prefixlen, int add)
{
	struct in6_rtmsg rt;
	char ipv6addr[INET6_ADDRSTRLEN];

	if (ifr6fd < 0)
	{
		LOG(0, 0, 0, "Asked to set IPv6 route, but IPv6 not setup.\n");
		return;
	}

	memset(&rt, 0, sizeof(rt));

	memcpy(&rt.rtmsg_dst, &ip, sizeof(struct in6_addr));
	rt.rtmsg_dst_len = prefixlen;
	rt.rtmsg_metric = 1;
	rt.rtmsg_flags = RTF_UP;
	rt.rtmsg_ifindex = tunidx;

	LOG(1, 0, 0, "Route %s %s/%d\n",
	    add ? "add" : "del",
	    inet_ntop(AF_INET6, &ip, ipv6addr, INET6_ADDRSTRLEN),
	    prefixlen);

	if (ioctl(ifr6fd, add ? SIOCADDRT : SIOCDELRT, (void *) &rt) < 0)
		LOG(0, 0, 0, "route6set() error in ioctl: %s\n",
				strerror(errno));

	// FIXME: need to add BGP routing (RFC2858)

	if (s)
	{
		if (!add)	// Are we deleting a route?
			s = 0;	// Caching the session as '0' is the same as uncaching.

		cache_ipv6map(ip, prefixlen, s);
	}
	
	return;
}

// defined in linux/ipv6.h, but tricky to include from user-space
// TODO: move routing to use netlink rather than ioctl
struct in6_ifreq {
	struct in6_addr ifr6_addr;
	__u32 ifr6_prefixlen;
	unsigned int ifr6_ifindex;
};

//
// Set up TUN interface
static void inittun(void)
{
	struct ifreq ifr;
	struct in6_ifreq ifr6;
	struct sockaddr_in sin = {0};
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;

	tunfd = open(TUNDEVICE, O_RDWR);
	if (tunfd < 0)
	{                          // fatal
		LOG(0, 0, 0, "Can't open %s: %s\n", TUNDEVICE, strerror(errno));
		exit(1);
	}
	{
		int flags = fcntl(tunfd, F_GETFL, 0);
		fcntl(tunfd, F_SETFL, flags | O_NONBLOCK);
	}
	if (ioctl(tunfd, TUNSETIFF, (void *) &ifr) < 0)
	{
		LOG(0, 0, 0, "Can't set tun interface: %s\n", strerror(errno));
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
		LOG(0, 0, 0, "Error setting tun address: %s\n", strerror(errno));
		exit(1);
	}
	/* Bump up the qlen to deal with bursts from the network */
	ifr.ifr_qlen = 1000;
	if (ioctl(ifrfd, SIOCSIFTXQLEN, (void *) &ifr) < 0)
	{
		LOG(0, 0, 0, "Error setting tun queue length: %s\n", strerror(errno));
		exit(1);
	}
	ifr.ifr_flags = IFF_UP;
	if (ioctl(ifrfd, SIOCSIFFLAGS, (void *) &ifr) < 0)
	{
		LOG(0, 0, 0, "Error setting tun flags: %s\n", strerror(errno));
		exit(1);
	}
	if (ioctl(ifrfd, SIOCGIFINDEX, (void *) &ifr) < 0)
	{
		LOG(0, 0, 0, "Error getting tun ifindex: %s\n", strerror(errno));
		exit(1);
	}
	tunidx = ifr.ifr_ifindex;

	// Only setup IPv6 on the tun device if we have a configured prefix
	if (config->ipv6_prefix.s6_addr[0] > 0) {
		ifr6fd = socket(PF_INET6, SOCK_DGRAM, 0);

		// Link local address is FE80::1
		memset(&ifr6.ifr6_addr, 0, sizeof(ifr6.ifr6_addr));
		ifr6.ifr6_addr.s6_addr[0] = 0xFE;
		ifr6.ifr6_addr.s6_addr[1] = 0x80;
		ifr6.ifr6_addr.s6_addr[15] = 1;
		ifr6.ifr6_prefixlen = 64;
		ifr6.ifr6_ifindex = ifr.ifr_ifindex;
		if (ioctl(ifr6fd, SIOCSIFADDR, (void *) &ifr6) < 0)
		{
			LOG(0, 0, 0, "Error setting tun IPv6 link local address:"
				" %s\n", strerror(errno));
		}

		// Global address is prefix::1
		memset(&ifr6.ifr6_addr, 0, sizeof(ifr6.ifr6_addr));
		ifr6.ifr6_addr = config->ipv6_prefix;
		ifr6.ifr6_addr.s6_addr[15] = 1;
		ifr6.ifr6_prefixlen = 64;
		ifr6.ifr6_ifindex = ifr.ifr_ifindex;
		if (ioctl(ifr6fd, SIOCSIFADDR, (void *) &ifr6) < 0)
		{
			LOG(0, 0, 0, "Error setting tun IPv6 global address: %s\n",
				strerror(errno));
		}
	}
}

// set up UDP port
static void initudp(void)
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
		LOG(0, 0, 0, "Error in UDP bind: %s\n", strerror(errno));
		exit(1);
	}
	snoopfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	// Control
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(NSCTL_PORT);
	controlfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	setsockopt(controlfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (bind(controlfd, (void *) &addr, sizeof(addr)) < 0)
	{
		LOG(0, 0, 0, "Error in control bind: %s\n", strerror(errno));
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

static int lookup_ipmap(in_addr_t ip)
{
	uint8_t *a = (uint8_t *) &ip;
	uint8_t **d = (uint8_t **) ip_hash;

	if (!(d = (uint8_t **) d[(size_t) *a++])) return 0;
	if (!(d = (uint8_t **) d[(size_t) *a++])) return 0;
	if (!(d = (uint8_t **) d[(size_t) *a++])) return 0;

	return (int) (intptr_t) d[(size_t) *a];
}

static int lookup_ipv6map(struct in6_addr ip)
{
	struct ipv6radix *curnode;
	int i;
	int s;
	char ipv6addr[INET6_ADDRSTRLEN];

	curnode = &ipv6_hash[ip.s6_addr[0]];
	i = 1;
	s = curnode->sess;

	while (s == 0 && i < 15 && curnode->branch != NULL)
	{
		curnode = &curnode->branch[ip.s6_addr[i]];
		s = curnode->sess;
		i++;
	}

	LOG(4, s, session[s].tunnel, "Looking up address %s and got %d\n",
    			inet_ntop(AF_INET6, &ip, ipv6addr,
				INET6_ADDRSTRLEN),
			s);

	return s;
}

sessionidt sessionbyip(in_addr_t ip)
{
	int s = lookup_ipmap(ip);
	CSTAT(sessionbyip);

	if (s > 0 && s < MAXSESSION && session[s].opened)
		return (sessionidt) s;

	return 0;
}

sessionidt sessionbyipv6(struct in6_addr ip)
{
	int s;
	CSTAT(sessionbyipv6);

	if (!memcmp(&config->ipv6_prefix, &ip, 8) ||
		(ip.s6_addr[0] == 0xFE && ip.s6_addr[1] == 0x80 &&
		 (ip.s6_addr16[1] == ip.s6_addr16[2] == ip.s6_addr16[3] == 0))) {
		s = lookup_ipmap(*(in_addr_t *) &ip.s6_addr[8]);
	} else {
		s = lookup_ipv6map(ip);
	}

	if (s > 0 && s < MAXSESSION && session[s].opened)
		return s;

	return 0;
}

//
// Take an IP address in HOST byte order and
// add it to the sessionid by IP cache.
//
// (It's actually cached in network order)
//
static void cache_ipmap(in_addr_t ip, int s)
{
	in_addr_t nip = htonl(ip);	// MUST be in network order. I.e. MSB must in be ((char *) (&ip))[0]
	uint8_t *a = (uint8_t *) &nip;
	uint8_t **d = (uint8_t **) ip_hash;
	int i;

	for (i = 0; i < 3; i++)
	{
		if (!d[(size_t) a[i]])
		{
			if (!(d[(size_t) a[i]] = calloc(256, sizeof(void *))))
				return;
		}

		d = (uint8_t **) d[(size_t) a[i]];
	}

	d[(size_t) a[3]] = (uint8_t *) (intptr_t) s;

	if (s > 0)
		LOG(4, s, session[s].tunnel, "Caching ip address %s\n", fmtaddr(nip, 0));

	else if (s == 0)
		LOG(4, 0, 0, "Un-caching ip address %s\n", fmtaddr(nip, 0));
	// else a map to an ip pool index.
}

static void uncache_ipmap(in_addr_t ip)
{
	cache_ipmap(ip, 0);	// Assign it to the NULL session.
}

static void cache_ipv6map(struct in6_addr ip, int prefixlen, int s)
{
	int i;
	int bytes;
	struct ipv6radix *curnode;
	char ipv6addr[INET6_ADDRSTRLEN];

	curnode = &ipv6_hash[ip.s6_addr[0]];

	bytes = prefixlen >> 3;
	i = 1;
	while (i < bytes) {
		if (curnode->branch == NULL)
		{
			if (!(curnode->branch = calloc(256,
					sizeof (struct ipv6radix))))
				return;
		}
		curnode = &curnode->branch[ip.s6_addr[i]];
		i++;
	}

	curnode->sess = s;

	if (s > 0)
		LOG(4, s, session[s].tunnel, "Caching ip address %s/%d\n",
	    			inet_ntop(AF_INET6, &ip, ipv6addr, 
					INET6_ADDRSTRLEN),
				prefixlen);
	else if (s == 0)
		LOG(4, 0, 0, "Un-caching ip address %s/%d\n",
	    			inet_ntop(AF_INET6, &ip, ipv6addr, 
					INET6_ADDRSTRLEN),
				prefixlen);
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
		e = (char **) d[i];
		for (j = 0; j < 256; ++j)
		{
			if (!e[j])
				continue;
			f = (char **) e[j];
			for (k = 0; k < 256; ++k)
			{
				if (!f[k])
					continue;
				g = (char **)f[k];
				for (l = 0; l < 256; ++l)
				{
					if (!g[l])
						continue;
					cli_print(cli, "%7d %d.%d.%d.%d", (int) (intptr_t) g[l], i, j, k, l);
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
	CSTAT(sessionbyuser);

	for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
	{
		if (!session[s].opened)
			continue;

		if (session[s].walled_garden)
			continue;		// Skip walled garden users.

		if (!strncmp(session[s].user, username, 128))
			return s;

	}
	return 0;	// Not found.
}

void send_garp(in_addr_t ip)
{
	int s;
	struct ifreq ifr;
	uint8_t mac[6];

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
	{
		LOG(0, 0, 0, "Error creating socket for GARP: %s\n", strerror(errno));
		return;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "eth0", sizeof(ifr.ifr_name) - 1);
	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
	{
		LOG(0, 0, 0, "Error getting eth0 hardware address for GARP: %s\n", strerror(errno));
		close(s);
		return;
	}
	memcpy(mac, &ifr.ifr_hwaddr.sa_data, 6*sizeof(char));
	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
	{
		LOG(0, 0, 0, "Error getting eth0 interface index for GARP: %s\n", strerror(errno));
		close(s);
		return;
	}
	close(s);
	sendarp(ifr.ifr_ifindex, mac, ip);
}

static sessiont *sessiontbysessionidt(sessionidt s)
{
	if (!s || s >= MAXSESSION) return NULL;
	return &session[s];
}

static sessionidt sessionidtbysessiont(sessiont *s)
{
	sessionidt val = s-session;
	if (s < session || val >= MAXSESSION) return 0;
	return val;
}

// actually send a control message for a specific tunnel
void tunnelsend(uint8_t * buf, uint16_t l, tunnelidt t)
{
	struct sockaddr_in addr;

	CSTAT(tunnelsend);

	if (!t)
	{
		static int backtrace_count = 0;
		LOG(0, 0, t, "tunnelsend called with 0 as tunnel id\n");
		STAT(tunnel_tx_errors);
		log_backtrace(backtrace_count, 5)
		return;
	}

	if (!tunnel[t].ip)
	{
		static int backtrace_count = 0;
		LOG(1, 0, t, "Error sending data out tunnel: no remote endpoint (tunnel not set up)\n");
		log_backtrace(backtrace_count, 5)
		STAT(tunnel_tx_errors);
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	*(uint32_t *) & addr.sin_addr = htonl(tunnel[t].ip);
	addr.sin_port = htons(tunnel[t].port);

	// sequence expected, if sequence in message
	if (*buf & 0x08) *(uint16_t *) (buf + ((*buf & 0x40) ? 10 : 8)) = htons(tunnel[t].nr);

	// If this is a control message, deal with retries
	if (*buf & 0x80)
	{
		tunnel[t].last = time_now; // control message sent
		tunnel[t].retry = backoff(tunnel[t].try); // when to resend
		if (tunnel[t].try > 1)
		{
			STAT(tunnel_retries);
			LOG(3, 0, t, "Control message resend try %d\n", tunnel[t].try);
		}
	}

	if (sendto(udpfd, buf, l, 0, (void *) &addr, sizeof(addr)) < 0)
	{
		LOG(0, ntohs((*(uint16_t *) (buf + 6))), t, "Error sending data out tunnel: %s (udpfd=%d, buf=%p, len=%d, dest=%s)\n",
				strerror(errno), udpfd, buf, l, inet_ntoa(addr.sin_addr));
		STAT(tunnel_tx_errors);
		return;
	}

	LOG_HEX(5, "Send Tunnel Data", buf, l);
	STAT(tunnel_tx_packets);
	INC_STAT(tunnel_tx_bytes, l);
}

//
// Tiny helper function to write data to
// the 'tun' device.
//
int tun_write(uint8_t * data, int size)
{
	return write(tunfd, data, size);
}

// process outgoing (to tunnel) IP
//
static void processipout(uint8_t * buf, int len)
{
	sessionidt s;
	sessiont *sp;
	tunnelidt t;
	in_addr_t ip;

	char *data = buf;	// Keep a copy of the originals.
	int size = len;

	uint8_t b[MAXETHER + 20];

	CSTAT(processipout);

	if (len < MIN_IP_SIZE)
	{
		LOG(1, 0, 0, "Short IP, %d bytes\n", len);
		STAT(tun_rx_errors);
		return;
	}
	if (len >= MAXETHER)
	{
		LOG(1, 0, 0, "Oversize IP packet %d bytes\n", len);
		STAT(tun_rx_errors);
		return;
	}

	// Skip the tun header
	buf += 4;
	len -= 4;

	// Got an IP header now
	if (*(uint8_t *)(buf) >> 4 != 4)
	{
		LOG(1, 0, 0, "IP: Don't understand anything except IPv4\n");
		return;
	}

	ip = *(uint32_t *)(buf + 16);
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
			LOG(4, 0, 0, "IP: Sending ICMP host unreachable to %s\n", fmtaddr(*(in_addr_t *)(buf + 12), 0));
			host_unreachable(*(in_addr_t *)(buf + 12), *(uint16_t *)(buf + 4), ip, buf, (len < 64) ? 64 : len);
		}
		return;
	}
	t = session[s].tunnel;
	sp = &session[s];

	// DoS prevention: enforce a maximum number of packets per 0.1s for a session
	if (config->max_packets > 0)
	{
		if (sess_local[s].last_packet_out == TIME)
		{
			int max = config->max_packets;

			// All packets for throttled sessions are handled by the
			// master, so further limit by using the throttle rate.
			// A bit of a kludge, since throttle rate is in kbps,
			// but should still be generous given our average DSL
			// packet size is 200 bytes: a limit of 28kbps equates
			// to around 180 packets per second.
			if (!config->cluster_iam_master && sp->throttle_out && sp->throttle_out < max)
				max = sp->throttle_out;

			if (++sess_local[s].packets_out > max)
			{
				sess_local[s].packets_dropped++;
				return;
			}
		}
		else
		{
			if (sess_local[s].packets_dropped)
			{
				INC_STAT(tun_rx_dropped, sess_local[s].packets_dropped);
				LOG(3, s, t, "Dropped %u/%u packets to %s for %suser %s\n",
					sess_local[s].packets_dropped, sess_local[s].packets_out,
					fmtaddr(ip, 0), sp->throttle_out ? "throttled " : "",
					sp->user);
			}

			sess_local[s].last_packet_out = TIME;
			sess_local[s].packets_out = 1;
			sess_local[s].packets_dropped = 0;
		}
	}

	// run access-list if any
	if (session[s].filter_out && !ip_filter(buf, len, session[s].filter_out - 1))
		return;

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

	LOG(5, s, t, "Ethernet -> Tunnel (%d bytes)\n", len);

	// Add on L2TP header
	{
		uint8_t *p = makeppp(b, sizeof(b), buf, len, t, s, PPPIP);
		if (!p) return;
		tunnelsend(b, len + (p-b), t); // send it...
	}

	// Snooping this session, send it to intercept box
	if (sp->snoop_ip && sp->snoop_port)
		snoop_send_packet(buf, len, sp->snoop_ip, sp->snoop_port);

	increment_counter(&sp->cout, &sp->cout_wrap, len); // byte count
	sp->cout_delta += len;
	sp->pout++;
	udp_tx += len;

	sess_local[s].cout += len;	// To send to master..
	sess_local[s].pout++;
}

// process outgoing (to tunnel) IPv6
//
static void processipv6out(uint8_t * buf, int len)
{
	sessionidt s;
	sessiont *sp;
	tunnelidt t;
	in_addr_t ip;
	struct in6_addr ip6;

	char *data = buf;	// Keep a copy of the originals.
	int size = len;

	uint8_t b[MAXETHER + 20];

	CSTAT(processipv6out);

	if (len < MIN_IP_SIZE)
	{
		LOG(1, 0, 0, "Short IPv6, %d bytes\n", len);
		STAT(tunnel_tx_errors);
		return;
	}
	if (len >= MAXETHER)
	{
		LOG(1, 0, 0, "Oversize IPv6 packet %d bytes\n", len);
		STAT(tunnel_tx_errors);
		return;
	}

	// Skip the tun header
	buf += 4;
	len -= 4;

	// Got an IP header now
	if (*(uint8_t *)(buf) >> 4 != 6)
	{
		LOG(1, 0, 0, "IP: Don't understand anything except IPv6\n");
		return;
	}

	ip6 = *(struct in6_addr *)(buf+24);
	s = sessionbyipv6(ip6);

	if (s == 0)
	{
		ip = *(uint32_t *)(buf + 32);
		s = sessionbyip(ip);
	}
	
	if (s == 0)
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
			// FIXME: Should send icmp6 host unreachable
		}
		return;
	}
	t = session[s].tunnel;
	sp = &session[s];

	// FIXME: add DoS prevention/filters?

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

	LOG(5, s, t, "Ethernet -> Tunnel (%d bytes)\n", len);

	// Add on L2TP header
	{
		uint8_t *p = makeppp(b, sizeof(b), buf, len, t, s, PPPIPV6);
		if (!p) return;
		tunnelsend(b, len + (p-b), t); // send it...
	}

	// Snooping this session, send it to intercept box
	if (sp->snoop_ip && sp->snoop_port)
		snoop_send_packet(buf, len, sp->snoop_ip, sp->snoop_port);

	increment_counter(&sp->cout, &sp->cout_wrap, len); // byte count
	sp->cout_delta += len;
	sp->pout++;
	udp_tx += len;

	sess_local[s].cout += len;	// To send to master..
	sess_local[s].pout++;
}

//
// Helper routine for the TBF filters.
// Used to send queued data in to the user!
//
static void send_ipout(sessionidt s, uint8_t *buf, int len)
{
	sessiont *sp;
	tunnelidt t;
	in_addr_t ip;

	uint8_t b[MAXETHER + 20];

	if (len < 0 || len > MAXETHER)
	{
		LOG(1, 0, 0, "Odd size IP packet: %d bytes\n", len);
		return;
	}

	// Skip the tun header
	buf += 4;
	len -= 4;

	ip = *(in_addr_t *)(buf + 16);

	if (!session[s].ip)
		return;

	t = session[s].tunnel;
	sp = &session[s];

	LOG(5, s, t, "Ethernet -> Tunnel (%d bytes)\n", len);

	// Add on L2TP header
	{
		uint8_t *p = makeppp(b, sizeof(b),  buf, len, t, s, PPPIP);
		if (!p) return;
		tunnelsend(b, len + (p-b), t); // send it...
	}

	// Snooping this session.
	if (sp->snoop_ip && sp->snoop_port)
		snoop_send_packet(buf, len, sp->snoop_ip, sp->snoop_port);

	increment_counter(&sp->cout, &sp->cout_wrap, len); // byte count
	sp->cout_delta += len;
	sp->pout++;
	udp_tx += len;

	sess_local[s].cout += len;	// To send to master..
	sess_local[s].pout++;
}

// add an AVP (16 bit)
static void control16(controlt * c, uint16_t avp, uint16_t val, uint8_t m)
{
	uint16_t l = (m ? 0x8008 : 0x0008);
	*(uint16_t *) (c->buf + c->length + 0) = htons(l);
	*(uint16_t *) (c->buf + c->length + 2) = htons(0);
	*(uint16_t *) (c->buf + c->length + 4) = htons(avp);
	*(uint16_t *) (c->buf + c->length + 6) = htons(val);
	c->length += 8;
}

// add an AVP (32 bit)
static void control32(controlt * c, uint16_t avp, uint32_t val, uint8_t m)
{
	uint16_t l = (m ? 0x800A : 0x000A);
	*(uint16_t *) (c->buf + c->length + 0) = htons(l);
	*(uint16_t *) (c->buf + c->length + 2) = htons(0);
	*(uint16_t *) (c->buf + c->length + 4) = htons(avp);
	*(uint32_t *) (c->buf + c->length + 6) = htonl(val);
	c->length += 10;
}

// add an AVP (string)
static void controls(controlt * c, uint16_t avp, char *val, uint8_t m)
{
	uint16_t l = ((m ? 0x8000 : 0) + strlen(val) + 6);
	*(uint16_t *) (c->buf + c->length + 0) = htons(l);
	*(uint16_t *) (c->buf + c->length + 2) = htons(0);
	*(uint16_t *) (c->buf + c->length + 4) = htons(avp);
	memcpy(c->buf + c->length + 6, val, strlen(val));
	c->length += 6 + strlen(val);
}

// add a binary AVP
static void controlb(controlt * c, uint16_t avp, char *val, unsigned int len, uint8_t m)
{
	uint16_t l = ((m ? 0x8000 : 0) + len + 6);
	*(uint16_t *) (c->buf + c->length + 0) = htons(l);
	*(uint16_t *) (c->buf + c->length + 2) = htons(0);
	*(uint16_t *) (c->buf + c->length + 4) = htons(avp);
	memcpy(c->buf + c->length + 6, val, len);
	c->length += 6 + len;
}

// new control connection
static controlt *controlnew(uint16_t mtype)
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
	*(uint16_t *) (c->buf + 0) = htons(0xC802); // flags/ver
	c->length = 12;
	control16(c, 0, mtype, 1);
	return c;
}

// send zero block if nothing is waiting
// (ZLB send).
static void controlnull(tunnelidt t)
{
	uint8_t buf[12];
	if (tunnel[t].controlc)	// Messages queued; They will carry the ack.
		return;

	*(uint16_t *) (buf + 0) = htons(0xC802); // flags/ver
	*(uint16_t *) (buf + 2) = htons(12); // length
	*(uint16_t *) (buf + 4) = htons(tunnel[t].far); // tunnel
	*(uint16_t *) (buf + 6) = htons(0); // session
	*(uint16_t *) (buf + 8) = htons(tunnel[t].ns); // sequence
	*(uint16_t *) (buf + 10) = htons(tunnel[t].nr); // sequence
	tunnelsend(buf, 12, t);
}

// add a control message to a tunnel, and send if within window
static void controladd(controlt * c, tunnelidt t, sessionidt far)
{
	*(uint16_t *) (c->buf + 2) = htons(c->length); // length
	*(uint16_t *) (c->buf + 4) = htons(tunnel[t].far); // tunnel
	*(uint16_t *) (c->buf + 6) = htons(far); // session
	*(uint16_t *) (c->buf + 8) = htons(tunnel[t].ns); // sequence
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
// Throttle the data from/to through a session to no more than
// 'rate_in' kbit/sec in (from user) or 'rate_out' kbit/sec out (to
// user).
//
// If either value is -1, the current value is retained for that
// direction.
//
void throttle_session(sessionidt s, int rate_in, int rate_out)
{
	if (!session[s].opened)
		return; // No-one home.

	if (!*session[s].user)
	        return; // User not logged in

	if (rate_in >= 0)
	{
		int bytes = rate_in * 1024 / 8; // kbits to bytes
		if (session[s].tbf_in)
			free_tbf(session[s].tbf_in);

		if (rate_in > 0)
			session[s].tbf_in = new_tbf(s, bytes * 2, bytes, send_ipin);
		else
			session[s].tbf_in = 0;

		session[s].throttle_in = rate_in;
	}

	if (rate_out >= 0)
	{
		int bytes = rate_out * 1024 / 8;
		if (session[s].tbf_out)
			free_tbf(session[s].tbf_out);

		if (rate_out > 0)
			session[s].tbf_out = new_tbf(s, bytes * 2, bytes, send_ipout);
		else
			session[s].tbf_out = 0;

		session[s].throttle_out = rate_out;
	}
}

// add/remove filters from session (-1 = no change)
static void filter_session(sessionidt s, int filter_in, int filter_out)
{
	if (!session[s].opened)
		return; // No-one home.

	if (!*session[s].user)
	        return; // User not logged in

	// paranoia
	if (filter_in > MAXFILTER) filter_in = -1;
	if (filter_out > MAXFILTER) filter_out = -1;
	if (session[s].filter_in > MAXFILTER) session[s].filter_in = 0;
	if (session[s].filter_out > MAXFILTER) session[s].filter_out = 0;

	if (filter_in >= 0)
	{
		if (session[s].filter_in)
			ip_filters[session[s].filter_in - 1].used--;

		if (filter_in > 0)
			ip_filters[filter_in - 1].used++;

		session[s].filter_in = filter_in;
	}

	if (filter_out >= 0)
	{
		if (session[s].filter_out)
			ip_filters[session[s].filter_out - 1].used--;

		if (filter_out > 0)
			ip_filters[filter_out - 1].used++;

		session[s].filter_out = filter_out;
	}
}

// start tidy shutdown of session
void sessionshutdown(sessionidt s, char *reason, int result, int error)
{
	int walled_garden = session[s].walled_garden;


	CSTAT(sessionshutdown);

	if (!session[s].opened)
	{
		LOG(3, s, session[s].tunnel, "Called sessionshutdown on an unopened session.\n");
		return;                   // not a live session
	}

	if (!session[s].die)
	{
		struct param_kill_session data = { &tunnel[session[s].tunnel], &session[s] };
		LOG(2, s, session[s].tunnel, "Shutting down session %d: %s\n", s, reason);
		run_plugins(PLUGIN_KILL_SESSION, &data);
	}

	if (session[s].ip && !walled_garden && !session[s].die)
	{
		// RADIUS Stop message
		uint16_t r = sess_local[s].radius;
		if (!r)
			r = radiusnew(s);

		if (r)
		{
			// stop, if not already trying
			if (radius[r].state != RADIUSSTOP)
				radiussend(r, RADIUSSTOP);
		}
		else
			LOG(1, s, session[s].tunnel, "No free RADIUS sessions for Stop message\n");

	    	// Save counters to dump to accounting file
		if (*config->accounting_dir && shut_acct_n < sizeof(shut_acct) / sizeof(*shut_acct))
			memcpy(&shut_acct[shut_acct_n++], &session[s], sizeof(session[s]));
	}

	if (session[s].ip)
	{                          // IP allocated, clear and unroute
		int r;
		int routed = 0;
		for (r = 0; r < MAXROUTE && session[s].route[r].ip; r++)
		{
			if ((session[s].ip & session[s].route[r].mask) ==
			    (session[s].route[r].ip & session[s].route[r].mask))
				routed++;

			routeset(s, session[s].route[r].ip, session[s].route[r].mask, 0, 0);
			session[s].route[r].ip = 0;
		}

		if (session[s].ip_pool_index == -1) // static ip
		{
			if (!routed) routeset(s, session[s].ip, 0, 0, 0);
			session[s].ip = 0;
		}
		else
			free_ip_address(s);

		// unroute IPv6, if setup
		if (session[s].flags & SF_IPV6_ROUTED)
			route6set(s, session[s].ipv6route, session[s].ipv6prefixlen, 0);
	}

	if (session[s].throttle_in || session[s].throttle_out) // Unthrottle if throttled.
		throttle_session(s, 0, 0);

	if (result)
	{                            // Send CDN
		controlt *c = controlnew(14); // sending CDN
		if (error)
		{
			char buf[4];
			*(uint16_t *) buf     = htons(result);
			*(uint16_t *) (buf+2) = htons(error);
			controlb(c, 1, buf, 4, 1);
		}
		else
			control16(c, 1, result, 1);

		control16(c, 14, s, 1);   // assigned session (our end)
		controladd(c, session[s].tunnel, session[s].far); // send the message
	}

	if (!session[s].die)
		session[s].die = TIME + 150; // Clean up in 15 seconds

	// update filter refcounts
	if (session[s].filter_in) ip_filters[session[s].filter_in - 1].used--;
	if (session[s].filter_out) ip_filters[session[s].filter_out - 1].used--;

	cluster_send_session(s);
}

void sendipcp(tunnelidt t, sessionidt s)
{
	uint8_t buf[MAXCONTROL];
	uint16_t r = sess_local[s].radius;
	uint8_t *q;

	CSTAT(sendipcp);

	if (!r)
		r = radiusnew(s);

	if (!r)
	{
		sessionshutdown(s, "No free RADIUS sessions for IPCP", 3, 0);
		return;
	}

	if (radius[r].state != RADIUSIPCP)
	{
		radius[r].state = RADIUSIPCP;
		radius[r].try = 0;
	}

	radius[r].retry = backoff(radius[r].try++);
	if (radius[r].try > 10)
	{
		radiusclear(r, s);	// Clear radius session.
		sessionshutdown(s, "No reply to IPCP.", 3, 0);
		return;
	}

	q = makeppp(buf,sizeof(buf), 0, 0, t, s, PPPIPCP);
	if (!q) return;

	*q = ConfigReq;
	q[1] = r >> RADIUS_SHIFT;                    // ID, dont care, we only send one type of request
	*(uint16_t *) (q + 2) = htons(10);
	q[4] = 3;
	q[5] = 6;
	*(in_addr_t *) (q + 6) = config->peer_address ? config->peer_address :
				 config->bind_address ? config->bind_address :
				 my_address; // send my IP

	tunnelsend(buf, 10 + (q - buf), t); // send it
	session[s].flags &= ~SF_IPCP_ACKED;	// Clear flag.

	// If we have an IPv6 prefix length configured, assume we should
	// try to negotiate an IPv6 session as well. Unless we've had a
	// (N)ACK for IPV6CP.
	if (config->ipv6_prefix.s6_addr[0] > 0 && 
			!(session[s].flags & SF_IPV6CP_ACKED) &&
			!(session[s].flags & SF_IPV6_NACKED))
	{
		q = makeppp(buf,sizeof(buf), 0, 0, t, s, PPPIPV6CP);
		if (!q) return;

		*q = ConfigReq;
		q[1] = r >> RADIUS_SHIFT;		// ID, don't care, we
							// only send one type
							// of request
		*(uint16_t *) (q + 2) = htons(14);
		q[4] = 1;
		q[5] = 10;
		*(uint32_t *) (q + 6) = 0;		// We'll be prefix::1
		*(uint32_t *) (q + 10) = 0;
		q[13] = 1;

		tunnelsend(buf, 14 + (q - buf), t);	// send it
	}
}

static void sessionclear(sessionidt s)
{
	memset(&session[s], 0, sizeof(session[s]));
	memset(&sess_local[s], 0, sizeof(sess_local[s]));
	memset(&cli_session_actions[s], 0, sizeof(cli_session_actions[s]));

	session[s].tunnel = T_FREE;	// Mark it as free.
	session[s].next = sessionfree;
	sessionfree = s;
}

// kill a session now
void sessionkill(sessionidt s, char *reason)
{

	CSTAT(sessionkill);

	if (!session[s].opened) // not alive
		return;

	if (session[s].next)
	{
		LOG(0, s, session[s].tunnel, "Tried to kill a session with next pointer set (%d)\n", session[s].next);
		return;
	}

	session[s].die = TIME;
	sessionshutdown(s, reason, 3, 0);  // close radius/routes, etc.
	if (sess_local[s].radius)
		radiusclear(sess_local[s].radius, s); // cant send clean accounting data, session is killed

	LOG(2, s, session[s].tunnel, "Kill session %d (%s): %s\n", s, session[s].user, reason);
	sessionclear(s);
	cluster_send_session(s);
}

static void tunnelclear(tunnelidt t)
{
	if (!t) return;
	memset(&tunnel[t], 0, sizeof(tunnel[t]));
	tunnel[t].state = TUNNELFREE;
}

// kill a tunnel now
static void tunnelkill(tunnelidt t, char *reason)
{
	sessionidt s;
	controlt *c;

	CSTAT(tunnelkill);

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
	for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
		if (session[s].tunnel == t)
			sessionkill(s, reason);

	// free tunnel
	tunnelclear(t);
	LOG(1, 0, t, "Kill tunnel %d: %s\n", t, reason);
	cli_tunnel_actions[t].action = 0;
	cluster_send_tunnel(t);
}

// shut down a tunnel cleanly
static void tunnelshutdown(tunnelidt t, char *reason, int result, int error, char *msg)
{
	sessionidt s;

	CSTAT(tunnelshutdown);

	if (!tunnel[t].last || !tunnel[t].far || tunnel[t].state == TUNNELFREE)
	{
		// never set up, can immediately kill
		tunnelkill(t, reason);
		return;
	}
	LOG(1, 0, t, "Shutting down tunnel %d (%s)\n", t, reason);

	// close session
	for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
		if (session[s].tunnel == t)
			sessionshutdown(s, reason, 3, 0);

	tunnel[t].state = TUNNELDIE;
	tunnel[t].die = TIME + 700; // Clean up in 70 seconds
	cluster_send_tunnel(t);
	// TBA - should we wait for sessions to stop?
	if (result) 
	{
		controlt *c = controlnew(4);	// sending StopCCN
		if (error)
		{
			char buf[64];
			int l = 4;
			*(uint16_t *) buf     = htons(result);
			*(uint16_t *) (buf+2) = htons(error);
			if (msg)
			{
				int m = strlen(msg);
				if (m + 4 > sizeof(buf))
				    m = sizeof(buf) - 4;

				memcpy(buf+4, msg, m);
				l += m;
			}

			controlb(c, 1, buf, l, 1);
		}
		else
			control16(c, 1, result, 1);

		control16(c, 9, t, 1);		// assigned tunnel (our end)
		controladd(c, t, 0);		// send the message
	}
}

// read and process packet on tunnel (UDP)
void processudp(uint8_t * buf, int len, struct sockaddr_in *addr)
{
	char *chapresponse = NULL;
	uint16_t l = len, t = 0, s = 0, ns = 0, nr = 0;
	uint8_t *p = buf + 2;


	CSTAT(processudp);

	udp_rx += len;
	udp_rx_pkt++;
	LOG_HEX(5, "UDP Data", buf, len);
	STAT(tunnel_rx_packets);
	INC_STAT(tunnel_rx_bytes, len);
	if (len < 6)
	{
		LOG(1, 0, 0, "Short UDP, %d bytes\n", len);
		STAT(tunnel_rx_errors);
		return;
	}
	if ((buf[1] & 0x0F) != 2)
	{
		LOG(1, 0, 0, "Bad L2TP ver %d\n", (buf[1] & 0x0F) != 2);
		STAT(tunnel_rx_errors);
		return;
	}
	if (*buf & 0x40)
	{                          // length
		l = ntohs(*(uint16_t *) p);
		p += 2;
	}
	t = ntohs(*(uint16_t *) p);
	p += 2;
	s = ntohs(*(uint16_t *) p);
	p += 2;
	if (s >= MAXSESSION)
	{
		LOG(1, s, t, "Received UDP packet with invalid session ID\n");
		STAT(tunnel_rx_errors);
		return;
	}
	if (t >= MAXTUNNEL)
	{
		LOG(1, s, t, "Received UDP packet with invalid tunnel ID\n");
		STAT(tunnel_rx_errors);
		return;
	}
	if (*buf & 0x08)
	{                          // ns/nr
		ns = ntohs(*(uint16_t *) p);
		p += 2;
		nr = ntohs(*(uint16_t *) p);
		p += 2;
	}
	if (*buf & 0x02)
	{                          // offset
		uint16_t o = ntohs(*(uint16_t *) p);
		p += o + 2;
	}
	if ((p - buf) > l)
	{
		LOG(1, s, t, "Bad length %d>%d\n", (int) (p - buf), l);
		STAT(tunnel_rx_errors);
		return;
	}
	l -= (p - buf);
	if (*buf & 0x80)
	{                          // control
		uint16_t message = 0xFFFF;	// message type
		uint8_t fatal = 0;
		uint8_t mandatory = 0;
		uint8_t authtype = 0;		// proxy auth type
		uint16_t asession = 0;		// assigned session
		uint32_t amagic = 0;		// magic number
		uint8_t aflags = 0;		// flags from last LCF
		uint16_t version = 0x0100;	// protocol version (we handle 0.0 as well and send that back just in case)
		char called[MAXTEL] = "";	// called number
		char calling[MAXTEL] = "";	// calling number

		if (!config->cluster_iam_master)
		{
			master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port);
			return;
		}

		// control messages must have bits 0x80|0x40|0x08
		// (type, length and sequence) set, and bits 0x02|0x01
		// (offset and priority) clear
		if ((*buf & 0xCB) != 0xC8)
		{
			LOG(1, s, t, "Bad control header %02X\n", *buf);
			STAT(tunnel_rx_errors);
			return;
		}

		// check for duplicate tunnel open message
		if (!t && ns == 0)
		{
			int i;

				//
				// Is this a duplicate of the first packet? (SCCRQ)
				//
			for (i = 1; i <= config->cluster_highest_tunnelid ; ++i)
			{
				if (tunnel[i].state != TUNNELOPENING ||
					tunnel[i].ip != ntohl(*(in_addr_t *) & addr->sin_addr) ||
					tunnel[i].port != ntohs(addr->sin_port) )
					continue;
				t = i;
				LOG(3, s, t, "Duplicate SCCRQ?\n");
				break;
			}
		}

		LOG(3, s, t, "Control message (%d bytes): (unacked %d) l-ns %d l-nr %d r-ns %d r-nr %d\n",
			l, tunnel[t].controlc, tunnel[t].ns, tunnel[t].nr, ns, nr);

		// if no tunnel specified, assign one
		if (!t)
		{
			if (!(t = new_tunnel()))
			{
				LOG(1, 0, 0, "No more tunnels\n");
				STAT(tunnel_overflow);
				return;
			}
			tunnelclear(t);
			tunnel[t].ip = ntohl(*(in_addr_t *) & addr->sin_addr);
			tunnel[t].port = ntohs(addr->sin_port);
			tunnel[t].window = 4; // default window
			STAT(tunnel_created);
			LOG(1, 0, t, "   New tunnel from %s:%u ID %d\n",
				fmtaddr(htonl(tunnel[t].ip), 0), tunnel[t].port, t);
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
			STAT(tunnel_rx_errors);
			LOG(1, 0, t, "   Out of sequence tunnel %d, (%d is not the expected %d)\n",
				t, ns, tunnel[t].nr);

			if (l)	// Is this not a ZLB?
				controlnull(t);
			return;
		}

		// This is used to time out old tunnels
		tunnel[t].lastrec = time_now;

		// check sequence of this message
		{
			int skip = tunnel[t].window; // track how many in-window packets are still in queue
				// some to clear maybe?
			while (tunnel[t].controlc > 0 && (((tunnel[t].ns - tunnel[t].controlc) - nr) & 0x8000))
			{
				controlt *c = tunnel[t].controls;
				tunnel[t].controls = c->next;
				tunnel[t].controlc--;
				c->next = controlfree;
				controlfree = c;
				skip--;
				tunnel[t].try = 0; // we have progress
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
			int result = 0;
			int error = 0;
			char *msg = 0;

			// process AVPs
			while (l && !(fatal & 0x80)) // 0x80 = mandatory AVP
			{
				uint16_t n = (ntohs(*(uint16_t *) p) & 0x3FF);
				uint8_t *b = p;
				uint8_t flags = *p;
				uint16_t mtype;
				if (n > l)
				{
					LOG(1, s, t, "Invalid length in AVP\n");
					STAT(tunnel_rx_errors);
					return;
				}
				p += n;       // next
				l -= n;
				if (flags & 0x3C) // reserved bits, should be clear
				{
					LOG(1, s, t, "Unrecognised AVP flags %02X\n", *b);
					fatal = flags;
					result = 2; // general error
					error = 3; // reserved field non-zero
					msg = 0;
					continue; // next
				}
				b += 2;
				if (*(uint16_t *) (b))
				{
					LOG(2, s, t, "Unknown AVP vendor %d\n", ntohs(*(uint16_t *) (b)));
					fatal = flags;
					result = 2; // general error
					error = 6; // generic vendor-specific error
					msg = "unsupported vendor-specific";
					continue; // next
				}
				b += 2;
				mtype = ntohs(*(uint16_t *) (b));
				b += 2;
				n -= 6;

				if (flags & 0x40)
				{
					uint16_t orig_len;

					// handle hidden AVPs
					if (!*config->l2tpsecret)
					{
						LOG(1, s, t, "Hidden AVP requested, but no L2TP secret.\n");
						fatal = flags;
						result = 2; // general error
						error = 6; // generic vendor-specific error
						msg = "secret not specified";
						continue;
					}
					if (!session[s].random_vector_length)
					{
						LOG(1, s, t, "Hidden AVP requested, but no random vector.\n");
						fatal = flags;
						result = 2; // general error
						error = 6; // generic
						msg = "no random vector";
						continue;
					}
					if (n < 8)
					{
						LOG(2, s, t, "Short hidden AVP.\n");
						fatal = flags;
						result = 2; // general error
						error = 2; // length is wrong
						msg = 0;
						continue;
					}

					LOG(4, s, t, "Hidden AVP\n");

					// Unhide the AVP
					unhide_value(b, n, mtype, session[s].random_vector, session[s].random_vector_length);

					orig_len = ntohs(*(uint16_t *) b);
					if (orig_len > n + 2)
					{
						LOG(1, s, t, "Original length %d too long in hidden AVP of length %d; wrong secret?\n",
						    orig_len, n);

						fatal = flags;
						result = 2; // general error
						error = 2; // length is wrong
						msg = 0;
						continue;
					}

					b += 2;
					n = orig_len;
				}

				LOG(4, s, t, "   AVP %d (%s) len %d\n", mtype, avp_name(mtype), n);
				switch (mtype)
				{
				case 0:     // message type
					message = ntohs(*(uint16_t *) b);
					mandatory = flags & 0x80;
					LOG(4, s, t, "   Message type = %d (%s)\n", *b, l2tp_message_type(message));
					break;
				case 1:     // result code
					{
						uint16_t rescode = ntohs(*(uint16_t *) b);
						const char* resdesc = "(unknown)";
						if (message == 4)
						{ /* StopCCN */
							resdesc = stopccn_result_code(rescode);
						}
						else if (message == 14)
						{ /* CDN */
							resdesc = cdn_result_code(rescode);
						}

						LOG(4, s, t, "   Result Code %d: %s\n", rescode, resdesc);
						if (n >= 4)
						{
							uint16_t errcode = ntohs(*(uint16_t *)(b + 2));
							LOG(4, s, t, "   Error Code %d: %s\n", errcode, error_code(errcode));
						}
						if (n > 4)
							LOG(4, s, t, "   Error String: %.*s\n", n-4, b+4);

						break;
					}
					break;
				case 2:     // protocol version
					{
						version = ntohs(*(uint16_t *) (b));
						LOG(4, s, t, "   Protocol version = %d\n", version);
						if (version && version != 0x0100)
						{   // allow 0.0 and 1.0
							LOG(1, s, t, "   Bad protocol version %04X\n", version);
							fatal = flags;
							result = 5; // unspported protocol version
							error = 0x0100; // supported version
							msg = 0;
							continue; // next
						}
					}
					break;
				case 3:     // framing capabilities
//					LOG(4, s, t, "Framing capabilities\n");
					break;
				case 4:     // bearer capabilities
//					LOG(4, s, t, "Bearer capabilities\n");
					break;
				case 5:		// tie breaker
					// We never open tunnels, so we don't care about tie breakers
//					LOG(4, s, t, "Tie breaker\n");
					continue;
				case 6:     // firmware revision
//					LOG(4, s, t, "Firmware revision\n");
					break;
				case 7:     // host name
					memset(tunnel[t].hostname, 0, sizeof(tunnel[t].hostname));
					memcpy(tunnel[t].hostname, b, (n < sizeof(tunnel[t].hostname)) ? n : sizeof(tunnel[t].hostname) - 1);
					LOG(4, s, t, "   Tunnel hostname = \"%s\"\n", tunnel[t].hostname);
					// TBA - to send to RADIUS
					break;
				case 8:     // vendor name
					memset(tunnel[t].vendor, 0, sizeof(tunnel[t].vendor));
					memcpy(tunnel[t].vendor, b, (n < sizeof(tunnel[t].vendor)) ? n : sizeof(tunnel[t].vendor) - 1);
					LOG(4, s, t, "   Vendor name = \"%s\"\n", tunnel[t].vendor);
					break;
				case 9:     // assigned tunnel
					tunnel[t].far = ntohs(*(uint16_t *) (b));
					LOG(4, s, t, "   Remote tunnel id = %d\n", tunnel[t].far);
					break;
				case 10:    // rx window
					tunnel[t].window = ntohs(*(uint16_t *) (b));
					if (!tunnel[t].window)
						tunnel[t].window = 1; // window of 0 is silly
					LOG(4, s, t, "   rx window = %d\n", tunnel[t].window);
					break;
				case 11:	// Challenge
					{
						LOG(4, s, t, "   LAC requested CHAP authentication for tunnel\n");
						build_chap_response(b, 2, n, &chapresponse);
					}
					break;
				case 13:    // Response
					// Why did they send a response? We never challenge.
					LOG(2, s, t, "   received unexpected challenge response\n");
					break;

				case 14:    // assigned session
					asession = session[s].far = ntohs(*(uint16_t *) (b));
					LOG(4, s, t, "   assigned session = %d\n", asession);
					break;
				case 15:    // call serial number
					LOG(4, s, t, "   call serial number = %d\n", ntohl(*(uint32_t *)b));
					break;
				case 18:    // bearer type
					LOG(4, s, t, "   bearer type = %d\n", ntohl(*(uint32_t *)b));
					// TBA - for RADIUS
					break;
				case 19:    // framing type
					LOG(4, s, t, "   framing type = %d\n", ntohl(*(uint32_t *)b));
					// TBA
					break;
				case 21:    // called number
					memset(called, 0, sizeof(called));
					memcpy(called, b, (n < sizeof(called)) ? n : sizeof(called) - 1);
					LOG(4, s, t, "   Called <%s>\n", called);
					break;
				case 22:    // calling number
					memset(calling, 0, sizeof(calling));
					memcpy(calling, b, (n < sizeof(calling)) ? n : sizeof(calling) - 1);
					LOG(4, s, t, "   Calling <%s>\n", calling);
					break;
				case 23:    // subtype
					break;
				case 24:    // tx connect speed
					if (n == 4)
					{
						session[s].tx_connect_speed = ntohl(*(uint32_t *)b);
					}
					else
					{
						// AS5300s send connect speed as a string
						char tmp[30];
						memset(tmp, 0, sizeof(tmp));
						memcpy(tmp, b, (n < sizeof(tmp)) ? n : sizeof(tmp) - 1);
						session[s].tx_connect_speed = atol(tmp);
					}
					LOG(4, s, t, "   TX connect speed <%u>\n", session[s].tx_connect_speed);
					break;
				case 38:    // rx connect speed
					if (n == 4)
					{
						session[s].rx_connect_speed = ntohl(*(uint32_t *)b);
					}
					else
					{
						// AS5300s send connect speed as a string
						char tmp[30];
						memset(tmp, 0, sizeof(tmp));
						memcpy(tmp, b, (n < sizeof(tmp)) ? n : sizeof(tmp) - 1);
						session[s].rx_connect_speed = atol(tmp);
					}
					LOG(4, s, t, "   RX connect speed <%u>\n", session[s].rx_connect_speed);
					break;
				case 25:    // Physical Channel ID
					{
						uint32_t tmp = ntohl(*(uint32_t *) b);
						LOG(4, s, t, "   Physical Channel ID <%X>\n", tmp);
						break;
					}
				case 29:    // Proxy Authentication Type
					{
						uint16_t atype = ntohs(*(uint16_t *)b);
						LOG(4, s, t, "   Proxy Auth Type %d (%s)\n", atype, auth_type(atype));
						if (atype == 2)
							authtype = AUTHCHAP;
						else if (atype == 3)
							authtype = AUTHPAP;

						break;
					}
				case 30:    // Proxy Authentication Name
					{
						char authname[64];
						memset(authname, 0, sizeof(authname));
						memcpy(authname, b, (n < sizeof(authname)) ? n : sizeof(authname) - 1);
						LOG(4, s, t, "   Proxy Auth Name (%s)\n",
							authname);
						break;
					}
				case 31:    // Proxy Authentication Challenge
					{
						LOG(4, s, t, "   Proxy Auth Challenge\n");
						if (sess_local[s].radius)
							memcpy(radius[sess_local[s].radius].auth, b, 16);
						break;
					}
				case 32:    // Proxy Authentication ID
					{
						uint16_t authid = ntohs(*(uint16_t *)(b));
						LOG(4, s, t, "   Proxy Auth ID (%d)\n", authid);
						if (sess_local[s].radius)
							radius[sess_local[s].radius].id = authid;
						break;
					}
				case 33:    // Proxy Authentication Response
					LOG(4, s, t, "   Proxy Auth Response\n");
					break;
				case 27:    // last sent lcp
					{        // find magic number
						uint8_t *p = b, *e = p + n;
						while (p + 1 < e && p[1] && p + p[1] <= e)
						{
							if (*p == 5 && p[1] == 6) // Magic-Number
								amagic = ntohl(*(uint32_t *) (p + 2));
							else if (*p == 3 && p[1] == 4 && *(uint16_t *) (p + 2) == htons(PPPPAP)) // Authentication-Protocol (PAP)
								authtype = AUTHPAP;
							else if (*p == 3 && p[1] == 5 && *(uint16_t *) (p + 2) == htons(PPPCHAP) && p[4] == 5) // Authentication-Protocol (CHAP)
								authtype = AUTHCHAP;
							else if (*p == 7) // Protocol-Field-Compression
								aflags |= SESSIONPFC;
							else if (*p == 8) // Address-and-Control-Field-Compression
								aflags |= SESSIONACFC;
							p += p[1];
						}
					}
					break;
				case 28:    // last recv lcp confreq
					break;
				case 26:    // Initial Received LCP CONFREQ
					break;
				case 39:    // seq required - we control it as an LNS anyway...
					break;
				case 36:    // Random Vector
					LOG(4, s, t, "   Random Vector received.  Enabled AVP Hiding.\n");
					memset(session[s].random_vector, 0, sizeof(session[s].random_vector));
					memcpy(session[s].random_vector, b, n);
					session[s].random_vector_length = n;
					break;
				default:
					{
						static char e[] = "unknown AVP 0xXXXX";
						LOG(2, s, t, "   Unknown AVP type %d\n", mtype);
						fatal = flags;
						result = 2; // general error
						error = 8; // unknown mandatory AVP
						sprintf((msg = e) + 14, "%04x", mtype);
						continue; // next
					}
				}
			}
			// process message
			if (fatal & 0x80)
				tunnelshutdown(t, "Invalid mandatory AVP", result, error, msg);
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
						controladd(c, t, 0); // send the resply
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
					tunnelshutdown(t, "Stopped", 0, 0, 0); // Shut down cleanly
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
					if (sessionfree)
					{
						uint16_t r;

						s = sessionfree;
						sessionfree = session[s].next;
						memset(&session[s], 0, sizeof(session[s]));

						if (s > config->cluster_highest_sessionid)
							config->cluster_highest_sessionid = s;

						// make a RADIUS session
						if ((r = radiusnew(s)))
						{
							controlt *c = controlnew(11); // sending ICRP
							session[s].opened = time_now;
							session[s].tunnel = t;
							session[s].far = asession;
							session[s].last_packet = time_now;
							LOG(3, s, t, "New session (%d/%d)\n", tunnel[t].far, session[s].far);
							control16(c, 14, s, 1); // assigned session
							controladd(c, t, asession); // send the reply

							strncpy(radius[r].calling, calling, sizeof(radius[r].calling) - 1);
							strncpy(session[s].called, called, sizeof(session[s].called) - 1);
							strncpy(session[s].calling, calling, sizeof(session[s].calling) - 1);
							STAT(session_created);
							break;
						}


						LOG(1, s, t, "No free RADIUS sessions for ICRQ\n");
						sessionclear(s);
					}
					else
					{
						STAT(session_overflow);
						LOG(1, 0, t, "No free sessions\n");
					}

					{
						controlt *c = controlnew(14); // CDN
						control16(c, 1, 4, 1); // temporary lack of resources
						controladd(c, session[s].tunnel, asession); // send the message
					}
					return;
				case 11:      // ICRP
					// TBA
					break;
				case 12:      // ICCN
					if (amagic == 0) amagic = time_now;
					session[s].magic = amagic; // set magic number
					session[s].l2tp_flags = aflags; // set flags received
					LOG(3, s, t, "Magic %X Flags %X\n", amagic, aflags);
					controlnull(t); // ack
					// proxy authentication type is not supported
					if (!(config->radius_authtypes & authtype))
						authtype = config->radius_authprefer;

					// start LCP
					sendlcp(t, s, authtype);
					break;
				case 14:      // CDN
					controlnull(t); // ack
					sessionshutdown(s, "Closed (Received CDN).", 0, 0);
					break;
				case 0xFFFF:
					LOG(1, s, t, "Missing message type\n");
					break;
				default:
					STAT(tunnel_rx_errors);
					if (mandatory)
						tunnelshutdown(t, "Unknown message type", 2, 6, "unknown message type");
					else
						LOG(1, s, t, "Unknown message type %d\n", message);
					break;
				}
			if (chapresponse) free(chapresponse);
			cluster_send_tunnel(t);
		}
		else
		{
			LOG(4, s, t, "   Got a ZLB ack\n");
		}
	}
	else
	{                          // data
		uint16_t prot;

		LOG_HEX(5, "Receive Tunnel Data", p, l);
		if (l > 2 && p[0] == 0xFF && p[1] == 0x03)
		{                     // HDLC address header, discard
			p += 2;
			l -= 2;
		}
		if (l < 2)
		{
			LOG(1, s, t, "Short ppp length %d\n", l);
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
			prot = ntohs(*(uint16_t *) p);
			p += 2;
			l -= 2;
		}

		if (s && !session[s].opened)	// Is something wrong??
		{
			if (!config->cluster_iam_master)
			{
				// Pass it off to the master to deal with..
				master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port);
				return;
			}


			LOG(1, s, t, "UDP packet contains session which is not opened.  Dropping packet.\n");
			STAT(tunnel_rx_errors);
			return;
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
		else if (prot == PPPIPV6CP)
		{
			if (config->ipv6_prefix.s6_addr[0] > 0)
			{
				session[s].last_packet = time_now;
				if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port); return; }
				processipv6cp(t, s, p, l);
			}
			else
			{
				LOG(1, s, t, "IPv6 not configured; ignoring IPv6CP\n");
			}
		}
		else if (prot == PPPCCP)
		{
			session[s].last_packet = time_now;
			if (!config->cluster_iam_master) { master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port); return; }
			processccp(t, s, p, l);
		}
		else if (prot == PPPIP)
		{
			if (session[s].die)
			{
				LOG(4, s, t, "Session %d is closing.  Don't process PPP packets\n", s);
				return;              // closing session, PPP not processed
			}

			session[s].last_packet = time_now;
			if (session[s].walled_garden && !config->cluster_iam_master)
			{
				master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port);
				return;
			}

			processipin(t, s, p, l);
		}
		else if (prot == PPPIPV6)
		{
			if (!config->ipv6_prefix.s6_addr[0] > 0)
			{
				LOG(1, s, t, "IPv6 not configured; yet received IPv6 packet. Ignoring.\n");
				return;
			}
			if (session[s].die)
			{
				LOG(4, s, t, "Session %d is closing.  Don't process PPP packets\n", s);
				return;              // closing session, PPP not processed
			}

			session[s].last_packet = time_now;
			if (session[s].walled_garden && !config->cluster_iam_master)
			{
				master_forward_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port);
				return;
			}

			processipv6in(t, s, p, l);
		}
		else
		{
			STAT(tunnel_rx_errors);
			LOG(1, s, t, "Unknown PPP protocol %04X\n", prot);
		}
	}
}

// read and process packet on tun
static void processtun(uint8_t * buf, int len)
{
	LOG_HEX(5, "Receive TUN Data", buf, len);
	STAT(tun_rx_packets);
	INC_STAT(tun_rx_bytes, len);

	CSTAT(processtun);

	eth_rx_pkt++;
	eth_rx += len;
	if (len < 22)
	{
		LOG(1, 0, 0, "Short tun packet %d bytes\n", len);
		STAT(tun_rx_errors);
		return;
	}

	if (*(uint16_t *) (buf + 2) == htons(PKTIP)) // IPv4
		processipout(buf, len);
	else if (*(uint16_t *) (buf + 2) == htons(PKTIPV6) // IPV6
	    && config->ipv6_prefix.s6_addr[0] > 0)
		processipv6out(buf, len);

	// Else discard.
}

// Handle retries, timeouts.  Runs every 1/10th sec, want to ensure
// that we look at the whole of the tunnel, radius and session tables
// every second
static void regular_cleanups(double period)
{
	// Next tunnel, radius and session to check for actions on.
	static tunnelidt t = 0;
	static int r = 0;
	static sessionidt s = 0;

	int t_actions = 0;
	int r_actions = 0;
	int s_actions = 0;

	int t_slice;
	int r_slice;
	int s_slice;

	int i;
	int a;

	// divide up tables into slices based on the last run
	t_slice = config->cluster_highest_tunnelid  * period;
	r_slice = (MAXRADIUS - 1)                   * period;
	s_slice = config->cluster_highest_sessionid * period;

	if (t_slice < 1)
	    t_slice = 1;
	else if (t_slice > config->cluster_highest_tunnelid)
	    t_slice = config->cluster_highest_tunnelid;

	if (r_slice < 1)
	    r_slice = 1;
	else if (r_slice > (MAXRADIUS - 1))
	    r_slice = MAXRADIUS - 1;

	if (s_slice < 1)
	    s_slice = 1;
	else if (s_slice > config->cluster_highest_sessionid)
	    s_slice = config->cluster_highest_sessionid;

	LOG(4, 0, 0, "Begin regular cleanup (last %f seconds ago)\n", period);

	for (i = 0; i < t_slice; i++)
	{
		t++;
		if (t > config->cluster_highest_tunnelid)
			t = 1;

		// check for expired tunnels
		if (tunnel[t].die && tunnel[t].die <= TIME)
		{
			STAT(tunnel_timeout);
			tunnelkill(t, "Expired");
			t_actions++;
			continue;
		}
		// check for message resend
		if (tunnel[t].retry && tunnel[t].controlc)
		{
			// resend pending messages as timeout on reply
			if (tunnel[t].retry <= TIME)
			{
				controlt *c = tunnel[t].controls;
				uint8_t w = tunnel[t].window;
				tunnel[t].try++; // another try
				if (tunnel[t].try > 5)
					tunnelkill(t, "Timeout on control message"); // game over
				else
					while (c && w--)
					{
						tunnelsend(c->buf, c->length, t);
						c = c->next;
					}

				t_actions++;
			}
		}
		// Send hello
		if (tunnel[t].state == TUNNELOPEN && tunnel[t].lastrec < TIME + 600)
		{
			controlt *c = controlnew(6); // sending HELLO
			controladd(c, t, 0); // send the message
			LOG(3, 0, t, "Sending HELLO message\n");
			t_actions++;
		}

		// Check for tunnel changes requested from the CLI
		if ((a = cli_tunnel_actions[t].action))
		{
			cli_tunnel_actions[t].action = 0;
			if (a & CLI_TUN_KILL)
			{
				LOG(2, 0, t, "Dropping tunnel by CLI\n");
				tunnelshutdown(t, "Requested by administrator", 1, 0, 0);
				t_actions++;
			}
		}
	}

	for (i = 0; i < r_slice; i++)
	{
		r++;
		if (r >= MAXRADIUS)
			r = 1;

		if (!radius[r].state)
			continue;

		if (radius[r].retry <= TIME)
		{
			radiusretry(r);
			r_actions++;
		}
	}

	for (i = 0; i < s_slice; i++)
	{
		s++;
		if (s > config->cluster_highest_sessionid)
			s = 1;

		if (!session[s].opened)	// Session isn't in use
			continue;

		// check for expired sessions
		if (session[s].die)
		{
			if (session[s].die <= TIME)
			{
				sessionkill(s, "Expired");
				s_actions++;
			}
			continue;
		}

		if (session[s].ip && !(session[s].flags & SF_IPCP_ACKED))
		{
			// IPCP has not completed yet. Resend
			LOG(3, s, session[s].tunnel, "No ACK for initial IPCP ConfigReq... resending\n");
			sendipcp(session[s].tunnel, s);
			s_actions++;
		}

		// Drop sessions who have not responded within IDLE_TIMEOUT seconds
		if (session[s].last_packet && (time_now - session[s].last_packet >= IDLE_TIMEOUT))
		{
			sessionshutdown(s, "No response to LCP ECHO requests.", 3, 0);
			STAT(session_timeout);
			s_actions++;
			continue;
		}

		// No data in ECHO_TIMEOUT seconds, send LCP ECHO
		if (session[s].user[0] && (time_now - session[s].last_packet >= ECHO_TIMEOUT))
		{
			uint8_t b[MAXCONTROL] = {0};

			uint8_t *q = makeppp(b, sizeof(b), 0, 0, session[s].tunnel, s, PPPLCP);
			if (!q) continue;

			*q = EchoReq;
			*(uint8_t *)(q + 1) = (time_now % 255); // ID
			*(uint16_t *)(q + 2) = htons(8); // Length
			*(uint32_t *)(q + 4) = 0; // Magic Number (not supported)

			LOG(4, s, session[s].tunnel, "No data in %d seconds, sending LCP ECHO\n",
					(int)(time_now - session[s].last_packet));
			tunnelsend(b, 24, session[s].tunnel); // send it
			s_actions++;
		}

		// Check for actions requested from the CLI
		if ((a = cli_session_actions[s].action))
		{
			int send = 0;

			cli_session_actions[s].action = 0;
			if (a & CLI_SESS_KILL)
			{
				LOG(2, s, session[s].tunnel, "Dropping session by CLI\n");
				sessionshutdown(s, "Requested by administrator.", 3, 0);
				a = 0; // dead, no need to check for other actions
				s_actions++;
			}

			if (a & CLI_SESS_NOSNOOP)
			{
				LOG(2, s, session[s].tunnel, "Unsnooping session by CLI\n");
				session[s].snoop_ip = 0;
				session[s].snoop_port = 0;
				s_actions++;
				send++;
			}
			else if (a & CLI_SESS_SNOOP)
			{
				LOG(2, s, session[s].tunnel, "Snooping session by CLI (to %s:%d)\n",
				    fmtaddr(cli_session_actions[s].snoop_ip, 0),
				    cli_session_actions[s].snoop_port);

				session[s].snoop_ip = cli_session_actions[s].snoop_ip;
				session[s].snoop_port = cli_session_actions[s].snoop_port;
				s_actions++;
				send++;
			}

			if (a & CLI_SESS_NOTHROTTLE)
			{
				LOG(2, s, session[s].tunnel, "Un-throttling session by CLI\n");
				throttle_session(s, 0, 0);
				s_actions++;
				send++;
			}
			else if (a & CLI_SESS_THROTTLE)
			{
				LOG(2, s, session[s].tunnel, "Throttling session by CLI (to %dkb/s up and %dkb/s down)\n",
				    cli_session_actions[s].throttle_in,
				    cli_session_actions[s].throttle_out);

				throttle_session(s, cli_session_actions[s].throttle_in, cli_session_actions[s].throttle_out);
				s_actions++;
				send++;
			}

			if (a & CLI_SESS_NOFILTER)
			{
				LOG(2, s, session[s].tunnel, "Un-filtering session by CLI\n");
				filter_session(s, 0, 0);
				s_actions++;
				send++;
			}
			else if (a & CLI_SESS_FILTER)
			{
				LOG(2, s, session[s].tunnel, "Filtering session by CLI (in=%d, out=%d)\n",
				    cli_session_actions[s].filter_in,
				    cli_session_actions[s].filter_out);

				filter_session(s, cli_session_actions[s].filter_in, cli_session_actions[s].filter_out);
				s_actions++;
				send++;
			}

			if (send)
				cluster_send_session(s);
		}

		// RADIUS interim accounting
		if (config->radius_accounting && config->radius_interim > 0
		    && session[s].ip && !session[s].walled_garden
		    && !sess_local[s].radius // RADIUS already in progress
		    && time_now - sess_local[s].last_interim >= config->radius_interim)
		{
			if (!(r = radiusnew(s)))
			{
				LOG(1, s, session[s].tunnel, "No free RADIUS sessions for Interim message\n");
				STAT(radius_overflow);
				continue;
			}

			LOG(3, s, session[s].tunnel, "Sending RADIUS Interim for %s (%u)\n",
				session[s].user, session[s].unique_id);

			radiussend(r, RADIUSINTERIM);
			sess_local[s].last_interim = time_now;
			s_actions++;
		}
	}

	LOG(4, 0, 0, "End regular cleanup: checked %d/%d/%d tunnels/radius/sessions; %d/%d/%d actions\n",
		t_slice, r_slice, s_slice, t_actions, r_actions, s_actions);
}

//
// Are we in the middle of a tunnel update, or radius
// requests??
//
static int still_busy(void)
{
	int i;
	static time_t stopped_bgp = 0;
	static clockt last_talked = 0;
	static clockt start_busy_wait = 0;

	if (!config->cluster_iam_master)
	{
#ifdef BGP
	    	if (bgp_configured)
		{
			if (!stopped_bgp)
			{
			    	LOG(1, 0, 0, "Shutting down in %d seconds, stopping BGP...\n", QUIT_DELAY);

				for (i = 0; i < BGP_NUM_PEERS; i++)
					if (bgp_peers[i].state == Established)
						bgp_stop(&bgp_peers[i]);

				stopped_bgp = time_now;

				// we don't want to become master
				cluster_send_ping(0);

				return 1;
			}

			if (time_now < (stopped_bgp + QUIT_DELAY))
				return 1;
		}
#endif /* BGP */

		return 0;
	}

	if (start_busy_wait == 0)
		start_busy_wait = TIME;

	for (i = config->cluster_highest_tunnelid ; i > 0 ; --i)
	{
		if (!tunnel[i].controlc)
			continue;

		if (last_talked != TIME)
		{
			LOG(2, 0, 0, "Tunnel %d still has un-acked control messages.\n", i);
			last_talked = TIME;
		}
		return 1;
	}

	// We stop waiting for radius after BUSY_WAIT_TIME 1/10th seconds
	if (abs(TIME - start_busy_wait) > BUSY_WAIT_TIME)
	{
		LOG(1, 0, 0, "Giving up waiting for RADIUS to be empty.  Shutting down anyway.\n");
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
			LOG(2, 0, 0, "Radius session %d is still busy (sid %d)\n", i, radius[i].session);
			last_talked = TIME;
		}
		return 1;
	}

	return 0;
}

static fd_set readset;
static int readset_n = 0;

// main loop - gets packets on tun or udp and processes them
static void mainloop(void)
{
	int i;
	uint8_t buf[65536];
	struct timeval to;
	clockt next_cluster_ping = 0;	// send initial ping immediately

	LOG(4, 0, 0, "Beginning of main loop.  udpfd=%d, tunfd=%d, cluster_sockfd=%d, controlfd=%d\n",
		udpfd, tunfd, cluster_sockfd, controlfd);

	FD_ZERO(&readset);
	FD_SET(udpfd, &readset);
	FD_SET(tunfd, &readset);
	FD_SET(controlfd, &readset);
	FD_SET(clifd, &readset);
	if (cluster_sockfd) FD_SET(cluster_sockfd, &readset);
	readset_n = udpfd;
	if (tunfd > readset_n)          readset_n = tunfd;
	if (controlfd > readset_n)      readset_n = controlfd;
	if (clifd > readset_n)          readset_n = clifd;
	if (cluster_sockfd > readset_n) readset_n = cluster_sockfd;

	while (!main_quit || still_busy())
	{
		fd_set r;
		int n = readset_n;
#ifdef BGP
		fd_set w;
		int bgp_set[BGP_NUM_PEERS];
#endif /* BGP */
		int more = 0;

		if (config->reload_config)
		{
			// Update the config state based on config settings
			update_config();
		}

		memcpy(&r, &readset, sizeof(fd_set));
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

		STAT(select_called);

		TIME = now(NULL);
		if (n < 0)
		{
			if (errno == EINTR ||
			    errno == ECHILD) // EINTR was clobbered by sigchild_handler()
				continue;

			LOG(0, 0, 0, "Error returned from select(): %s\n", strerror(errno));
			main_quit++;
			break;
		}
		else if (n)
		{
			struct sockaddr_in addr;
			int alen, c, s;
			int udp_pkts = 0;
			int tun_pkts = 0;
			int cluster_pkts = 0;

			// nsctl commands
			if (FD_ISSET(controlfd, &r))
			{
				alen = sizeof(addr);
				processcontrol(buf, recvfrom(controlfd, buf, sizeof(buf), MSG_WAITALL, (void *) &addr, &alen), &addr, alen);
				n--;
			}

			// RADIUS responses
			if (config->cluster_iam_master)
			{
				for (i = 0; i < config->num_radfds; i++)
				{
					if (FD_ISSET(radfds[i], &r))
					{
						processrad(buf, recv(radfds[i], buf, sizeof(buf), 0), i);
						n--;
					}
				}
			}

			// CLI connections
			if (FD_ISSET(clifd, &r))
			{
				int cli;
				
				alen = sizeof(addr);
				if ((cli = accept(clifd, (struct sockaddr *)&addr, &alen)) >= 0)
				{
					cli_do(cli);
					close(cli);
				}
				else
					LOG(0, 0, 0, "accept error: %s\n", strerror(errno));

				n--;
			}

#ifdef BGP
			for (i = 0; i < BGP_NUM_PEERS; i++)
			{
				int isr = bgp_set[i] ? FD_ISSET(bgp_peers[i].sock, &r) : 0;
				int isw = bgp_set[i] ? FD_ISSET(bgp_peers[i].sock, &w) : 0;
				bgp_process(&bgp_peers[i], isr, isw);
				if (isr) n--;
				if (isw) n--;
			}
#endif /* BGP */

			for (c = 0; n && c < config->multi_read_count; c++)
			{
				// L2TP
				if (FD_ISSET(udpfd, &r))
				{
					alen = sizeof(addr);
					if ((s = recvfrom(udpfd, buf, sizeof(buf), 0, (void *) &addr, &alen)) > 0)
					{
						processudp(buf, s, &addr);
						udp_pkts++;
					}
					else
					{
						FD_CLR(udpfd, &r);
						n--;
					}
				}

				// incoming IP
				if (FD_ISSET(tunfd, &r))
				{
					if ((s = read(tunfd, buf, sizeof(buf))) > 0)
					{
						processtun(buf, s);
					    	tun_pkts++;
					}
					else
					{
						FD_CLR(tunfd, &r);
						n--;
					}
				}

				// cluster
				if (FD_ISSET(cluster_sockfd, &r))
				{
					alen = sizeof(addr);
					if ((s = recvfrom(cluster_sockfd, buf, sizeof(buf), MSG_WAITALL, (void *) &addr, &alen)) > 0)
					{
						processcluster(buf, s, addr.sin_addr.s_addr);
						cluster_pkts++;
					}
					else
					{
						FD_CLR(cluster_sockfd, &r);
						n--;
					}
				}
			}

			if (udp_pkts > 1 || tun_pkts > 1 || cluster_pkts > 1)
				STAT(multi_read_used);

			if (c >= config->multi_read_count)
			{
				LOG(3, 0, 0, "Reached multi_read_count (%d); processed %d udp, %d tun and %d cluster packets\n",
					config->multi_read_count, udp_pkts, tun_pkts, cluster_pkts);

				STAT(multi_read_exceeded);
				more++;
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

		if (!config->cluster_iam_master)
			continue;

			// Run token bucket filtering queue..
			// Only run it every 1/10th of a second.
		{
			static clockt last_run = 0;
			if (last_run != TIME)
			{
				last_run = TIME;
				tbf_run_timer();
			}
		}

			// Handle timeouts, retries etc.
		{
			static double last_clean = 0;
			double this_clean;
			double diff;

			TIME = now(&this_clean);
			diff = this_clean - last_clean;

			// Run during idle time (after we've handled
			// all incoming packets) or every 1/10th sec
			if (!more || diff > 0.1)
			{
				regular_cleanups(diff);
				last_clean = this_clean;
			}
		}

		if (*config->accounting_dir)
		{
			static clockt next_acct = 0;
			static clockt next_shut_acct = 0;

			if (next_acct <= TIME)
			{
				// Dump accounting data
				next_acct = TIME + ACCT_TIME;
				next_shut_acct = TIME + ACCT_SHUT_TIME;
				dump_acct_info(1);
			}
			else if (next_shut_acct <= TIME)
			{
				// Dump accounting data for shutdown sessions
				next_shut_acct = TIME + ACCT_SHUT_TIME;
				if (shut_acct_n)
					dump_acct_info(0);
			}
		}
	}

		// Are we the master and shutting down??
	if (config->cluster_iam_master)
		cluster_heartbeat(); // Flush any queued changes..

		// Ok. Notify everyone we're shutting down. If we're
		// the master, this will force an election.
	cluster_send_ping(0);

	//
	// Important!!! We MUST not process any packets past this point!
	LOG(1, 0, 0, "Clean shutdown complete\n");
}

static void stripdomain(char *host)
{
	char *p;

	if ((p = strchr(host, '.')))
	{
		char *domain = 0;
		char _domain[1024];

		// strip off domain
		FILE *resolv = fopen("/etc/resolv.conf", "r");
		if (resolv)
		{
			char buf[1024];
			char *b;

			while (fgets(buf, sizeof(buf), resolv))
			{
				if (strncmp(buf, "domain", 6) && strncmp(buf, "search", 6))
					continue;

				if (!isspace(buf[6]))
					continue;

				b = buf + 7;
				while (isspace(*b)) b++;

				if (*b)
				{
					char *d = b;
					while (*b && !isspace(*b)) b++;
					*b = 0;
					if (buf[0] == 'd') // domain is canonical
					{
						domain = d;
						break;
					}

					// first search line
					if (!domain)
					{
						// hold, may be subsequent domain line
						strncpy(_domain, d, sizeof(_domain))[sizeof(_domain)-1] = 0;
						domain = _domain;
					}
				}
			}

			fclose(resolv);
		}

		if (domain)
		{
			int hl = strlen(host);
			int dl = strlen(domain);
			if (dl < hl && host[hl - dl - 1] == '.' && !strcmp(host + hl - dl, domain))
				host[hl -dl - 1] = 0;
		}
		else
		{
			*p = 0; // everything after first dot
		}
	}
}

// Init data structures
static void initdata(int optdebug, char *optconfig)
{
	int i;

	if (!(config = shared_malloc(sizeof(configt))))
	{
		fprintf(stderr, "Error doing malloc for configuration: %s\n", strerror(errno));
		exit(1);
	}

	memset(config, 0, sizeof(configt));
	time(&config->start_time);
	strncpy(config->config_file, optconfig, strlen(optconfig));
	config->debug = optdebug;
	config->num_tbfs = MAXTBFS;
	config->rl_rate = 28; // 28kbps
 	config->cluster_master_min_adv = 1;
	strcpy(config->random_device, RANDOMDEVICE);

	log_stream = stderr;

#ifdef RINGBUFFER
	if (!(ringbuffer = shared_malloc(sizeof(struct Tringbuffer))))
	{
		LOG(0, 0, 0, "Error doing malloc for ringbuffer: %s\n", strerror(errno));
		exit(1);
	}
	memset(ringbuffer, 0, sizeof(struct Tringbuffer));
#endif

	if (!(_statistics = shared_malloc(sizeof(struct Tstats))))
	{
		LOG(0, 0, 0, "Error doing malloc for _statistics: %s\n", strerror(errno));
		exit(1);
	}
	if (!(tunnel = shared_malloc(sizeof(tunnelt) * MAXTUNNEL)))
	{
		LOG(0, 0, 0, "Error doing malloc for tunnels: %s\n", strerror(errno));
		exit(1);
	}
	if (!(session = shared_malloc(sizeof(sessiont) * MAXSESSION)))
	{
		LOG(0, 0, 0, "Error doing malloc for sessions: %s\n", strerror(errno));
		exit(1);
	}

	if (!(sess_local = shared_malloc(sizeof(sessionlocalt) * MAXSESSION)))
	{
		LOG(0, 0, 0, "Error doing malloc for sess_local: %s\n", strerror(errno));
		exit(1);
	}

	if (!(radius = shared_malloc(sizeof(radiust) * MAXRADIUS)))
	{
		LOG(0, 0, 0, "Error doing malloc for radius: %s\n", strerror(errno));
		exit(1);
	}

	if (!(ip_address_pool = shared_malloc(sizeof(ippoolt) * MAXIPPOOL)))
	{
		LOG(0, 0, 0, "Error doing malloc for ip_address_pool: %s\n", strerror(errno));
		exit(1);
	}

	if (!(ip_filters = shared_malloc(sizeof(ip_filtert) * MAXFILTER)))
	{
		LOG(0, 0, 0, "Error doing malloc for ip_filters: %s\n", strerror(errno));
		exit(1);
	}
	memset(ip_filters, 0, sizeof(ip_filtert) * MAXFILTER);

	if (!(cli_session_actions = shared_malloc(sizeof(struct cli_session_actions) * MAXSESSION)))
	{
		LOG(0, 0, 0, "Error doing malloc for cli session actions: %s\n", strerror(errno));
		exit(1);
	}
	memset(cli_session_actions, 0, sizeof(struct cli_session_actions) * MAXSESSION);

	if (!(cli_tunnel_actions = shared_malloc(sizeof(struct cli_tunnel_actions) * MAXSESSION)))
	{
		LOG(0, 0, 0, "Error doing malloc for cli tunnel actions: %s\n", strerror(errno));
		exit(1);
	}
	memset(cli_tunnel_actions, 0, sizeof(struct cli_tunnel_actions) * MAXSESSION);

	memset(tunnel, 0, sizeof(tunnelt) * MAXTUNNEL);
	memset(session, 0, sizeof(sessiont) * MAXSESSION);
	memset(radius, 0, sizeof(radiust) * MAXRADIUS);
	memset(ip_address_pool, 0, sizeof(ippoolt) * MAXIPPOOL);

		// Put all the sessions on the free list marked as undefined.
	for (i = 1; i < MAXSESSION; i++)
	{
		session[i].next = i + 1;
		session[i].tunnel = T_UNDEF;	// mark it as not filled in.
	}
	session[MAXSESSION - 1].next = 0;
	sessionfree = 1;

		// Mark all the tunnels as undefined (waiting to be filled in by a download).
	for (i = 1; i < MAXTUNNEL; i++)
		tunnel[i].state = TUNNELUNDEF;	// mark it as not filled in.

	if (!*hostname)
	{
		// Grab my hostname unless it's been specified
		gethostname(hostname, sizeof(hostname));
		stripdomain(hostname);
	}

	_statistics->start_time = _statistics->last_reset = time(NULL);

#ifdef BGP
	if (!(bgp_peers = shared_malloc(sizeof(struct bgp_peer) * BGP_NUM_PEERS)))
	{
		LOG(0, 0, 0, "Error doing malloc for bgp: %s\n", strerror(errno));
		exit(1);
	}
#endif /* BGP */
}

static int assign_ip_address(sessionidt s)
{
	uint32_t i;
	int best = -1;
	time_t best_time = time_now;
	char *u = session[s].user;
	char reuse = 0;


	CSTAT(assign_ip_address);

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
		LOG(0, s, session[s].tunnel, "assign_ip_address(): out of addresses\n");
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
	LOG(4, s, session[s].tunnel, "assign_ip_address(): %s ip address %d from pool\n",
		reuse ? "Reusing" : "Allocating", best);

	return 1;
}

static void free_ip_address(sessionidt s)
{
	int i = session[s].ip_pool_index;


	CSTAT(free_ip_address);

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
		if (!(session[i].opened && session[i].ip))
			continue;

		ipid = - lookup_ipmap(htonl(session[i].ip));

		if (session[i].ip_pool_index < 0)
		{
			// Not allocated out of the pool.
			if (ipid < 1)			// Not found in the pool either? good.
				continue;

			LOG(0, i, 0, "Session %d has an IP address (%s) that was marked static, but is in the pool (%d)!\n",
				i, fmtaddr(session[i].ip, 0), ipid);

			// Fall through and process it as part of the pool.
		}


		if (ipid > MAXIPPOOL || ipid < 0)
		{
			LOG(0, i, 0, "Session %d has a pool IP that's not found in the pool! (%d)\n", i, ipid);
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
static void fix_address_pool(int sid)
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
static void add_to_ip_pool(in_addr_t addr, in_addr_t mask)
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
			LOG(0, 0, 0, "Overflowed IP pool adding %s\n", fmtaddr(htonl(addr), 0));
			return;
		}
	}
}

// Initialize the IP address pool
static void initippool()
{
	FILE *f;
	char *p;
	char buf[4096];
	memset(ip_address_pool, 0, sizeof(ip_address_pool));

	if (!(f = fopen(IPPOOLFILE, "r")))
	{
		LOG(0, 0, 0, "Can't load pool file " IPPOOLFILE ": %s\n", strerror(errno));
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
			in_addr_t src;
			*p = '\0';
			src = inet_addr(buf);
			if (src == INADDR_NONE)
			{
				LOG(0, 0, 0, "Invalid address pool IP %s\n", buf);
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
			in_addr_t start = 0, mask = 0;

			LOG(2, 0, 0, "Adding IP address range %s\n", buf);
			*p++ = 0;
			if (!*p || !(numbits = atoi(p)))
			{
				LOG(0, 0, 0, "Invalid pool range %s\n", buf);
				continue;
			}
			start = ntohl(inet_addr(pool));
			mask = (in_addr_t) (pow(2, numbits) - 1) << (32 - numbits);

			// Add a static route for this pool
			LOG(5, 0, 0, "Adding route for address pool %s/%u\n",
				fmtaddr(htonl(start), 0), 32 + mask);

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
	LOG(1, 0, 0, "IP address pool is %d addresses\n", ip_pool_size - 1);
}

void snoop_send_packet(char *packet, uint16_t size, in_addr_t destination, uint16_t port)
{
	struct sockaddr_in snoop_addr = {0};
	if (!destination || !port || snoopfd <= 0 || size <= 0 || !packet)
		return;

	snoop_addr.sin_family = AF_INET;
	snoop_addr.sin_addr.s_addr = destination;
	snoop_addr.sin_port = ntohs(port);

	LOG(5, 0, 0, "Snooping %d byte packet to %s:%d\n", size,
		fmtaddr(snoop_addr.sin_addr.s_addr, 0),
		htons(snoop_addr.sin_port));

	if (sendto(snoopfd, packet, size, MSG_DONTWAIT | MSG_NOSIGNAL, (void *) &snoop_addr, sizeof(snoop_addr)) < 0)
		LOG(0, 0, 0, "Error sending intercept packet: %s\n", strerror(errno));

	STAT(packets_snooped);
}

static int dump_session(FILE **f, sessiont *s)
{
	if (!s->opened || !s->ip || !(s->cin_delta || s->cout_delta) || !*s->user || s->walled_garden)
		return 1;

	if (!*f)
	{
		char filename[1024];
		char timestr[64];
		time_t now = time(NULL);

		strftime(timestr, sizeof(timestr), "%Y%m%d%H%M%S", localtime(&now));
		snprintf(filename, sizeof(filename), "%s/%s", config->accounting_dir, timestr);

		if (!(*f = fopen(filename, "w")))
		{
			LOG(0, 0, 0, "Can't write accounting info to %s: %s\n", filename, strerror(errno));
			return 0;
		}

		LOG(3, 0, 0, "Dumping accounting information to %s\n", filename);
		fprintf(*f, "# dslwatch.pl dump file V1.01\n"
			"# host: %s\n"
			"# time: %ld\n"
			"# uptime: %ld\n"
			"# format: username ip qos uptxoctets downrxoctets\n",
			hostname,
			now,
			now - basetime);
	}

	LOG(4, 0, 0, "Dumping accounting information for %s\n", s->user);
	fprintf(*f, "%s %s %d %u %u\n",
		s->user,						// username
		fmtaddr(htonl(s->ip), 0),				// ip
		(s->throttle_in || s->throttle_out) ? 2 : 1,		// qos
		(uint32_t) s->cin_delta,				// uptxoctets
		(uint32_t) s->cout_delta);				// downrxoctets

	s->cin_delta = s->cout_delta = 0;

	return 1;
}

static void dump_acct_info(int all)
{
	int i;
	FILE *f = NULL;


	CSTAT(dump_acct_info);

	if (shut_acct_n)
	{
		for (i = 0; i < shut_acct_n; i++)
			dump_session(&f, &shut_acct[i]);

		shut_acct_n = 0;
	}

	if (all)
		for (i = 1; i <= config->cluster_highest_sessionid; i++)
			dump_session(&f, &session[i]);

	if (f)
		fclose(f);
}

// Main program
int main(int argc, char *argv[])
{
	int i;
	int optdebug = 0;
	char *optconfig = CONFIGFILE;

	time(&basetime);             // start clock

	// scan args
	while ((i = getopt(argc, argv, "dvc:h:")) >= 0)
	{
		switch (i)
		{
		case 'd':
			if (fork()) exit(0);
			setsid();
			freopen("/dev/null", "r", stdin);
			freopen("/dev/null", "w", stdout);
			freopen("/dev/null", "w", stderr);
			break;
		case 'v':
			optdebug++;
			break;
		case 'c':
			optconfig = optarg;
			break;
		case 'h':
			snprintf(hostname, sizeof(hostname), "%s", optarg);
			break;
		default:
			printf("Args are:\n"
			       "\t-d\t\tDetach from terminal\n"
			       "\t-c <file>\tConfig file\n"
			       "\t-h <hostname>\tForce hostname\n"
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

	initplugins();
	initdata(optdebug, optconfig);

	init_cli(hostname);
	read_config_file();
	init_tbf(config->num_tbfs);

	LOG(0, 0, 0, "L2TPNS version " VERSION "\n");
	LOG(0, 0, 0, "Copyright (c) 2003, 2004, 2005 Optus Internet Engineering\n");
	LOG(0, 0, 0, "Copyright (c) 2002 FireBrick (Andrews & Arnold Ltd / Watchfront Ltd) - GPL licenced\n");
	{
		struct rlimit rlim;
		rlim.rlim_cur = RLIM_INFINITY;
		rlim.rlim_max = RLIM_INFINITY;
		// Remove the maximum core size
		if (setrlimit(RLIMIT_CORE, &rlim) < 0)
			LOG(0, 0, 0, "Can't set ulimit: %s\n", strerror(errno));

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
			LOG(0, 0, 0, "Not using FIFO scheduler, there is only 1 processor in the system.\n");
			config->scheduler_fifo = 0;
		}
		else
		{
			if ((ret = sched_setscheduler(0, SCHED_FIFO, &params)) == 0)
			{
				LOG(1, 0, 0, "Using FIFO scheduler.  Say goodbye to any other processes running\n");
			}
			else
			{
				LOG(0, 0, 0, "Error setting scheduler to FIFO: %s\n", strerror(errno));
				config->scheduler_fifo = 0;
			}
		}
	}

	/* Set up the cluster communications port. */
	if (cluster_init() < 0)
		exit(1);

#ifdef BGP
	signal(SIGPIPE, SIG_IGN);
	bgp_setup(config->as_number);
	bgp_add_route(config->bind_address, 0xffffffff);
	for (i = 0; i < BGP_NUM_PEERS; i++)
	{
		if (config->neighbour[i].name[0])
			bgp_start(&bgp_peers[i], config->neighbour[i].name,
				config->neighbour[i].as, config->neighbour[i].keepalive,
				config->neighbour[i].hold, 0); /* 0 = routing disabled */
	}
#endif /* BGP */

	inittun();
	LOG(1, 0, 0, "Set up on interface %s\n", config->tundevice);

	initudp();
	initrad();
	initippool();

	signal(SIGHUP, sighup_handler);
	signal(SIGTERM, sigterm_handler);
	signal(SIGINT, sigterm_handler);
	signal(SIGQUIT, sigquit_handler);
	signal(SIGCHLD, sigchild_handler);

	// Prevent us from getting paged out
	if (config->lock_pages)
	{
		if (!mlockall(MCL_CURRENT))
			LOG(1, 0, 0, "Locking pages into memory\n");
		else
			LOG(0, 0, 0, "Can't lock pages: %s\n", strerror(errno));
	}

	alarm(1);

	// Drop privileges here
	if (config->target_uid > 0 && geteuid() == 0)
		setuid(config->target_uid);

	mainloop();

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

static void sighup_handler(int sig)
{
	if (log_stream)
	{
		if (log_stream != stderr)
			fclose(log_stream);

		log_stream = NULL;
	}

	read_config_file();
}

static void sigalrm_handler(int sig)
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

static void sigterm_handler(int sig)
{
	LOG(1, 0, 0, "Shutting down cleanly\n");
	main_quit++;
}

static void sigquit_handler(int sig)
{
	int i;

	LOG(1, 0, 0, "Shutting down without saving sessions\n");

	if (config->cluster_iam_master)
	{
		for (i = 1; i < MAXSESSION; i++)
		{
			if (session[i].opened)
				sessionkill(i, "L2TPNS Closing");
		}
		for (i = 1; i < MAXTUNNEL; i++)
		{
			if (tunnel[i].ip || tunnel[i].state)
				tunnelshutdown(i, "L2TPNS Closing", 6, 0, 0);
		}
	}

	main_quit++;
}

static void sigchild_handler(int sig)
{
	while (waitpid(-1, NULL, WNOHANG) > 0)
	    ;
}

static void build_chap_response(char *challenge, uint8_t id, uint16_t challenge_length, char **challenge_response)
{
	MD5_CTX ctx;
	*challenge_response = NULL;

	if (!*config->l2tpsecret)
	{
		LOG(0, 0, 0, "LNS requested CHAP authentication, but no l2tp secret is defined\n");
		return;
	}

	LOG(4, 0, 0, "   Building challenge response for CHAP request\n");

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

static void update_config()
{
	int i;
	char *p;
	static int timeout = 0;
	static int interval = 0;

	// Update logging
	closelog();
	syslog_log = 0;
	if (log_stream)
	{
		if (log_stream != stderr)
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
			if (i > 0 && !config->radiusport[i])
				config->radiusport[i] = config->radiusport[i-1];
			if (!config->radiusport[i])
				config->radiusport[i] = RADPORT;
		}

	if (!config->numradiusservers)
		LOG(0, 0, 0, "No RADIUS servers defined!\n");

	config->num_radfds = 1 << RADIUS_SHIFT;

	// parse radius_authtypes_s
	config->radius_authtypes = config->radius_authprefer = 0;
	p = config->radius_authtypes_s;
	while (p && *p)
	{
		char *s = strpbrk(p, " \t,");
		int type = 0;

		if (s)
		{
			*s++ = 0;
			while (*s == ' ' || *s == '\t')
				s++;

			if (!*s)
				s = 0;
		}

		if (!strncasecmp("chap", p, strlen(p)))
			type = AUTHCHAP;
		else if (!strncasecmp("pap", p, strlen(p)))
			type = AUTHPAP;
		else
			LOG(0, 0, 0, "Invalid RADIUS authentication type \"%s\"\n", p);

		config->radius_authtypes |= type;
		if (!config->radius_authprefer)
			config->radius_authprefer = type;

		p = s;
	}

	if (!config->radius_authtypes)
	{
		LOG(0, 0, 0, "Defaulting to PAP authentication\n");
		config->radius_authtypes = config->radius_authprefer = AUTHPAP;
	}

	// normalise radius_authtypes_s
	if (config->radius_authprefer == AUTHPAP)
	{
		strcpy(config->radius_authtypes_s, "pap");
		if (config->radius_authtypes & AUTHCHAP)
			strcat(config->radius_authtypes_s, ", chap");
	}
	else
	{
		strcpy(config->radius_authtypes_s, "chap");
		if (config->radius_authtypes & AUTHPAP)
			strcat(config->radius_authtypes_s, ", pap");
	}

	// re-initialise the random number source
	initrandom(config->random_device);

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
			LOG(0, 0, 0, "Heartbeat timeout %d too low, adjusting to %d\n", config->cluster_hb_timeout, t);
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
			LOG(0, 0, 0, "Can't write to PID file %s: %s\n", config->pid_file, strerror(errno));
		}
	}

	config->reload_config = 0;
}

static void read_config_file()
{
	FILE *f;

	if (!config->config_file) return;
	if (!(f = fopen(config->config_file, "r")))
	{
		fprintf(stderr, "Can't open config file %s: %s\n", config->config_file, strerror(errno));
		return;
	}

	LOG(3, 0, 0, "Reading config file %s\n", config->config_file);
	cli_do_file(f);
	LOG(3, 0, 0, "Done reading config file\n");
	fclose(f);
	update_config();
}

int sessionsetup(tunnelidt t, sessionidt s)
{
	// A session now exists, set it up
	in_addr_t ip;
	char *user;
	sessionidt i;
	int r;

	CSTAT(sessionsetup);

	LOG(3, s, t, "Doing session setup for session\n");

	if (!session[s].ip)
	{
		assign_ip_address(s);
		if (!session[s].ip)
		{
			LOG(0, s, t, "   No IP allocated.  The IP address pool is FULL!\n");
			sessionshutdown(s, "No IP addresses available.", 2, 7);
			return 0;
		}
		LOG(3, s, t, "   No IP allocated.  Assigned %s from pool\n",
			fmtaddr(htonl(session[s].ip), 0));
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
			if (!session[s].opened) continue;
			if (ip == session[i].ip)
			{
				sessionkill(i, "Duplicate IP address");
				continue;
			}

			if (config->allow_duplicate_users) continue;
			if (session[s].walled_garden || session[i].walled_garden) continue;
			if (!strcasecmp(user, session[i].user))
				sessionkill(i, "Duplicate session for users");
		}
	}

	{
	    	int routed = 0;

		// Add the route for this session.
		for (r = 0; r < MAXROUTE && session[s].route[r].ip; r++)
		{
			if ((session[s].ip & session[s].route[r].mask) ==
			    (session[s].route[r].ip & session[s].route[r].mask))
				routed++;

			routeset(s, session[s].route[r].ip, session[s].route[r].mask, 0, 1);
		}

		// Static IPs need to be routed if not already
		// convered by a Framed-Route.  Anything else is part
		// of the IP address pool and is already routed, it
		// just needs to be added to the IP cache.
		// IPv6 route setup is done in ppp.c, when IPV6CP is acked.
		if (session[s].ip_pool_index == -1) // static ip
		{
			if (!routed) routeset(s, session[s].ip, 0, 0, 1);
		}
		else
			cache_ipmap(session[s].ip, s);
	}

	if (!session[s].unique_id)
	{
		// did this session just finish radius?
		LOG(3, s, t, "Sending initial IPCP to client\n");
		sendipcp(t, s);
		session[s].unique_id = ++last_id;
	}

	// Run the plugin's against this new session.
	{
		struct param_new_session data = { &tunnel[t], &session[s] };
		run_plugins(PLUGIN_NEW_SESSION, &data);
	}

	// Allocate TBFs if throttled
	if (session[s].throttle_in || session[s].throttle_out)
		throttle_session(s, session[s].throttle_in, session[s].throttle_out);

	session[s].last_packet = time_now;

	LOG(2, s, t, "Login by %s at %s from %s (%s)\n", session[s].user,
		fmtaddr(htonl(session[s].ip), 0),
		fmtaddr(htonl(tunnel[t].ip), 1), tunnel[t].hostname);

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
	int newip = 0;

		// Sanity checks.
	if (new->ip_pool_index >= MAXIPPOOL ||
		new->tunnel >= MAXTUNNEL)
	{
		LOG(0, s, 0, "Strange session update received!\n");
			// FIXME! What to do here?
		return 0;
	}

		//
		// Ok. All sanity checks passed. Now we're committed to
		// loading the new session.
		//

	session[s].tunnel = new->tunnel; // For logging in cache_ipmap

	// See if routes/ip cache need updating
	if (new->ip != session[s].ip)
		newip++;

	for (i = 0; !newip && i < MAXROUTE && (session[s].route[i].ip || new->route[i].ip); i++)
		if (new->route[i].ip != session[s].route[i].ip ||
		    new->route[i].mask != session[s].route[i].mask)
			newip++;

	// needs update
	if (newip)
	{
	    	int routed = 0;

		// remove old routes...
		for (i = 0; i < MAXROUTE && session[s].route[i].ip; i++)
		{
			if ((session[s].ip & session[s].route[i].mask) ==
			    (session[s].route[i].ip & session[s].route[i].mask))
				routed++;

			routeset(s, session[s].route[i].ip, session[s].route[i].mask, 0, 0);
		}

		// ...ip
		if (session[s].ip)
		{
			if (session[s].ip_pool_index == -1) // static IP
			{
				if (!routed) routeset(s, session[s].ip, 0, 0, 0);
			}
			else		// It's part of the IP pool, remove it manually.
				uncache_ipmap(session[s].ip);
		}

		routed = 0;

		// add new routes...
		for (i = 0; i < MAXROUTE && new->route[i].ip; i++)
		{
			if ((new->ip & new->route[i].mask) ==
			    (new->route[i].ip & new->route[i].mask))
				routed++;

			routeset(s, new->route[i].ip, new->route[i].mask, 0, 1);
		}

		// ...ip
		if (new->ip)
		{
			// If there's a new one, add it.
			if (new->ip_pool_index == -1)
			{
				if (!routed) routeset(s, new->ip, 0, 0, 1);
			}
			else
				cache_ipmap(new->ip, s);
		}
	}

	// check v6 routing
	if (new->flags & SF_IPV6_ROUTED && !(session[s].flags & SF_IPV6_ROUTED))
		    route6set(s, new->ipv6route, new->ipv6prefixlen, 1);

	// check filters
	if (new->filter_in && (new->filter_in > MAXFILTER || !ip_filters[new->filter_in - 1].name[0]))
	{
		LOG(2, s, session[s].tunnel, "Dropping invalid input filter %d\n", (int) new->filter_in);
		new->filter_in = 0;
	}

	if (new->filter_out && (new->filter_out > MAXFILTER || !ip_filters[new->filter_out - 1].name[0]))
	{
		LOG(2, s, session[s].tunnel, "Dropping invalid output filter %d\n", (int) new->filter_out);
		new->filter_out = 0;
	}

	if (new->filter_in != session[s].filter_in)
	{
		if (session[s].filter_in) ip_filters[session[s].filter_in - 1].used--;
		if (new->filter_in)       ip_filters[new->filter_in - 1].used++;
	}

	if (new->filter_out != session[s].filter_out)
	{
		if (session[s].filter_out) ip_filters[session[s].filter_out - 1].used--;
		if (new->filter_out)       ip_filters[new->filter_out - 1].used++;
	}

	if (new->tunnel && s > config->cluster_highest_sessionid)	// Maintain this in the slave. It's used
					// for walking the sessions to forward byte counts to the master.
		config->cluster_highest_sessionid = s;

	// TEMP: old session struct used a uint32_t to define the throttle
	// speed for both up/down, new uses a uint16_t for each.  Deal with
	// sessions from an old master for migration.
	if (new->throttle_out == 0 && new->tbf_out)
		new->throttle_out = new->throttle_in;

	memcpy(&session[s], new, sizeof(session[s]));	// Copy over..

		// Do fixups into address pool.
	if (new->ip_pool_index != -1)
		fix_address_pool(s);

	return 1;
}

static void initplugins()
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
	LOG(2, 0, 0, "%soading plugin from %s\n", load ? "L" : "Un-l", path);
	return dlopen(path, RTLD_NOW);
}

// plugin callback to get a config value
static void *getconfig(char *key, enum config_typet type)
{
	int i;

	for (i = 0; config_values[i].key; i++)
	{
		if (!strcmp(config_values[i].key, key))
		{
			if (config_values[i].type == type)
				return ((void *) config) + config_values[i].offset;

			LOG(1, 0, 0, "plugin requested config item \"%s\" expecting type %d, have type %d\n",
				key, type, config_values[i].type);

			return 0;
		}
	}

	LOG(1, 0, 0, "plugin requested unknown config item \"%s\"\n", key);
	return 0;
}

static int add_plugin(char *plugin_name)
{
	static struct pluginfuncs funcs = {
		_log,
		_log_hex,
		fmtaddr,
		sessionbyuser,
		sessiontbysessionidt,
		sessionidtbysessiont,
		radiusnew,
		radiussend,
		getconfig,
		sessionshutdown,
		sessionkill,
		throttle_session,
		cluster_send_session,
	};

	void *p = open_plugin(plugin_name, 1);
	int (*initfunc)(struct pluginfuncs *);
	int i;

	if (!p)
	{
		LOG(1, 0, 0, "   Plugin load failed: %s\n", dlerror());
		return -1;
	}

	if (ll_contains(loaded_plugins, p))
	{
		dlclose(p);
		return 0; // already loaded
	}

	{
		int *v = dlsym(p, "plugin_api_version");
		if (!v || *v != PLUGIN_API_VERSION)
		{
			LOG(1, 0, 0, "   Plugin load failed: API version mismatch: %s\n", dlerror());
			dlclose(p);
			return -1;
		}
	}

	if ((initfunc = dlsym(p, "plugin_init")))
	{
		if (!initfunc(&funcs))
		{
			LOG(1, 0, 0, "   Plugin load failed: plugin_init() returned FALSE: %s\n", dlerror());
			dlclose(p);
			return -1;
		}
	}

	ll_push(loaded_plugins, p);

	for (i = 0; i < max_plugin_functions; i++)
	{
		void *x;
		if (plugin_functions[i] && (x = dlsym(p, plugin_functions[i])))
		{
			LOG(3, 0, 0, "   Supports function \"%s\"\n", plugin_functions[i]);
			ll_push(plugins[i], x);
		}
	}

	LOG(2, 0, 0, "   Loaded plugin %s\n", plugin_name);
	return 1;
}

static void run_plugin_done(void *plugin)
{
	int (*donefunc)(void) = dlsym(plugin, "plugin_done");

	if (donefunc)
		donefunc();
}

static int remove_plugin(char *plugin_name)
{
	void *p = open_plugin(plugin_name, 0);
	int loaded = 0;

	if (!p)
		return -1;

	if (ll_contains(loaded_plugins, p))
	{
		int i;
		for (i = 0; i < max_plugin_functions; i++)
		{
			void *x;
			if (plugin_functions[i] && (x = dlsym(p, plugin_functions[i])))
				ll_delete(plugins[i], x);
		}

		ll_delete(loaded_plugins, p);
		run_plugin_done(p);
		loaded = 1;
	}

	dlclose(p);
	LOG(2, 0, 0, "Removed plugin %s\n", plugin_name);
	return loaded;
}

int run_plugins(int plugin_type, void *data)
{
	int (*func)(void *data);

	if (!plugins[plugin_type] || plugin_type > max_plugin_functions)
		return PLUGIN_RET_ERROR;

	ll_reset(plugins[plugin_type]);
	while ((func = ll_next(plugins[plugin_type])))
	{
		int r = func(data);

		if (r != PLUGIN_RET_OK)
			return r; // stop here
	}

	return PLUGIN_RET_OK;
}

static void plugins_done()
{
	void *p;

	ll_reset(loaded_plugins);
	while ((p = ll_next(loaded_plugins)))
		run_plugin_done(p);
}

static void processcontrol(uint8_t * buf, int len, struct sockaddr_in *addr, int alen)
{
	struct nsctl request;
	struct nsctl response;
	int type = unpack_control(&request, buf, len);
	int r;
	void *p;

	if (log_stream && config->debug >= 4)
	{
		if (type < 0)
		{
			LOG(4, 0, 0, "Bogus control message from %s (%d)\n",
				fmtaddr(addr->sin_addr.s_addr, 0), type);
		}
		else
		{
			LOG(4, 0, 0, "Received [%s] ", fmtaddr(addr->sin_addr.s_addr, 0));
			dump_control(&request, log_stream);
		}
	}

	switch (type)
	{
	case NSCTL_REQ_LOAD:
		if (request.argc != 1)
		{
			response.type = NSCTL_RES_ERR;
			response.argc = 1;
			response.argv[0] = "name of plugin required";
		}
		else if ((r = add_plugin(request.argv[0])) < 1)
		{
			response.type = NSCTL_RES_ERR;
			response.argc = 1;
			response.argv[0] = !r
				? "plugin already loaded"
				: "error loading plugin";
		}
		else
		{
			response.type = NSCTL_RES_OK;
			response.argc = 0;
		}

		break;

	case NSCTL_REQ_UNLOAD:
		if (request.argc != 1)
		{
			response.type = NSCTL_RES_ERR;
			response.argc = 1;
			response.argv[0] = "name of plugin required";
		}
		else if ((r = remove_plugin(request.argv[0])) < 1)
		{
			response.type = NSCTL_RES_ERR;
			response.argc = 1;
			response.argv[0] = !r
				? "plugin not loaded"
				: "plugin not found";
		}
		else
		{
			response.type = NSCTL_RES_OK;
			response.argc = 0;
		}

		break;

	case NSCTL_REQ_HELP:
		response.type = NSCTL_RES_OK;
		response.argc = 0;

		ll_reset(loaded_plugins);
		while ((p = ll_next(loaded_plugins)))
		{
			char **help = dlsym(p, "plugin_control_help");
			while (response.argc < 0xff && help && *help)
				response.argv[response.argc++] = *help++;
		}

		break;

	case NSCTL_REQ_CONTROL:
		{
			struct param_control param = {
				config->cluster_iam_master,
				request.argc,
				request.argv,
				0,
				NULL,
			};

			int r = run_plugins(PLUGIN_CONTROL, &param);

			if (r == PLUGIN_RET_ERROR)
			{
				response.type = NSCTL_RES_ERR;
				response.argc = 1;
				response.argv[0] = param.additional
					? param.additional
					: "error returned by plugin";
			}
			else if (r == PLUGIN_RET_NOTMASTER)
			{
				static char msg[] = "must be run on master: 000.000.000.000";

				response.type = NSCTL_RES_ERR;
				response.argc = 1;
				if (config->cluster_master_address)
				{
					strcpy(msg + 23, fmtaddr(config->cluster_master_address, 0));
					response.argv[0] = msg;
				}
				else
				{
				    	response.argv[0] = "must be run on master: none elected";
				}
			}
			else if (!(param.response & NSCTL_RESPONSE))
			{
				response.type = NSCTL_RES_ERR;
				response.argc = 1;
				response.argv[0] = param.response
					? "unrecognised response value from plugin"
					: "unhandled action";
			}
			else
			{
				response.type = param.response;
				response.argc = 0;
				if (param.additional)
				{
					response.argc = 1;
					response.argv[0] = param.additional;
				}
			}
		}

		break;

	default:
		response.type = NSCTL_RES_ERR;
		response.argc = 1;
		response.argv[0] = "error unpacking control packet";
	}

	buf = calloc(NSCTL_MAX_PKT_SZ, 1);
	if (!buf)
	{
		LOG(2, 0, 0, "Failed to allocate nsctl response\n");
		return;
	}

	r = pack_control(buf, NSCTL_MAX_PKT_SZ, response.type, response.argc, response.argv);
	if (r > 0)
	{
		sendto(controlfd, buf, r, 0, (const struct sockaddr *) addr, alen);
		if (log_stream && config->debug >= 4)
		{
			LOG(4, 0, 0, "Sent [%s] ", fmtaddr(addr->sin_addr.s_addr, 0));
			dump_control(&response, log_stream);
		}
	}
	else
		LOG(2, 0, 0, "Failed to pack nsctl response for %s (%d)\n",
			fmtaddr(addr->sin_addr.s_addr, 0), r);

	free(buf);
}

static tunnelidt new_tunnel()
{
	tunnelidt i;
	for (i = 1; i < MAXTUNNEL; i++)
	{
		if (tunnel[i].state == TUNNELFREE)
		{
			LOG(4, 0, i, "Assigning tunnel ID %d\n", i);
			if (i > config->cluster_highest_tunnelid)
				config->cluster_highest_tunnelid = i;
			return i;
		}
	}
	LOG(0, 0, 0, "Can't find a free tunnel! There shouldn't be this many in use!\n");
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
	int s, i;
	run_plugins(PLUGIN_BECOME_MASTER, NULL);

	// running a bunch of iptables commands is slow and can cause
	// the master to drop tunnels on takeover--kludge around the
	// problem by forking for the moment (note: race)
	if (!fork_and_close())
	{
		for (s = 1; s <= config->cluster_highest_sessionid ; ++s)
		{
			if (!session[s].opened) // Not an in-use session.
				continue;

			run_plugins(PLUGIN_NEW_SESSION_MASTER, &session[s]);
		}
		exit(0);
	}

	// add radius fds
	for (i = 0; i < config->num_radfds; i++)
	{
		FD_SET(radfds[i], &readset);
		if (radfds[i] > readset_n)
			readset_n = radfds[i];
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
		if (!session[s].opened)
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
		if (!session[s].opened)
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
 * This unencodes the AVP using the L2TP secret and the previously
 * stored random vector.  It overwrites the hidden data with the
 * unhidden AVP subformat.
 */
static void unhide_value(uint8_t *value, size_t len, uint16_t type, uint8_t *vector, size_t vec_len)
{
	MD5_CTX ctx;
	uint8_t digest[16];
	uint8_t *last;
	size_t d = 0;

	// Compute initial pad
	MD5Init(&ctx);
	MD5Update(&ctx, (uint8_t) (type >> 8) & 0xff, 1);
	MD5Update(&ctx, (uint8_t)  type       & 0xff, 1);
	MD5Update(&ctx, config->l2tpsecret, strlen(config->l2tpsecret));
	MD5Update(&ctx, vector, vec_len);
	MD5Final(digest, &ctx);

	// pointer to last decoded 16 octets
	last = value;

	while (len > 0)
	{
		// calculate a new pad based on the last decoded block
		if (d >= sizeof(digest))
		{
			MD5Init(&ctx);
			MD5Update(&ctx, config->l2tpsecret, strlen(config->l2tpsecret));
			MD5Update(&ctx, last, sizeof(digest));
			MD5Final(digest, &ctx);

			d = 0;
			last = value;
		}

		*value++ ^= digest[d++];
		len--;
	}
}

static int ip_filter_port(ip_filter_portt *p, uint16_t port)
{
	switch (p->op)
	{
	case FILTER_PORT_OP_EQ:    return port == p->port;
	case FILTER_PORT_OP_NEQ:   return port != p->port;
	case FILTER_PORT_OP_GT:    return port > p->port;
	case FILTER_PORT_OP_LT:    return port < p->port;
	case FILTER_PORT_OP_RANGE: return port >= p->port && port <= p->port2;
	}

	return 0;
}

static int ip_filter_flag(uint8_t op, uint8_t sflags, uint8_t cflags, uint8_t flags)
{
	switch (op)
	{
	case FILTER_FLAG_OP_ANY:
		return (flags & sflags) || (~flags & cflags);

	case FILTER_FLAG_OP_ALL:
		return (flags & sflags) == sflags && (~flags & cflags) == cflags;

	case FILTER_FLAG_OP_EST:
		return (flags & (TCP_FLAG_ACK|TCP_FLAG_RST)) && (~flags & TCP_FLAG_SYN);
	}

	return 0;
}

int ip_filter(uint8_t *buf, int len, uint8_t filter)
{
	uint16_t frag_offset;
	uint8_t proto;
    	in_addr_t src_ip;
	in_addr_t dst_ip;
	uint16_t src_port = 0;
	uint16_t dst_port = 0;
	uint8_t flags = 0;
	ip_filter_rulet *rule;

    	if (len < 20) // up to end of destination address
		return 0;

	if ((*buf >> 4) != 4) // IPv4
		return 0;

	frag_offset = ntohs(*(uint16_t *) (buf + 6)) & 0x1fff;
	proto = buf[9];
	src_ip = *(in_addr_t *) (buf + 12);
	dst_ip = *(in_addr_t *) (buf + 16);

	if (frag_offset == 0 && (proto == IPPROTO_TCP || proto == IPPROTO_UDP))
	{
		int l = (buf[0] & 0xf) * 4; // length of IP header
		if (len < l + 4) // ports
			return 0;

		src_port = ntohs(*(uint16_t *) (buf + l));
		dst_port = ntohs(*(uint16_t *) (buf + l + 2));
		if (proto == IPPROTO_TCP)
		{
		    	if (len < l + 14) // flags
				return 0;

			flags = buf[l + 13] & 0x3f;
		}
	}

	for (rule = ip_filters[filter].rules; rule->action; rule++)
	{
		if (rule->proto != IPPROTO_IP && proto != rule->proto)
			continue;

		if (rule->src_wild != INADDR_BROADCAST &&
		    (src_ip & ~rule->src_wild) != (rule->src_ip & ~rule->src_wild))
			continue;

		if (rule->dst_wild != INADDR_BROADCAST &&
		    (dst_ip & ~rule->dst_wild) != (rule->dst_ip & ~rule->dst_wild))
			continue;

		if (frag_offset)
		{
			if (!rule->frag || rule->action == FILTER_ACTION_DENY)
				continue;
		}
		else
		{
			if (rule->frag)
				continue;

			if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
			{
				if (rule->src_ports.op && !ip_filter_port(&rule->src_ports, src_port))
					continue;

				if (rule->dst_ports.op && !ip_filter_port(&rule->dst_ports, dst_port))
					continue;

				if (proto == IPPROTO_TCP && rule->tcp_flag_op &&
				    !ip_filter_flag(rule->tcp_flag_op, rule->tcp_sflags, rule->tcp_cflags, flags))
					continue;
			}
		}

		// matched
		rule->counter++;
		return rule->action == FILTER_ACTION_PERMIT;
	}

	// default deny
    	return 0;
}
