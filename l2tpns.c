// L2TP Network Server
// Adrian Kennard 2002
// (c) Copyrigth 2002 FireBrick (Andrews & Arnold Ltd / Watchfront Ltd)
// vim: sw=8 ts=8

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <malloc.h>
#include <math.h>
#include <net/route.h>
#include <sys/mman.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/if.h>
#include <time.h>
#include <dlfcn.h>
#include <unistd.h>
#ifdef HAVE_LIBCLI
#include <libcli.h>
#endif
#include "md5.h"
#include "l2tpns.h"
#include "cluster.h"
#include "plugin.h"
#include "ll.h"
#include "constants.h"
#include "control.h"
#include "util.h"

ipt radiusserver[MAXRADSERVER]; // radius servers
u8 numradiusservers = 0;  // how many radius servers

// Globals
char tapdevice[10] = "";    // tap device name
int tapfd = -1;            // tap interface file handle
int udpfd = -1;            // UDP file handle
int controlfd = -1;        // Control signal handle
int snoopfd = -1;          // UDP file handle for sending out intercept data
int radfd = -1;            // RADIUS requests file handle
int ifrfd = -1;            // File descriptor for routing, etc
char debug = 0;		// debug leveL
time_t basetime = 0;          // base clock
char hostname[1000] = ""; // us.
ipt myip = 0;              // MY IP
u16 tapmac[3];             // MAC of tap interface
int tapidx;		   // ifr_ifindex of tap device
char *radiussecret = 0;      // RADIUS secret
char *l2tpsecret = 0;        // L2TP secret
u32 sessionid = 0;         // session id for radius accounting
char	*snoop_destination_host = NULL;
u16	snoop_destination_port = 0;
char *log_filename = NULL;
char *config_file = CONFIGFILE;
FILE *log_stream = NULL;
unsigned long default_dns1 = 0, default_dns2 = 0;
struct sockaddr_in snoop_addr = {0};
extern unsigned long rl_rate;
extern int cluster_sockfd;
unsigned long last_sid = 0;
int config_save_state = 0;
int radius_accounting = 0;
char *accounting_dir = NULL;
uint32_t cluster_address = 0;
uint32_t bind_address = INADDR_ANY;
int handle_interface = 0;
#ifdef HAVE_LIBCLI
pid_t cli_pid = 0;
int clifd = 0;
sessionidt *cli_session_kill = NULL;
tunnelidt *cli_tunnel_kill = NULL;
#endif
static void *ip_hash[256];
unsigned long udp_tx = 0, udp_rx = 0, udp_rx_pkt = 0;
unsigned long eth_tx = 0, eth_rx = 0, eth_rx_pkt = 0;
unsigned int ip_pool_index = 0;
unsigned int ip_pool_size = 0;
time_t time_now;
char time_now_string[64] = {0};
char main_quit = 0;
int dump_speed = 0;
int target_uid = 500;
char *_program_name = NULL;
linked_list *loaded_plugins;
linked_list *plugins[MAX_PLUGIN_TYPES];

char *plugin_functions[] = {
	NULL,
	"plugin_pre_auth",
	"plugin_post_auth",
	"plugin_packet_rx",
	"plugin_packet_tx",
	"plugin_timer",
	"plugin_config",
	"plugin_new_session",
	"plugin_kill_session",
	"plugin_control",
	"plugin_radius_response",
};
#define max_plugin_functions (sizeof(plugin_functions) / sizeof(char *))

tunnelt *tunnel = NULL;	// 1000 * 45 = 45000 = 45k
sessiont *session = NULL;	// 5000 * 213 = 1065000 = 1 Mb
radiust *radius = NULL;
ippoolt *ip_address_pool = NULL;
tunnelidt tunnelfree;           // free list link heads
sessionidt sessionfree = 0;
u8 radiusfree;
controlt *controlfree = 0;
struct Tstats *_statistics = NULL;
#ifdef RINGBUFFER
struct Tringbuffer *ringbuffer = NULL;
#endif
tbft *filter_buckets = NULL;

void sigalrm_handler(int);
void sighup_handler(int);
void sigterm_handler(int);
void sigquit_handler(int);
void sigchild_handler(int);
void sigsegv_handler(int);
void read_config_file();
void read_state();
void dump_state();

// return internal time (10ths since run)
clockt now(void)
{
	struct timeval t;
	gettimeofday(&t, 0);
	return (t.tv_sec - basetime) * 10 + t.tv_usec / 100000 + 1;
}

// work out a retry time based on try number
clockt backoff(u8 try)
{
	if (try > 5) try = 5;                  // max backoff
	return now() + 10 * (1 << try);
}

void _log(int level, ipt address, sessionidt s, tunnelidt t, const char *format, ...)
{
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

	if (debug < level) return;

	if (!log_stream && log_filename)
	{
		if ((log_stream = fopen(log_filename, "a")))
		fseek(log_stream, 0, SEEK_END);
		setbuf(log_stream, NULL);
	}
	if (!log_stream)
	{
		log_stream = stderr;
		setbuf(log_stream, NULL);
	}

	va_start(ap, format);
	fprintf(log_stream, "%s %02d/%02d ", time_now_string, t, s);
	vfprintf(log_stream, format, ap);
	va_end(ap);
}

void _log_hex(int level, ipt address, sessionidt s, tunnelidt t, const char *title, const char *data, int maxsize)
{
	unsigned int i, j;
	unsigned const char *d = (unsigned const char *)data;

	if (debug < level) return;
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


// Add a route
void routeset(ipt ip, ipt mask, ipt gw, u8 add)
{
	struct rtentry r;
	memset(&r, 0, sizeof(r));
	r.rt_dev = tapdevice;
	r.rt_dst.sa_family = AF_INET;
	*(u32 *) & (((struct sockaddr_in *) &r.rt_dst)->sin_addr.s_addr) = htonl(ip);
	r.rt_gateway.sa_family = AF_INET;
	*(u32 *) & (((struct sockaddr_in *) &r.rt_gateway)->sin_addr.s_addr) = htonl(gw);
	r.rt_genmask.sa_family = AF_INET;
	*(u32 *) & (((struct sockaddr_in *) &r.rt_genmask)->sin_addr.s_addr) = htonl(mask ? : 0xFFFFFFF);
	r.rt_flags = (RTF_UP | RTF_STATIC);
	if (gw)
		r.rt_flags |= RTF_GATEWAY;
	else
		r.rt_flags |= RTF_HOST;
	if (ioctl(ifrfd, add ? SIOCADDRT : SIOCDELRT, (void *) &r) < 0) perror("routeset");
	log(1, ip, 0, 0, "Route %s %u.%u.%u.%u/%u.%u.%u.%u %u.%u.%u.%u\n", add ? "Add" : "Del", ip >> 24, ip >> 16 & 255, ip >> 8 & 255, ip & 255, mask >> 24, mask >> 16 & 255, mask >> 8 & 255, mask & 255, gw >> 24, gw >> 16 & 255, gw >> 8 & 255, gw & 255);
}

// Set up TAP interface
void inittap(void)
{
	struct ifreq ifr;
	struct sockaddr_in sin = {0};
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;

	tapfd = open(TAPDEVICE, O_RDWR);
	if (tapfd < 0)
	{                          // fatal
		log(0, 0, 0, 0, "Can't open %s: %s\n", TAPDEVICE, strerror(errno));
		exit(-1);
	}
	if (ioctl(tapfd, TUNSETIFF, (void *) &ifr) < 0)
	{
		log(0, 0, 0, 0, "Can't set tap interface: %s\n", strerror(errno));
		exit(-1);
	}
	assert(strlen(ifr.ifr_name) < sizeof(tapdevice));
	strcpy(tapdevice, ifr.ifr_name);
	ifrfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = handle_interface ? bind_address : 0x01010101; // 1.1.1.1
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));

	if (ioctl(ifrfd, SIOCSIFADDR, (void *) &ifr) < 0)
	{
		perror("set tap addr");
		exit( -1);
	}
	ifr.ifr_flags = IFF_UP;
	if (ioctl(ifrfd, SIOCSIFFLAGS, (void *) &ifr) < 0)
	{
		perror("set tap flags");
		exit( -1);
	}
	if (ioctl(ifrfd, SIOCGIFHWADDR, (void *) &ifr) < 0)
	{
		perror("get tap hwaddr");
		exit( -1);
	}
	memcpy(&tapmac, 2 + (u8 *) & ifr.ifr_hwaddr, 6);
	if (ioctl(ifrfd, SIOCGIFINDEX, (void *) &ifr) < 0)
	{
		perror("get tap ifindex");
		exit( -1);
	}
	tapidx = ifr.ifr_ifindex;
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
	addr.sin_addr.s_addr = bind_address;
	udpfd = socket(AF_INET, SOCK_DGRAM, UDP);
	setsockopt(udpfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (bind(udpfd, (void *) &addr, sizeof(addr)) < 0)
	{
		perror("bind");
		exit( -1);
	}
	snoopfd = socket(AF_INET, SOCK_DGRAM, UDP);

	// Control
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(1702);
	controlfd = socket(AF_INET, SOCK_DGRAM, 17);
	setsockopt(controlfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (bind(controlfd, (void *) &addr, sizeof(addr)) < 0)
	{
		perror("bind");
		exit(-1);
	}
}

// Find session by IP, 0 for not found
sessionidt sessionbyip(ipt ip)
{
	unsigned char *a = (char *)&ip;
	char **d = (char **) ip_hash;

#ifdef STAT_CALLS
	STAT(call_sessionbyip);
#endif

	if (!(d = (char **) d[(size_t) *a++])) return 0;
	if (!(d = (char **) d[(size_t) *a++])) return 0;
	if (!(d = (char **) d[(size_t) *a++])) return 0;

	return (ipt) d[(size_t) *a];
}

void cache_sessionid(ipt ip, sessionidt s)
{
	unsigned char *a = (char *) &ip;
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

	log(4, ip, s, session[s].tunnel, "Caching session ID %d for ip address\n", s);
	d[(size_t) a[3]] = (char *)((int)s);
}

void uncache_sessionid(ipt ip)
{
	unsigned char *a = (char *) &ip;
	char **d = (char **) ip_hash;
	int i;

	for (i = 0; i < 3; i++)
	{
		if (!d[(size_t) a[i]]) return;
		d = (char **) d[(size_t) a[i]];
	}
	d[(size_t) a[3]] = NULL;
}

// Find session by username, 0 for not found
// walled garden'd users aren't authenticated, so the username is
// reasonably useless. Ignore them to avoid incorrect actions
sessionidt sessionbyuser(char *username)
{
	int s;
#ifdef STAT_CALLS
	STAT(call_sessionbyuser);
#endif
	for (s = 1; s < MAXSESSION && (session[s].walled_garden || strncmp(session[s].user, username, 128)); s++);
	if (s < MAXSESSION)
		return s;
	return 0;
}

void send_garp(ipt ip)
{
    int s;
    struct ifreq ifr;
    unsigned char mac[6];

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0)
    {
      perror("socket");
      exit(-1);
    }
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, "eth0");
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
    {
      perror("get eth0 hwaddr");
      exit(-1);
    }
    memcpy(mac, &ifr.ifr_hwaddr.sa_data, 6*sizeof(char));
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
    {
      perror("get eth0 ifindex");
      exit(-1);
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

// send gratuitous ARP to set ARP table for newly allocated IP
void sessionsendarp(sessionidt s)
{
        unsigned char mac[6];
#ifdef STAT_CALLS
	STAT(call_sendarp);
#endif
	*(u16 *) (mac + 0) = htons(tapmac[0]); // set source address
	*(u16 *) (mac + 2) = htons(tapmac[1]);
	*(u16 *) (mac + 4) = htons(tapmac[2]);
	sendarp(tapidx, mac, session[s].ip);
	STAT(arp_sent);
}

// Handle ARP requests
void processarp(u8 * buf, int len)
{
	ipt ip;
	sessionidt s;

#ifdef STAT_CALLS
	STAT(call_processarp);
#endif
	STAT(arp_recv);
	if (len != 46)
	{
		log(0, 0, 0, 0, "Unexpected length ARP %d bytes\n", len);
		STAT(arp_errors);
		return;
	}
	if (*(u16 *) (buf + 16) != htons(PKTARP))
	{
		log(0, 0, 0, 0, "Unexpected ARP type %04X\n", ntohs(*(u16 *) (buf + 16)));
		STAT(arp_errors);
		return;
	}
	if (*(u16 *) (buf + 18) != htons(0x0001))
	{
		log(0, 0, 0, 0, "Unexpected ARP hard type %04X\n", ntohs(*(u16 *) (buf + 18)));
		STAT(arp_errors);
		return;
	}
	if (*(u16 *) (buf + 20) != htons(PKTIP))
	{
		log(0, 0, 0, 0, "Unexpected ARP prot type %04X\n", ntohs(*(u16 *) (buf + 20)));
		STAT(arp_errors);
		return;
	}
	if (buf[22] != 6)
	{
		log(0, 0, 0, 0, "Unexpected ARP hard len %d\n", buf[22]);
		STAT(arp_errors);
		return;
	}
	if (buf[23] != 4)
	{
		log(0, 0, 0, 0, "Unexpected ARP prot len %d\n", buf[23]);
		STAT(arp_errors);
		return;
	}
	if (*(u16 *) (buf + 24) != htons(0x0001))
	{
		log(0, 0, 0, 0, "Unexpected ARP op %04X\n", ntohs(*(u16 *) (buf + 24)));
		STAT(arp_errors);
		return;
	}
	ip = ntohl(*(u32 *) (buf + 42));
	// look up session
	s = sessionbyip(htonl(ip));
	if (s)
	{
		log(3, ip, s, session[s].tunnel, "ARP reply for %u.%u.%u.%u\n", ip >> 24, ip >> 16 & 255, ip >> 8 & 255, ip & 255, session[s].tunnel, s);
		memcpy(buf + 4, buf + 10, 6); // set destination as source
		*(u16 *) (buf + 10) = htons(tapmac[0]); // set soucre address
		*(u16 *) (buf + 12) = htons(tapmac[1]);
		*(u16 *) (buf + 14) = htons(tapmac[2]);
		*(u16 *) (buf + 24) = htons(0x0002); // ARP reply
		memcpy(buf + 26, buf + 10, 6); // sender ethernet
		memcpy(buf + 36, buf + 4, 6); // target ethernet
		*(u32 *) (buf + 42) = *(u32 *) (buf + 32); // target IP
		*(u32 *) (buf + 32) = htonl(ip); // sender IP
		write(tapfd, buf, len);
		STAT(arp_replies);
	}
	else
	{
		log(3, ip, 0, 0, "ARP request for unknown IP %u.%u.%u.%u\n", ip >> 24, ip >> 16 & 255, ip >> 8 & 255, ip & 255);
		STAT(arp_discarded);
	}
}

// actually send a control message for a specific tunnel
void tunnelsend(u8 * buf, u16 l, tunnelidt t)
{
	struct sockaddr_in addr;

#ifdef STAT_CALLS
	STAT(call_tunnelsend);
#endif
	if (!tunnel[t].ip)
	{
		log(1, 0, 0, t, "Error sending data out tunnel: no remote endpoint (tunnel not set up)\n");
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

// process outgoing (to tunnel) IP
void processipout(u8 * buf, int len)
{
	sessionidt s;
	sessiont *sp;
	tunnelidt t;
	ipt ip;
	u8 b[MAXETHER];
#ifdef STAT_CALLS
	STAT(call_processipout);
#endif
	if (len < 38)
	{
		log(1, 0, 0, 0, "Short IP, %d bytes\n", len);
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
//		log(4, 0, 0, 0, "IP: Can't find session for IP %s\n", inet_toa(ip));
		return;
	}
	t = session[s].tunnel;
	sp = &session[s];

	// Snooping this session, send it to ASIO
	if (sp->snoop) snoop_send_packet(buf, len);

	log(5, session[s].ip, s, t, "Ethernet -> Tunnel (%d bytes)\n", len);

	// Plugin hook
	{
		struct param_packet_rx packet = { &tunnel[t], &session[s], buf, len };
		run_plugins(PLUGIN_PACKET_RX, &packet);
	}

	// Add on L2TP header
	{
		u8 *p = makeppp(b, buf, len, t, s, PPPIP);
		tunnelsend(b, len + (p-b), t); // send it...
		sp->cout += len; // byte count
		sp->pout++;
		udp_tx += len;
	}
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
void controlnull(tunnelidt t)
{
	u8 buf[12];
	if (tunnel[t].controlc)
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

// start tidy shutdown of session
void sessionshutdown(sessionidt s, char *reason)
{
	int dead = session[s].die;
	int walled_garden = session[s].walled_garden;

#ifdef STAT_CALLS
	STAT(call_sessionshutdown);
#endif
	if (!session[s].tunnel)
		return;                   // not a live session

	if (!session[s].die)
		log(2, 0, s, session[s].tunnel, "Shutting down session %d: %s\n", s, reason);

	session[s].die = now() + 150; // Clean up in 15 seconds

	{
		struct param_kill_session data = { &tunnel[session[s].tunnel], &session[s] };
		run_plugins(PLUGIN_KILL_SESSION, &data);
	}

	// RADIUS Stop message
	if (session[s].opened && !walled_garden && !dead) {
		u8 r = session[s].radius;
		if (!r)
		{
			if (!radiusfree)
			{
				log(1, 0, s, session[s].tunnel, "No free RADIUS sessions for Stop message\n");
				STAT(radius_overflow);
			} else {
				int n;
				r = radiusnew(s);
				for (n = 0; n < 15; n++)
					radius[r].auth[n] = rand();
			}
		}
		if (r && radius[r].state != RADIUSSTOP)
			radiussend(r, RADIUSSTOP); // stop, if not already trying
	}

	if (session[s].ip)
	{                          // IP allocated, clear and unroute
		u8 r;
		if (session[s].route[0].ip)
		{
			routeset(session[s].ip, 0, 0, 0);
			for (r = 0; r < MAXROUTE; r++)
			{
				if (session[s].route[r].ip)
				{
					routeset(session[s].route[r].ip, session[s].route[r].mask, session[s].ip, 0);
					session[s].route[r].ip = 0;
				}
			}
		}
		if (session[s].throttle) throttle_session(s, 0); session[s].throttle = 0;
		free_ip_address(session[s].ip);
		session[s].ip = 0;
	}
	{                            // Send CDN
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
	u8 r = session[s].radius;
	u8 *q;
#ifdef STAT_CALLS
	STAT(call_sendipcp);
#endif
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
		sessionshutdown(s, "No reply on IPCP");
		return;
	}
	q = makeppp(buf, 0, 0, t, s, PPPIPCP);
	*q = ConfigReq;
	q[1] = r;                    // ID, dont care, we only send one type of request
	*(u16 *) (q + 2) = htons(10);
	q[4] = 3;
	q[5] = 6;
	*(u32 *) (q + 6) = htonl(myip ? : session[s].ip); // send my IP (use theirs if I dont have one)
	tunnelsend(buf, 10 + (q - buf), t); // send it
}

// kill a session now
void sessionkill(sessionidt s, char *reason)
{
#ifdef STAT_CALLS
	STAT(call_sessionkill);
#endif
	sessionshutdown(s, reason);  // close radius/routes, etc.
	if (session[s].radius)
		radius[session[s].radius].session = 0; // cant send clean accounting data, session is killed
	memset(&session[s], 0, sizeof(session[s]));
	session[s].next = sessionfree;
	sessionfree = s;
	log(2, 0, s, session[s].tunnel, "Kill session %d: %s\n", s, reason);
	cluster_send_session(s);
}

// kill a tunnel now
void tunnelkill(tunnelidt t, char *reason)
{
	sessionidt s;
	controlt *c;
#ifdef STAT_CALLS
	STAT(call_tunnelkill);
#endif
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
	for (s = 0; s < MAXSESSION; s++)
		if (session[s].tunnel == t)
			sessionkill(s, reason);
	// free tunnel
	memset(&tunnel[t], 0, sizeof(tunnel[t]));
	tunnel[t].next = tunnelfree;
	cluster_send_tunnel(t);
	log(1, 0, 0, t, "Kill tunnel %d: %s\n", t, reason);
	tunnelfree = t;
}

// shut down a tunnel
void tunnelshutdown(tunnelidt t, char *reason)
{
	sessionidt s;
#ifdef STAT_CALLS
	STAT(call_tunnelshutdown);
#endif
	if (!tunnel[t].last || !tunnel[t].far)
	{                          // never set up, can immediately kill
		tunnelkill(t, reason);
		return;
	}
	log(1, 0, 0, t, "Shutting down tunnel %d (%s)\n", t, reason);
	// close session
	for (s = 0; s < MAXSESSION; s++)
		if (session[s].tunnel == t)
			sessionkill(s, reason);
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
void processudp(u8 * buf, int len, struct sockaddr_in *addr)
{
	char *chapresponse = NULL;
	u16 l = len, t = 0, s = 0, ns = 0, nr = 0;
	u8 *p = buf + 2;

#ifdef STAT_CALLS
	STAT(call_processudp);
#endif
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
	if (s && !session[s].tunnel)
	{
		log(1, ntohl(addr->sin_addr.s_addr), s, t, "UDP packet contains session %d but no session[%d].tunnel exists (LAC said tunnel = %d). Dropping packet.\n", s, s, t);
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
	if (t) tunnel[t].last = time_now;
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
		if ((*buf & 0xCA) != 0xC8)
		{
			log(1, ntohl(addr->sin_addr.s_addr), s, t, "Bad control header %02X\n", *buf);
			STAT(tunnel_rx_errors);
			return;
		}
		log(3, ntohl(addr->sin_addr.s_addr), s, t, "Control message (%d bytes): %d ns %d nr %d ns %d nr %d\n",
				l, tunnel[t].controlc, tunnel[t].ns, tunnel[t].nr, ns, nr);
		// if no tunnel specified, assign one
		if (!t)
		{
			/*
			ipt ip = ntohl(*(ipt *) & addr->sin_addr);
			portt port = ntohs(addr->sin_port);

			// find existing tunnel that was not fully set up
			for (t = 0; t < MAXTUNNEL; t++)
			{
				if ((tunnel[t].ip == ip && tunnel[t].port == port) &&
					(!tunnel[t].die || !tunnel[t].hostname[0]))
				{
					char buf[600] = {0};
					snprintf(buf, 600, "Duplicate tunnel with %d. ip=%u port=%d die=%d hostname=%s",
							t, tunnel[t].ip, tunnel[t].port, tunnel[t].die, tunnel[t].hostname);
					tunnelshutdown(t, buf);
					break;
				}
			}
			*/

			t = tunnelfree;
			if (!t)
			{
				log(1, ntohl(addr->sin_addr.s_addr), 0, 0, "No more tunnels\n");
				STAT(tunnel_overflow);
				return;
			}
			tunnelfree = tunnel[t].next;
			memset(&tunnel[t], 0, sizeof(tunnelt));
			tunnel[t].ip = ntohl(*(ipt *) & addr->sin_addr);
			tunnel[t].port = ntohs(addr->sin_port);
			tunnel[t].window = 4; // default window
			log(1, ntohl(addr->sin_addr.s_addr), 0, t, "   New tunnel from %u.%u.%u.%u/%u ID %d\n", tunnel[t].ip >> 24, tunnel[t].ip >> 16 & 255, tunnel[t].ip >> 8 & 255, tunnel[t].ip & 255, tunnel[t].port, t);
			STAT(tunnel_created);
		}
		{                       // check sequence of this message
			int skip = tunnel[t].window; // track how many in-window packets are still in queue
			if (tunnel[t].controlc)
			{                  // some to clear maybe
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
			}
			if (tunnel[t].nr < ns && tunnel[t].nr != 0)
			{
				// is this the sequence we were expecting?
				log(1, ntohl(addr->sin_addr.s_addr), 0, t, "   Out of sequence tunnel %d, (%d not %d)\n", t, ns, tunnel[t].nr);
				STAT(tunnel_rx_errors);
//				controlnull(t);
				return;
			}
			if (l)
				tunnel[t].nr++;   // receiver advance (do here so quoted correctly in any sends below)
			if (skip < 0)
				skip = 0;
			if (skip < tunnel[t].controlc)
			{                  // some control packets can now be sent that were previous stuck out of window
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
					if (!l2tpsecret)
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
					log(1, ntohl(addr->sin_addr.s_addr), s, t, "Hidden AVP\n");
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
						if (message == 4) { /* StopCCN */
							if (rescode <= MAX_STOPCCN_RESULT_CODE)
								resdesc = stopccn_result_codes[rescode];
						} else if (message == 14) { /* CDN */
							if (rescode <= MAX_CDN_RESULT_CODE)
								resdesc = cdn_result_codes[rescode];
						}

						log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Result Code %d: %s\n",
							rescode, resdesc);
						if (n >= 4) {
							u16 errcode = ntohs(*(u16 *)(b + 2));
							const char* errdesc = "(unknown)";
							if (errcode <= MAX_ERROR_CODE)
								errdesc = error_codes[errcode];
							log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Error Code %d: %s\n",
								errcode, errdesc);
						}
						if (n > 4) {
							/* %*s doesn't work?? */
							char buf[n-4+2];
							memcpy(buf, b+4, n-4);
							buf[n-4+1] = '\0';
							log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Error String: %s\n",
								buf);
						}
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
					// We never open tunnels, so we don't
					// care about tie breakers
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
					memset(tunnel[t].vendor, 0, 128);
					memcpy(tunnel[t].vendor, b, (n >= 127) ? 127 : n);
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
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   TX connect speed <%d>\n",
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
					log(4, ntohl(addr->sin_addr.s_addr), s, t, "   RX connect speed <%d>\n",
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
						log(4, ntohl(addr->sin_addr.s_addr), s, t, "   Proxy Auth Challenge (%X)\n", radius[session[s].radius].auth);
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
					break;
				case 2:       // SCCRP
					// TBA
					break;
				case 3:       // SCCN
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
					if (!sessionfree)
					{
						STAT(session_overflow);
						tunnelshutdown(t, "No free sessions");
					}
					else
					{
						u8 r;
						controlt *c;

						// make a RADIUS session
						if (!radiusfree)
						{
							STAT(radius_overflow);
							log(1, ntohl(addr->sin_addr.s_addr), s, t, "No free RADIUS sessions for ICRQ\n");
							return;
						}

						c = controlnew(11); // sending ICRP
						s = sessionfree;
						sessionfree = session[s].next;
						memset(&session[s], 0, sizeof(session[s]));
						session[s].id = sessionid++;
						session[s].opened = time(NULL);
						session[s].tunnel = t;
						session[s].far = asession;
						log(3, ntohl(addr->sin_addr.s_addr), s, t, "New session (%d/%d)\n", tunnel[t].far, session[s].far);
						control16(c, 14, s, 1); // assigned session
						controladd(c, t, s); // send the reply
						r = radiusfree;
						radiusfree = radius[r].next;
						memset(&radius[r], 0, sizeof(radius[r]));
						session[s].radius = r;
						radius[r].session = s;
						{
							// Generate a random challenge
							int n;
							for (n = 0; n < 15; n++)
								radius[r].auth[n] = rand();
						}
						strcpy(radius[r].calling, calling);
						strcpy(session[s].called, called);
						strcpy(session[s].calling, calling);
						STAT(session_created);
					}
					break;
				case 11:      // ICRP
					// TBA
					break;
				case 12:      // ICCN
					session[s].magic = amagic; // set magic number
					session[s].flags = aflags; // set flags received
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
	{                          // data
		u16 prot;

		log_hex(5, "Receive Tunnel Data", p, l);
		if (session[s].die)
		{
			log(3, ntohl(addr->sin_addr.s_addr), s, t, "Session %d is closing. Don't process PPP packets\n", s);
			return;              // closing session, PPP not processed
		}
		if (l > 2 && p[0] == 0xFF && p[1] == 0x03)
		{                     // HDLC address header, discard
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
			processpap(t, s, p, l);
		}
		else if (prot == PPPCHAP)
		{
			session[s].last_packet = time_now;
			processchap(t, s, p, l);
		}
		else if (prot == PPPLCP)
		{
			session[s].last_packet = time_now;
			processlcp(t, s, p, l);
		}
		else if (prot == PPPIPCP)
		{
			session[s].last_packet = time_now;
			processipcp(t, s, p, l);
		}
		else if (prot == PPPCCP)
		{
			session[s].last_packet = time_now;
			processccp(t, s, p, l);
		}
		else if (prot == PPPIP)
		{
			session[s].last_packet = time_now;
			processipin(t, s, p, l);
		}
		else
		{
			STAT(tunnel_rx_errors);
			log(1, ntohl(addr->sin_addr.s_addr), s, t, "Unknown PPP protocol %04X\n", prot);
		}
	}
}

// read and process packet on tap
void processtap(u8 * buf, int len)
{
	log_hex(5, "Receive TAP Data", buf, len);
	STAT(tap_rx_packets);
	INC_STAT(tap_rx_bytes, len);
#ifdef STAT_CALLS
	STAT(call_processtap);
#endif
	eth_rx_pkt++;
	eth_rx += len;
	if (len < 22)
	{
		log(1, 0, 0, 0, "Short tap packet %d bytes\n", len);
		STAT(tap_rx_errors);
		return;
	}
	if (*(u16 *) (buf + 2) == htons(PKTARP)) // ARP
		processarp(buf, len);
	else if (*(u16 *) (buf + 2) == htons(PKTIP)) // ARP
		processipout(buf, len);
	else
	{
		log(1, 0, 0, 0, "Unexpected tap packet %04X, %d bytes\n", ntohs(*(u16 *) (buf + 2)), len);
	}
}

// main loop - gets packets on tap or udp and processes them
void mainloop(void)
{
	fd_set cr;
	int cn;
	u8 buf[65536];
	struct timeval to;
	clockt slow = now();       // occasional functions like session/tunnel expiry, tunnel hello, etc
	clockt next_acct = slow + ACCT_TIME;
	clockt next_cluster_ping = slow + 50;
	to.tv_sec = 1;
	to.tv_usec = 0;
	log(4, 0, 0, 0, "Beginning of main loop. udpfd=%d, tapfd=%d, radfd=%d, cluster_sockfd=%d, controlfd=%d\n",
			udpfd, tapfd, radfd, cluster_sockfd, controlfd);

	FD_ZERO(&cr);
	FD_SET(udpfd, &cr);
	FD_SET(tapfd, &cr);
	FD_SET(radfd, &cr);
	FD_SET(controlfd, &cr);
#ifdef HAVE_LIBCLI
	FD_SET(clifd, &cr);
#endif
	if (cluster_sockfd) FD_SET(cluster_sockfd, &cr);
	cn = udpfd;
	if (cn < radfd) cn = radfd;
	if (cn < tapfd) cn = tapfd;
	if (cn < controlfd) cn = controlfd;
#ifdef HAVE_LIBCLI
	if (cn < clifd) cn = clifd;
#endif
	if (cn < cluster_sockfd) cn = cluster_sockfd;

	while (!main_quit)
	{
		fd_set r;
		int n = cn;
		memcpy(&r, &cr, sizeof(fd_set));
		n = select(n + 1, &r, 0, 0, &to);
		if (n < 0)
		{
			if (errno != EINTR)
			{
				perror("select");
				exit( -1);
			}
		}
		else if (n)
		{
			struct sockaddr_in addr;
			int alen = sizeof(addr);
			if (FD_ISSET(udpfd, &r))
				processudp(buf, recvfrom(udpfd, buf, sizeof(buf), 0, (void *) &addr, &alen), &addr);
			else if (FD_ISSET(tapfd, &r))
				processtap(buf, read(tapfd, buf, sizeof(buf)));
			else if (FD_ISSET(radfd, &r))
				processrad(buf, recv(radfd, buf, sizeof(buf), 0));
			else if (FD_ISSET(cluster_sockfd, &r))
				processcluster(buf, recvfrom(cluster_sockfd, buf, sizeof(buf), MSG_WAITALL, (void *) &addr, &alen));
			else if (FD_ISSET(controlfd, &r))
				processcontrol(buf, recvfrom(controlfd, buf, sizeof(buf), MSG_WAITALL, (void *) &addr, &alen), &addr);
#ifdef HAVE_LIBCLI
			else if (FD_ISSET(clifd, &r))
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
#endif
			else
			{
				log(1, 0, 0, 0, "Main select() loop returned %d, but no fds have data waiting\n", n);
				continue;
			}
		}
		else if (n == 0) {                       // handle timeouts
			clockt when = now();
			clockt best = when + 100; // default timeout
			sessionidt s;
			tunnelidt t;
			u8 r;
			for (r = 0; r < MAXRADIUS; r++)
				if (radius[r].state && radius[r].retry)
				{
					if (radius[r].retry <= when)
						radiusretry(r);
					if (radius[r].retry && radius[r].retry < best)
						best = radius[r].retry;
				}
			for (t = 0; t < MAXTUNNEL; t++)
			{
				// check for expired tunnels
				if (tunnel[t].die && tunnel[t].die <= when)
				{
					STAT(tunnel_timeout);
					tunnelkill(t, "Expired");
					continue;
				}
				// check for message resend
				if (tunnel[t].retry && tunnel[t].controlc)
				{
					// resend pending messages as timeout on reply
					if (tunnel[t].retry <= when)
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
					if (tunnel[t].retry && tunnel[t].retry < best)
						best = tunnel[t].retry;
				}
				// Send hello
				if (tunnel[t].ip && !tunnel[t].die && tunnel[t].last < when + 600 && !tunnel[t].controlc)
				{
					controlt *c = controlnew(6); // sending HELLO
					controladd(c, t, 0); // send the message
					log(3, tunnel[t].ip, 0, t, "Sending HELLO message\n");
				}
			}

#ifdef HAVE_LIBCLI
			// Check for sessions that have been killed from the CLI
			if (cli_session_kill[0])
			{
				int i;
				for (i = 0; i < MAXSESSION && cli_session_kill[i]; i++)
				{
					log(2, 0, cli_session_kill[i], 0, "Dropping session by CLI\n");
					sessionshutdown(cli_session_kill[i], "Requested by CLI");
					cli_session_kill[i] = 0;
				}
			}
			// Check for tunnels that have been killed from the CLI
			if (cli_tunnel_kill[0])
			{
				int i;
				for (i = 0; i < MAXTUNNEL && cli_tunnel_kill[i]; i++)
				{
					log(2, 0, cli_tunnel_kill[i], 0, "Dropping tunnel by CLI\n");
					tunnelshutdown(cli_tunnel_kill[i], "Requested by CLI");
					cli_tunnel_kill[i] = 0;
				}
			}
#endif

			for (s = 0; s < MAXSESSION; s++)
			{
				// check for expired sessions
				if (session[s].die && session[s].die <= when)
				{
					STAT(session_timeout);
					sessionkill(s, "Expired");
					continue;
				}

				// Drop sessions who have not responded within IDLE_TIMEOUT seconds
				if (session[s].user[0] && (time_now - session[s].last_packet >= IDLE_TIMEOUT))
				{
					sessionkill(s, "No response to LCP ECHO requests");
					continue;
				}

				// No data in IDLE_TIMEOUT seconds, send LCP ECHO
				if (session[s].user[0] && (time_now - session[s].last_packet >= ECHO_TIMEOUT))
				{
					u8 b[MAXCONTROL] = {0};
					u8 *q = makeppp(b, 0, 0, session[s].tunnel, s, PPPLCP);

					*q = EchoReq;
					*(u8 *)(q + 1) = (time_now % 255); // ID
					*(u16 *)(q + 2) = htons(8); // Length
					*(u32 *)(q + 4) = 0; // Magic Number (not supported)

					log(4, session[s].ip, s, session[s].tunnel, "No data in %d seconds, sending LCP ECHO\n",
							time_now - session[s].last_packet);
					tunnelsend(b, 24, session[s].tunnel); // send it
					continue;
				}
			}
			if (accounting_dir && next_acct <= when)
			{
				// Dump accounting data
				next_acct = when + ACCT_TIME;
				dump_acct_info();
			}

			if (cluster_sockfd && next_cluster_ping <= when)
			{
				// Dump accounting data
				next_cluster_ping = when + 50;
				cluster_send_message(cluster_address, bind_address, C_PING, hostname, strlen(hostname));
			}

			if (best <= when)
				best = when + 1;  // should not really happen
			to.tv_sec = (best - when) / 10;
			to.tv_usec = 100000 * ((best - when) % 10);
			log(5, 0, 0, 0, "Next time check in %d.%d seconds\n", (best - when) / 10, ((best - when) % 10));
		}
	}
}

// Init data structures
void initdata(void)
{
	int i;

	_statistics = mmap(NULL, sizeof(struct Tstats), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (_statistics <= 0)
	{
		log(0, 0, 0, 0, "Error doing mmap for _statistics: %s\n", strerror(errno));
		exit(1);
	}
	tunnel = mmap(NULL, sizeof(tunnelt) * MAXTUNNEL, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (tunnel <= 0)
	{
		log(0, 0, 0, 0, "Error doing mmap for tunnels: %s\n", strerror(errno));
		exit(1);
	}
	session = mmap(NULL, sizeof(sessiont) * MAXSESSION, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (session <= 0)
	{
		log(0, 0, 0, 0, "Error doing mmap for sessions: %s\n", strerror(errno));
		exit(1);
	}
	radius = mmap(NULL, sizeof(radiust) * MAXRADIUS, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (radius <= 0)
	{
		log(0, 0, 0, 0, "Error doing mmap for radius: %s\n", strerror(errno));
		exit(1);
	}
	ip_address_pool = mmap(NULL, sizeof(ippoolt) * MAXIPPOOL, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (ip_address_pool <= 0)
	{
		log(0, 0, 0, 0, "Error doing mmap for radius: %s\n", strerror(errno));
		exit(1);
	}
#ifdef RINGBUFFER
	ringbuffer = mmap(NULL, sizeof(struct Tringbuffer), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (ringbuffer <= 0)
	{
		log(0, 0, 0, 0, "Error doing mmap for radius: %s\n", strerror(errno));
		exit(1);
	}
	memset(ringbuffer, 0, sizeof(struct Tringbuffer));
#endif

#ifdef HAVE_LIBCLI
	cli_session_kill = mmap(NULL, sizeof(sessionidt) * MAXSESSION, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (cli_session_kill <= 0)
	{
		log(0, 0, 0, 0, "Error doing mmap for cli session kill: %s\n", strerror(errno));
		exit(1);
	}
	memset(cli_session_kill, 0, sizeof(sessionidt) * MAXSESSION);
	cli_tunnel_kill = mmap(NULL, sizeof(tunnelidt) * MAXSESSION, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (cli_tunnel_kill <= 0)
	{
		log(0, 0, 0, 0, "Error doing mmap for cli tunnel kill: %s\n", strerror(errno));
		exit(1);
	}
	memset(cli_tunnel_kill, 0, sizeof(tunnelidt) * MAXSESSION);

	filter_buckets = mmap(NULL, sizeof(tbft) * MAXSESSION, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (filter_buckets <= 0)
	{
		log(0, 0, 0, 0, "Error doing mmap for filter buckets: %s\n", strerror(errno));
		exit(1);
	}
	memset(filter_buckets, 0, sizeof(tbft) * MAXSESSION);

#endif

	memset(tunnel, 0, sizeof(tunnelt) * MAXTUNNEL);
	memset(session, 0, sizeof(sessiont) * MAXSESSION);
	memset(radius, 0, sizeof(radiust) * MAXRADIUS);
	memset(ip_address_pool, 0, sizeof(ippoolt) * MAXIPPOOL);
	for (i = 1; i < MAXTUNNEL - 1; i++)
		tunnel[i].next = i + 1;
	tunnel[MAXTUNNEL - 1].next = 0;
	tunnelfree = 1;
	for (i = 1; i < MAXSESSION - 1; i++)
		session[i].next = i + 1;
	session[MAXSESSION - 1].next = 0;
	sessionfree = 1;
	for (i = 1; i < MAXRADIUS - 1; i++)
		radius[i].next = i + 1;
	radius[MAXRADIUS - 1].next = 0;
	radiusfree = 1;
	if (!*hostname)
	{
		// Grab my hostname unless it's been specified
		gethostname(hostname, sizeof(hostname));
		{
			struct hostent *h = gethostbyname(hostname);
			if (h)
				myip = ntohl(*(u32 *) h->h_addr);
		}
	}
	_statistics->start_time = _statistics->last_reset = time(NULL);

	// Start the timer routine off
	time(&time_now);
	strftime(time_now_string, 64, "%Y-%m-%d %H:%M:%S", localtime(&time_now));
}

void initiptables(void)
{
	/* Flush the tables here so that we have a clean slate */
	system("iptables -t nat -F l2tpns");
	system("iptables -t mangle -F l2tpns");
}

ipt assign_ip_address()
{
	int c = 0;
#ifdef STAT_CALLS
	STAT(call_assign_ip_address);
#endif
	ip_pool_index++;
	while (1)
	{
		if (ip_pool_index >= ip_pool_size)
		{
			if (++c == 2)
				return 0;
			ip_pool_index = 0;
		}
		if (!ip_address_pool[ip_pool_index].assigned && ip_address_pool[ip_pool_index].address)
		{
			ip_address_pool[ip_pool_index].assigned = 1;
			log(4, ip_address_pool[ip_pool_index].address, 0, 0, "assign_ip_address(): Allocating ip address %lu from pool\n", ip_pool_index);
			STAT(ip_allocated);
			return ntohl(ip_address_pool[ip_pool_index].address);
		}
		ip_pool_index++;
	}
	return 0;
}

void free_ip_address(ipt address)
{
	int i;
	ipt a;
#ifdef STAT_CALLS
	STAT(call_free_ip_address);
#endif

	a = ntohl(address);
	for (i = 0; i <= ip_pool_size; i++)
	{
		if (ip_address_pool[i].address == a)
		{
			STAT(ip_freed);
			ip_address_pool[i].assigned = 0;
		}
	}
	uncache_sessionid(htonl(address));
}

// Initialize the IP address pool
void initippool()
{
	FILE *f;
	char *buf, *p;
	int pi = 0;
	memset(ip_address_pool, 0, sizeof(ip_address_pool));

	if (!(f = fopen(IPPOOLFILE, "r")))
	{
		log(0, 0, 0, 0, "Can't load pool file " IPPOOLFILE ": %s\n", strerror(errno));
		exit(-1);
	}

	buf = (char *)malloc(4096);

	while (pi < MAXIPPOOL && fgets(buf, 4096, f))
	{
		char* pool = buf;
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
				log(0, 0, 0, 0, "Invalid address pool IP %s", buf);
				exit(-1);
			}
			// This entry is for a specific IP only
			if (src != bind_address)
				continue;
			*p = ':';
			pool = p+1;
		}
		if ((p = (char *)strchr(pool, '/')))
		{
			// It's a range
			int numbits = 0;
			unsigned long start = 0, end = 0, mask = 0, ip;
			struct rtentry r;

			log(2, 0, 0, 0, "Adding IP address range %s\n", buf);
			*p++ = 0;
			if (!*p || !(numbits = atoi(p)))
			{
				log(0, 0, 0, 0, "Invalid pool range %s/\n", buf, p);
				continue;
			}
			start = end = ntohl(inet_addr(pool));
			mask = (unsigned long)(pow(2, numbits) - 1) << (32 - numbits);
			start &= mask;
			end = start + (int)(pow(2, (32 - numbits))) - 1;
			for (ip = (start + 1); ip < end && pi < MAXIPPOOL; ip++)
			{
				if ((ip & 0xFF) == 0 || (ip & 0xFF) == 255)
					continue;
				ip_address_pool[pi++].address = htonl(ip);
			}

			// Add a static route for this pool
			log(5, 0, 0, 0, "Adding route for address pool %s/%d\n", inet_toa(htonl(start)), 32+mask);
			memset(&r, 0, sizeof(r));
			r.rt_dev = tapdevice;
			r.rt_dst.sa_family = AF_INET;
			*(u32 *) & (((struct sockaddr_in *) &r.rt_dst)->sin_addr.s_addr) = htonl(start);
			r.rt_genmask.sa_family = AF_INET;
			*(u32 *) & (((struct sockaddr_in *) &r.rt_genmask)->sin_addr.s_addr) = htonl(mask);
			r.rt_flags = (RTF_UP | RTF_STATIC);
			if (ioctl(ifrfd, SIOCADDRT, (void *) &r) < 0)
			{
				log(0, 0, 0, 0, "Error adding ip address pool route %s/%d: %s\n", inet_toa(start), mask, strerror(errno));
			}
		}
		else
		{
			// It's a single ip address
			ip_address_pool[pi++].address = inet_addr(pool);
		}
	}

	free(buf);
	fclose(f);
	log(1, 0, 0, 0, "IP address pool is %d addresses\n", pi);
	ip_pool_size = pi;
}

void snoop_send_packet(char *packet, u16 size)
{
	if (!snoop_addr.sin_port || snoopfd <= 0 || size <= 0 || !packet)
		return;

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

#ifdef STAT_CALLS
	STAT(call_dump_acct_info);
#endif
    strftime(timestr, 64, "%Y%m%d%H%M%S", localtime(&t));
    snprintf(filename, 1024, "%s/%s", accounting_dir, timestr);

    for (i = 0; i < MAXSESSION; i++)
    {
	if (!session[i].opened || !session[i].cin || !session[i].cout || !*session[i].user || session[i].walled_garden)
		continue;
	if (!f)
	{
	    time_t now = time(NULL);
	    if (!(f = fopen(filename, "w")))
	    {
		    log(0, 0, 0, 0, "Can't write accounting info to %s: %s\n", filename, strerror(errno));
		    return;
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
	fprintf(f, "%s %s %d %lu %lu\n",
	    session[i].user,				// username
	    inet_toa(htonl(session[i].ip)),		// ip
	    (session[i].throttle) ? 2 : 1,		// qos
	    (unsigned long)session[i].cin,		// uptxoctets
	    (unsigned long)session[i].cout);		// downrxoctets

	session[i].pin = session[i].cin = 0;
	session[i].pout = session[i].cout = 0;
    }

    if (f) fclose(f);
}

// Main program
int main(int argc, char *argv[])
{
	int o;

	_program_name = strdup(argv[0]);

	{
		struct rlimit rlim;
		rlim.rlim_cur = RLIM_INFINITY;
		rlim.rlim_max = RLIM_INFINITY;
		// Remove the maximum core size
		setrlimit(RLIMIT_CORE, &rlim);
		// Make core dumps go to /tmp
		chdir("/tmp");
	}

	time(&basetime);             // start clock
	// scan args

	while ((o = getopt(argc, argv, "vc:f:h:a:")) >= 0)
	{
		switch (o)
		{
			case 'v':
				debug++;
				break;
			case 'c':
				config_file = strdup(optarg);
				break;
			case 'f':
				log_filename = strdup(optarg);
				break;
			case 'h':
				strncpy(hostname, optarg, 1000);
				break;
			case 'a':
				myip = inet_addr(optarg);
				if (myip == INADDR_NONE) {
					log(0, 0, 0, 0, "Invalid ip %s\n", optarg);
					exit(-1);
				}
				bind_address = myip;
				handle_interface = 1;
				break;
			case '?':
			default:
				printf("Args are:\n\t-c <file>\tConfig file\n\t-h <hostname>\tForce hostname\n\t-a <address>\tUse specific address\n\t-f <file>\tLog File\n\t-v\t\tDebug\n");
				return (0);
				break;
		}
	}

	initiptables();
	initplugins();
	read_config_file();
	initdata();
	log(0, 0, 0, 0, "$Id: l2tpns.c,v 1.1.1.1 2003-12-16 07:07:39 fred_nerk Exp $\n(c) Copyright 2002 FireBrick (Andrews & Arnold Ltd / Watchfront Ltd) - GPL licenced\n");

	/* Start up the cluster first, so that we don't have two machines with
	 * the same IP at once.
	 * This is still racy, but the second GARP should fix that
	 */
	cluster_init(bind_address, 0);
	cluster_send_message(cluster_address, bind_address, C_HELLO, hostname, strlen(hostname));

	inittap();
	log(1, 0, 0, 0, "Set up on interface %s\n", tapdevice);

	initudp();
	initrad();
	initippool();
	init_rl();
	if (handle_interface) {
		send_garp(bind_address);
	}
	read_state();

#ifdef HAVE_LIBCLI
	init_cli();
#endif

	signal(SIGALRM, sigalrm_handler);
	signal(SIGHUP, sighup_handler);
	signal(SIGTERM, sigterm_handler);
	signal(SIGINT, sigterm_handler);
	signal(SIGQUIT, sigquit_handler);
	signal(SIGCHLD, sigchild_handler);
	signal(SIGSEGV, sigsegv_handler);
	if (debug)
	{
		int n;
		for (n = 0; n < numradiusservers; n++)
			log(1, 0, 0, 0, "RADIUS to %s\n", inet_toa(htonl(radiusserver[n])));
	}

	alarm(1);

	// Drop privileges here
	if (target_uid > 0 && geteuid() == 0)
		setuid(target_uid);

	mainloop();

	if (l2tpsecret) free(l2tpsecret);
	if (log_filename) free(log_filename);
	if (snoop_destination_host) free(snoop_destination_host);
	if (radiussecret) free(radiussecret);

	return 0;
}

void sighup_handler(int junk)
{
	if (log_stream != stderr)
		fclose(log_stream);

	log_stream = NULL;
	read_config_file();
}

void sigalrm_handler(int junk)
{
	// Log current traffic stats
	if (dump_speed)
	{
		printf("UDP-ETH:%1.0f/%1.0f  ETH-UDP:%1.0f/%1.0f  TOTAL:%0.1f   IN:%lu OUT:%lu\n",
			(udp_rx / 1024.0 / 1024.0 * 8),
			(eth_tx / 1024.0 / 1024.0 * 8),
			(eth_rx / 1024.0 / 1024.0 * 8),
			(udp_tx / 1024.0 / 1024.0 * 8),
			((udp_tx + udp_rx + eth_tx + eth_rx) / 1024.0 / 1024.0 * 8),
			udp_rx_pkt, eth_rx_pkt);

		udp_tx = udp_rx = 0;
		udp_rx_pkt = eth_rx_pkt = 0;
		eth_tx = eth_rx = 0;
	}

	// Update the internal time counter
	time(&time_now);
	strftime(time_now_string, 64, "%Y-%m-%d %H:%M:%S", localtime(&time_now));
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
	if (config_save_state)
		dump_state();
	main_quit++;
}

void sigquit_handler(int junk)
{
	int i;
	log(1, 0, 0, 0, "Shutting down without saving sessions\n");
	for (i = 0; i < MAXSESSION; i++)
	{
		if (session[i].opened)
			sessionkill(i, "L2TPNS Closing");
	}
	for (i = 0; i < MAXTUNNEL; i++)
	{
		if (tunnel[i].ip)
			tunnelshutdown(i, "L2TPNS Closing");
	}
	main_quit++;
}

void sigchild_handler(int signal)
{
	int status;
	int pid;

	pid = wait(&status);
#ifdef HAVE_LIBCLI
	status = (WIFEXITED(status)) ? WEXITSTATUS(status) : 0;
	if (pid == cli_pid)
	{
		if (status == 0)
			log(3, 0, 0, 0, "CLI client closed connection\n");
		else
			log(2, 0, 0, 0, "CLI child died with rc %d!\n", status);
	}
#endif
}

void *backtrace_buffer[30] = {0};

void sigsegv_handler(int signal)
{
	log(0, 0, 0, 0, "----------------------------------------------\n");
	log(0, 0, 0, 0, "- SEGFAULT!                                  -\n");
	log(0, 0, 0, 0, "----------------------------------------------\n");
	_exit(0);
}

void read_state()
{
	struct stat sb;
	FILE *f;

	if (!config_save_state) return;

	if (stat(STATEFILE, &sb) < 0)
		return;

	if (sb.st_mtime < (time(NULL) - 60))
	{
		log(0, 0, 0, 0, "State file is too old to read\n");
		unlink(STATEFILE);
		return;
	}

	if (!(f = fopen(STATEFILE, "r")))
	{
		log(0, 0, 0, 0, "Can't read state file: %s\n", strerror(errno));
		unlink(STATEFILE);
		return;
	}
	fseek(f, 0, 0);

	log(1, 0, 0, 0, "Reading state information\n");
	{
		u32 i, numtunnels;
		if (fread(&numtunnels, sizeof(numtunnels), 1, f) <= 0)
		{
			log(0, 0, 0, 0, "Error reading saved state (tunnel count): %s\n", strerror(errno));
			fclose(f);
			unlink(STATEFILE);
			return;
		}
		log(2, 0, 0, 0, "Reading %lu tunnels\n", numtunnels);
		fread(tunnel, sizeof(tunnelt), numtunnels, f);
		tunnelfree = 0;
		for (i = 0; i < numtunnels; i++)
		{
			tunnel[i].controlc = 0;
			tunnel[i].controls = NULL;
			tunnel[i].controle = NULL;
			if (*tunnel[i].hostname)
			{
				log(3, 0, 0, 0, "Created tunnel for %s\n", tunnel[i].hostname);
				tunnelfree = i;
			}
		}
		tunnelfree++;
	}
	{
		u32 i, numsessions;
		if (fread(&numsessions, sizeof(numsessions), 1, f) <= 0)
		{
			log(0, 0, 0, 0, "Error reading saved state (session count): %s\n", strerror(errno));
			fclose(f);
			unlink(STATEFILE);
			return;
		}
		log(2, 0, 0, 0, "Reading %lu sessions\n", numsessions);
		if (fread(session, sizeof(sessiont), numsessions, f) < numsessions)
		{
			log(0, 0, 0, 0, "Error reading saved state (%d sessions): %s\n", numsessions, strerror(errno));
			fclose(f);
			unlink(STATEFILE);
			return;
		}
		for (i = 0; i < numsessions; i++)
		{
			session[i].tbf = 0;
			session[i].throttle = 0;
			if (session[i].opened)
			{
				log(2, 0, i, 0, "Loaded active session for user %s\n", session[i].user);
				if (session[i].ip && session[i].ip != 0xFFFFFFFE)
				{
					int x;
					sessionsetup(session[i].tunnel, i, 0);
					for (x = 0; x < MAXIPPOOL && ip_address_pool[x].address; x++)
					{
						if (ip_address_pool[x].address == session[i].ip)
						{
							ip_address_pool[x].assigned = 1;
							break;
						}
					}
				}
				else
				{
					log(2, 0, i, 0, "No IP for session\n");
				}
			}
		}
		for (i = 0; i < numsessions && session[i].opened; i++)
			sessionfree = session[i].next;
	}
	fclose(f);
	log(0, 0, 0, 0, "Loaded saved state information\n");
	unlink(STATEFILE);
}

void dump_state()
{
	FILE *f;

	if (!config_save_state) return;

	if ((f = fopen(STATEFILE, "w")))
	{
		u32 i;
		log(1, 0, 0, 0, "Dumping state information\n");

		i = MAXTUNNEL;
		fwrite(&i, sizeof(i), 1, f);	// Number of tunnels

		log(2, 0, 0, 0, "Dumping %lu tunnels\n", i);
		fwrite(tunnel, sizeof(tunnelt), MAXTUNNEL, f);

		i = MAXSESSION;
		fwrite(&i, sizeof(i), 1, f);	// Number of sessions
		log(2, 0, 0, 0, "Dumping %lu sessions\n", i);
		fwrite(session, sizeof(sessiont), MAXSESSION, f);

		fclose(f);
	}
	else
	{
		log(0, 0, 0, 0, "Can't write state information: %s\n", strerror(errno));
	}
	return;
}

void build_chap_response(char *challenge, u8 id, u16 challenge_length, char **challenge_response)
{
	MD5_CTX ctx;
	*challenge_response = NULL;

	if (!l2tpsecret || !*l2tpsecret)
	{
		log(0, 0, 0, 0, "LNS requested CHAP authentication, but no l2tp secret is defined\n");
		return;
	}

	/*
	if (challenge_length != 16)
	{
		log(0, 0, 0, 0, "Challenge length != 16.\n");
		return;
	}
	*/

	log(4, 0, 0, 0, "   Building challenge response for CHAP request\n");

	*challenge_response = (char *)calloc(17, 1);

	MD5Init(&ctx);
	MD5Update(&ctx, &id, 1);
	MD5Update(&ctx, l2tpsecret, strlen(l2tpsecret));
	MD5Update(&ctx, challenge, challenge_length);
	MD5Final(*challenge_response, &ctx);

	return;
}

void read_config_file()
{
	FILE *f;
	char *buf;

	if (!config_file) return;
	if (!(f = fopen(config_file, "r"))) {
		fprintf(stderr, "Can't open config file %s: %s\n", config_file, strerror(errno));
		return;
	}

	if (radiussecret)
	{
		free(radiussecret);
		radiussecret = NULL;
	}

	if (l2tpsecret)
	{
		free(l2tpsecret);
		l2tpsecret = NULL;
	}

	if (log_filename)
	{
		free(log_filename);
		log_filename = NULL;
	}

	if (snoop_destination_host)
	{
		free(snoop_destination_host);
		snoop_destination_host = NULL;
	}

	if (numradiusservers) {
		int n;
		for (n = 0; n < numradiusservers; n++)
			radiusserver[n] = 0;
		numradiusservers = 0;
	}

	snoop_destination_port = 0L;
	config_save_state = 0;
	rl_rate = 0L;
	debug = 1;
	default_dns1 = default_dns2 = 0;
	radius_accounting = 0;

	buf = (char *)malloc(4096);

	while (fgets(buf, 4096, f)) {
		char *p, *t;

		if (*buf == '#') continue;
		if ((p = strchr(buf, '\n'))) *p = 0;
		p = t = strchr(buf, '=');
		if (!p) continue;
		*p = 0; p++;
		t--;
		while (*p && *p == ' ') p++;
		while (*t && *t == ' ') *t-- = 0;

		if (strcmp(buf, "log file") == 0) {
			if (!log_filename)
				log_filename = strdup(p);
		} else if (strcmp(buf, "l2tp secret") == 0) {
			if (!l2tpsecret)
				l2tpsecret = strdup(p);
			log(0, 0, 0, 0, "L2TP Secret is \"%s\"\n", l2tpsecret);
		} else if (strcmp(buf, "radius secret") == 0) {
			if (!radiussecret)
				radiussecret = strdup(p);
			log(4, 0, 0, 0, "Radius Secret is \"%s\"\n", radiussecret);
		} else if (strcmp(buf, "radius accounting") == 0) {
			radius_accounting = atoi(p);
			log(4, 0, 0, 0, "Radius Account is %s\n", radius_accounting ? "on" : "off");
		} else if (strcmp(buf, "throttle rate") == 0) {
			rl_rate = atol(p);
			if (rl_rate == 0)
			{
				log(1, 0, 0, 0, "Disabled throttling.\n");
			}
			else
			{
				log(1, 0, 0, 0, "Enabled throttling (rate is %lu kbits/s)\n", rl_rate);
			}
		} else if (strcmp(buf, "debug") == 0) {
			debug = atoi(p);
			log(debug, 0, 0, 0, "Set debugging level to %d\n", debug);
		} else if (strcmp(buf, "accounting dir") == 0) {
			accounting_dir = strdup(p);
			log(debug, 0, 0, 0, "Will dump accounting information to %s\n", accounting_dir);
		} else if (strcmp(buf, "dns server") == 0) {
			unsigned long addr = 0;
			if (inet_aton(p, (struct in_addr *)&addr) < 0) {
				printf("Invalid DNS server %s\n", p);
				continue;
			}
			if (default_dns1 == 0)
				default_dns1 = addr;
			else if (default_dns2 == 0)
				default_dns2 = addr;
		} else if (strcmp(buf, "radius server") == 0) {
			struct hostent *h = gethostbyname(p);
			if (h)
			{
				while (*h->h_addr_list)
				{
					ipt ip = ntohl(*(u32 *) * h->h_addr_list);
					if (numradiusservers < MAXRADSERVER)
						radiusserver[numradiusservers++] = ip;
					else
						log(0, 0, 0, 0, "Too many RADIUS IPs\n");
					h->h_addr_list++;
				}
			}
			else
			{        // may be IP?
				ipt ip = ntohl(inet_addr(p));
				if (ip && ip != 0xFFFFFFFF)
				{
					if (numradiusservers < MAXRADSERVER)
						radiusserver[numradiusservers++] = ip;
					else
						log(0, 0, 0, 0, "Too many RADIUS IPs\n");
				}
				else
					log(0, 0, 0, 0, "Unknown server %s\n", p);
			}
		} else if (strcmp(buf, "snoop host") == 0) {
			snoop_destination_host = strdup(p);
		} else if (strcmp(buf, "snoop port") == 0) {
			snoop_destination_port = atol(p);
		} else if (strcmp(buf, "bind address") == 0) {
			if (!bind_address)
			{
				// Already overridden on the command line
				bind_address = inet_addr(p);
				handle_interface = 1;
			}
		} else if (strcmp(buf, "dump speed") == 0) {
			dump_speed = atoi(p);
		} else if (strcmp(buf, "setuid") == 0) {
			target_uid = atoi(p);
		} else if (strcmp(buf, "cluster master") == 0) {
			struct hostent *h = gethostbyname(p);
			if (h)
			{
				if (*h->h_addr_list)
				{
					cluster_address = *(u32 *) *h->h_addr_list;
				}
			}
			else
			{        // may be IP?
				cluster_address = inet_addr(p);
			}
		} else if (strcmp(buf, "save state") == 0) {
			if (strcasecmp(p, "no") == 0) {
				config_save_state = 0;
			} else {
				config_save_state = 1;
			}
		} else if (strcmp(buf, "plugin") == 0) {
			add_plugin(p);
		} else {
			struct param_config cp = { buf, p };
			int rc = run_plugins(PLUGIN_CONFIG, &cp);
			if (rc == 0) log(0, 0, 0, 0, "Unknown config directive \"%s\"\n", buf);
		}
	}

	if (snoop_destination_host)
	{
		if (inet_aton(snoop_destination_host, &snoop_addr.sin_addr))
		{
			snoop_addr.sin_port = htons(snoop_destination_port);
			snoop_addr.sin_family = AF_INET;
		}
		else
		{
			log(0, 0, 0, 0, "Can't find address for snoop host %s\n", snoop_destination_host);
		}
	}

	free(buf);
	fclose(f);
	log(2, 0, 0, 0, "Done reading config file\n");
}

int sessionsetup(tunnelidt t, sessionidt s, u8 routes)
{
	// A session now exists, set it up
	ipt ip;
	char *user;
	sessionidt i;
#ifdef STAT_CALLS
	STAT(call_sessionsetup);
#endif
	log(3, session[s].ip, s, t, "Doing session setup for session\n");
	if (!session[s].ip) {
		log(0, session[s].ip, s, t, "VERY VERY BAD! sessionsetup() called with no session[s].ip\n");
		return 1;
	}
	if (session[s].ip == 0xFFFFFFFE)
	{
		session[s].ip = assign_ip_address(); // Assign one from the pool;

		log(2, session[s].ip, s, t, "IP assigned is a magic token. Assign address from pool: %s\n",
				inet_toa(htonl(session[s].ip)));
	}

	// Make sure this is right
	session[s].tunnel = t;
	// zap old sessions with same IP and/or username
	// Don't kill walled_garden sessions - doing so leads to a DoS
	// from someone who doesn't need to know the password
	ip = session[s].ip;
	user = session[s].user;
	for (i = 0; i < MAXSESSION; i++)
	{
		if (i == s) continue;
		if (ip == session[i].ip) sessionkill(i, "Duplicate IP address");
		if (!session[s].walled_garden && !session[i].walled_garden && strcasecmp(user, session[i].user) == 0)
			sessionkill(i, "Duplicate session for user");
	}

	if (routes)
	{
		if (session[s].route[routes].ip && session[s].route[routes].mask)
		{
			log(2, session[s].ip, s, t, "Routing session\n");
			routeset(session[s].ip, 0, 0, 1);
			while (routes--)
				routeset(session[s].route[routes].ip, session[s].route[routes].mask,
						session[s].ip, 1);
		}
	}
	sessionsendarp(s);
	if (!session[s].sid)
		sendipcp(t, s);

	// Force throttling on or off
	// This has the advantage of cleaning up after another throttled user who may have left
	// firewall rules lying around
	throttle_session(s, session[s].throttle);

	{
		struct param_new_session data = { &tunnel[t], &session[s] };
		run_plugins(PLUGIN_NEW_SESSION, &data);
	}

	session[s].sid = ++last_sid;
	cache_sessionid(htonl(session[s].ip), s);

	cluster_send_session(s);
	session[s].last_packet = time_now;
	{
		char *sessionip, *tunnelip;
		sessionip = strdup(inet_toa(ntohl(session[s].ip)));
		tunnelip = strdup(inet_toa(ntohl(tunnel[t].ip)));
		log(2, session[s].ip, s, t, "Login by %s at %s from %s (%s)\n",
				session[s].user, sessionip, tunnelip, tunnel[t].hostname);
		if (sessionip) free(sessionip);
		if (tunnelip) free(tunnelip);
	}

	return 1;       // RADIUS OK and IP allocated, done...
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

void add_plugin(char *plugin_name)
{
	void *p;
	int (*initfunc)(struct pluginfuncs *);
	char path[256] = {0};
	int i;
	struct pluginfuncs funcs;

	funcs._log = _log;
	funcs._log_hex = _log_hex;
	funcs.inet_toa = inet_toa;
	funcs.get_session_by_username = sessionbyuser;
	funcs.get_session_by_id = sessiontbysessionidt;
	funcs.get_id_by_session = sessionidtbysessiont;
	funcs.sessionkill = sessionkill;
	funcs.radiusnew = radiusnew;
	funcs.radiussend = radiussend;

	snprintf(path, 256, "%s/%s.so", LIBDIR, plugin_name);

	log(2, 0, 0, 0, "Loading plugin from %s\n", path);
	p = dlopen(path, RTLD_NOW);
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
			log(1, 0, 0, 0, "   Plugin load failed: API version mismatch\n", dlerror());
			dlclose(p);
			return;
		}
	}

	initfunc = dlsym(p, "plugin_init");
	if (!initfunc)
	{
		log(1, 0, 0, 0, "   Plugin load failed: function plugin_init() does not exist.\n", dlerror());
		dlclose(p);
		return;
	}

	if (!initfunc(&funcs))
	{
		log(1, 0, 0, 0, "   Plugin load failed: plugin_init() returned FALSE.\n", dlerror());
		dlclose(p);
		return;
	}

	for (i = 0; i < max_plugin_functions; i++)
	{
		void *x;
		if (!plugin_functions[i]) continue;
		if ((x = dlsym(p, plugin_functions[i])))
		{
			log(3, 0, 0, 0, "   Supports function \"%s\"\n", plugin_functions[i]);
			ll_push(plugins[i], x);
		}
	}
	log(2, 0, 0, 0, "   Loaded plugin %s\n", plugin_name);
}

void remove_plugin(char *plugin_name)
{
	void *p;
	int (*donefunc)();
	char path[256] = {0};
	int i;

	snprintf(path, 256, "%s/%s.so", LIBDIR, plugin_name);

	log(2, 0, 0, 0, "Removing plugin %s\n", plugin_name);
	// Get the existing pointer
	p = dlopen(path, RTLD_LAZY);
	if (!p) return;

	for (i = 0; i < max_plugin_functions; i++)
	{
		void *x;
		if (!plugin_functions[i]) continue;
		if ((x = dlsym(p, plugin_functions[i]))) ll_delete(plugins[i], x);
	}

	if (ll_contains(loaded_plugins, p))
	{
		ll_delete(loaded_plugins, p);

		donefunc = dlsym(p, "plugin_done");
		if (donefunc) donefunc();
	}

	dlclose(p);
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

void processcontrol(u8 * buf, int len, struct sockaddr_in *addr)
{
	char *resp;
	int l;
	struct param_control param = { buf, len, ntohl(addr->sin_addr.s_addr), ntohs(addr->sin_port), NULL, 0, 0 };

	log(4, ntohl(addr->sin_addr.s_addr), 0, 0, "Received ");
	dump_packet(buf, log_stream);

	resp = calloc(1400, 1);
	l = new_packet(PKT_RESP_ERROR, resp);
	*(int *)(resp + 6) = *(int *)(buf + 6);

	param.type = ntohs(*(short *)(buf + 2));
	param.id = ntohl(*(int *)(buf + 6));
	param.data_length = ntohs(*(short *)(buf + 4)) - 10;
	param.data = (param.data_length > 0) ? (char *)(buf + 10) : NULL;
	param.response = resp;
	param.response_length = l;

	if (param.type == PKT_LOAD_PLUGIN && param.data_length)
	{
		add_plugin(param.data);
	}
	else if (param.type == PKT_UNLOAD_PLUGIN && param.data_length)
	{
		remove_plugin(param.data);
	}
	else
	{
		run_plugins(PLUGIN_CONTROL, &param);
	}

	if (param.send_response)
	{
		send_packet(controlfd, ntohl(addr->sin_addr.s_addr), ntohs(addr->sin_port), param.response, param.response_length);
		log(4, ntohl(addr->sin_addr.s_addr), 0, 0, "Sent Control packet response\n");
	}

	free(resp);
}

