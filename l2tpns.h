// L2TPNS Global Stuff
// $Id: l2tpns.h,v 1.6 2004-05-24 04:33:35 fred_nerk Exp $

#include <netinet/in.h>
#include <stdio.h>
#include <execinfo.h>
#include "config.h"

#define VERSION	"1.2.0"

// Limits
#define MAXTUNNEL	500		// could be up to 65535
#define MAXSESSION	50000		// could be up to 65535
#define RADIUS_SHIFT	5
#define RADIUS_MASK	((unsigned short)(((unsigned short)~0) >> (16 - RADIUS_SHIFT)))
#define	MAXRADIUS	((2 << (RADIUS_SHIFT - 1)) * 255)

#define	MAXCONTROL	1000		// max length control message we ever send...
#define	MAXETHER	(1500+18)	// max packet we try sending to tap
#define	MAXTEL		96		// telephone number
#define MAXPLUGINS	20		// maximum number of plugins to load
#define MAXRADSERVER	10		// max radius servers
#define	MAXROUTE	10		// max static routes per session
#define MAXIPPOOL	131072		// max number of ip addresses in pool
#define RINGBUFFER_SIZE	10000		// Number of ringbuffer entries to allocate
#define MAX_LOG_LENGTH	512		// Maximum size of log message
#define ECHO_TIMEOUT	60		// Time between last packet sent and LCP ECHO generation
#define IDLE_TIMEOUT	240		// Time between last packet sent and LCP ECHO generation

// Constants
#define STATISTICS
#define STAT_CALLS
#define RINGBUFFER
#define TAPDEVICE	"/dev/net/tun"
#define	UDP		17
#define HOMEDIR		"/home/l2tpns/"			// Base dir for data
#define STATEFILE	"/tmp/l2tpns.dump"              // State dump file
#define NOSTATEFILE	"/tmp/l2tpns.no_state_reload"   // If exists, state will not be reloaded
#define CONFIGFILE	ETCDIR "/l2tpns.cfg"            // Configuration file
#define CLIUSERS	ETCDIR "/l2tpns.users"          // CLI Users file
#define IPPOOLFILE	ETCDIR "/l2tpns.ip_pool"        // Address pool configuration
#ifndef LIBDIR
#define LIBDIR		"/usr/lib/l2tpns"
#endif
#define ACCT_TIME	3000		// 5 minute accounting interval
#define	L2TPPORT	1701		// L2TP port
#define RADPORT		1645		// old radius port...
#define	RADAPORT	1646		// old radius accounting port
#define	PKTARP		0x0806		// ARP packet type
#define	PKTIP		0x0800		// IP packet type
#define PSEUDOMAC	0x0200		// pseudo MAC prefix (local significant MAC)
#define	PPPPAP		0xC023
#define	PPPCHAP		0xC223
#define	PPPLCP		0xC021
#define	PPPIPCP		0x8021
#define	PPPCCP		0x80FD
#define PPPIP		0x0021
#define PPPMP		0x003D
#define MIN_IP_SIZE	0x20
enum
{
	ConfigReq = 1,
	ConfigAck,
	ConfigNak,
	ConfigRej,
	TerminateReq,
	TerminateAck,
	CodeRej,
	ProtocolRej,
	EchoReq,
	EchoReply,
	DiscardRequest
};

// Types
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned char u8;
typedef u32 ipt;
typedef u16 portt;
typedef u16 sessionidt;
typedef u16 tunnelidt;
typedef u32 clockt;
typedef u8 hasht[16];

// dump header: update number if internal format changes
#define DUMP_MAGIC "L2TPNS#" VERSION "#"

// structures
typedef struct routes           // route
{
	ipt ip;
	ipt mask;
}
routet;

typedef struct controls         // control message
{
	struct controls *next;  // next in queue
	u16 length;             // length
	u8 buf[MAXCONTROL];
}
controlt;

typedef struct stbft
{
    char handle[10];
    char in_use;
} tbft;


// 336 bytes per session
typedef struct sessions
{
	sessionidt next;		// next session in linked list
	sessionidt far;			// far end session ID
	tunnelidt tunnel;		// tunnel ID
	ipt ip;				// IP of session set by RADIUS response
	int ip_pool_index;		// index to IP pool
	unsigned long sid;		// session id for hsddb
	u16 nr;				// next receive
	u16 ns;				// next send
	u32 magic;			// ppp magic number
	u32 cin, cout;			// byte counts
	u32 pin, pout;			// packet counts
	u32 total_cin;			// This counter is never reset while a session is open
	u32 total_cout;			// This counter is never reset while a session is open
	u32 id;				// session id
	clockt opened;			// when started
	clockt die;			// being closed, when to finally free
	time_t last_packet;		// Last packet from the user (used for idle timeouts)
	ipt dns1, dns2;			// DNS servers
	routet route[MAXROUTE];		// static routes
	u16 radius;			// which radius session is being used (0 for not waiting on authentication)
	u8 flags;			// various bit flags
	u8 snoop;			// are we snooping this session?
	u8 throttle;			// is this session throttled?
	u8 walled_garden;		// is this session gardened?
	u16 mru;			// maximum receive unit
	u16 tbf;			// filter bucket for throttling
	char random_vector[MAXTEL];
	int random_vector_length;
	char user[129];			// user (needed in seesion for radius stop messages)
	char called[MAXTEL];		// called number
	char calling[MAXTEL];		// calling number
	unsigned long tx_connect_speed;
	unsigned long rx_connect_speed;
}
sessiont;

#define	SESSIONPFC	1            // PFC negotiated flags
#define	SESSIONACFC	2           // ACFC negotiated flags

// 168 bytes per tunnel
typedef struct tunnels
{
	tunnelidt far;		// far end tunnel ID
	ipt ip;			// Ip for far end
	portt port;		// port for far end
	u16 window;		// Rx window
	u16 nr;			// next receive
	u16 ns;			// next send
	int state;		// current state (tunnelstate enum)
	clockt last;		// when last control message sent (used for resend timeout)
	clockt retry;		// when to try resenting pending control
	clockt die;		// being closed, when to finally free
	clockt lastrec;		// when the last control message was received
	char hostname[128];	// tunnel hostname
	char vendor[128];	// LAC vendor
	u8 try;			// number of retrys on a control message
	u16 controlc;		// outstaind messages in queue
	controlt *controls;	// oldest message
	controlt *controle;	// newest message
}
tunnelt;

// 180 bytes per radius session
typedef struct radiuss		// outstanding RADIUS requests
{
	sessionidt session;	// which session this applies to
	hasht auth;		// request authenticator
	clockt retry;		// when to try next
	char calling[MAXTEL];	// calling number
	char pass[129];		// password
	u8 id;			// ID for PPP response
	u8 try;			// which try we are on
	u8 state;		// state of radius requests
	u8 chap;		// set if CHAP used (is CHAP identifier)
}
radiust;

typedef struct
{
	ipt		address;
	char		assigned;	// 1 if assigned, 0 if free
	sessionidt	session;
	clockt		last;		// last used
	char		user[129];      // user (try to have ip addresses persistent)
}
ippoolt;

#ifdef RINGBUFFER
struct Tringbuffer
{
	struct {
		char level;
		sessionidt session;
		tunnelidt tunnel;
		ipt address;
		char message[MAX_LOG_LENGTH];
	} buffer[RINGBUFFER_SIZE];
	int head;
	int tail;
};
#endif

/*
 * Possible tunnel states
 * TUNNELFREE -> TUNNELOPEN -> TUNNELDIE -> TUNNELFREE
 */
enum
{
	TUNNELFREE,		// Not in use
	TUNNELOPEN,		// Active tunnel
	TUNNELDIE,		// Currently closing
	TUNNELOPENING		// Busy opening
};

enum
{
	RADIUSNULL,             // Not in use
	RADIUSCHAP,             // sending CHAP down PPP
	RADIUSAUTH,             // sending auth to RADIUS server
	RADIUSIPCP,             // sending IPCP to end user
	RADIUSSTART,            // sending start accounting to RADIUS server
	RADIUSSTOP,             // sending stop accounting to RADIUS server
	RADIUSWAIT		// waiting timeout before available, in case delayed replies
};

struct Tstats
{
    time_t		start_time;
    time_t		last_reset;

    unsigned long	tap_rx_packets;
    unsigned long	tap_tx_packets;
    unsigned long	tap_rx_bytes;
    unsigned long	tap_tx_bytes;
    unsigned long	tap_rx_errors;
    unsigned long	tap_tx_errors;

    unsigned long	tunnel_rx_packets;
    unsigned long	tunnel_tx_packets;
    unsigned long	tunnel_rx_bytes;
    unsigned long	tunnel_tx_bytes;
    unsigned long	tunnel_rx_errors;
    unsigned long	tunnel_tx_errors;

    unsigned long	tunnel_retries;
    unsigned long	radius_retries;

    unsigned long	arp_errors;
    unsigned long	arp_replies;
    unsigned long	arp_discarded;
    unsigned long	arp_sent;
    unsigned long	arp_recv;

    unsigned long	packets_snooped;

    unsigned long	tunnel_created;
    unsigned long	session_created;
    unsigned long	tunnel_timeout;
    unsigned long	session_timeout;
    unsigned long	radius_timeout;
    unsigned long	radius_overflow;
    unsigned long	tunnel_overflow;
    unsigned long	session_overflow;

    unsigned long	ip_allocated;
    unsigned long	ip_freed;
#ifdef STAT_CALLS
    unsigned long	call_processtap;
    unsigned long	call_processarp;
    unsigned long	call_processipout;
    unsigned long	call_processudp;
    unsigned long	call_sessionbyip;
    unsigned long	call_sessionbyuser;
    unsigned long	call_sendarp;
    unsigned long	call_sendipcp;
    unsigned long	call_tunnelsend;
    unsigned long	call_sessionkill;
    unsigned long	call_sessionshutdown;
    unsigned long	call_tunnelkill;
    unsigned long	call_tunnelshutdown;
    unsigned long	call_assign_ip_address;
    unsigned long	call_free_ip_address;
    unsigned long	call_dump_acct_info;
    unsigned long	call_sessionsetup;
    unsigned long	call_processpap;
    unsigned long	call_processchap;
    unsigned long	call_processlcp;
    unsigned long	call_processipcp;
    unsigned long	call_processipin;
    unsigned long	call_processccp;
    unsigned long	call_sendchap;
    unsigned long	call_processrad;
    unsigned long	call_radiussend;
    unsigned long	call_radiusretry;
#endif
};

#ifdef STATISTICS
#define STAT(x)		_statistics->x++
#define INC_STAT(x,y)	_statistics->x += y
#define GET_STAT(x)	_statistics->x
#define SET_STAT(x, y)	_statistics->x = y
#else
#define STAT(x)
#define INC_STAT(x,y)
#define GET_STAT(x)	0
#define SET_STAT(x, y)
#endif

struct configt
{
	int		debug;				// debugging level
	time_t		start_time;			// time when l2tpns was started
	char		bandwidth[256];			// current bandwidth

	char		config_file[128];
	int		reload_config;			// flag to re-read config (set by cli)
	int		cleanup_interval;		// interval between regular cleanups (in seconds)
	int		multi_read_count;		// amount of packets to read per fd in processing loop

	char		tapdevice[10];			// tap device name
	char		log_filename[128];
	char		l2tpsecret[64];

	char		radiussecret[64];
	int		radius_accounting;
	ipt		radiusserver[MAXRADSERVER];	// radius servers
	u8		numradiusservers;		// radius server count
	short		num_radfds;			// Number of radius filehandles allocated

	ipt		default_dns1, default_dns2;

	ipt		snoop_destination_host;
	u16		snoop_destination_port;

	unsigned long	rl_rate;
	int		save_state;
	uint32_t	cluster_address;
	int		ignore_cluster_updates;
	char		accounting_dir[128];
	ipt		bind_address;
	int		target_uid;
	int		dump_speed;
	char		plugins[64][MAXPLUGINS];
	char		old_plugins[64][MAXPLUGINS];

	int		next_tbf;			// Next HTB id available to use
};

struct config_descriptt
{
	char *key;
	int offset;
	int size;
	enum { INT, STRING, UNSIGNED_LONG, SHORT, BOOL, IP } type;
};

// arp.c
void sendarp(int ifr_idx, const unsigned char* mac, ipt ip);


// ppp.c
void processpap(tunnelidt t, sessionidt s, u8 * p, u16 l);
void processchap(tunnelidt t, sessionidt s, u8 * p, u16 l);
void processlcp(tunnelidt t, sessionidt s, u8 * p, u16 l);
void processipcp(tunnelidt t, sessionidt s, u8 * p, u16 l);
void processipin(tunnelidt t, sessionidt s, u8 * p, u16 l);
void processccp(tunnelidt t, sessionidt s, u8 * p, u16 l);
void sendchap(tunnelidt t, sessionidt s);
u8 *makeppp(u8 * b, u8 * p, int l, tunnelidt t, sessionidt s, u16 mtype);
u8 *findppp(u8 * b, u8 mtype);
void initlcp(tunnelidt t, sessionidt s);
void dumplcp(char *p, int l);


// radius.c
void initrad(void);
void radiussend(u16 r, u8 state);
void processrad(u8 *buf, int len, char socket_index);
void radiusretry(u16 r);
u16 radiusnew(sessionidt s);
void radiusclear(u16 r, sessionidt s);

// throttle.c
int throttle_session(sessionidt s, int throttle);


// rl.c
void init_rl();
u16 rl_create_tbf();
u16 rl_get_tbf();
void rl_done_tbf(u16 t);
void rl_destroy_tbf(u16 t);


// l2tpns.c
clockt now(void);
clockt backoff(u8 try);
void routeset(ipt ip, ipt mask, ipt gw, u8 add);
void inittap(void);
void initudp(void);
void initdata(void);
void initippool();
sessionidt sessionbyip(ipt ip);
sessionidt sessionbyuser(char *username);
void sessionshutdown(sessionidt s, char *reason);
void sessionsendarp(sessionidt s);
void send_garp(ipt ip);
void sessionkill(sessionidt s, char *reason);
void control16(controlt * c, u16 avp, u16 val, u8 m);
void control32(controlt * c, u16 avp, u32 val, u8 m);
void controls(controlt * c, u16 avp, char *val, u8 m);
void controlb(controlt * c, u16 avp, char *val, unsigned int len, u8 m);
controlt *controlnew(u16 mtype);
void controlnull(tunnelidt t);
void controladd(controlt * c, tunnelidt t, sessionidt s);
void tunnelsend(u8 * buf, u16 l, tunnelidt t);
void tunnelkill(tunnelidt t, char *reason);
void tunnelshutdown(tunnelidt t, char *reason);
void sendipcp(tunnelidt t, sessionidt s);
void processipout(u8 * buf, int len);
void processarp(u8 * buf, int len);
void processudp(u8 * buf, int len, struct sockaddr_in *addr);
void processtap(u8 * buf, int len);
void processcontrol(u8 * buf, int len, struct sockaddr_in *addr);
int assign_ip_address(sessionidt s);
void free_ip_address(sessionidt s);
void snoop_send_packet(char *packet, u16 size);
void dump_acct_info();
void mainloop(void);
#define log _log
#ifndef log_hex
#define log_hex(a,b,c,d) do{if (a <= config->debug) _log_hex(a,0,0,0,b,c,d);}while (0)
#endif
void _log(int level, ipt address, sessionidt s, tunnelidt t, const char *format, ...) __attribute__((format (printf, 5, 6)));
void _log_hex(int level, ipt address, sessionidt s, tunnelidt t, const char *title, const char *data, int maxsize);
void build_chap_response(char *challenge, u8 id, u16 challenge_length, char **challenge_response);
int sessionsetup(tunnelidt t, sessionidt s, u8 routes);
int cluster_send_session(int s);
int cluster_send_tunnel(int t);
int cluster_send_goodbye();
void init_cli();
void cli_do_file(FILE *fh);
void cli_do(int sockfd);
#ifdef RINGBUFFER
void ringbuffer_dump(FILE *stream);
#endif
void initplugins();
int run_plugins(int plugin_type, void *data);
void add_plugin(char *plugin_name);
void remove_plugin(char *plugin_name);
void tunnelclear(tunnelidt t);
void host_unreachable(ipt destination, u16 id, ipt source, char *packet, int packet_len);

extern tunnelt *tunnel;
extern sessiont *session;
#define sessionfree (session[0].next)

#define log_backtrace(count, max) \
if (count++ < max) { \
	void *array[20]; \
	char **strings; \
	int size, i; \
	log(0, 0, 0, t, "Backtrace follows"); \
	size = backtrace(array, 10); \
	strings = backtrace_symbols(array, size); \
	if (strings) for (i = 0; i < size; i++) \
	{ \
		log(0, 0, 0, t, "%s\n", strings[i]); \
	} \
	free(strings); \
}

