// L2TPNS Global Stuff
// $Id: l2tpns.h,v 1.45 2004-12-03 06:40:02 bodea Exp $

#ifndef __L2TPNS_H__
#define __L2TPNS_H__

#include <netinet/in.h>
#include <execinfo.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <libcli.h>

#define VERSION	"2.0.13"

// Limits
#define MAXTUNNEL	500		// could be up to 65535
#define MAXSESSION	50000		// could be up to 65535
#define MAXTBFS		6000		// Maximum token bucket filters. Might need up to 2 * session.

#define RADIUS_SHIFT	5
#define RADIUS_MASK	((unsigned short)(((unsigned short)~0) >> (16 - RADIUS_SHIFT)))
#define	MAXRADIUS	((unsigned long)(1L << RADIUS_SHIFT) * 255)

#define T_UNDEF		(0xffff)	// A tunnel ID that won't ever be used. Mark session as undefined.
#define T_FREE		(0)		// A tunnel ID that won't ever be used. Mark session as free.

#define	MAXCONTROL	1000		// max length control message we ever send...
#define	MAXETHER	(1500+18)	// max packet we try sending to tun
#define	MAXTEL		96		// telephone number
#define MAXPLUGINS	20		// maximum number of plugins to load
#define MAXRADSERVER	10		// max radius servers
#define	MAXROUTE	10		// max static routes per session
#define MAXIPPOOL	131072		// max number of ip addresses in pool
#define RINGBUFFER_SIZE	10000		// Number of ringbuffer entries to allocate
#define MAX_LOG_LENGTH	512		// Maximum size of log message
#define ECHO_TIMEOUT	60		// Time between last packet sent and LCP ECHO generation
#define IDLE_TIMEOUT	240		// Time between last packet sent and LCP ECHO generation
#define BUSY_WAIT_TIME	3000		// 5 minutes in 1/10th seconds to wait for radius to cleanup on shutdown

// Constants
#ifndef ETCDIR
#define ETCDIR		"/etc/l2tpns"
#endif

#ifndef LIBDIR
#define LIBDIR		"/usr/lib/l2tpns"
#endif

#ifndef STATEDIR
#define STATEDIR	"/var/lib/l2tpns"
#endif

#ifndef PLUGINDIR
#define PLUGINDIR	LIBDIR		// Plugins
#endif

#ifndef PLUGINCONF
#define PLUGINCONF	ETCDIR		// Plugin config dir
#endif

#ifndef FLASHDIR
#define FLASHDIR	ETCDIR
#endif

#ifndef DATADIR
#define DATADIR		STATEDIR
#endif

#define TUNDEVICE	"/dev/net/tun"
#define STATEFILE	DATADIR "/state.dump"		// State dump file
#define CONFIGFILE	FLASHDIR "/startup-config"	// Configuration file
#define CLIUSERS	FLASHDIR "/users"		// CLI Users file
#define IPPOOLFILE	FLASHDIR "/ip_pool"		// Address pool configuration
#define ACCT_TIME	3000		// 5 minute accounting interval
#define	L2TPPORT	1701		// L2TP port
#define RADPORT		1645		// old radius port...
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
#define MIN_IP_SIZE	0x19
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
	DiscardRequest,
	IdentRequest
};

// Types
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned char u8;
typedef u32 ipt;
typedef u16 portt;
typedef u16 sessionidt;
typedef u16 tunnelidt;
typedef u32 clockt;
typedef u8 hasht[16];

// CLI actions
struct cli_session_actions {
	char action;
	ipt snoop_ip;
	u16 snoop_port;
	int throttle_in;
	int throttle_out;
	int filter_in;
	int filter_out;
};

#define CLI_SESS_KILL		0x01
#define CLI_SESS_SNOOP		0x02
#define CLI_SESS_NOSNOOP	0x04
#define CLI_SESS_THROTTLE	0x08
#define CLI_SESS_NOTHROTTLE	0x10
#define CLI_SESS_FILTER		0x20
#define CLI_SESS_NOFILTER	0x40

struct cli_tunnel_actions {
	char action;
};

#define CLI_TUN_KILL		0x01

// dump header: update number if internal format changes
#define DUMP_MAGIC "L2TPNS#" VERSION "#"

// structures
typedef struct			// route
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

typedef struct
{
	sessionidt next;		// next session in linked list
	sessionidt far;			// far end session ID
	tunnelidt tunnel;		// near end tunnel ID
	ipt ip;				// IP of session set by RADIUS response (host byte order).
	int ip_pool_index;		// index to IP pool
	unsigned long unique_id;	// unique session id
	u16 nr;				// next receive
	u16 ns;				// next send
	u32 magic;			// ppp magic number
	u32 cin, cout;			// byte counts
	u32 pin, pout;			// packet counts
	u32 total_cin;			// This counter is never reset while a session is open
	u32 total_cout;			// This counter is never reset while a session is open
	u32 id;				// session id
	u16 throttle_in;		// upstream throttle rate (kbps)
	u16 throttle_out;		// downstream throttle rate
	clockt opened;			// when started
	clockt die;			// being closed, when to finally free
	time_t last_packet;		// Last packet from the user (used for idle timeouts)
	ipt dns1, dns2;			// DNS servers
	routet route[MAXROUTE];		// static routes
	u16 radius;			// which radius session is being used (0 for not waiting on authentication)
	u16 mru;			// maximum receive unit
	u16 tbf_in;			// filter bucket for throttling in from the user.
	u16 tbf_out;			// filter bucket for throttling out to the user.
	u8 l2tp_flags;			// various bit flags from the ICCN on the l2tp tunnel.
	u8 reserved_old_snoop;		// No longer used - remove at some time
	u8 walled_garden;		// is this session gardened?
	u8 flags1;			// additional flags (currently unused);
	char random_vector[MAXTEL];
	int random_vector_length;
	char user[129];			// user (needed in seesion for radius stop messages) (can we reduce this? --mo)
	char called[MAXTEL];		// called number
	char calling[MAXTEL];		// calling number
	u32 tx_connect_speed;
	u32 rx_connect_speed;
	u32 flags;			// Various session flags.
	ipt snoop_ip;			// Interception destination IP
	u16 snoop_port;			// Interception destination port
	u16 sid;			// near end session id.
	u8 filter_in;			// input filter index (to ip_filters[N-1]; 0 if none)
	u8 filter_out;			// output filter index
	char reserved[18];		// Space to expand structure without changing HB_VERSION
}
sessiont;

#define SF_IPCP_ACKED	1	// Has this session seen an IPCP Ack?
#define SF_LCP_ACKED	2	// LCP negotiated
#define SF_CCP_ACKED	4	// CCP negotiated

typedef struct
{
	u32	cin;
	u32	cout;
} sessioncountt;

#define	SESSIONPFC	1	// PFC negotiated flags
#define	SESSIONACFC	2	// ACFC negotiated flags

// 168 bytes per tunnel
typedef struct
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
typedef struct			// outstanding RADIUS requests
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
	ipt		address;	// Host byte order..
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
	TUNNELOPENING,		// Busy opening
	TUNNELUNDEF,		// Undefined
};

enum
{
	RADIUSNULL,             // Not in use
	RADIUSCHAP,             // sending CHAP down PPP
	RADIUSAUTH,             // sending auth to RADIUS server
	RADIUSIPCP,             // sending IPCP to end user
	RADIUSSTART,            // sending start accounting to RADIUS server
	RADIUSSTOP,             // sending stop accounting to RADIUS server
	RADIUSWAIT,		// waiting timeout before available, in case delayed replies
	RADIUSDEAD,		// errored while talking to radius server.
};

struct Tstats
{
    time_t		start_time;
    time_t		last_reset;

    unsigned long	tun_rx_packets;
    unsigned long	tun_tx_packets;
    unsigned long	tun_rx_bytes;
    unsigned long	tun_tx_bytes;
    unsigned long	tun_rx_errors;
    unsigned long	tun_tx_errors;

    unsigned long	tunnel_rx_packets;
    unsigned long	tunnel_tx_packets;
    unsigned long	tunnel_rx_bytes;
    unsigned long	tunnel_tx_bytes;
    unsigned long	tunnel_rx_errors;
    unsigned long	tunnel_tx_errors;

    unsigned long	tunnel_retries;
    unsigned long	radius_retries;

    unsigned long	arp_sent;

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

    unsigned long	c_forwarded;
    unsigned long	recv_forward;
#ifdef STATISTICS
    unsigned long	call_processtun;
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

#ifdef STAT_CALLS
#define CSTAT(x)	STAT(x)
#else
#define CSTAT(x)
#endif

#define STAT(x)		(_statistics->x++)
#define INC_STAT(x,y)	(_statistics->x += (y))
#define GET_STAT(x)	(_statistics->x)
#define SET_STAT(x, y)	(_statistics->x = (y))
#else
#define CSTAT(x)
#define STAT(x)
#define INC_STAT(x,y)
#define GET_STAT(x)	0
#define SET_STAT(x, y)
#endif

typedef struct
{
	int		debug;				// debugging level
	time_t		start_time;			// time when l2tpns was started
	char		bandwidth[256];			// current bandwidth
	char		pid_file[256];			// file to write PID to on startup
	int		wrote_pid;
	clockt		current_time;			// 1/10ths of a second since the process started.
							// means that we can only run a given process
							// for 13 years without re-starting!

	char		config_file[128];
	int		reload_config;			// flag to re-read config (set by cli)
	int		cleanup_interval;		// interval between regular cleanups (in seconds)
	int		multi_read_count;		// amount of packets to read per fd in processing loop

	char		tundevice[10];			// tun device name
	char		log_filename[128];
	char		l2tpsecret[64];

	char		radiussecret[64];
	int		radius_accounting;
	ipt		radiusserver[MAXRADSERVER];	// radius servers
	u16		radiusport[MAXRADSERVER];	// radius base ports
	u8		numradiusservers;		// radius server count
	short		num_radfds;			// Number of radius filehandles allocated

	ipt		default_dns1, default_dns2;

	unsigned long	rl_rate;			// default throttle rate
	int		num_tbfs;			// number of throttle buckets

	int		save_state;
	char		accounting_dir[128];
	ipt		bind_address;
	ipt		peer_address;
	int		send_garp;			// Set to true to garp for vip address on startup

	int		target_uid;
	int		dump_speed;
	char		plugins[64][MAXPLUGINS];
	char		old_plugins[64][MAXPLUGINS];

	int		next_tbf;			// Next HTB id available to use
	int		scheduler_fifo;			// If the system has multiple CPUs, use FIFO scheduling policy for this process.
	int		lock_pages;			// Lock pages into memory.
	int		icmp_rate;			// Max number of ICMP unreachable per second to send>

	u32		cluster_address;		// Multicast address of cluster.
							// Send to this address to have everyone hear.
	char		cluster_interface[64];		// Which interface to listen for multicast on.
	int		cluster_iam_master;		// Are we the cluster master???
	int		cluster_iam_uptodate;		// Set if we've got a full set of state from the master.
	u32		cluster_master_address;		// The network address of the cluster master.
							// Zero if i am the cluster master.
	int		cluster_seq_number;		// Sequence number of the next heartbeat we'll send out
							// (or the seq number we're next expecting if we're a slave).
	int		cluster_undefined_sessions;	// How many sessions we're yet to receive from the master.
	int		cluster_undefined_tunnels;	// How many tunnels we're yet to receive from the master.
	int		cluster_highest_sessionid;
	int		cluster_highest_tunnelid;
	clockt		cluster_last_hb;		// Last time we saw a heartbeat from the master.
	int		cluster_num_changes;		// Number of changes queued.

	int		cluster_hb_interval;		// How often to send a heartbeat.
	int		cluster_hb_timeout;		// How many missed heartbeats trigger an election.
	u64		cluster_table_version;		// # state changes processed by cluster

#ifdef BGP
#define BGP_NUM_PEERS	2
	u16		as_number;
	struct {
		char	name[64];
	    	u16	as;
		int	keepalive;
		int	hold;
	}		neighbour[BGP_NUM_PEERS];
#endif
} configt;

enum config_typet { INT, STRING, UNSIGNED_LONG, SHORT, BOOL, IP, MAC };
typedef struct
{
	char *key;
	int offset;
	int size;
	enum config_typet type;
} config_descriptt;

typedef struct
{
	u8 op;		// operation
#define FILTER_PORT_OP_NONE	0 // all ports match
#define FILTER_PORT_OP_EQ	1
#define FILTER_PORT_OP_NEQ	2
#define FILTER_PORT_OP_GT	3
#define FILTER_PORT_OP_LT	4
#define FILTER_PORT_OP_RANGE	5
	portt port;	// port (host byte order)
	portt port2;	// range
} ip_filter_portt;

typedef struct
{
	int action;		// permit/deny
#define FILTER_ACTION_DENY	1
#define FILTER_ACTION_PERMIT	2
	u8 proto;		// protocol: IPPROTO_* (netinet/in.h)
	ipt src_ip;		// source ip (network byte order)
	ipt src_wild;
	ip_filter_portt src_ports;
	ipt dst_ip;		// dest ip
	ipt dst_wild;
	ip_filter_portt dst_ports;
	u8 frag;		// apply to non-initial fragments
	u8 tcp_flag_op;		// match type: any, all, established
#define FILTER_FLAG_OP_ANY	1
#define FILTER_FLAG_OP_ALL	2
#define FILTER_FLAG_OP_EST	3
	u8 tcp_sflags;		// flags set
	u8 tcp_cflags;		// flags clear
	u32 counter;		// match count
} ip_filter_rulet;

#define TCP_FLAG_FIN	0x01
#define TCP_FLAG_SYN	0x02
#define TCP_FLAG_RST	0x04
#define TCP_FLAG_PSH	0x08
#define TCP_FLAG_ACK	0x10
#define TCP_FLAG_URG	0x20

#define MAXFILTER		32
#define MAXFILTER_RULES		32
typedef struct
{
    	char name[32];		// ACL name
	int extended;		// type: 0 = standard, 1 = extended
	ip_filter_rulet rules[MAXFILTER_RULES];
	int used;		// session ref count
} ip_filtert;

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
u8 *makeppp(u8 * b, int size, u8 * p, int l, tunnelidt t, sessionidt s, u16 mtype);
void initlcp(tunnelidt t, sessionidt s);
void send_ipin(sessionidt s, u8 * buf, int len);


// radius.c
void initrad(void);
void radiussend(u16 r, u8 state);
void processrad(u8 *buf, int len, char socket_index);
void radiusretry(u16 r);
u16 radiusnew(sessionidt s);
void radiusclear(u16 r, sessionidt s);


// l2tpns.c
clockt backoff(u8 try);
sessionidt sessionbyip(ipt ip);
sessionidt sessionbyuser(char *username);
void sessionshutdown(sessionidt s, char *reason);
void send_garp(ipt ip);
void tunnelsend(u8 * buf, u16 l, tunnelidt t);
void sendipcp(tunnelidt t, sessionidt s);
void processudp(u8 * buf, int len, struct sockaddr_in *addr);
void snoop_send_packet(char *packet, u16 size, ipt destination, u16 port);
int ip_filter(u8 *buf, int len, u8 filter);
int cmd_show_ipcache(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_hist_idle(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_hist_open(struct cli_def *cli, char *command, char **argv, int argc);

#undef LOG
#undef LOG_HEX
#define LOG(D, s, t, f, ...)	({ if (D <= config->debug) _log(D, s, t, f, ## __VA_ARGS__); })
#define LOG_HEX(D, t, d, s)	({ if (D <= config->debug) _log_hex(D, t, d, s); })

void _log(int level, sessionidt s, tunnelidt t, const char *format, ...) __attribute__((format (printf, 4, 5)));
void _log_hex(int level, const char *title, const char *data, int maxsize);

int sessionsetup(tunnelidt t, sessionidt s);
int run_plugins(int plugin_type, void *data);
void rebuild_address_pool(void);
void throttle_session(sessionidt s, int rate_in, int rate_out);
int load_session(sessionidt, sessiont *);
void become_master(void);	// We're the master; kick off any required master initializations.


// cli.c
void init_cli(char *hostname);
void cli_do_file(FILE *fh);
void cli_do(int sockfd);
int cli_arg_help(struct cli_def *cli, int cr_ok, char *entry, ...);


// icmp.c
void host_unreachable(ipt destination, u16 id, ipt source, char *packet, int packet_len);


extern tunnelt *tunnel;
extern sessiont *session;
extern sessioncountt *sess_count;
extern ippoolt *ip_address_pool;
#define sessionfree (session[0].next)

#define log_backtrace(count, max) \
if (count++ < max) { \
	void *array[20]; \
	char **strings; \
	int size, i; \
	LOG(0, 0, t, "Backtrace follows"); \
	size = backtrace(array, 10); \
	strings = backtrace_symbols(array, size); \
	if (strings) for (i = 0; i < size; i++) \
	{ \
		LOG(0, 0, t, "%s\n", strings[i]); \
	} \
	free(strings); \
}


extern configt *config;
extern time_t basetime;		// Time when this process started.
extern time_t time_now;		// Seconds since EPOCH.
extern u32 last_id;
extern struct Tstats *_statistics;
extern ipt my_address;
extern int tun_write(u8 *data, int size);
extern int clifd;


#define TIME (config->current_time)

// macros for handling help in cli commands
#define CLI_HELP_REQUESTED	(argc > 0 && argv[argc-1][strlen(argv[argc-1])-1] == '?')
#define CLI_HELP_NO_ARGS	(argc > 1 || argv[0][1]) ? CLI_OK : cli_arg_help(cli, 1, NULL)

// CVS identifiers (for "show version file")
extern char const *cvs_id_arp;
extern char const *cvs_id_cli;
extern char const *cvs_id_cluster;
extern char const *cvs_id_constants;
extern char const *cvs_id_control;
extern char const *cvs_id_icmp;
extern char const *cvs_id_l2tpns;
extern char const *cvs_id_ll;
extern char const *cvs_id_md5;
extern char const *cvs_id_ppp;
extern char const *cvs_id_radius;
extern char const *cvs_id_tbf;
extern char const *cvs_id_util;

#endif /* __L2TPNS_H__ */
