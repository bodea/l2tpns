// L2TPNS Global Stuff
// $Id: l2tpns.h,v 1.18.2.3 2004-10-05 04:56:26 fred_nerk Exp $

#ifndef __L2TPNS_H__
#define __L2TPNS_H__

#include <netinet/in.h>
#include <net/ethernet.h>
#include <execinfo.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <libcli.h>

#define VERSION	"2.0.2"

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
#define BUSY_WAIT_TIMEOUT	3000	// 5 minutes in 1/10th seconds to wait for radius to cleanup on shutdown

// Constants
#include "config.h"
#ifndef PLUGINDIR
#define PLUGINDIR	LIBDIR			// Plugins
#endif

#ifndef PLUGINCONF
#define PLUGINCONF	ETCDIR			// Plugin config dir
#endif

#ifndef DATADIR
#define DATADIR		"/tmp"
#endif

#ifndef FLASHDIR
#define FLASHDIR	ETCDIR
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
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint8_t u8;
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
	int throttle;
};

#define CLI_SESS_KILL		0x01
#define CLI_SESS_SNOOP		0x02
#define CLI_SESS_NOSNOOP	0x04
#define CLI_SESS_THROTTLE	0x08
#define CLI_SESS_NOTHROTTLE	0x10

struct cli_tunnel_actions {
	char action;
};

#define CLI_TUN_KILL		0x01

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

typedef struct sessions
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
	u32 throttle;			// non-zero if this session is throttled.
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
	struct ether_addr client_mac;	// Client MAC address for PPPoE
	u16 vlan;			// VLAN for PPPoE
	char reserved[32];		// Space to expand structure without changing HB_VERSION
}
sessiont;

#define SF_IPCP_ACKED	(1<<0)		// Has this session seen an IPCP Ack?

typedef struct {
	u32	cin;
	u32	cout;
} sessioncountt;

#define	SESSIONPFC	1		// PFC negotiated flags
#define	SESSIONACFC	2		// ACFC negotiated flags
#define SESSIONLCPACK	4		// LCP negotiated
#define SESSIONPPPOE	8		// This is a PPPoE session, not L2TP

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
	u16 vlan;		// VLAN for PPPoE
	u8 reserved[32];
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
    unsigned long	call_processpcap;
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

struct configt
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

	unsigned long	rl_rate;
	int		save_state;
	char		accounting_dir[128];
	ipt		bind_address;
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

#ifdef BGP
	u16		as_number;
	char		bgp_peer[2][64];
	u16		bgp_peer_as[2];
#endif
	char		hostname[256];			// our hostname - set to gethostname() by default
	struct ether_addr mac_address;			// MAC address for PPPoE
	char		pppoe_interface[16];		// Interface to use for PPPoE
};

struct config_descriptt
{
	char *key;
	int offset;
	int size;
	enum { INT, STRING, UNSIGNED_LONG, SHORT, BOOL, IP, MAC } type;
};

// arp.c
void sendarp(int ifr_idx, const unsigned char *mac, ipt ip);


// ppp.c
void processpap(tunnelidt t, sessionidt s, u8 * p, u16 l);
void processchap(tunnelidt t, sessionidt s, u8 * p, u16 l);
void processlcp(tunnelidt t, sessionidt s, u8 * p, u16 l);
void processipcp(tunnelidt t, sessionidt s, u8 * p, u16 l);
void processipin(tunnelidt t, sessionidt s, u8 * p, u16 l);
void processccp(tunnelidt t, sessionidt s, u8 * p, u16 l);
void sendchap(tunnelidt t, sessionidt s);
u8 *makeppp(u8 * b, int size, u8 * p, int l, tunnelidt t, sessionidt s, u16 mtype);
u8 *findppp(u8 * b, u8 mtype);
void initlcp(tunnelidt t, sessionidt s);
void dumplcp(u8 *p, int l);


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
void routeset(sessionidt, ipt ip, ipt mask, ipt gw, u8 add);
void inittun(void);
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
void returnpacket(u8 *buf, u16 l, sessionidt s, tunnelidt t);
void tunnelkill(tunnelidt t, char *reason);
void tunnelshutdown(tunnelidt t, char *reason);
void sendipcp(tunnelidt t, sessionidt s);
void processipout(u8 * buf, int len);
void processarp(u8 * buf, int len);
void processudp(u8 * buf, int len, struct sockaddr_in *addr);
void processtun(u8 * buf, int len);
void processcontrol(u8 * buf, int len, struct sockaddr_in *addr);
int assign_ip_address(sessionidt s);
void free_ip_address(sessionidt s);
void snoop_send_packet(char *packet, u16 size, ipt destination, u16 port);
void dump_acct_info();
void mainloop(void);
int cmd_show_ipcache(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_hist_idle(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_hist_open(struct cli_def *cli, char *command, char **argv, int argc);

#define log _log
#ifndef log_hex
#define log_hex(a,b,c,d) do{if (a <= config->debug) _log_hex(a,0,0,0,b,c,d);}while (0)
#endif
void _log(int level, ipt address, sessionidt s, tunnelidt t, const char *format, ...) __attribute__((format (printf, 5, 6)));
void _log_hex(int level, ipt address, sessionidt s, tunnelidt t, const char *title, const char *data, int maxsize);
void build_chap_response(char *challenge, u8 id, u16 challenge_length, char **challenge_response);
int sessionsetup(tunnelidt t, sessionidt s);
int cluster_send_session(int s);
int cluster_send_tunnel(int t);
int cluster_send_goodbye();
void init_cli();
void cli_do_file(FILE *fh);
void cli_do(int sockfd);
int cli_arg_help(struct cli_def *cli, int cr_ok, char *entry, ...);
#ifdef RINGBUFFER
void ringbuffer_dump(FILE *stream);
#endif
void initplugins(void);
int run_plugins(int plugin_type, void *data);
void add_plugin(char *plugin_name);
void remove_plugin(char *plugin_name);
void plugins_done(void);
void tunnelclear(tunnelidt t);
void host_unreachable(ipt destination, u16 id, ipt source, char *packet, int packet_len);
void fix_address_pool(int sid);
void rebuild_address_pool(void);
void send_ipin(sessionidt s, u8 * buf, int len);
int throttle_session(sessionidt s, int throttle);
int load_session(sessionidt, sessiont *);
void become_master(void);	// We're the master; kick off any required master initializations.
extern tunnelt *tunnel;
extern sessiont *session;
extern sessioncountt *sess_count;
extern ippoolt *ip_address_pool;
void processpcap(u8 *buf, int len);
void processppp(sessionidt s, tunnelidt t, u8 *buf, int len, u8 *p, int l, struct sockaddr_in *addr);
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


extern struct configt *config;
extern time_t basetime;		// Time when this process started.
extern time_t time_now;		// Seconds since EPOCH.
extern u32 last_id;
extern struct Tstats *_statistics;
extern ipt my_address;
extern int tun_write(u8 *data, int size);


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
