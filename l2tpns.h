// L2TPNS Global Stuff
// $Id: l2tpns.h,v 1.121 2009-12-08 14:49:28 bodea Exp $

#ifndef __L2TPNS_H__
#define __L2TPNS_H__

#include <netinet/in.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <libcli.h>

#define VERSION	"2.2.1"

// Limits
#define MAXTUNNEL	500		// could be up to 65535
#define MAXBUNDLE	300		// could be up to 65535
#define MAXBUNDLESES	12		// Maximum number of member links in bundle
#define MAXADDRESS	20		// Maximum length for the Endpoint Discrminiator address
#define MAXSESSION	60000		// could be up to 65535
#define MAXTBFS		6000		// Maximum token bucket filters. Might need up to 2 * session.

#define RADIUS_SHIFT	6
#define RADIUS_FDS	(1 << RADIUS_SHIFT)
#define RADIUS_MASK	((1 << RADIUS_SHIFT) - 1)
#define MAXRADIUS	(1 << (8 + RADIUS_SHIFT))

#define T_UNDEF		(0xffff)	// A tunnel ID that won't ever be used. Mark session as undefined.
#define T_FREE		(0)		// A tunnel ID that won't ever be used. Mark session as free.

#define MAXCONTROL	1000		// max length control message we ever send...
#define MINMTU		576		// minimum recommended MTU (rfc1063)
#define MAXMTU		2600		// arbitrary maximum MTU
#define PPPoE_MRU	1492		// maximum PPPoE MRU (rfc2516: 1500 less PPPoE header (6) and PPP protocol ID (2))
#define MAXETHER	(MAXMTU+18)	// max packet we try sending to tun
#define MAXTEL		96		// telephone number
#define MAXUSER		128		// username
#define MAXPASS		128		// password
#define MAXCLASS	128		// radius class attribute size
#define MAXPLUGINS	20		// maximum number of plugins to load
#define MAXRADSERVER	10		// max radius servers
#define MAXROUTE	10		// max static routes per session
#define MAXIPPOOL	131072		// max number of ip addresses in pool
#define RINGBUFFER_SIZE	10000		// Number of ringbuffer entries to allocate
#define MAX_LOG_LENGTH	512		// Maximum size of log message
#define ECHO_TIMEOUT	10		// Time between last packet sent and LCP ECHO generation
#define IDLE_TIMEOUT	240		// Time between last packet seen and session shutdown
#define BUSY_WAIT_TIME	3000		// 5 minutes in 1/10th seconds to wait for radius to cleanup on shutdown

#define MP_BEGIN        0x80            // This value is used when (b)egin bit is set in MP header
#define MP_END          0x40            // This value is used when (e)nd bit is set in MP header
#define MP_BOTH_BITS    0xC0            // This value is used when both bits (begin and end) are set in MP header

#define MINFRAGLEN	64		// Minumum fragment length
#define MAXFRAGLEN	750		// Maximum length for Multilink fragment (MTU / 2 sessions)
#define MAXFRAGNUM	128		// Maximum number of Multilink fragment in a bundle (must be in the form of 2^X)
					// it's not expected to have a space for more than 10 unassembled packets = 10 * MAXBUNDLESES
#define	MAXFRAGNUM_MASK	127		// Must be equal to MAXFRAGNUM-1

// Constants
#ifndef ETCDIR
#define ETCDIR		"/etc/l2tpns"
#endif

#ifndef LIBDIR
#define LIBDIR		"/usr/lib/l2tpns"
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

#define TUNDEVICE	"/dev/net/tun"
#define RANDOMDEVICE	"/dev/urandom"			// default, not as secure as /dev/random but non-blocking
#define CONFIGFILE	FLASHDIR "/startup-config"	// Configuration file
#define CLIUSERS	FLASHDIR "/users"		// CLI Users file
#define IPPOOLFILE	FLASHDIR "/ip_pool"		// Address pool configuration
#define ACCT_TIME	3000				// 5 minute accounting interval
#define ACCT_SHUT_TIME	600				// 1 minute for counters of shutdown sessions
#define L2TPPORT	1701				// L2TP port
#define RADPORT		1645				// old radius port...
#define DAEPORT		3799				// DAE port
#define PKTARP		0x0806				// ARP packet type
#define PKTIP		0x0800				// IPv4 packet type
#define PKTIPV6		0x86DD				// IPv6 packet type
#define PPPPAP		0xC023
#define PPPCHAP		0xC223
#define PPPLCP		0xC021
#define PPPIPCP		0x8021
#define PPPIPV6CP	0x8057
#define PPPCCP		0x80FD
#define PPPIP		0x0021
#define PPPIPV6		0x0057
#define PPPMP		0x003D
#define MIN_IP_SIZE	0x19

enum {
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

enum {
	AccessRequest = 1,
	AccessAccept,
	AccessReject,
	AccountingRequest,
	AccountingResponse,
	AccessChallenge = 11,
	DisconnectRequest = 40,
	DisconnectACK,
	DisconnectNAK,
	CoARequest,
	CoAACK,
	CoANAK
};

// PPP phases
enum {
    	Dead,
	Establish,
	Authenticate,
	Network,
	Terminate
};

// PPP states
enum {
	Initial,
	Starting,
	Closed,
	Stopped,
	Closing,
	Stopping,
	RequestSent,
	AckReceived,
	AckSent,
	Opened
};

// reset state machine counters
#define initialise_restart_count(_s, _fsm)			\
	sess_local[_s]._fsm.conf_sent =				\
	sess_local[_s]._fsm.nak_sent = 0

// no more attempts
#define zero_restart_count(_s, _fsm) ({				\
	sess_local[_s]._fsm.conf_sent =				\
		config->ppp_max_configure;			\
	sess_local[_s]._fsm.restart =				\
		time_now + config->ppp_restart_time;		\
})

// increment ConfReq counter and reset timer
#define restart_timer(_s, _fsm) ({				\
	sess_local[_s]._fsm.conf_sent++;			\
	sess_local[_s]._fsm.restart =				\
		time_now + config->ppp_restart_time;		\
})

// stop timer on change to state where timer does not run
#define change_state(_s, _fsm, _new) ({				\
	if (_new != session[_s].ppp._fsm)			\
	{ 							\
		switch (_new)					\
		{						\
		case Initial:					\
		case Starting:					\
		case Closed:					\
		case Stopped:					\
		case Opened:					\
			sess_local[_s]._fsm.restart = 0;	\
			initialise_restart_count(_s, _fsm);	\
		}						\
		session[_s].ppp._fsm = _new;			\
		cluster_send_session(_s);			\
	}							\
})

// Types
typedef uint16_t sessionidt;
typedef uint16_t bundleidt;
typedef uint16_t tunnelidt;
typedef uint32_t clockt;
typedef uint8_t hasht[16];

// CLI actions
struct cli_session_actions {
	char action;
	in_addr_t snoop_ip;
	uint16_t snoop_port;
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

// structures
typedef struct			// route
{
	in_addr_t ip;
	in_addr_t mask;
}
routet;

typedef struct controls		// control message
{
	struct controls *next;	// next in queue
	uint16_t length;	// length
	uint8_t buf[MAXCONTROL];
}
controlt;

typedef struct {
	uint8_t length;			// Endpoint Discriminator length
	uint8_t addr_class;		// Endpoint Discriminator class
	uint8_t address[MAXADDRESS];	// Endpoint Discriminator address
} epdist;

typedef struct {
	sessionidt sid;			// Fragment originating session
	uint8_t	flags;			// MP frame flags
	uint32_t seq;			// fragment seq num
        uint16_t length;                // Fragment length
        uint8_t data[MAXFRAGLEN];       // Fragment data
} fragmentt;

typedef struct
{
	sessionidt next;		// next session in linked list
	sessionidt far;			// far end session ID
	tunnelidt tunnel;		// near end tunnel ID
	uint8_t flags;			// session flags: see SESSION_*
	struct {
		uint8_t phase;		// PPP phase
		uint8_t lcp:4;		//   LCP    state
		uint8_t ipcp:4;		//   IPCP   state
		uint8_t ipv6cp:4;	//   IPV6CP state
		uint8_t ccp:4;		//   CCP    state
	} ppp;
	uint16_t mru;			// maximum receive unit
	in_addr_t ip;			// IP of session set by RADIUS response (host byte order).
	int ip_pool_index;		// index to IP pool
	uint32_t unique_id;		// unique session id
	uint32_t magic;			// ppp magic number
	uint32_t pin, pout;		// packet counts
	uint32_t cin, cout;		// byte counts
	uint32_t cin_wrap, cout_wrap;	// byte counter wrap count (RADIUS accounting giagawords)
	uint32_t cin_delta, cout_delta;	// byte count changes (for dump_session())
	uint16_t throttle_in;		// upstream throttle rate (kbps)
	uint16_t throttle_out;		// downstream throttle rate
	uint8_t filter_in;		// input filter index (to ip_filters[N-1]; 0 if none)
	uint8_t filter_out;		// output filter index
	uint16_t snoop_port;		// Interception destination port
	in_addr_t snoop_ip;		// Interception destination IP
	clockt opened;			// when started
	clockt die;			// being closed, when to finally free
	uint32_t session_timeout;	// Maximum session time in seconds
	uint32_t idle_timeout;		// Maximum idle time in seconds
	time_t last_packet;		// Last packet from the user (used for idle timeouts)
	time_t last_data;		// Last data packet to/from the user (used for idle timeouts)
	in_addr_t dns1, dns2;		// DNS servers
	routet route[MAXROUTE];		// static routes
	uint16_t tbf_in;		// filter bucket for throttling in from the user.
	uint16_t tbf_out;		// filter bucket for throttling out to the user.
	int random_vector_length;
	uint8_t random_vector[MAXTEL];
	char user[MAXUSER];		// user (needed in session for radius stop messages)
	char called[MAXTEL];		// called number
	char calling[MAXTEL];		// calling number
	uint32_t tx_connect_speed;
	uint32_t rx_connect_speed;
	clockt timeout;                 // Session timeout
	uint32_t mrru;                  // Multilink Max-Receive-Reconstructed-Unit
	epdist epdis;                   // Multilink Endpoint Discriminator
	bundleidt bundle;               // Multilink Bundle Identifier
	uint8_t mssf;                   // Multilink Short Sequence Number Header Format
	uint8_t walled_garden;		// is this session gardened?
	uint8_t classlen;		// class (needed for radius accounting messages)
	char class[MAXCLASS];
	uint8_t ipv6prefixlen;		// IPv6 route prefix length
	struct in6_addr ipv6route;	// Static IPv6 route
	char reserved[12];		// Space to expand structure without changing HB_VERSION
}
sessiont;

typedef struct
{
        int state;                              // current state (bundlestate enum)
        uint32_t seq_num_t;                     // Sequence Number (transmission)
        uint32_t timeout;                       // Session-Timeout for bundle
	uint32_t max_seq;			// Max value of sequence number field
        uint8_t num_of_links;                   // Number of links joint to this bundle
        uint32_t online_time;                   // The time this bundle is online
        clockt last_check;                      // Last time the timeout is checked
        uint32_t mrru;                          // Multilink Max-Receive-Reconstructed-Unit
        uint8_t mssf;                           // Multilink Short Sequence Number Header Format
        epdist epdis;                           // Multilink Endpoint Discriminator
        char user[MAXUSER];                     // Needed for matching member links
        sessionidt current_ses;                 // Current session to use for sending (used in RR load-balancing)
        sessionidt members[MAXBUNDLESES];       // Array for member links sessions
}
bundlet;

typedef struct
{
        fragmentt fragment[MAXFRAGNUM];
        uint8_t reassembled_frame[MAXETHER];    // The reassembled frame
        uint16_t re_frame_len;                  // The reassembled frame length
	uint16_t re_frame_begin_index, re_frame_end_index;	// reassembled frame begin index, end index respectively
	uint16_t start_index, end_index;	// start and end sequence numbers available on the fragments array respectively
	uint32_t M;				// Minumum frame sequence number received over all bundle members
	uint32_t start_seq;                     // Last received frame sequence number (bearing B bit)
}
fragmentationt;

#define AUTHPAP		1	// allow PAP
#define AUTHCHAP	2	// allow CHAP

typedef struct
{
	// packet counters
	uint32_t pin;
	uint32_t pout;

	// byte counters
	uint32_t cin;
	uint32_t cout;

	// PPP restart timer/counters
	struct {
		time_t restart;
		int conf_sent;
		int nak_sent;
	} lcp, ipcp, ipv6cp, ccp;

	// identifier for Protocol-Reject, Code-Reject
	uint8_t lcp_ident;

	// authentication to use
	int lcp_authtype;

	// our MRU
	uint16_t ppp_mru;

	// our MRRU
	uint16_t mp_mrru;

	// our mssf
	uint16_t mp_mssf;

	// our Endpoint Discriminator
	in_addr_t mp_epdis;

	// DoS prevention
	clockt last_packet_out;
	uint32_t packets_out;
	uint32_t packets_dropped;

	// RADIUS session in use
	uint16_t radius;

	// interim RADIUS
	time_t last_interim;

	// last LCP Echo
	time_t last_echo;

	// Last Multilink frame sequence number received
	uint32_t last_seq;
} sessionlocalt;

// session flags
#define SESSION_PFC	(1 << 0)	// use Protocol-Field-Compression
#define SESSION_ACFC	(1 << 1)	// use Address-and-Control-Field-Compression
#define SESSION_STARTED	(1 << 2)	// RADIUS Start record sent

// 168 bytes per tunnel
typedef struct
{
	tunnelidt far;		// far end tunnel ID
	in_addr_t ip;		// Ip for far end
	uint16_t port;		// port for far end
	uint16_t window;	// Rx window
	uint16_t nr;		// next receive
	uint16_t ns;		// next send
	int state;		// current state (tunnelstate enum)
	clockt last;		// when last control message sent (used for resend timeout)
	clockt retry;		// when to try resending pending control
	clockt die;		// being closed, when to finally free
	clockt lastrec;		// when the last control message was received
	char hostname[128];	// tunnel hostname
	char vendor[128];	// LAC vendor
	uint8_t try;		// number of retrys on a control message
	uint16_t controlc;	// outstaind messages in queue
	controlt *controls;	// oldest message
	controlt *controle;	// newest message
}
tunnelt;

// 164 bytes per radius session
typedef struct			// outstanding RADIUS requests
{
	sessionidt session;	// which session this applies to
	hasht auth;		// request authenticator
	clockt retry;		// when to try next
	char pass[129];		// password
	uint8_t id;		// ID for PPP response
	uint8_t try;		// which try we are on
	uint8_t state;		// state of radius requests
	uint8_t chap;		// set if CHAP used (is CHAP identifier)
	uint8_t term_cause;	// Stop record: Acct-Terminate-Cause
	char const *term_msg;	//   terminate reason
}
radiust;

typedef struct
{
	in_addr_t	address;	// Host byte order..
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
	BUNDLEFREE,		// Not in use
	BUNDLEOPEN,		// Active bundle
	BUNDLEUNDEF,		// Undefined
};

enum
{
	NULLCLASS = 0,		//End Point Discriminator classes
	LOCALADDR,
	IPADDR,
	IEEEMACADDR,
	PPPMAGIC,
	PSNDN,
};

enum
{
	RADIUSNULL,             // Not in use
	RADIUSCHAP,             // sending CHAP down PPP
	RADIUSAUTH,             // sending auth to RADIUS server
	RADIUSSTART,            // sending start accounting to RADIUS server
	RADIUSSTOP,             // sending stop accounting to RADIUS server
	RADIUSINTERIM,		// sending interim accounting to RADIUS server
	RADIUSWAIT,		// waiting timeout before available, in case delayed replies
	RADIUSJUSTAUTH,         // sending auth to RADIUS server, just authentication, no ip assigning
};

struct Tstats
{
    time_t	start_time;
    time_t	last_reset;

    uint32_t	tun_rx_packets;
    uint32_t	tun_tx_packets;
    uint32_t	tun_rx_bytes;
    uint32_t	tun_tx_bytes;
    uint32_t	tun_rx_errors;
    uint32_t	tun_tx_errors;
    uint32_t	tun_rx_dropped;

    uint32_t	tunnel_rx_packets;
    uint32_t	tunnel_tx_packets;
    uint32_t	tunnel_rx_bytes;
    uint32_t	tunnel_tx_bytes;
    uint32_t	tunnel_rx_errors;
    uint32_t	tunnel_tx_errors;

    uint32_t	tunnel_retries;
    uint32_t	radius_retries;

    uint32_t	arp_sent;

    uint32_t	packets_snooped;

    uint32_t	tunnel_created;
    uint32_t	session_created;
    uint32_t	tunnel_timeout;
    uint32_t	session_timeout;
    uint32_t	radius_timeout;
    uint32_t	radius_overflow;
    uint32_t	tunnel_overflow;
    uint32_t	session_overflow;

    uint32_t	ip_allocated;
    uint32_t	ip_freed;

    uint32_t	c_forwarded;
    uint32_t	recv_forward;

    uint32_t	select_called;
    uint32_t	multi_read_used;
    uint32_t	multi_read_exceeded;

#ifdef STATISTICS
    uint32_t	call_processtun;
    uint32_t	call_processipout;
    uint32_t	call_processipv6out;
    uint32_t	call_processudp;
    uint32_t	call_sessionbyip;
    uint32_t	call_sessionbyipv6;
    uint32_t	call_sessionbyuser;
    uint32_t	call_sendarp;
    uint32_t	call_sendipcp;
    uint32_t	call_sendipv6cp;
    uint32_t	call_processipv6cp;
    uint32_t	call_tunnelsend;
    uint32_t	call_sessionkill;
    uint32_t	call_sessionshutdown;
    uint32_t	call_tunnelkill;
    uint32_t	call_tunnelshutdown;
    uint32_t	call_assign_ip_address;
    uint32_t	call_free_ip_address;
    uint32_t	call_dump_acct_info;
    uint32_t	call_sessionsetup;
    uint32_t	call_processpap;
    uint32_t	call_processchap;
    uint32_t	call_processlcp;
    uint32_t	call_processipcp;
    uint32_t	call_processipin;
    uint32_t	call_processipv6in;
    uint32_t	call_processccp;
    uint32_t	call_sendchap;
    uint32_t	call_processrad;
    uint32_t	call_radiussend;
    uint32_t	call_radiusretry;
    uint32_t    call_random_data;
#endif
};

#ifdef STATISTICS

#ifdef STAT_CALLS
#define CSTAT(x)	STAT(call_ ## x)
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
	int		multi_read_count;		// amount of packets to read per fd in processing loop

	char		tundevice[10];			// tun device name
	char		log_filename[128];

	char		l2tp_secret[64];		// L2TP shared secret
	int		l2tp_mtu;			// MTU of interface used for L2TP

	char		random_device[256];		// random device path, defaults to RANDOMDEVICE

	int		ppp_restart_time;		// timeout for PPP restart
	int		ppp_max_configure;		// max lcp configure requests to send
	int		ppp_max_failure;		// max lcp configure naks to send

	char		radiussecret[64];
	int		radius_accounting;
	int		radius_interim;
	in_addr_t	radiusserver[MAXRADSERVER];	// radius servers
	uint16_t	radiusport[MAXRADSERVER];	// radius base ports
	uint8_t		numradiusservers;		// radius server count

	uint16_t	radius_dae_port;		// port for radius DAE
	uint16_t	radius_bind_min;		// port range for udp sockets used to send/recv radius packets
	uint16_t	radius_bind_max;

	char		radius_authtypes_s[32];		// list of valid authentication types (chap, pap) in order of preference
	int		radius_authtypes;
	int		radius_authprefer;

	int		allow_duplicate_users;		// allow multiple logins with the same username
	int		kill_timedout_sessions;		// kill authenticated sessions with "session_timeout == 0"

	in_addr_t	default_dns1, default_dns2;

	unsigned long	rl_rate;			// default throttle rate
	int		num_tbfs;			// number of throttle buckets

	char		accounting_dir[128];
	in_addr_t	bind_address;
	in_addr_t	peer_address;
	int		send_garp;			// Set to true to garp for vip address on startup

	int		dump_speed;
	char		plugins[64][MAXPLUGINS];
	char		old_plugins[64][MAXPLUGINS];

	int		next_tbf;			// Next HTB id available to use
	int		scheduler_fifo;			// If the system has multiple CPUs, use FIFO scheduling
							// policy for this process.
	int		lock_pages;			// Lock pages into memory.
	int		icmp_rate;			// Max number of ICMP unreachable per second to send
	int		max_packets;			// DoS prevention: per session limit of packets/0.1s
	char		epdis_addr[20];			// MP Endpoint Discriminator address

	in_addr_t	cluster_address;		// Multicast address of cluster.
							// Send to this address to have everyone hear.
	char		cluster_interface[64];		// Which interface to listen for multicast on.
	int		cluster_iam_master;		// Are we the cluster master???
	int		cluster_iam_uptodate;		// Set if we've got a full set of state from the master.
	in_addr_t	cluster_master_address;		// The network address of the cluster master.
							// Zero if i am the cluster master.
	int		cluster_seq_number;		// Sequence number of the next heartbeat we'll send out
							// (or the seq number we're next expecting if we're a slave).
	int		cluster_undefined_sessions;	// How many sessions we're yet to receive from the master.
	int		cluster_undefined_bundles;	// How many bundles we're yet to receive from the master.
	int		cluster_undefined_tunnels;	// How many tunnels we're yet to receive from the master.
	int		cluster_highest_sessionid;
	int		cluster_highest_bundleid;
	int		cluster_highest_tunnelid;
	clockt		cluster_last_hb;		// Last time we saw a heartbeat from the master.
	int		cluster_last_hb_ver;		// Heartbeat version last seen from master
	int		cluster_num_changes;		// Number of changes queued.

	int		cluster_mcast_ttl;		// TTL for multicast packets
	int		cluster_hb_interval;		// How often to send a heartbeat.
	int		cluster_hb_timeout;		// How many missed heartbeats trigger an election.
	uint64_t	cluster_table_version;		// # state changes processed by cluster

	struct in6_addr ipv6_prefix;			// Our IPv6 network pool.


	int		cluster_master_min_adv;		// Master advertises routes while the number of up to date
							// slaves is less than this value.
	// Guest change
	char            guest_user[MAXUSER];            // Guest account username

#ifdef BGP
#define BGP_NUM_PEERS	2
	uint16_t as_number;
	struct {
		char name[64];
	    	uint16_t as;
		int keepalive;
		int hold;
	} neighbour[BGP_NUM_PEERS];
#endif
} configt;

enum config_typet { INT, STRING, UNSIGNED_LONG, SHORT, BOOL, IPv4, IPv6 };
typedef struct
{
	char *key;
	int offset;
	int size;
	enum config_typet type;
} config_descriptt;

typedef struct
{
	uint8_t op;	// operation
#define FILTER_PORT_OP_NONE	0 // all ports match
#define FILTER_PORT_OP_EQ	1
#define FILTER_PORT_OP_NEQ	2
#define FILTER_PORT_OP_GT	3
#define FILTER_PORT_OP_LT	4
#define FILTER_PORT_OP_RANGE	5
	uint16_t port;	// port (host byte order)
	uint16_t port2;	// range
} ip_filter_portt;

typedef struct
{
	int action;		// permit/deny
#define FILTER_ACTION_DENY	1
#define FILTER_ACTION_PERMIT	2
	uint8_t proto;		// protocol: IPPROTO_* (netinet/in.h)
	in_addr_t src_ip;	// source ip (network byte order)
	in_addr_t src_wild;
	ip_filter_portt src_ports;
	in_addr_t dst_ip;	// dest ip
	in_addr_t dst_wild;
	ip_filter_portt dst_ports;
	uint8_t frag;		// apply to non-initial fragments
	uint8_t tcp_flag_op;	// match type: any, all, established
#define FILTER_FLAG_OP_ANY	1
#define FILTER_FLAG_OP_ALL	2
#define FILTER_FLAG_OP_EST	3
	uint8_t tcp_sflags;	// flags set
	uint8_t tcp_cflags;	// flags clear
	uint32_t counter;	// match count
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

// CDN result/error codes
#define CDN_NONE			0, 0
#define CDN_TRY_ANOTHER			2, 7
#define CDN_ADMIN_DISC			3, 0
#define CDN_UNAVAILABLE			4, 0

// RADIUS Acct-Terminate-Cause values
#define TERM_USER_REQUEST		1
#define TERM_LOST_CARRIER		2
#define TERM_LOST_SERVICE		3
#define TERM_IDLE_TIMEOUT		4
#define TERM_SESSION_TIMEOUT		5
#define TERM_ADMIN_RESET		6
#define TERM_ADMIN_REBOOT		7
#define TERM_PORT_ERROR			8
#define TERM_NAS_ERROR			9
#define TERM_NAS_REQUEST		10
#define TERM_NAS_REBOOT			11
#define TERM_PORT_UNNEEDED		12
#define TERM_PORT_PREEMPTED		13
#define TERM_PORT_SUSPENDED		14
#define TERM_SERVICE_UNAVAILABLE	15
#define TERM_CALLBACK			16
#define TERM_USER_ERROR			17
#define TERM_HOST_REQUEST		18
#define TERM_SUPPLICANT_RESTART		19
#define TERM_REAUTHENTICATION_FAILURE	20
#define TERM_PORT_REINIT		21
#define TERM_PORT_DISABLED		22

// arp.c
void sendarp(int ifr_idx, const unsigned char* mac, in_addr_t ip);


// ppp.c
void processpap(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l);
void processchap(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l);
void lcp_open(sessionidt s, tunnelidt t);
void processlcp(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l);
void processipcp(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l);
void processipv6cp(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l);
void processipin(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l);
void processmpin(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l);
void processmpframe(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l, uint8_t extra);
void processipv6in(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l);
void processccp(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l);
void sendchap(sessionidt s, tunnelidt t);
uint8_t *makeppp(uint8_t *b, int size, uint8_t *p, int l, sessionidt s, tunnelidt t, uint16_t mtype, uint8_t prio, bundleidt bid, uint8_t mp_bits);
void sendlcp(sessionidt s, tunnelidt t);
void send_ipin(sessionidt s, uint8_t *buf, int len);
void sendccp(sessionidt s, tunnelidt t);
void protoreject(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l, uint16_t proto);
int join_bundle(sessionidt s);


// radius.c
void initrad(void);
void radiussend(uint16_t r, uint8_t state);
void processrad(uint8_t *buf, int len, char socket_index);
void radiusretry(uint16_t r);
uint16_t radiusnew(sessionidt s);
void radiusclear(uint16_t r, sessionidt s);
void processdae(uint8_t *buf, int len, struct sockaddr_in *addr, int alen, struct in_addr *local);


// l2tpns.c
clockt backoff(uint8_t try);
void send_ipv6_ra(sessionidt s, tunnelidt t, struct in6_addr *ip);
void route6set(sessionidt s, struct in6_addr ip, int prefixlen, int add);
sessionidt sessionbyip(in_addr_t ip);
sessionidt sessionbyipv6(struct in6_addr ip);
sessionidt sessionbyuser(char *username);
void increment_counter(uint32_t *counter, uint32_t *wrap, uint32_t delta);
void random_data(uint8_t *buf, int len);
void sessionkill(sessionidt s, char *reason);
void sessionshutdown(sessionidt s, char const *reason, int cdn_result, int cdn_error, int term_cause);
void filter_session(sessionidt s, int filter_in, int filter_out);
void send_garp(in_addr_t ip);
void tunnelsend(uint8_t *buf, uint16_t l, tunnelidt t);
int tun_write(uint8_t *data, int size);
void adjust_tcp_mss(sessionidt s, tunnelidt t, uint8_t *buf, int len, uint8_t *tcp);
void sendipcp(sessionidt s, tunnelidt t);
void sendipv6cp(sessionidt s, tunnelidt t);
void processudp(uint8_t *buf, int len, struct sockaddr_in *addr);
void snoop_send_packet(uint8_t *packet, uint16_t size, in_addr_t destination, uint16_t port);
int find_filter(char const *name, size_t len);
int ip_filter(uint8_t *buf, int len, uint8_t filter);
int cmd_show_ipcache(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_hist_idle(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_hist_open(struct cli_def *cli, char *command, char **argv, int argc);

#undef LOG
#undef LOG_HEX
#define LOG(D, s, t, f, ...)	({ if (D <= config->debug) _log(D, s, t, f, ## __VA_ARGS__); })
#define LOG_HEX(D, t, d, s)	({ if (D <= config->debug) _log_hex(D, t, d, s); })

void _log(int level, sessionidt s, tunnelidt t, const char *format, ...) __attribute__((format (printf, 4, 5)));
void _log_hex(int level, const char *title, const uint8_t *data, int maxsize);


int sessionsetup(sessionidt s, tunnelidt t);
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
void host_unreachable(in_addr_t destination, uint16_t id, in_addr_t source, uint8_t *packet, int packet_len);


extern tunnelt *tunnel;
extern bundlet *bundle;
extern sessiont *session;
extern sessionlocalt *sess_local;
extern ippoolt *ip_address_pool;
#define sessionfree (session[0].next)


extern configt *config;
extern time_t basetime;		// Time when this process started.
extern time_t time_now;		// Seconds since EPOCH.
extern char main_quit;
extern uint32_t last_id;
extern struct Tstats *_statistics;
extern in_addr_t my_address;
extern int clifd;
extern int epollfd;

struct event_data {
	enum {
	    	FD_TYPE_CLI,
	    	FD_TYPE_CLUSTER,
	    	FD_TYPE_TUN,
	    	FD_TYPE_UDP,
	    	FD_TYPE_CONTROL,
	    	FD_TYPE_DAE,
		FD_TYPE_RADIUS,
		FD_TYPE_BGP,
	} type;
	int index; // for RADIUS, BGP
};

#define TIME (config->current_time)

extern uint16_t MRU;
extern uint16_t MSS;

// macros for handling help in cli commands
#define CLI_HELP_REQUESTED	(argc > 0 && argv[argc-1][strlen(argv[argc-1])-1] == '?')
#define CLI_HELP_NO_ARGS	(argc > 1 || argv[0][1]) ? CLI_OK : cli_arg_help(cli, 1, NULL)

#endif /* __L2TPNS_H__ */
