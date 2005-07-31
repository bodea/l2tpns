// L2TPNS Clustering Stuff
// $Id: cluster.h,v 1.14 2005-07-31 10:04:10 bodea Exp $

#ifndef __CLUSTER_H__
#define __CLUSTER_H__


#define C_HEARTBEAT		1
#define C_ACK			2
#define C_PING			3
#define C_TUNNEL		4	// Tunnel structure.
#define C_SESSION		5	// Session structure.
#define C_GOODBYE		6
#define C_LASTSEEN		7	// Tell master the last heartbeat that I handled.
#define C_KILL			8	// Tell a slave to die.
#define C_FORWARD		9	// Forwarded packet..
#define C_BYTES			10	// Update byte counters.
#define C_THROTTLE		11	// A packet for the master to throttle. (The TBF tells direction).
#define C_CSESSION		12	// Compressed session structure.
#define C_CTUNNEL		13	// Compressed tunnel structure.
#define C_GARDEN		14	// Gardened packet
#define C_MASTER		15	// Tell a slave the address of the master.
#define C_FORWARD_DAE		16	// A DAE packet for the master to handle

#define HB_VERSION		5	// Protocol version number..
#define HB_MAX_SEQ		(1<<30)	// Maximum sequence number. (MUST BE A POWER OF 2!)
#define HB_HISTORY_SIZE		64	// How many old heartbeats we remember?? (Must be a factor of HB_MAX_SEQ)

#define PING_INTERVAL		5	// 0.5 seconds. Needs to be short to keep session tables fresh.
#define HB_TIMEOUT		(15*2*PING_INTERVAL) // 15 seconds without heartbeat triggers an election..

#define CLUSTERPORT		32792
#define CLUSTER_MAX_SIZE	32	// No more than 32 machines in a cluster!

#define DEFAULT_MCAST_ADDR	"239.192.13.13"		// Need an assigned number!
#define DEFAULT_MCAST_INTERFACE	"eth0"

typedef struct {
	uint32_t version;	// protocol version.
	uint32_t seq;		// Sequence number for this heatbeat.
	uint32_t basetime;	// What time I started
	uint32_t clusterid;	// Id for this cluster?

	uint32_t highsession;	// Id of the highest in-use session.
	uint32_t freesession;	// Id of the first free session.
	uint32_t hightunnel;	// Id of the highest used tunnel.
	uint32_t size_sess;	// Size of the session structure.

	uint32_t size_tunn;	// size of the tunnel structure.
	uint32_t interval;	// ping/heartbeat interval
	uint32_t timeout;	// heartbeat timeout

	uint64_t table_version;	// # state changes processed by cluster

	char reserved[128 - 13*sizeof(uint32_t)];	// Pad out to 128 bytes.
} heartt;

typedef struct {		/* Used to update byte counters on the */
				/* master. */
	uint32_t sid;
	uint32_t pin;
	uint32_t pout;
	uint32_t cin;
	uint32_t cout;
} bytest;

typedef struct {
	in_addr_t addr;		// peer address
	uint32_t ver;		// version of structure.
	uint32_t undef;		// Number of undefined structures. 0 if up-to-date.
	uint32_t basetime;	// start time of this peer.
} pingt;

int cluster_init(void);
int processcluster(uint8_t *buf, int size, in_addr_t addr);
int cluster_send_session(int sid);
int cluster_send_tunnel(int tid);
int master_forward_packet(uint8_t *data, int size, in_addr_t addr, int port);
int master_forward_dae_packet(uint8_t *data, int size, in_addr_t addr, int port);
int master_throttle_packet(int tid, uint8_t *data, int size);
int master_garden_packet(sessionidt s, uint8_t *data, int size);
void master_update_counts(void);
void cluster_send_ping(time_t basetime);
void cluster_heartbeat(void);
void cluster_check_master(void);
void cluster_check_slaves(void);
int cmd_show_cluster(struct cli_def *cli, char *command, char **argv, int argc);

#endif /* __CLUSTER_H__ */
