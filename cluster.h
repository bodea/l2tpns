// L2TPNS Clustering Stuff
// $Id: cluster.h,v 1.4 2004-07-07 09:09:53 bodea Exp $

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
#define C_BYTES                 10      // Update byte counters.
#define C_THROTTLE		11	// A packet for the master to throttle. (The TBF tells direction).
#define C_CSESSION		12	// Compressed session structure.
#define C_CTUNNEL		13	// Compressed tunnel structure.
#define C_GARDEN		14	// Gardened packet

#define HB_VERSION		3	// Protocol version number..
#define HB_MAX_SEQ		(1<<30)	// Maximum sequence number. (MUST BE A POWER OF 2!)
#define HB_HISTORY_SIZE		64	// How many old heartbeats we remember?? (Must be a factor of HB_MAX_SEQ)

#define PING_INTERVAL		5	// 0.5 seconds. Needs to be short to keep session tables fresh.
#define HB_TIMEOUT		(15*2*PING_INTERVAL) // 15 seconds without heartbeat triggers an election..

#define CLUSTERPORT		32792
#define CLUSTER_MAX_SIZE	32	// No more than 32 machines in a cluster!

#define DEFAULT_MCAST_ADDR	"239.192.13.13"		// Need an assigned number!
#define DEFAULT_MCAST_INTERFACE	"eth0"

typedef struct {
	u32	version;	// protocol version.
	u32	seq;		// Sequence number for this heatbeat.
	u32	basetime;	// What time I started
	u32	clusterid;	// Id for this cluster?

	u32	highsession;	// Id of the highest in-use session.
	u32	freesession;	// Id of the first free session.
	u32	hightunnel;	// Id of the highest used tunnel.
	u32	size_sess;	// Size of the session structure.

	u32	size_tunn;	// size of the tunnel structure.
	u32	interval;	// ping/heartbeat interval (if changed)
	u32	timeout;	// heartbeat timeout (if changed)

	char reserved[128 - 11*sizeof(u32)];	// Pad out to 128 bytes.
} heartt;

typedef struct {		/* Used to update byte counters on the */
				/* master. */
	u32        sid;
	u32        in;
	u32        out;
} bytest;

typedef struct {
	u32	addr;		//
	u32	ver;		// version of structure.
	u32	undef;		// Number of undefined structures. 0 if up-to-date.
	u32	basetime;	// start time of this peer.
} pingt;

int cluster_init();
int processcluster(char *buf, int size, u32 addr);
int cluster_forward_packet(char *buf, int size, u32 addr);
int cluster_send_session(int sid);
int cluster_send_tunnel(int tid);
int master_forward_packet(char * data, int size, u32 addr, int port);
int master_throttle_packet(int tid, char * data, int size);
int master_garden_packet(sessionidt s, char * data, int size);
void master_update_counts(void);

void cluster_send_ping(time_t basetime);
void cluster_heartbeat(void);
void cluster_check_master(void);
int show_cluster(struct cli_def *cli, char *command, char **argv, int argc);

#endif /* __CLUSTER_H__ */
