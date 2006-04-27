// L2TPNS Clustering Stuff

char const *cvs_id_cluster = "$Id: cluster.c,v 1.51 2006-04-27 09:53:49 bodea Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <libcli.h>

#include "l2tpns.h"
#include "cluster.h"
#include "util.h"
#include "tbf.h"

#ifdef BGP
#include "bgp.h"
#endif
/*
 * All cluster packets have the same format.
 *
 * One or more instances of
 *	a 32 bit 'type' id.
 *	a 32 bit 'extra' data dependant on the 'type'.
 *	zero or more bytes of structure data, dependant on the type.
 *
 */

// Module variables.
extern int cluster_sockfd;		// The filedescriptor for the cluster communications port.

in_addr_t my_address = 0;		// The network address of my ethernet port.
static int walk_session_number = 0;	// The next session to send when doing the slow table walk.
static int walk_bundle_number = 0;	// The next bundle to send when doing the slow table walk.
static int walk_tunnel_number = 0;	// The next tunnel to send when doing the slow table walk.
int forked = 0;				// Sanity check: CLI must not diddle with heartbeat table

#define MAX_HEART_SIZE (8192)	// Maximum size of heartbeat packet. Must be less than max IP packet size :)
#define MAX_CHANGES  (MAX_HEART_SIZE/(sizeof(sessiont) + sizeof(int) ) - 2)	// Assumes a session is the biggest type!

static struct {
	int type;
	int id;
} cluster_changes[MAX_CHANGES];	// Queue of changed structures that need to go out when next heartbeat.

static struct {
	int seq;
	int size;
	uint8_t data[MAX_HEART_SIZE];
} past_hearts[HB_HISTORY_SIZE];	// Ring buffer of heartbeats that we've recently sent out. Needed so
				// we can re-transmit if needed.

static struct {
	in_addr_t peer;
	uint32_t basetime;
	clockt timestamp;
	int uptodate;
} peers[CLUSTER_MAX_SIZE];	// List of all the peers we've heard from.
static int num_peers;		// Number of peers in list.

static int rle_decompress(uint8_t **src_p, int ssize, uint8_t *dst, int dsize);
static int rle_compress(uint8_t **src_p, int ssize, uint8_t *dst, int dsize);

//
// Create a listening socket
//
// This joins the cluster multi-cast group.
//
int cluster_init()
{
	struct sockaddr_in addr;
	struct sockaddr_in interface_addr;
	struct ip_mreq mreq;
	struct ifreq   ifr;
	int opt;

	config->cluster_undefined_sessions = MAXSESSION-1;
	config->cluster_undefined_bundles = MAXBUNDLE-1;
	config->cluster_undefined_tunnels = MAXTUNNEL-1;

	if (!config->cluster_address)
		return 0;
	if (!*config->cluster_interface)
		return 0;

	cluster_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(CLUSTERPORT);
	addr.sin_addr.s_addr = INADDR_ANY;
	setsockopt(cluster_sockfd, SOL_SOCKET, SO_REUSEADDR, &addr, sizeof(addr));

	opt = fcntl(cluster_sockfd, F_GETFL, 0);
	fcntl(cluster_sockfd, F_SETFL, opt | O_NONBLOCK);

	if (bind(cluster_sockfd, (void *) &addr, sizeof(addr)) < 0)
	{
		LOG(0, 0, 0, "Failed to bind cluster socket: %s\n", strerror(errno));
		return -1;
	}

	strcpy(ifr.ifr_name, config->cluster_interface);
	if (ioctl(cluster_sockfd, SIOCGIFADDR, &ifr) < 0)
	{
		LOG(0, 0, 0, "Failed to get interface address for (%s): %s\n", config->cluster_interface, strerror(errno));
		return -1;
	}

	memcpy(&interface_addr, &ifr.ifr_addr, sizeof(interface_addr));
	my_address = interface_addr.sin_addr.s_addr;

	// Join multicast group.
	mreq.imr_multiaddr.s_addr = config->cluster_address;
	mreq.imr_interface = interface_addr.sin_addr;


	opt = 0;	// Turn off multicast loopback.
	setsockopt(cluster_sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &opt, sizeof(opt));

	if (config->cluster_mcast_ttl != 1)
	{
		uint8_t ttl = 0;
		if (config->cluster_mcast_ttl > 0)
			ttl = config->cluster_mcast_ttl < 256 ? config->cluster_mcast_ttl : 255;

		setsockopt(cluster_sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
	}

	if (setsockopt(cluster_sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
	{
		LOG(0, 0, 0, "Failed to setsockopt (join mcast group): %s\n", strerror(errno));
		return -1;
	}

	if (setsockopt(cluster_sockfd, IPPROTO_IP, IP_MULTICAST_IF, &interface_addr, sizeof(interface_addr)) < 0)
	{
		LOG(0, 0, 0, "Failed to setsockopt (set mcast interface): %s\n", strerror(errno));
		return -1;
	}

	config->cluster_last_hb = TIME;
	config->cluster_seq_number = -1;

	return cluster_sockfd;
}


//
// Send a chunk of data to the entire cluster (usually via the multicast
// address ).
//

static int cluster_send_data(void *data, int datalen)
{
	struct sockaddr_in addr = {0};

	if (!cluster_sockfd) return -1;
	if (!config->cluster_address) return 0;

	addr.sin_addr.s_addr = config->cluster_address;
	addr.sin_port = htons(CLUSTERPORT);
	addr.sin_family = AF_INET;

	LOG(5, 0, 0, "Cluster send data: %d bytes\n", datalen);

	if (sendto(cluster_sockfd, data, datalen, MSG_NOSIGNAL, (void *) &addr, sizeof(addr)) < 0)
	{
		LOG(0, 0, 0, "sendto: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

//
// Add a chunk of data to a heartbeat packet.
// Maintains the format. Assumes that the caller
// has passed in a big enough buffer!
//
static void add_type(uint8_t **p, int type, int more, uint8_t *data, int size)
{
	*((uint32_t *) (*p)) = type;
	*p += sizeof(uint32_t);

	*((uint32_t *)(*p)) = more;
	*p += sizeof(uint32_t);

	if (data && size > 0) {
		memcpy(*p, data, size);
		*p += size;
	}
}

// advertise our presence via BGP or gratuitous ARP
static void advertise_routes(void)
{
#ifdef BGP
	if (bgp_configured)
		bgp_enable_routing(1);
	else
#endif /* BGP */
		if (config->send_garp)
			send_garp(config->bind_address);	// Start taking traffic.
}

// withdraw our routes (BGP only)
static void withdraw_routes(void)
{
#ifdef BGP
	if (bgp_configured)
		bgp_enable_routing(0);
#endif /* BGP */
}

static void cluster_uptodate(void)
{
	if (config->cluster_iam_uptodate)
		return;

	if (config->cluster_undefined_sessions || config->cluster_undefined_tunnels || config->cluster_undefined_bundles)
		return;

	config->cluster_iam_uptodate = 1;

	LOG(0, 0, 0, "Now uptodate with master.\n");
	advertise_routes();
}

//
// Send a unicast UDP packet to a peer with 'data' as the
// contents.
//
static int peer_send_data(in_addr_t peer, uint8_t *data, int size)
{
	struct sockaddr_in addr = {0};

	if (!cluster_sockfd) return -1;
	if (!config->cluster_address) return 0;

	if (!peer)	// Odd??
		return -1;

	addr.sin_addr.s_addr = peer;
	addr.sin_port = htons(CLUSTERPORT);
	addr.sin_family = AF_INET;

	LOG_HEX(5, "Peer send", data, size);

	if (sendto(cluster_sockfd, data, size, MSG_NOSIGNAL, (void *) &addr, sizeof(addr)) < 0)
	{
		LOG(0, 0, 0, "sendto: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

//
// Send a structured message to a peer with a single element of type 'type'.
//
static int peer_send_message(in_addr_t peer, int type, int more, uint8_t *data, int size)
{
	uint8_t buf[65536];	// Vast overkill.
	uint8_t *p = buf;

	LOG(4, 0, 0, "Sending message to peer (type %d, more %d, size %d)\n", type, more, size);
	add_type(&p, type, more, data, size);

	return peer_send_data(peer, buf, (p-buf) );
}

// send a packet to the master
static int _forward_packet(uint8_t *data, int size, in_addr_t addr, int port, int type)
{
	uint8_t buf[65536];	// Vast overkill.
	uint8_t *p = buf;

	if (!config->cluster_master_address) // No election has been held yet. Just skip it.
		return -1;

	LOG(4, 0, 0, "Forwarding packet from %s to master (size %d)\n", fmtaddr(addr, 0), size);

	STAT(c_forwarded);
	add_type(&p, type, addr, (uint8_t *) &port, sizeof(port)); // ick. should be uint16_t
	memcpy(p, data, size);
	p += size;

	return peer_send_data(config->cluster_master_address, buf, (p - buf));
}

// 
// Forward a state changing packet to the master.
//
// The master just processes the payload as if it had
// received it off the tun device.
//
int master_forward_packet(uint8_t *data, int size, in_addr_t addr, int port)
{
	return _forward_packet(data, size, addr, port, C_FORWARD);
}

// Forward a DAE RADIUS packet to the master.
int master_forward_dae_packet(uint8_t *data, int size, in_addr_t addr, int port)
{
	return _forward_packet(data, size, addr, port, C_FORWARD_DAE);
}

//
// Forward a throttled packet to the master for handling.
//
// The master just drops the packet into the appropriate
// token bucket queue, and lets normal processing take care
// of it.
//
int master_throttle_packet(int tbfid, uint8_t *data, int size)
{
	uint8_t buf[65536];	// Vast overkill.
	uint8_t *p = buf;

	if (!config->cluster_master_address) // No election has been held yet. Just skip it.
		return -1;

	LOG(4, 0, 0, "Throttling packet master (size %d, tbfid %d)\n", size, tbfid);

	add_type(&p, C_THROTTLE, tbfid, data, size);

	return peer_send_data(config->cluster_master_address, buf, (p-buf) );

}

//
// Forward a walled garden packet to the master for handling.
//
// The master just writes the packet straight to the tun
// device (where is will normally loop through the
// firewall rules, and come back in on the tun device)
//
// (Note that this must be called with the tun header
// as the start of the data).
int master_garden_packet(sessionidt s, uint8_t *data, int size)
{
	uint8_t buf[65536];	// Vast overkill.
	uint8_t *p = buf;

	if (!config->cluster_master_address) // No election has been held yet. Just skip it.
		return -1;

	LOG(4, 0, 0, "Walled garden packet to master (size %d)\n", size);

	add_type(&p, C_GARDEN, s, data, size);

	return peer_send_data(config->cluster_master_address, buf, (p-buf));

}

//
// Send a chunk of data as a heartbeat..
// We save it in the history buffer as we do so.
//
static void send_heartbeat(int seq, uint8_t *data, int size)
{
	int i;

	if (size > sizeof(past_hearts[0].data))
	{
		LOG(0, 0, 0, "Tried to heartbeat something larger than the maximum packet!\n");
		kill(0, SIGTERM);
		exit(1);
	}
	i = seq % HB_HISTORY_SIZE;
	past_hearts[i].seq = seq;
	past_hearts[i].size = size;
	memcpy(&past_hearts[i].data, data, size);	// Save it.
	cluster_send_data(data, size);
}

//
// Send an 'i am alive' message to every machine in the cluster.
//
void cluster_send_ping(time_t basetime)
{
	uint8_t buff[100 + sizeof(pingt)];
	uint8_t *p = buff;
	pingt x;

	if (config->cluster_iam_master && basetime)		// We're heartbeating so no need to ping.
		return;

	LOG(5, 0, 0, "Sending cluster ping...\n");

	x.ver = 1;
	x.addr = config->bind_address;
	x.undef = config->cluster_undefined_sessions + config->cluster_undefined_tunnels;
	x.basetime = basetime;

	add_type(&p, C_PING, basetime, (uint8_t *) &x, sizeof(x));
	cluster_send_data(buff, (p-buff) );
}

//
// Walk the session counters looking for non-zero ones to send
// to the master. We send up to 600 of them at one time.
// We examine a maximum of 3000 sessions.
// (50k max session should mean that we normally
// examine the entire session table every 25 seconds).

#define MAX_B_RECS (600)
void master_update_counts(void)
{
	int i, c;
	bytest b[MAX_B_RECS+1];

	if (config->cluster_iam_master)		// Only happens on the slaves.
		return;

	if (!config->cluster_master_address)	// If we don't have a master, skip it for a while.
		return;

	// C_BYTES format changed in 2.1.0 (cluster version 5)
	// during upgrade from previous versions, hang onto our counters
	// for a bit until the new master comes up
	if (config->cluster_last_hb_ver < 5)
		return;

	i = MAX_B_RECS * 5; // Examine max 3000 sessions;
	if (config->cluster_highest_sessionid > i)
		i = config->cluster_highest_sessionid;

	for ( c = 0; i > 0 ; --i) {
			// Next session to look at.
		walk_session_number++;
		if ( walk_session_number > config->cluster_highest_sessionid)
			walk_session_number = 1;

		if (!sess_local[walk_session_number].cin && !sess_local[walk_session_number].cout)
			continue; // Unchanged. Skip it.

		b[c].sid = walk_session_number;
		b[c].pin = sess_local[walk_session_number].pin;
		b[c].pout = sess_local[walk_session_number].pout;
		b[c].cin = sess_local[walk_session_number].cin;
		b[c].cout = sess_local[walk_session_number].cout;

			// Reset counters.
		sess_local[walk_session_number].pin = sess_local[walk_session_number].pout = 0;
		sess_local[walk_session_number].cin = sess_local[walk_session_number].cout = 0;

		if (++c > MAX_B_RECS)	// Send a max of 600 elements in a packet.
			break;
	}

	if (!c)		// Didn't find any that changes. Get out of here!
		return;


			// Forward the data to the master.
	LOG(4, 0, 0, "Sending byte counters to master (%d elements)\n", c);
	peer_send_message(config->cluster_master_address, C_BYTES, c, (uint8_t *) &b, sizeof(b[0]) * c);
	return;
}

//
// On the master, check how our slaves are going. If
// one of them's not up-to-date we'll heartbeat faster.
// If we don't have any of them, then we need to turn
// on our own packet handling!
//
void cluster_check_slaves(void)
{
	int i;
	static int have_peers = 0;
	int had_peers = have_peers;
	clockt t = TIME;

	if (!config->cluster_iam_master)
		return;		// Only runs on the master...

	config->cluster_iam_uptodate = 1;	// cleared in loop below

	for (i = have_peers = 0; i < num_peers; i++)
	{
		if ((peers[i].timestamp + config->cluster_hb_timeout) < t)
			continue;	// Stale peer! Skip them.

		if (!peers[i].basetime)
			continue;	// Shutdown peer! Skip them.

		if (peers[i].uptodate)
			have_peers++;
		else
			config->cluster_iam_uptodate = 0; // Start fast heartbeats
	}

	// in a cluster, withdraw/add routes when we get a peer/lose peers
	if (have_peers != had_peers)
	{
		if (had_peers < config->cluster_master_min_adv &&
		    have_peers >= config->cluster_master_min_adv)
			withdraw_routes();

		else if (had_peers >= config->cluster_master_min_adv &&
		    have_peers < config->cluster_master_min_adv)
			advertise_routes();
	}
}

//
// Check that we have a master. If it's been too
// long since we heard from a master then hold an election.
//
void cluster_check_master(void)
{
	int i, count, tcount, bcount, high_unique_id = 0;
	int last_free = 0;
	clockt t = TIME;
	static int probed = 0;
	int have_peers;

	if (config->cluster_iam_master)
		return;		// Only runs on the slaves...

	// If the master is late (missed 2 hearbeats by a second and a
	// hair) it may be that the switch has dropped us from the
	// multicast group, try unicasting probes to the master
	// which will hopefully respond with a unicast heartbeat that
	// will allow us to limp along until the querier next runs.
	if (config->cluster_master_address
	    && TIME > (config->cluster_last_hb + 2 * config->cluster_hb_interval + 11))
	{
		if (!probed || (TIME > (probed + 2 * config->cluster_hb_interval)))
		{
			probed = TIME;
			LOG(1, 0, 0, "Heartbeat from master %.1fs late, probing...\n",
				0.1 * (TIME - (config->cluster_last_hb + config->cluster_hb_interval)));

			peer_send_message(config->cluster_master_address,
				C_LASTSEEN, config->cluster_seq_number, NULL, 0);
		}
	} else {	// We got a recent heartbeat; reset the probe flag.
		probed = 0;
	}

	if (TIME < (config->cluster_last_hb + config->cluster_hb_timeout))
		return;	// Everything's ok!

	config->cluster_last_hb = TIME + 1;	// Just the one election thanks.
	config->cluster_master_address = 0;

	LOG(0, 0, 0, "Master timed out! Holding election...\n");

	// In the process of shutting down, can't be master
	if (main_quit)
		return;

	for (i = have_peers = 0; i < num_peers; i++)
	{
		if ((peers[i].timestamp + config->cluster_hb_timeout) < t)
			continue;	// Stale peer! Skip them.

		if (!peers[i].basetime)
			continue;	// Shutdown peer! Skip them.

		if (peers[i].basetime < basetime) {
			LOG(1, 0, 0, "Expecting %s to become master\n", fmtaddr(peers[i].peer, 0));
			return;		// They'll win the election. Get out of here.
		}

		if (peers[i].basetime == basetime &&
			peers[i].peer > my_address) {
			LOG(1, 0, 0, "Expecting %s to become master\n", fmtaddr(peers[i].peer, 0));
			return;		// They'll win the election. Wait for them to come up.
		}

		if (peers[i].uptodate)
			have_peers++;
	}

		// Wow. it's been ages since I last heard a heartbeat
		// and I'm better than an of my peers so it's time
		// to become a master!!!

	config->cluster_iam_master = 1;

	LOG(0, 0, 0, "I am declaring myself the master!\n");

	if (have_peers < config->cluster_master_min_adv)
		advertise_routes();
	else
		withdraw_routes();

	if (config->cluster_seq_number == -1)
		config->cluster_seq_number = 0;

		//
		// Go through and mark all the tunnels as defined.
		// Count the highest used tunnel number as well.
		//
	config->cluster_highest_tunnelid = 0;
	for (i = 0, tcount = 0; i < MAXTUNNEL; ++i) {
		if (tunnel[i].state == TUNNELUNDEF)
			tunnel[i].state = TUNNELFREE;

		if (tunnel[i].state != TUNNELFREE && i > config->cluster_highest_tunnelid)
			config->cluster_highest_tunnelid = i;
	}

		//
                // Go through and mark all the bundles as defined.
                // Count the highest used bundle number as well.
                //
        config->cluster_highest_bundleid = 0;
        for (i = 0, bcount = 0; i < MAXBUNDLE; ++i) {
                if (bundle[i].state == BUNDLEUNDEF)
                        bundle[i].state = BUNDLEFREE;

                if (bundle[i].state != BUNDLEFREE && i > config->cluster_highest_bundleid)
                        config->cluster_highest_bundleid = i;
        }

		//
		// Go through and mark all the sessions as being defined.
		// reset the idle timeouts.
		// add temporary byte counters to permanent ones.
		// Re-string the free list.
		// Find the ID of the highest session.
	last_free = 0;
	high_unique_id = 0;
	config->cluster_highest_sessionid = 0;
	for (i = 0, count = 0; i < MAXSESSION; ++i) {
		if (session[i].tunnel == T_UNDEF) {
			session[i].tunnel = T_FREE;
			++count;
		}

		if (!session[i].opened) { // Unused session. Add to free list.
			memset(&session[i], 0, sizeof(session[i]));
			session[i].tunnel = T_FREE;
			session[last_free].next = i;
			session[i].next = 0;
			last_free = i;
			continue;
		}

			// Reset idle timeouts..
		session[i].last_packet = time_now;

			// Reset die relative to our uptime rather than the old master's
		if (session[i].die) session[i].die = TIME;

			// Accumulate un-sent byte/packet counters.
		increment_counter(&session[i].cin, &session[i].cin_wrap, sess_local[i].cin);
		increment_counter(&session[i].cout, &session[i].cout_wrap, sess_local[i].cout);
		session[i].cin_delta += sess_local[i].cin;
		session[i].cout_delta += sess_local[i].cout;

		session[i].pin += sess_local[i].pin;
		session[i].pout += sess_local[i].pout;

		sess_local[i].cin = sess_local[i].cout = 0;
		sess_local[i].pin = sess_local[i].pout = 0;

		sess_local[i].radius = 0;	// Reset authentication as the radius blocks aren't up to date.

		if (session[i].unique_id >= high_unique_id)	// This is different to the index into the session table!!!
			high_unique_id = session[i].unique_id+1;

		session[i].tbf_in = session[i].tbf_out = 0; // Remove stale pointers from old master.
		throttle_session(i, session[i].throttle_in, session[i].throttle_out);

		config->cluster_highest_sessionid = i;
	}

	session[last_free].next = 0;	// End of chain.
	last_id = high_unique_id;	// Keep track of the highest used session ID.

	become_master();

	rebuild_address_pool();

		// If we're not the very first master, this is a big issue!
	if (count > 0)
		LOG(0, 0, 0, "Warning: Fixed %d uninitialized sessions in becoming master!\n", count);

	config->cluster_undefined_sessions = 0;
	config->cluster_undefined_bundles = 0;
	config->cluster_undefined_tunnels = 0;
	config->cluster_iam_uptodate = 1; // assume all peers are up-to-date

	// FIXME. We need to fix up the tunnel control message
	// queue here! There's a number of other variables we
	// should also update.
}


//
// Check that our session table is validly matching what the
// master has in mind.
//
// In particular, if we have too many sessions marked 'undefined'
// we fix it up here, and we ensure that the 'first free session'
// pointer is valid.
//
static void cluster_check_sessions(int highsession, int freesession_ptr, int highbundle, int hightunnel)
{
	int i;

	sessionfree = freesession_ptr;	// Keep the freesession ptr valid.

	if (config->cluster_iam_uptodate)
		return;

	if (highsession > config->cluster_undefined_sessions && highbundle > config->cluster_undefined_bundles && hightunnel > config->cluster_undefined_tunnels)
		return;

		// Clear out defined sessions, counting the number of
		// undefs remaining.
	config->cluster_undefined_sessions = 0;
	for (i = 1 ; i < MAXSESSION; ++i) {
		if (i > highsession) {
			if (session[i].tunnel == T_UNDEF) session[i].tunnel = T_FREE; // Defined.
			continue;
		}

		if (session[i].tunnel == T_UNDEF)
			++config->cluster_undefined_sessions;
	}

		// Clear out defined bundles, counting the number of
		// undefs remaining.
	config->cluster_undefined_bundles = 0;
	for (i = 1 ; i < MAXBUNDLE; ++i) {
		if (i > highbundle) {
			if (bundle[i].state == BUNDLEUNDEF) bundle[i].state = BUNDLEFREE; // Defined.
			continue;
		}

		if (bundle[i].state == BUNDLEUNDEF)
			++config->cluster_undefined_bundles;
	}

		// Clear out defined tunnels, counting the number of
		// undefs remaining.
	config->cluster_undefined_tunnels = 0;
	for (i = 1 ; i < MAXTUNNEL; ++i) {
		if (i > hightunnel) {
			if (tunnel[i].state == TUNNELUNDEF) tunnel[i].state = TUNNELFREE; // Defined.
			continue;
		}

		if (tunnel[i].state == TUNNELUNDEF)
			++config->cluster_undefined_tunnels;
	}


	if (config->cluster_undefined_sessions || config->cluster_undefined_tunnels || config->cluster_undefined_bundles) {
		LOG(2, 0, 0, "Cleared undefined sessions/bundles/tunnels. %d sess (high %d), %d bund (high %d), %d tunn (high %d)\n",
			config->cluster_undefined_sessions, highsession, config->cluster_undefined_bundles, highbundle, config->cluster_undefined_tunnels, hightunnel);
		return;
	}

		// Are we up to date?

	if (!config->cluster_iam_uptodate)
		cluster_uptodate();
}

static int hb_add_type(uint8_t **p, int type, int id)
{
	switch (type) {
		case C_CSESSION: { // Compressed C_SESSION.
			uint8_t c[sizeof(sessiont) * 2]; // Bigger than worst case.
			uint8_t *d = (uint8_t *) &session[id];
			uint8_t *orig = d;
			int size;

			size = rle_compress( &d,  sizeof(sessiont), c, sizeof(c) );

				// Did we compress the full structure, and is the size actually
				// reduced??
			if ( (d - orig) == sizeof(sessiont) && size < sizeof(sessiont) ) {
				add_type(p, C_CSESSION, id, c, size);
				break;
			}
			// Failed to compress : Fall through.
		}
		case C_SESSION:
		    	add_type(p, C_SESSION, id, (uint8_t *) &session[id], sizeof(sessiont));
			break;

		case C_CBUNDLE: { // Compressed C_BUNDLE
                        uint8_t c[sizeof(bundlet) * 2]; // Bigger than worst case.
                        uint8_t *d = (uint8_t *) &bundle[id];
                        uint8_t *orig = d;
                        int size;

                        size = rle_compress( &d,  sizeof(bundlet), c, sizeof(c) );

                                // Did we compress the full structure, and is the size actually
                                // reduced??
                        if ( (d - orig) == sizeof(bundlet) && size < sizeof(bundlet) ) {
                                add_type(p, C_CBUNDLE, id, c, size);
                                break;
                        }
                        // Failed to compress : Fall through.
                }

		case C_BUNDLE:
		    	add_type(p, C_BUNDLE, id, (uint8_t *) &bundle[id], sizeof(bundlet));
			break;

		case C_CTUNNEL: { // Compressed C_TUNNEL
			uint8_t c[sizeof(tunnelt) * 2]; // Bigger than worst case.
			uint8_t *d = (uint8_t *) &tunnel[id];
			uint8_t *orig = d;
			int size;

			size = rle_compress( &d,  sizeof(tunnelt), c, sizeof(c) );

				// Did we compress the full structure, and is the size actually
				// reduced??
			if ( (d - orig) == sizeof(tunnelt) && size < sizeof(tunnelt) ) {
				add_type(p, C_CTUNNEL, id, c, size);
				break;
			}
			// Failed to compress : Fall through.
		}
		case C_TUNNEL:
		    	add_type(p, C_TUNNEL, id, (uint8_t *) &tunnel[id], sizeof(tunnelt));
			break;
		default:
			LOG(0, 0, 0, "Found an invalid type in heart queue! (%d)\n", type);
			kill(0, SIGTERM);
			exit(1);
	}
	return 0;
}

//
// Send a heartbeat, incidently sending out any queued changes..
//
void cluster_heartbeat()
{
	int i, count = 0, tcount = 0, bcount = 0;
	uint8_t buff[MAX_HEART_SIZE + sizeof(heartt) + sizeof(int) ];
	heartt h;
	uint8_t *p = buff;

	if (!config->cluster_iam_master)	// Only the master does this.
		return;

	config->cluster_table_version += config->cluster_num_changes;

	// Fill out the heartbeat header.
	memset(&h, 0, sizeof(h));

	h.version = HB_VERSION;
	h.seq = config->cluster_seq_number;
	h.basetime = basetime;
	h.clusterid = config->bind_address;	// Will this do??
	h.basetime = basetime;
	h.highsession = config->cluster_highest_sessionid;
	h.freesession = sessionfree;
	h.hightunnel = config->cluster_highest_tunnelid;
	h.highbundle = config->cluster_highest_bundleid;
	h.size_sess = sizeof(sessiont);		// Just in case.
	h.size_bund = sizeof(bundlet);
	h.size_tunn = sizeof(tunnelt);
	h.interval = config->cluster_hb_interval;
	h.timeout  = config->cluster_hb_timeout;
	h.table_version = config->cluster_table_version;

	add_type(&p, C_HEARTBEAT, HB_VERSION, (uint8_t *) &h, sizeof(h));

	for (i = 0; i < config->cluster_num_changes; ++i) {
		hb_add_type(&p, cluster_changes[i].type, cluster_changes[i].id);
	}

	if (p > (buff + sizeof(buff))) {	// Did we somehow manage to overun the buffer?
		LOG(0, 0, 0, "FATAL: Overran the heartbeat buffer! This is fatal. Exiting. (size %d)\n", (int) (p - buff));
		kill(0, SIGTERM);
		exit(1);
	}

		//
		// Fill out the packet with sessions from the session table...
		// (not forgetting to leave space so we can get some tunnels in too )
	while ( (p + sizeof(uint32_t) * 2 + sizeof(sessiont) * 2 ) < (buff + MAX_HEART_SIZE) ) {

		if (!walk_session_number)	// session #0 isn't valid.
			++walk_session_number;

		if (count >= config->cluster_highest_sessionid)	// If we're a small cluster, don't go wild.
			break;

		hb_add_type(&p, C_CSESSION, walk_session_number);
		walk_session_number = (1+walk_session_number)%(config->cluster_highest_sessionid+1);	// +1 avoids divide by zero.

		++count;			// Count the number of extra sessions we're sending.
	}

		//
		// Fill out the packet with tunnels from the tunnel table...
		// This effectively means we walk the tunnel table more quickly
		// than the session table. This is good because stuffing up a 
		// tunnel is a much bigger deal than stuffing up a session.
		//
	while ( (p + sizeof(uint32_t) * 2 + sizeof(tunnelt) ) < (buff + MAX_HEART_SIZE) ) {

		if (!walk_tunnel_number)	// tunnel #0 isn't valid.
			++walk_tunnel_number;

		if (tcount >= config->cluster_highest_tunnelid)
			break;

		hb_add_type(&p, C_CTUNNEL, walk_tunnel_number);
		walk_tunnel_number = (1+walk_tunnel_number)%(config->cluster_highest_tunnelid+1);	// +1 avoids divide by zero.

		++tcount;
	}

		//
		// Fill out the packet with bundles from the bundle table...
	while ( (p + sizeof(uint32_t) * 2 + sizeof(bundlet) ) < (buff + MAX_HEART_SIZE) ) {

		if (!walk_bundle_number)        // bundle #0 isn't valid.
			++walk_bundle_number;

		if (bcount >= config->cluster_highest_bundleid)
			break;

		hb_add_type(&p, C_CTUNNEL, walk_bundle_number);
		walk_tunnel_number = (1+walk_bundle_number)%(config->cluster_highest_bundleid+1);       // +1 avoids divide by zero.

		++bcount;
        }

		//
		// Did we do something wrong?
	if (p > (buff + sizeof(buff))) {	// Did we somehow manage to overun the buffer?
		LOG(0, 0, 0, "Overran the heartbeat buffer now! This is fatal. Exiting. (size %d)\n", (int) (p - buff));
		kill(0, SIGTERM);
		exit(1);
	}

	LOG(3, 0, 0, "Sending v%d heartbeat #%d, change #%" PRIu64 " with %d changes "
		     "(%d x-sess, %d x-bundles, %d x-tunnels, %d highsess, %d highbund, %d hightun, size %d)\n",
	    HB_VERSION, h.seq, h.table_version, config->cluster_num_changes,
	    count, bcount, tcount, config->cluster_highest_sessionid, config->cluster_highest_bundleid,
	    config->cluster_highest_tunnelid, (int) (p - buff));

	config->cluster_num_changes = 0;

	send_heartbeat(h.seq, buff, (p-buff) ); // Send out the heartbeat to the cluster, keeping a copy of it.

	config->cluster_seq_number = (config->cluster_seq_number+1)%HB_MAX_SEQ;	// Next seq number to use.
}

//
// A structure of type 'type' has changed; Add it to the queue to send.
//
static int type_changed(int type, int id)
{
	int i;

	for (i = 0 ; i < config->cluster_num_changes ; ++i)
		if ( cluster_changes[i].id == id &&
			cluster_changes[i].type == type)
			return 0;	// Already marked for change.

	cluster_changes[i].type = type;
	cluster_changes[i].id = id;
	++config->cluster_num_changes;

	if (config->cluster_num_changes > MAX_CHANGES)
		cluster_heartbeat(); // flush now

	return 1;
}


// A particular session has been changed!
int cluster_send_session(int sid)
{
	if (!config->cluster_iam_master) {
		LOG(0, sid, 0, "I'm not a master, but I just tried to change a session!\n");
		return -1;
	}

	if (forked) {
		LOG(0, sid, 0, "cluster_send_session called from child process!\n");
		return -1;
	}

	return type_changed(C_CSESSION, sid);
}

// A particular bundle has been changed!
int cluster_send_bundle(int bid)
{
	if (!config->cluster_iam_master) {
		LOG(0, 0, bid, "I'm not a master, but I just tried to change a bundle!\n");
		return -1;
	}

	return type_changed(C_CBUNDLE, bid);
}

// A particular tunnel has been changed!
int cluster_send_tunnel(int tid)
{
	if (!config->cluster_iam_master) {
		LOG(0, 0, tid, "I'm not a master, but I just tried to change a tunnel!\n");
		return -1;
	}

	return type_changed(C_CTUNNEL, tid);
}


//
// We're a master, and a slave has just told us that it's
// missed a packet. We'll resend it every packet since
// the last one it's seen.
//
static int cluster_catchup_slave(int seq, in_addr_t slave)
{
	int s;
	int diff;

	LOG(1, 0, 0, "Slave %s sent LASTSEEN with seq %d\n", fmtaddr(slave, 0), seq);
	if (!config->cluster_iam_master) {
		LOG(1, 0, 0, "Got LASTSEEN but I'm not a master! Redirecting it to %s.\n",
			fmtaddr(config->cluster_master_address, 0));

		peer_send_message(slave, C_MASTER, config->cluster_master_address, NULL, 0);
		return 0;
	}

	diff = config->cluster_seq_number - seq;	// How many packet do we need to send?
	if (diff < 0)
		diff += HB_MAX_SEQ;

	if (diff >= HB_HISTORY_SIZE) {	// Ouch. We don't have the packet to send it!
		LOG(0, 0, 0, "A slave asked for message %d when our seq number is %d. Killing it.\n",
			seq, config->cluster_seq_number);
		return peer_send_message(slave, C_KILL, seq, NULL, 0);// Kill the slave. Nothing else to do.
	}

	LOG(1, 0, 0, "Sending %d catchup packets to slave %s\n", diff, fmtaddr(slave, 0) );

		// Now resend every packet that it missed, in order.
	while (seq != config->cluster_seq_number) {
		s = seq % HB_HISTORY_SIZE;
		if (seq != past_hearts[s].seq) {
			LOG(0, 0, 0, "Tried to re-send heartbeat for %s but %d doesn't match %d! (%d,%d)\n",
				fmtaddr(slave, 0), seq, past_hearts[s].seq, s, config->cluster_seq_number);
			return -1;	// What to do here!?
		}
		peer_send_data(slave, past_hearts[s].data, past_hearts[s].size);
		seq = (seq+1)%HB_MAX_SEQ;	// Increment to next seq number.
	}
	return 0; // All good!
}

//
// We've heard from another peer! Add it to the list
// that we select from at election time.
//
static int cluster_add_peer(in_addr_t peer, time_t basetime, pingt *pp, int size)
{
	int i;
	in_addr_t clusterid;
	pingt p;

	// Allow for backward compatability.
	// Just the ping packet into a new structure to allow
	// for the possibility that we might have received
	// more or fewer elements than we were expecting.
	if (size > sizeof(p))
		size = sizeof(p);

	memset( (void *) &p, 0, sizeof(p) );
	memcpy( (void *) &p, (void *) pp, size);

	clusterid = p.addr;
	if (clusterid != config->bind_address)
	{
		// Is this for us?
		LOG(4, 0, 0, "Skipping ping from %s (different cluster)\n", fmtaddr(peer, 0));
		return 0;
	}

	for (i = 0; i < num_peers ; ++i)
	{
		if (peers[i].peer != peer)
			continue;

		// This peer already exists. Just update the timestamp.
		peers[i].basetime = basetime;
		peers[i].timestamp = TIME;
		peers[i].uptodate = !p.undef;
		break;
	}

	// Is this the master shutting down??
	if (peer == config->cluster_master_address) {
		LOG(3, 0, 0, "Master %s %s\n", fmtaddr(config->cluster_master_address, 0),
			basetime ? "has restarted!" : "shutting down...");

		config->cluster_master_address = 0;
		config->cluster_last_hb = 0; // Force an election.
		cluster_check_master();
	}

	if (i >= num_peers)
	{
		LOG(4, 0, 0, "Adding %s as a peer\n", fmtaddr(peer, 0));

		// Not found. Is there a stale slot to re-use?
		for (i = 0; i < num_peers ; ++i)
		{
			if (!peers[i].basetime) // Shutdown
				break;

			if ((peers[i].timestamp + config->cluster_hb_timeout * 10) < TIME) // Stale.
				break;
		}

		if (i >= CLUSTER_MAX_SIZE)
		{
			// Too many peers!!
			LOG(0, 0, 0, "Tried to add %s as a peer, but I already have %d of them!\n", fmtaddr(peer, 0), i);
			return -1;
		}

		peers[i].peer = peer;
		peers[i].basetime = basetime;
		peers[i].timestamp = TIME;
		peers[i].uptodate = !p.undef;
		if (i == num_peers)
			++num_peers;

		LOG(1, 0, 0, "Added %s as a new peer. Now %d peers\n", fmtaddr(peer, 0), num_peers);
	}

	return 1;
}

// A slave responds with C_MASTER when it gets a message which should have gone to a master.
static int cluster_set_master(in_addr_t peer, in_addr_t master)
{
	if (config->cluster_iam_master)	// Sanity...
		return 0;

	LOG(3, 0, 0, "Peer %s set the master to %s...\n", fmtaddr(peer, 0),
		fmtaddr(master, 1));

	config->cluster_master_address = master;
	if (master)
	{
		// catchup with new master
		peer_send_message(master, C_LASTSEEN, config->cluster_seq_number, NULL, 0);

		// delay next election
		config->cluster_last_hb = TIME;
	}

	// run election (or reset "probed" if master was set)
	cluster_check_master();
	return 0;
}

/* Handle the slave updating the byte counters for the master. */
//
// Note that we don't mark the session as dirty; We rely on
// the slow table walk to propogate this back out to the slaves.
//
static int cluster_handle_bytes(uint8_t *data, int size)
{
	bytest *b;

	b = (bytest *) data;

	LOG(3, 0, 0, "Got byte counter update (size %d)\n", size);

				/* Loop around, adding the byte
				counts to each of the sessions. */

	while (size >= sizeof(*b) ) {
		if (b->sid > MAXSESSION) {
			LOG(0, 0, 0, "Got C_BYTES with session #%d!\n", b->sid);
			return -1; /* Abort processing */
		}

		session[b->sid].pin += b->pin;
		session[b->sid].pout += b->pout;

		increment_counter(&session[b->sid].cin, &session[b->sid].cin_wrap, b->cin);
		increment_counter(&session[b->sid].cout, &session[b->sid].cout_wrap, b->cout);

		session[b->sid].cin_delta += b->cin;
		session[b->sid].cout_delta += b->cout;

		if (b->cin)
			session[b->sid].last_packet = time_now; // Reset idle timer!

		size -= sizeof(*b);
		++b;
	}

	if (size != 0)
		LOG(0, 0, 0, "Got C_BYTES with %d bytes of trailing junk!\n", size);

	return size;
}

//
// Handle receiving a session structure in a heartbeat packet.
//
static int cluster_recv_session(int more, uint8_t *p)
{
	if (more >= MAXSESSION) {
		LOG(0, 0, 0, "DANGER: Received a heartbeat session id > MAXSESSION!\n");
		return -1;
	}

	if (session[more].tunnel == T_UNDEF) {
		if (config->cluster_iam_uptodate) { // Sanity.
			LOG(0, 0, 0, "I thought I was uptodate but I just found an undefined session!\n");
		} else {
			--config->cluster_undefined_sessions;
		}
	}

	load_session(more, (sessiont *) p);	// Copy session into session table..

	LOG(5, more, 0, "Received session update (%d undef)\n", config->cluster_undefined_sessions);

	if (!config->cluster_iam_uptodate)
		cluster_uptodate();	// Check to see if we're up to date.

	return 0;
}

static int cluster_recv_bundle(int more, uint8_t *p)
{
	if (more >= MAXBUNDLE) {
		LOG(0, 0, 0, "DANGER: Received a bundle id > MAXBUNDLE!\n");
		return -1;
	}

	if (bundle[more].state == BUNDLEUNDEF) {
		if (config->cluster_iam_uptodate) { // Sanity.
			LOG(0, 0, 0, "I thought I was uptodate but I just found an undefined bundle!\n");
		} else {
			--config->cluster_undefined_bundles;
		}
	}

	memcpy(&bundle[more], p, sizeof(bundle[more]) );

	LOG(5, 0, more, "Received bundle update\n");

	if (!config->cluster_iam_uptodate)
		cluster_uptodate();     // Check to see if we're up to date.

        return 0;
}

static int cluster_recv_tunnel(int more, uint8_t *p)
{
	if (more >= MAXTUNNEL) {
		LOG(0, 0, 0, "DANGER: Received a tunnel session id > MAXTUNNEL!\n");
		return -1;
	}

	if (tunnel[more].state == TUNNELUNDEF) {
		if (config->cluster_iam_uptodate) { // Sanity.
			LOG(0, 0, 0, "I thought I was uptodate but I just found an undefined tunnel!\n");
		} else {
			--config->cluster_undefined_tunnels;
		}
	}

	memcpy(&tunnel[more], p, sizeof(tunnel[more]) );

		//
		// Clear tunnel control messages. These are dynamically allocated.
		// If we get unlucky, this may cause the tunnel to drop!
		//
	tunnel[more].controls = tunnel[more].controle = NULL;
	tunnel[more].controlc = 0;

	LOG(5, 0, more, "Received tunnel update\n");

	if (!config->cluster_iam_uptodate)
		cluster_uptodate();	// Check to see if we're up to date.

	return 0;
}


// pre v5 heartbeat session structure
struct oldsession {
	sessionidt next;
	sessionidt far;
	tunnelidt tunnel;
	in_addr_t ip;
	int ip_pool_index;
	unsigned long unique_id;
	uint16_t nr;
	uint16_t ns;
	uint32_t magic;
	uint32_t cin, cout;
	uint32_t pin, pout;
	uint32_t total_cin;
	uint32_t total_cout;
	uint32_t id;
	uint16_t throttle_in;
	uint16_t throttle_out;
	clockt opened;
	clockt die;
	time_t last_packet;
	in_addr_t dns1, dns2;
	routet route[MAXROUTE];
	uint16_t radius;
	uint16_t mru;
	uint16_t tbf_in;
	uint16_t tbf_out;
	uint8_t l2tp_flags;
	uint8_t reserved_old_snoop;
	uint8_t walled_garden;
	uint8_t flags1;
	char random_vector[MAXTEL];
	int random_vector_length;
	char user[129];
	char called[MAXTEL];
	char calling[MAXTEL];
	uint32_t tx_connect_speed;
	uint32_t rx_connect_speed;
	uint32_t flags;
#define SF_IPCP_ACKED	1	// Has this session seen an IPCP Ack?
#define SF_LCP_ACKED	2	// LCP negotiated
#define SF_CCP_ACKED	4	// CCP negotiated
	in_addr_t snoop_ip;
	uint16_t snoop_port;
	uint16_t sid;
	uint8_t filter_in;
	uint8_t filter_out;
	char reserved[18];
};

static uint8_t *convert_session(struct oldsession *old)
{
	static sessiont new;
	int i;

	memset(&new, 0, sizeof(new));

	new.next = old->next;
	new.far = old->far;
	new.tunnel = old->tunnel;
	new.flags = old->l2tp_flags;
	new.ip = old->ip;
	new.ip_pool_index = old->ip_pool_index;
	new.unique_id = old->unique_id;
	new.magic = old->magic;
	new.pin = old->pin;
	new.pout = old->pout;
	new.cin = old->total_cin;
	new.cout = old->total_cout;
	new.cin_delta = old->cin;
	new.cout_delta = old->cout;
	new.throttle_in = old->throttle_in;
	new.throttle_out = old->throttle_out;
	new.filter_in = old->filter_in;
	new.filter_out = old->filter_out;
	new.mru = old->mru;
	new.opened = old->opened;
	new.die = old->die;
	new.last_packet = old->last_packet;
	new.dns1 = old->dns1;
	new.dns2 = old->dns2;
	new.tbf_in = old->tbf_in;
	new.tbf_out = old->tbf_out;
	new.random_vector_length = old->random_vector_length;
	new.tx_connect_speed = old->tx_connect_speed;
	new.rx_connect_speed = old->rx_connect_speed;
	new.snoop_ip = old->snoop_ip;
	new.snoop_port = old->snoop_port;
	new.walled_garden = old->walled_garden;

	memcpy(new.random_vector, old->random_vector, sizeof(new.random_vector));
	memcpy(new.user, old->user, sizeof(new.user));
	memcpy(new.called, old->called, sizeof(new.called));
	memcpy(new.calling, old->calling, sizeof(new.calling));

	for (i = 0; i < MAXROUTE; i++)
		memcpy(&new.route[i], &old->route[i], sizeof(new.route[i]));

	if (new.opened)
	{
		new.ppp.phase = Establish;
		if (old->flags & (SF_IPCP_ACKED|SF_LCP_ACKED))
		{
			new.ppp.phase = Network;
			new.ppp.lcp   = Opened;
			new.ppp.ipcp  = (old->flags & SF_IPCP_ACKED) ? Opened : Starting;
			new.ppp.ccp   = (old->flags & SF_CCP_ACKED)  ? Opened : Stopped;
		}

		// no PPPv6 in old session
		new.ppp.ipv6cp = Stopped;
	}

	return (uint8_t *) &new;
}

//
// Process a heartbeat..
//
// v3: added interval, timeout
// v4: added table_version
// v5: added ipv6, re-ordered session structure
static int cluster_process_heartbeat(uint8_t *data, int size, int more, uint8_t *p, in_addr_t addr)
{
	heartt *h;
	int s = size - (p-data);
	int i, type;
	int hb_ver = more;

#if HB_VERSION != 5
# error "need to update cluster_process_heartbeat()"
#endif

	// we handle versions 3 through 5
	if (hb_ver < 3 || hb_ver > HB_VERSION) {
		LOG(0, 0, 0, "Received a heartbeat version that I don't support (%d)!\n", hb_ver);
		return -1; // Ignore it??
	}

		// Ok. It's a heartbeat packet from a cluster master!
	if (s < sizeof(*h))
		goto shortpacket;

	h = (heartt *) p;
	p += sizeof(*h);
	s -= sizeof(*h);

	if (h->clusterid != config->bind_address)
		return -1;	// It's not part of our cluster.

	if (config->cluster_iam_master) {	// Sanity...
				// Note that this MUST match the election process above!

		LOG(0, 0, 0, "I just got a heartbeat from master %s, but _I_ am the master!\n", fmtaddr(addr, 0));
		if (!h->basetime) {
			LOG(0, 0, 0, "Heartbeat with zero basetime!  Ignoring\n");
			return -1; // Skip it.
		}

		if (hb_ver >= 4) {
			if (h->table_version > config->cluster_table_version) {
				LOG(0, 0, 0, "They've seen more state changes (%" PRIu64 " vs my %" PRIu64 ") so I'm gone!\n",
					h->table_version, config->cluster_table_version);

				kill(0, SIGTERM);
				exit(1);
			}
			if (h->table_version < config->cluster_table_version)
			    	return -1;
		}

		if (basetime > h->basetime) {
			LOG(0, 0, 0, "They're an older master than me so I'm gone!\n");
			kill(0, SIGTERM);
			exit(1);
		}

		if (basetime < h->basetime)
			return -1;

		if (my_address < addr) { // Tie breaker.
			LOG(0, 0, 0, "They're a higher IP address than me, so I'm gone!\n");
			kill(0, SIGTERM);
			exit(1);
		}

			//
			// Send it a unicast heartbeat to see give it a chance to die.
			// NOTE: It's actually safe to do seq-number - 1 without checking
			// for wrap around.
			//
		cluster_catchup_slave(config->cluster_seq_number - 1, addr);

		return -1; // Skip it.
	}

		//
		// Try and guard against a stray master appearing.
		//
		// Ignore heartbeats received from another master before the
		// timeout (less a smidgen) for the old master has elapsed.
		//
		// Note that after a clean failover, the cluster_master_address
		// is cleared, so this doesn't run. 
		//
	if (config->cluster_master_address && addr != config->cluster_master_address) {
		    LOG(0, 0, 0, "Ignoring stray heartbeat from %s, current master %s has not yet timed out (last heartbeat %.1f seconds ago).\n",
			    fmtaddr(addr, 0), fmtaddr(config->cluster_master_address, 1),
			    0.1 * (TIME - config->cluster_last_hb));
		    return -1; // ignore
	}

	if (config->cluster_seq_number == -1)	// Don't have one. Just align to the master...
		config->cluster_seq_number = h->seq;

	config->cluster_last_hb = TIME;	// Reset to ensure that we don't become master!!
	config->cluster_last_hb_ver = hb_ver; // remember what cluster version the master is using

	if (config->cluster_seq_number != h->seq) {	// Out of sequence heartbeat!
		static int lastseen_seq = 0;
		static time_t lastseen_time = 0;

		// limit to once per second for a particular seq#
		int ask = (config->cluster_seq_number != lastseen_seq || time_now != lastseen_time);

		LOG(1, 0, 0, "HB: Got seq# %d but was expecting %d.  %s.\n",
			h->seq, config->cluster_seq_number,
			ask ? "Asking for resend" : "Ignoring");

		if (ask)
		{
			lastseen_seq = config->cluster_seq_number;
			lastseen_time = time_now;
			peer_send_message(addr, C_LASTSEEN, config->cluster_seq_number, NULL, 0);
		}

		config->cluster_last_hb = TIME;	// Reset to ensure that we don't become master!!

			// Just drop the packet. The master will resend it as part of the catchup.

		return 0;
	}
		// Save the packet in our buffer.
		// This is needed in case we become the master.
	config->cluster_seq_number = (h->seq+1)%HB_MAX_SEQ;
	i = h->seq % HB_HISTORY_SIZE;
	past_hearts[i].seq = h->seq;
	past_hearts[i].size = size;
	memcpy(&past_hearts[i].data, data, size);	// Save it.


			// Check that we don't have too many undefined sessions, and
			// that the free session pointer is correct.
	cluster_check_sessions(h->highsession, h->freesession, h->highbundle, h->hightunnel);

	if (h->interval != config->cluster_hb_interval)
	{
		LOG(2, 0, 0, "Master set ping/heartbeat interval to %u (was %u)\n",
			h->interval, config->cluster_hb_interval);

		config->cluster_hb_interval = h->interval;
	}

	if (h->timeout != config->cluster_hb_timeout)
	{
		LOG(2, 0, 0, "Master set heartbeat timeout to %u (was %u)\n",
			h->timeout, config->cluster_hb_timeout);

		config->cluster_hb_timeout = h->timeout;
	}

		// Ok. process the packet...
	while ( s > 0) {

		type = *((uint32_t *) p);
		p += sizeof(uint32_t);
		s -= sizeof(uint32_t);

		more = *((uint32_t *) p);
		p += sizeof(uint32_t);
		s -= sizeof(uint32_t);

		switch (type) {
			case C_CSESSION: { // Compressed session structure.
				uint8_t c[ sizeof(sessiont) + 2];
				int size;
				uint8_t *orig_p = p;

				size = rle_decompress((uint8_t **) &p, s, c, sizeof(c) );
				s -= (p - orig_p);

				// session struct changed with v5
				if (hb_ver < 5)
				{
					if (size != sizeof(struct oldsession)) {
						LOG(0, 0, 0, "DANGER: Received a v%d CSESSION that didn't decompress correctly!\n", hb_ver);
							// Now what? Should exit! No-longer up to date!
						break;
					}
					cluster_recv_session(more, convert_session((struct oldsession *) c));
					break;
				}

				if (size != sizeof(sessiont) ) { // Ouch! Very very bad!
					LOG(0, 0, 0, "DANGER: Received a CSESSION that didn't decompress correctly!\n");
						// Now what? Should exit! No-longer up to date!
					break;
				}

				cluster_recv_session(more, c);
				break;
			}
			case C_SESSION:
			    	if (hb_ver < 5)
				{
					if (s < sizeof(struct oldsession))
						goto shortpacket;

					cluster_recv_session(more, convert_session((struct oldsession *) p));

					p += sizeof(struct oldsession);
					s -= sizeof(struct oldsession);
					break;
				}

				if ( s < sizeof(session[more]))
					goto shortpacket;

				cluster_recv_session(more, p);

				p += sizeof(session[more]);
				s -= sizeof(session[more]);
				break;

			case C_CTUNNEL: { // Compressed tunnel structure.
				uint8_t c[ sizeof(tunnelt) + 2];
				int size;
				uint8_t *orig_p = p;

				size = rle_decompress((uint8_t **) &p, s, c, sizeof(c));
				s -= (p - orig_p);

				if (size != sizeof(tunnelt) ) { // Ouch! Very very bad!
					LOG(0, 0, 0, "DANGER: Received a CTUNNEL that didn't decompress correctly!\n");
						// Now what? Should exit! No-longer up to date!
					break;
				}

				cluster_recv_tunnel(more, c);
				break;

			}
			case C_TUNNEL:
				if ( s < sizeof(tunnel[more]))
					goto shortpacket;

				cluster_recv_tunnel(more, p);

				p += sizeof(tunnel[more]);
				s -= sizeof(tunnel[more]);
				break;

			case C_CBUNDLE: { // Compressed bundle structure.
				uint8_t c[ sizeof(bundlet) + 2];
				int size;
				uint8_t *orig_p = p;

				size = rle_decompress((uint8_t **) &p, s, c, sizeof(c));
				s -= (p - orig_p);

				if (size != sizeof(bundlet) ) { // Ouch! Very very bad!
					LOG(0, 0, 0, "DANGER: Received a CBUNDLE that didn't decompress correctly!\n");
						// Now what? Should exit! No-longer up to date!
					break;
				}

				cluster_recv_bundle(more, c);
				break;

			}
			case C_BUNDLE:
				if ( s < sizeof(bundle[more]))
                                        goto shortpacket;

                                cluster_recv_bundle(more, p);

                                p += sizeof(bundle[more]);
                                s -= sizeof(bundle[more]);
                                break;
			default:
				LOG(0, 0, 0, "DANGER: I received a heartbeat element where I didn't understand the type! (%d)\n", type);
				return -1; // can't process any more of the packet!!
		}
	}

	if (config->cluster_master_address != addr)
	{
		LOG(0, 0, 0, "My master just changed from %s to %s!\n",
			fmtaddr(config->cluster_master_address, 0), fmtaddr(addr, 1));

		config->cluster_master_address = addr;
	}

	config->cluster_last_hb = TIME;	// Successfully received a heartbeat!
	config->cluster_table_version = h->table_version;
	return 0;

shortpacket:
	LOG(0, 0, 0, "I got an incomplete heartbeat packet! This means I'm probably out of sync!!\n");
	return -1;
}

//
// We got a packet on the cluster port!
// Handle pings, lastseens, and heartbeats!
//
int processcluster(uint8_t *data, int size, in_addr_t addr)
{
	int type, more;
	uint8_t *p = data;
	int s = size;

	if (addr == my_address)
		return -1;	// Ignore it. Something looped back the multicast!

	LOG(5, 0, 0, "Process cluster: %d bytes from %s\n", size, fmtaddr(addr, 0));

	if (s <= 0)	// Any data there??
		return -1;

	if (s < 8)
		goto shortpacket;

	type = *((uint32_t *) p);
	p += sizeof(uint32_t);
	s -= sizeof(uint32_t);

	more = *((uint32_t *) p);
	p += sizeof(uint32_t);
	s -= sizeof(uint32_t);

	switch (type)
	{
	case C_PING: // Update the peers table.
		return cluster_add_peer(addr, more, (pingt *) p, s);

	case C_MASTER: // Our master is wrong
	    	return cluster_set_master(addr, more);

	case C_LASTSEEN: // Catch up a slave (slave missed a packet).
		return cluster_catchup_slave(more, addr);

	case C_FORWARD: // Forwarded control packet. pass off to processudp.
	case C_FORWARD_DAE: // Forwarded DAE packet. pass off to processdae.
		if (!config->cluster_iam_master)
		{
			LOG(0, 0, 0, "I'm not the master, but I got a C_FORWARD_%s from %s?\n",
				type == C_FORWARD_DAE ? "_DAE" : "", fmtaddr(addr, 0));

			return -1;
		}
		else
		{
			struct sockaddr_in a;
			a.sin_addr.s_addr = more;

			a.sin_port = *(int *) p;
			s -= sizeof(int);
			p += sizeof(int);

			LOG(4, 0, 0, "Got a forwarded %spacket... (%s:%d)\n",
				type == C_FORWARD_DAE ? "DAE " : "", fmtaddr(more, 0), a.sin_port);

			STAT(recv_forward);
			if (type == C_FORWARD_DAE)
			{
				struct in_addr local;
				local.s_addr = config->bind_address ? config->bind_address : my_address;
				processdae(p, s, &a, sizeof(a), &local);
			}
			else
				processudp(p, s, &a);

			return 0;
		}

	case C_THROTTLE: {	// Receive a forwarded packet from a slave.
		if (!config->cluster_iam_master) {
			LOG(0, 0, 0, "I'm not the master, but I got a C_THROTTLE from %s?\n", fmtaddr(addr, 0));
			return -1;
		}

		tbf_queue_packet(more, p, s);	// The TBF id tells wether it goes in or out.
		return 0;
	}
	case C_GARDEN:
		// Receive a walled garden packet from a slave.
		if (!config->cluster_iam_master) {
			LOG(0, 0, 0, "I'm not the master, but I got a C_GARDEN from %s?\n", fmtaddr(addr, 0));
			return -1;
		}

		tun_write(p, s);
		return 0;

	case C_BYTES:
		if (!config->cluster_iam_master) {
			LOG(0, 0, 0, "I'm not the master, but I got a C_BYTES from %s?\n", fmtaddr(addr, 0));
			return -1;
		}

		return cluster_handle_bytes(p, s);

	case C_KILL:	// The master asked us to die!? (usually because we're too out of date).
		if (config->cluster_iam_master) {
			LOG(0, 0, 0, "_I_ am master, but I received a C_KILL from %s! (Seq# %d)\n", fmtaddr(addr, 0), more);
			return -1;
		}
		if (more != config->cluster_seq_number) {
			LOG(0, 0, 0, "The master asked us to die but the seq number didn't match!?\n");
			return -1;
		}

		if (addr != config->cluster_master_address) {
			LOG(0, 0, 0, "Received a C_KILL from %s which doesn't match config->cluster_master_address (%s)\n",
				fmtaddr(addr, 0), fmtaddr(config->cluster_master_address, 1));
			// We can only warn about it. The master might really have switched!
		}

		LOG(0, 0, 0, "Received a valid C_KILL: I'm going to die now.\n");
		kill(0, SIGTERM);
		exit(0);	// Lets be paranoid;
		return -1;		// Just signalling the compiler.

	case C_HEARTBEAT:
		LOG(4, 0, 0, "Got a heartbeat from %s\n", fmtaddr(addr, 0));
		return cluster_process_heartbeat(data, size, more, p, addr);

	default:
		LOG(0, 0, 0, "Strange type packet received on cluster socket (%d)\n", type);
		return -1;
	}
	return 0;

shortpacket:
	LOG(0, 0, 0, "I got a _short_ cluster heartbeat packet! This means I'm probably out of sync!!\n");
	return -1;
}

//====================================================================================================

int cmd_show_cluster(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_print(cli, "Cluster status   : %s", config->cluster_iam_master ? "Master" : "Slave" );
	cli_print(cli, "My address       : %s", fmtaddr(my_address, 0));
	cli_print(cli, "VIP address      : %s", fmtaddr(config->bind_address, 0));
	cli_print(cli, "Multicast address: %s", fmtaddr(config->cluster_address, 0));
	cli_print(cli, "Multicast i'face : %s", config->cluster_interface);

	if (!config->cluster_iam_master) {
		cli_print(cli, "My master        : %s (last heartbeat %.1f seconds old)",
			config->cluster_master_address
				? fmtaddr(config->cluster_master_address, 0)
				: "Not defined",
			0.1 * (TIME - config->cluster_last_hb));
		cli_print(cli, "Uptodate         : %s", config->cluster_iam_uptodate ? "Yes" : "No");
		cli_print(cli, "Table version #  : %" PRIu64, config->cluster_table_version);
		cli_print(cli, "Next sequence number expected: %d", config->cluster_seq_number);
		cli_print(cli, "%d sessions undefined of %d", config->cluster_undefined_sessions, config->cluster_highest_sessionid);
		cli_print(cli, "%d bundles undefined of %d", config->cluster_undefined_bundles, config->cluster_highest_bundleid);
		cli_print(cli, "%d tunnels undefined of %d", config->cluster_undefined_tunnels, config->cluster_highest_tunnelid);
	} else {
		cli_print(cli, "Table version #  : %" PRIu64, config->cluster_table_version);
		cli_print(cli, "Next heartbeat # : %d", config->cluster_seq_number);
		cli_print(cli, "Highest session  : %d", config->cluster_highest_sessionid);
		cli_print(cli, "Highest bundle   : %d", config->cluster_highest_bundleid);
		cli_print(cli, "Highest tunnel   : %d", config->cluster_highest_tunnelid);
		cli_print(cli, "%d changes queued for sending", config->cluster_num_changes);
	}
	cli_print(cli, "%d peers.", num_peers);

	if (num_peers)
		cli_print(cli, "%20s  %10s %8s", "Address", "Basetime", "Age");
	for (i = 0; i < num_peers; ++i) {
		cli_print(cli, "%20s  %10u %8d", fmtaddr(peers[i].peer, 0),
			peers[i].basetime, TIME - peers[i].timestamp);
	}
	return CLI_OK;
}

//
// Simple run-length-encoding compression.
// Format is
//	1 byte < 128 = count of non-zero bytes following.	// Not legal to be zero.
//	n non-zero bytes;
// or
//	1 byte > 128 = (count - 128) run of zero bytes.		//
//   repeat.
//   count == 0 indicates end of compressed stream.
//
// Compress from 'src' into 'dst'. return number of bytes
// used from 'dst'.
// Updates *src_p to indicate 1 past last bytes used.
//
// We could get an extra byte in the zero runs by storing (count-1)
// but I'm playing it safe.
//
// Worst case is a 50% expansion in space required (trying to
// compress { 0x00, 0x01 } * N )
static int rle_compress(uint8_t **src_p, int ssize, uint8_t *dst, int dsize)
{
	int count;
	int orig_dsize = dsize;
	uint8_t *x, *src;
	src = *src_p;

	while (ssize > 0 && dsize > 2) {
		count = 0;
		x = dst++; --dsize;	// Reserve space for count byte..

		if (*src) {		// Copy a run of non-zero bytes.
			while (*src && count < 127 && ssize > 0 && dsize > 1) { // Count number of non-zero bytes.
				*dst++ = *src++;
				--dsize; --ssize;
				++count;
			}
			*x = count;	// Store number of non-zero bytes. Guarenteed to be non-zero!

		} else {		// Compress a run of zero bytes.
			while (*src == 0 && count < 127 && ssize > 0) {
				++src;
				--ssize;
				++count;
			}
			*x = count | 0x80 ;
		}
	}

	*dst++ = 0x0; // Add Stop byte.
	--dsize;

	*src_p = src;
	return (orig_dsize - dsize);
}

//
// Decompress the buffer into **p.
// 'psize' is the size of the decompression buffer available.
//
// Returns the number of bytes decompressed.
//
// Decompresses from '*src_p' into 'dst'.
// Return the number of dst bytes used.
// Updates the 'src_p' pointer to point to the
// first un-used byte.
static int rle_decompress(uint8_t **src_p, int ssize, uint8_t *dst, int dsize)
{
	int count;
	int orig_dsize = dsize;
	uint8_t *src = *src_p;

	while (ssize >0 && dsize > 0) {	// While there's more to decompress, and there's room in the decompress buffer...
		count = *src++; --ssize;  // get the count byte from the source.
		if (count == 0x0)	// End marker reached? If so, finish.
			break;

		if (count & 0x80) {	// Decompress a run of zeros
			for (count &= 0x7f ; count > 0 && dsize > 0; --count) {
				*dst++ = 0x0;
				--dsize;
			}
		} else { 		// Copy run of non-zero bytes.
			for ( ; count > 0 && ssize && dsize; --count) {	// Copy non-zero bytes across.
				*dst++ = *src++;
				--ssize; --dsize;
			}
		}
	}
	*src_p = src;
	return (orig_dsize - dsize);
}
