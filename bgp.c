/*
 * BGPv4
 * Used to advertise routes for upstream (l2tp port, rather than gratiutious
 * arp) and downstream--allowing routers to load-balance both.
 *
 * Implementation limitations:
 * - We never listen for incoming connections (session always initiated by us).
 * - Any routes advertised by the peer are accepted, but ignored.
 * - No password support; neither RFC1771 (which no-one seems to do anyway)
 *   nor RFC2385 (which requires a kernel patch on 2.4 kernels).
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include "l2tpns.h"
#include "bgp.h"
#include "util.h"

static void bgp_clear(struct bgp_peer *peer);
static void bgp_set_retry(struct bgp_peer *peer);
static void bgp_cidr(in_addr_t ip, in_addr_t mask, struct bgp_ip_prefix *pfx);
static struct bgp_route_list *bgp_insert_route(struct bgp_route_list *head,
    struct bgp_route_list *new);

static void bgp_free_routes(struct bgp_route_list *routes);
static char const *bgp_msg_type_str(uint8_t type);
static int bgp_connect(struct bgp_peer *peer);
static int bgp_handle_connect(struct bgp_peer *peer);
static int bgp_write(struct bgp_peer *peer);
static int bgp_read(struct bgp_peer *peer);
static int bgp_handle_input(struct bgp_peer *peer);
static int bgp_send_open(struct bgp_peer *peer);
static int bgp_send_keepalive(struct bgp_peer *peer);
static int bgp_send_update(struct bgp_peer *peer);
static int bgp_send_notification(struct bgp_peer *peer, uint8_t code,
    uint8_t subcode);

static uint16_t our_as;
static struct bgp_route_list *bgp_routes = 0;

int bgp_configured = 0;
struct bgp_peer *bgp_peers = 0;

/* prepare peer structure, globals */
int bgp_setup(int as)
{
    int i;
    struct bgp_peer *peer;

    for (i = 0; i < BGP_NUM_PEERS; i++)
    {
	peer = &bgp_peers[i];
	memset(peer, 0, sizeof(*peer));

	peer->addr = INADDR_NONE;
	peer->sock = -1;
	peer->state = peer->next_state = Disabled;

	if (!((peer->outbuf = malloc(sizeof(*peer->outbuf)))
	    && (peer->inbuf = malloc(sizeof(*peer->inbuf)))))
	{
	    LOG(0, 0, 0, "Can't allocate buffers for bgp peer (%s)\n",
		strerror(errno));

	    return 0;
	}

	peer->edata.type = FD_TYPE_BGP;
	peer->edata.index = i;
	peer->events = 0;
    }

    if (as < 1)
    	as = 0;

    if ((our_as = as))
    	return 0;

    bgp_routes = 0;
    bgp_configured = 0; /* set by bgp_start */

    return 1;
}

/* start connection with a peer */
int bgp_start(struct bgp_peer *peer, char *name, int as, int keepalive,
    int hold, int enable)
{
    struct hostent *h;
    int ibgp;
    int i;
    struct bgp_path_attr a;
    char path_attrs[64];
    char *p = path_attrs;
    in_addr_t ip;
    uint32_t metric = htonl(BGP_METRIC);
    uint32_t no_export = htonl(BGP_COMMUNITY_NO_EXPORT);

    if (!our_as)
	return 0;

    if (peer->state != Disabled)
	bgp_halt(peer);

    snprintf(peer->name, sizeof(peer->name), "%s", name);

    if (!(h = gethostbyname(name)) || h->h_addrtype != AF_INET)
    {
	LOG(0, 0, 0, "Can't get address for BGP peer %s (%s)\n",
	    name, h ? "no address" : hstrerror(h_errno));

	return 0;
    }

    memcpy(&peer->addr, h->h_addr, sizeof(peer->addr));
    peer->as = as > 0 ? as : our_as;
    ibgp = peer->as == our_as;

    /* set initial timer values */
    peer->init_keepalive = keepalive == -1 ? BGP_KEEPALIVE_TIME : keepalive;
    peer->init_hold = hold == -1 ? BGP_HOLD_TIME : hold;

    if (peer->init_hold < 3)
    	peer->init_hold = 3;

    if (peer->init_keepalive * 3 > peer->init_hold)
    	peer->init_keepalive = peer->init_hold / 3;

    /* clear buffers, go to Idle state */
    peer->next_state = Idle;
    bgp_clear(peer);

    /* set initial routing state */
    peer->routing = enable;

    /* all our routes use the same attributes, so prepare it in advance */
    if (peer->path_attrs)
    	free(peer->path_attrs);

    peer->path_attr_len = 0;

    /* ORIGIN */
    a.flags = BGP_PATH_ATTR_FLAG_TRANS;
    a.code = BGP_PATH_ATTR_CODE_ORIGIN;
    a.data.s.len = 1;
    a.data.s.value[0] = BGP_PATH_ATTR_CODE_ORIGIN_IGP;

#define ADD_ATTRIBUTE()		do { \
    i = BGP_PATH_ATTR_SIZE(a);	\
    memcpy(p, &a, i); 		\
    p += i; 			\
    peer->path_attr_len += i;	} while (0)

    ADD_ATTRIBUTE();

    /* AS_PATH */
    a.flags = BGP_PATH_ATTR_FLAG_TRANS;
    a.code = BGP_PATH_ATTR_CODE_AS_PATH;
    if (ibgp)
    {
	/* empty path */
	a.data.s.len = 0;
    }
    else
    {
	/* just our AS */
	struct {
	    uint8_t type;
	    uint8_t len;
	    uint16_t value;
	} as_path = {
	    BGP_PATH_ATTR_CODE_AS_PATH_AS_SEQUENCE,
	    1,
	    htons(our_as),
	};

	a.data.s.len = sizeof(as_path);
	memcpy(&a.data.s.value, &as_path, sizeof(as_path));
    }

    ADD_ATTRIBUTE();

    /* NEXT_HOP */
    a.flags = BGP_PATH_ATTR_FLAG_TRANS;
    a.code = BGP_PATH_ATTR_CODE_NEXT_HOP;
    ip = my_address; /* we're it */
    a.data.s.len = sizeof(ip);
    memcpy(a.data.s.value, &ip, sizeof(ip));

    ADD_ATTRIBUTE();

    /* MULTI_EXIT_DISC */
    a.flags = BGP_PATH_ATTR_FLAG_OPTIONAL;
    a.code = BGP_PATH_ATTR_CODE_MULTI_EXIT_DISC;
    a.data.s.len = sizeof(metric);
    memcpy(a.data.s.value, &metric, sizeof(metric));

    ADD_ATTRIBUTE();

    if (ibgp)
    {
	uint32_t local_pref = htonl(BGP_LOCAL_PREF);

	/* LOCAL_PREF */
	a.flags = BGP_PATH_ATTR_FLAG_TRANS;
	a.code = BGP_PATH_ATTR_CODE_LOCAL_PREF;
	a.data.s.len = sizeof(local_pref);
	memcpy(a.data.s.value, &local_pref, sizeof(local_pref));

	ADD_ATTRIBUTE();
    }

    /* COMMUNITIES */
    a.flags = BGP_PATH_ATTR_FLAG_OPTIONAL | BGP_PATH_ATTR_FLAG_TRANS;
    a.code = BGP_PATH_ATTR_CODE_COMMUNITIES;
    a.data.s.len = sizeof(no_export);
    memcpy(a.data.s.value, &no_export, sizeof(no_export));

    ADD_ATTRIBUTE();

    if (!(peer->path_attrs = malloc(peer->path_attr_len)))
    {
	LOG(0, 0, 0, "Can't allocate path_attrs for %s (%s)\n",
	    name, strerror(errno));

	return 0;
    }

    memcpy(peer->path_attrs, path_attrs, peer->path_attr_len);

    LOG(4, 0, 0, "Initiating BGP connection to %s (routing %s)\n",
	name, enable ? "enabled" : "suspended");

    /* we have at least one peer configured */
    bgp_configured = 1;

    /* connect */
    return bgp_connect(peer);
}

/* clear counters, timers, routes and buffers; close socket; move to
   next_state, which may be Disabled or Idle */
static void bgp_clear(struct bgp_peer *peer)
{
    if (peer->sock != -1)
    {
    	close(peer->sock);
	peer->sock = -1;
    }

    peer->keepalive_time = 0;
    peer->expire_time = 0;

    peer->keepalive = peer->init_keepalive;
    peer->hold = peer->init_hold;

    bgp_free_routes(peer->routes);
    peer->routes = 0;

    peer->outbuf->packet.header.len = 0;
    peer->outbuf->done = 0;
    peer->inbuf->packet.header.len = 0;
    peer->inbuf->done = 0;

    peer->cli_flag = 0;
    peer->events = 0;

    if (peer->state != peer->next_state)
    {
	peer->state = peer->next_state;
	peer->state_time = time_now;

	LOG(4, 0, 0, "BGP peer %s: state %s\n", peer->name,
	    bgp_state_str(peer->next_state));
    }
}

/* initiate a clean shutdown */
void bgp_stop(struct bgp_peer *peer)
{
    LOG(4, 0, 0, "Terminating BGP connection to %s\n", peer->name);
    bgp_send_notification(peer, BGP_ERR_CEASE, 0);
}

/* drop connection (if any) and set state to Disabled */
void bgp_halt(struct bgp_peer *peer)
{
    LOG(4, 0, 0, "Aborting BGP connection to %s\n", peer->name);
    peer->next_state = Disabled;
    bgp_clear(peer);
}

/* drop connection (if any) and set to Idle for connection retry */
int bgp_restart(struct bgp_peer *peer)
{
    peer->next_state = Idle;
    bgp_clear(peer);

    /* restart now */
    peer->retry_time = time_now;
    peer->retry_count = 0;

    /* connect */
    return bgp_connect(peer);
}

static void bgp_set_retry(struct bgp_peer *peer)
{
    if (peer->retry_count++ < BGP_MAX_RETRY)
    {
	peer->retry_time = time_now + (BGP_RETRY_BACKOFF * peer->retry_count);
	peer->next_state = Idle;
	bgp_clear(peer);
    }
    else
    	bgp_halt(peer); /* give up */
}

/* convert ip/mask to CIDR notation */
static void bgp_cidr(in_addr_t ip, in_addr_t mask, struct bgp_ip_prefix *pfx)
{
    int i;
    uint32_t b;

    /* convert to prefix notation */
    pfx->len = 32;
    pfx->prefix = ip;

    if (!mask) /* bogus */
	mask = 0xffffffff;

    for (i = 0; i < 32 && ((b = ntohl(1 << i)), !(mask & b)); i++)
    {
	pfx->len--;
	pfx->prefix &= ~b;
    }
}

/* insert route into list; sorted */
static struct bgp_route_list *bgp_insert_route(struct bgp_route_list *head,
    struct bgp_route_list *new)
{
    struct bgp_route_list *p = head;
    struct bgp_route_list *e = 0;

    while (p && memcmp(&p->dest, &new->dest, sizeof(p->dest)) < 0)
    {
	e = p;
	p = p->next;
    }

    if (e)
    {
	new->next = e->next;
	e->next = new;
    }
    else
    {
	new->next = head;
	head = new;
    }

    return head;
}

/* add route to list for peers */
/*
 * Note:  this doesn't do route aggregation, nor drop routes if a less
 * specific match already exists (partly because I'm lazy, but also so
 * that if that route is later deleted we don't have to be concerned
 * about adding back the more specific one).
 */
int bgp_add_route(in_addr_t ip, in_addr_t mask)
{
    struct bgp_route_list *r = bgp_routes;
    struct bgp_route_list add;
    int i;

    bgp_cidr(ip, mask, &add.dest);
    add.next = 0;

    /* check for duplicate */
    while (r)
    {
	i = memcmp(&r->dest, &add.dest, sizeof(r->dest));
	if (!i)
	    return 1; /* already covered */

	if (i > 0)
	    break;

	r = r->next;
    }

    /* insert into route list; sorted */
    if (!(r = malloc(sizeof(*r))))
    {
	LOG(0, 0, 0, "Can't allocate route for %s/%d (%s)\n",
	    fmtaddr(add.dest.prefix, 0), add.dest.len, strerror(errno));

	return 0;
    }

    memcpy(r, &add, sizeof(*r));
    bgp_routes = bgp_insert_route(bgp_routes, r);

    /* flag established peers for update */
    for (i = 0; i < BGP_NUM_PEERS; i++)
	if (bgp_peers[i].state == Established)
	    bgp_peers[i].update_routes = 1;

    LOG(4, 0, 0, "Registered BGP route %s/%d\n",
	fmtaddr(add.dest.prefix, 0), add.dest.len);

    return 1;
}

/* remove route from list for peers */
int bgp_del_route(in_addr_t ip, in_addr_t mask)
{
    struct bgp_route_list *r = bgp_routes;
    struct bgp_route_list *e = 0;
    struct bgp_route_list del;
    int i;

    bgp_cidr(ip, mask, &del.dest);
    del.next = 0;

    /* find entry in routes list and remove */
    while (r)
    {
	i = memcmp(&r->dest, &del.dest, sizeof(r->dest));
	if (!i)
	{
	    if (e)
		e->next = r->next;
	    else
	    	bgp_routes = r->next;

	    free(r);
	    break;
	}

	e = r;

	if (i > 0)
	    r = 0; /* stop */
	else
	    r = r->next;
    }

    /* not found */
    if (!r)
	return 1;

    /* flag established peers for update */
    for (i = 0; i < BGP_NUM_PEERS; i++)
	if (bgp_peers[i].state == Established)
	    bgp_peers[i].update_routes = 1;

    LOG(4, 0, 0, "Removed BGP route %s/%d\n",
	fmtaddr(del.dest.prefix, 0), del.dest.len);

    return 1;
}

/* enable or disable routing */
void bgp_enable_routing(int enable)
{
    int i;

    for (i = 0; i < BGP_NUM_PEERS; i++)
    {
	bgp_peers[i].routing = enable;

	/* flag established peers for update */
	if (bgp_peers[i].state == Established)
	    bgp_peers[i].update_routes = 1;
    }

    LOG(4, 0, 0, "%s BGP routing\n", enable ? "Enabled" : "Suspended");
}

#ifdef HAVE_EPOLL
# include <sys/epoll.h>
#else
# include "fake_epoll.h"
#endif

/* return a bitmask of the events required to poll this peer's fd */
int bgp_set_poll()
{
    int i;

    if (!bgp_configured)
    	return 0;

    for (i = 0; i < BGP_NUM_PEERS; i++)
    {
	struct bgp_peer *peer = &bgp_peers[i];
	int events = 0;

	if (peer->state == Disabled || peer->state == Idle)
	    continue;

	if (peer->inbuf->done < BGP_MAX_PACKET_SIZE)
	    events |= EPOLLIN;

	if (peer->state == Connect ||		/* connection in progress */
	    peer->update_routes ||		/* routing updates */
	    peer->outbuf->packet.header.len)	/* pending output */
	    events |= EPOLLOUT;

    	if (peer->events != events)
	{
	    struct epoll_event ev;

	    ev.events = peer->events = events;
	    ev.data.ptr = &peer->edata;
	    epoll_ctl(epollfd, EPOLL_CTL_MOD, peer->sock, &ev);
	}
    }

    return 1;
}

/* process bgp events/timers */
int bgp_process(uint32_t events[])
{
    int i;

    if (!bgp_configured)
    	return 0;

    for (i = 0; i < BGP_NUM_PEERS; i++)
    {
	struct bgp_peer *peer = &bgp_peers[i];

	if (*peer->name && peer->cli_flag == BGP_CLI_RESTART)
	{
	    bgp_restart(peer);
	    continue;
	}

	if (peer->state == Disabled)
	    continue;

	if (peer->cli_flag)
	{
	    switch (peer->cli_flag)
	    {
	    case BGP_CLI_SUSPEND:
		if (peer->routing)
		{
		    peer->routing = 0;
		    if (peer->state == Established)
			peer->update_routes = 1;
		}

		break;

	    case BGP_CLI_ENABLE:
		if (!peer->routing)
		{
		    peer->routing = 1;
		    if (peer->state == Established)
			peer->update_routes = 1;
		}

		break;
	    }

	    peer->cli_flag = 0;
	}

	/* handle empty/fill of buffers */
	if (events[i] & EPOLLOUT)
	{
	    int r = 1;
	    if (peer->state == Connect)
		r = bgp_handle_connect(peer);
	    else if (peer->outbuf->packet.header.len)
		r = bgp_write(peer);

	    if (!r)
		continue;
	}

	if (events[i] & (EPOLLIN|EPOLLHUP))
	{
	    if (!bgp_read(peer))
		continue;
	}

	/* process input buffer contents */
	while (peer->inbuf->done >= sizeof(peer->inbuf->packet.header)
	    && !peer->outbuf->packet.header.len) /* may need to queue a response */
	{
	    if (bgp_handle_input(peer) < 0)
		continue;
	}

	/* process pending updates */
	if (peer->update_routes
	    && !peer->outbuf->packet.header.len) /* ditto */
	{
	    if (!bgp_send_update(peer))
		continue;
	}

	/* process timers */
	if (peer->state == Established)
	{
	    if (time_now > peer->expire_time)
	    {
		LOG(1, 0, 0, "No message from BGP peer %s in %ds\n",
		    peer->name, peer->hold);

		bgp_send_notification(peer, BGP_ERR_HOLD_TIMER_EXP, 0);
		continue;
	    }

	    if (time_now > peer->keepalive_time && !peer->outbuf->packet.header.len)
		bgp_send_keepalive(peer);
	}
	else if (peer->state == Idle)
	{
	    if (time_now > peer->retry_time)
		bgp_connect(peer);
	}
	else if (time_now > peer->state_time + BGP_STATE_TIME)
	{
	    LOG(1, 0, 0, "%s timer expired for BGP peer %s\n",
		bgp_state_str(peer->state), peer->name);

	    bgp_restart(peer);
	}
    }

    return 1;
}

static void bgp_free_routes(struct bgp_route_list *routes)
{
    struct bgp_route_list *tmp;

    while ((tmp = routes))
    {
	routes = tmp->next;
	free(tmp);
    }
}

char const *bgp_state_str(enum bgp_state state)
{
    switch (state)
    {
    case Disabled:	return "Disabled";
    case Idle:		return "Idle";
    case Connect:	return "Connect";
    case Active:	return "Active";
    case OpenSent:	return "OpenSent";
    case OpenConfirm:	return "OpenConfirm";
    case Established:	return "Established";
    }

    return "?";
}

static char const *bgp_msg_type_str(uint8_t type)
{
    switch (type)
    {
    case BGP_MSG_OPEN:		return "OPEN";
    case BGP_MSG_UPDATE:	return "UPDATE";
    case BGP_MSG_NOTIFICATION:	return "NOTIFICATION";
    case BGP_MSG_KEEPALIVE:	return "KEEPALIVE";
    }

    return "?";
}

/* attempt to connect to peer */
static int bgp_connect(struct bgp_peer *peer)
{
    static int bgp_port = 0;
    struct sockaddr_in addr;
    struct epoll_event ev;

    if (!bgp_port)
    {
	struct servent *serv;
	if (!(serv = getservbyname("bgp", "tcp")))
	{
	    LOG(0, 0, 0, "Can't get bgp service (%s)\n", strerror(errno));
	    return 0;
	}

	bgp_port = serv->s_port;
    }

    if ((peer->sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
	LOG(0, 0, 0, "Can't create a socket for BGP peer %s (%s)\n",
	    peer->name, strerror(errno));

	peer->state = peer->next_state = Disabled;
	return 0;
    }

    /* add to poll set */
    ev.events = peer->events = EPOLLOUT;
    ev.data.ptr = &peer->edata;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, peer->sock, &ev);

    /* set to non-blocking */
    fcntl(peer->sock, F_SETFL, fcntl(peer->sock, F_GETFL, 0) | O_NONBLOCK);

    /* try connect */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = bgp_port;
    addr.sin_addr.s_addr = peer->addr;

    while (connect(peer->sock, (struct sockaddr *) &addr, sizeof(addr)) == -1)
    {
	if (errno == EINTR) /* SIGALARM handler */
	    continue;

	if (errno != EINPROGRESS)
	{
	    LOG(1, 0, 0, "Can't connect to BGP peer %s (%s)\n",
		inet_ntoa(addr.sin_addr), strerror(errno));

	    bgp_set_retry(peer);
	    return 0;
	}

	peer->state = Connect;
	peer->state_time = time_now;

	LOG(4, 0, 0, "BGP peer %s: state Connect\n", peer->name);
	return 1;
    }

    peer->state = Active;
    peer->state_time = time_now;
    peer->retry_time = peer->retry_count = 0;

    LOG(4, 0, 0, "BGP peer %s: state Active\n", inet_ntoa(addr.sin_addr));

    return bgp_send_open(peer);
}

/* complete partial connection (state = Connect) */
static int bgp_handle_connect(struct bgp_peer *peer)
{
    int err = 0;
    socklen_t len = sizeof(int);
    getsockopt(peer->sock, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err)
    {
	LOG(1, 0, 0, "Can't connect to BGP peer %s (%s)\n", peer->name,
	    strerror(err));

	bgp_set_retry(peer);
	return 0;
    }

    peer->state = Active;
    peer->state_time = time_now;

    LOG(4, 0, 0, "BGP peer %s: state Active\n", peer->name);

    return bgp_send_open(peer);
}

/* initiate a write */
static int bgp_write(struct bgp_peer *peer)
{
    int len = htons(peer->outbuf->packet.header.len);
    int r;

    while ((r = write(peer->sock, &peer->outbuf->packet + peer->outbuf->done,
	len - peer->outbuf->done)) == -1)
    {
	if (errno == EINTR)
	    continue;

	if (errno == EAGAIN)
	    return 1;

	if (errno == EPIPE)
	    LOG(1, 0, 0, "Connection to BGP peer %s closed\n", peer->name);
	else
	    LOG(1, 0, 0, "Can't write to BGP peer %s (%s)\n", peer->name,
		strerror(errno));

	bgp_set_retry(peer);
	return 0;
    }

    if (r < len)
    {
	peer->outbuf->done += r;
	return 1;
    }

    LOG(4, 0, 0, "Sent %s to BGP peer %s\n",
	bgp_msg_type_str(peer->outbuf->packet.header.type), peer->name);

    peer->outbuf->packet.header.len = 0;
    peer->outbuf->done = 0;

    if (peer->state == Established)
	peer->keepalive_time = time_now + peer->keepalive;

    if (peer->state != peer->next_state)
    {
	if (peer->next_state == Disabled || peer->next_state == Idle)
	{
	    bgp_clear(peer);
	    return 0;
	}

	peer->state = peer->next_state;
	peer->state_time = time_now;

	LOG(4, 0, 0, "BGP peer %s: state %s\n", peer->name,
	    bgp_state_str(peer->state));
    }

    return 1;
}

/* initiate a read */
static int bgp_read(struct bgp_peer *peer)
{
    int r;

    while ((r = read(peer->sock, &peer->inbuf->packet + peer->inbuf->done,
	BGP_MAX_PACKET_SIZE - peer->inbuf->done)) < 1)
    {
	if (!r)
	{
	    LOG(1, 0, 0, "Connection to BGP peer %s closed\n", peer->name);
	}
	else
	{
	    if (errno == EINTR)
		continue;

	    if (errno == EAGAIN)
		return 1;

	    LOG(1, 0, 0, "Can't read from BGP peer %s (%s)\n", peer->name,
		strerror(errno));
	}

	bgp_set_retry(peer);
	return 0;
    }

    peer->inbuf->done += r;
    return 1;
}

/* process buffered packets */
static int bgp_handle_input(struct bgp_peer *peer)
{
    struct bgp_packet *p = &peer->inbuf->packet;
    int len = ntohs(p->header.len);

    if (len > BGP_MAX_PACKET_SIZE)
    {
	LOG(1, 0, 0, "Bad header length from BGP %s\n", peer->name);
	bgp_send_notification(peer, BGP_ERR_HEADER, BGP_ERR_HDR_BAD_LEN);
	return 0;
    }

    if (peer->inbuf->done < len)
	return 0;

    LOG(4, 0, 0, "Received %s from BGP peer %s\n",
	bgp_msg_type_str(p->header.type), peer->name);

    switch (p->header.type)
    {
    case BGP_MSG_OPEN:
	{
	    struct bgp_data_open data;
	    int hold;
	    int i;

	    for (i = 0; i < sizeof(p->header.marker); i++)
	    {
		if ((unsigned char) p->header.marker[i] != 0xff)
		{
		    LOG(1, 0, 0, "Invalid marker from BGP peer %s\n",
			peer->name);

		    bgp_send_notification(peer, BGP_ERR_HEADER,
			BGP_ERR_HDR_NOT_SYNC);

		    return 0;
		}
	    }

	    if (peer->state != OpenSent)
	    {
		LOG(1, 0, 0, "OPEN from BGP peer %s in %s state\n",
		    peer->name, bgp_state_str(peer->state));

		bgp_send_notification(peer, BGP_ERR_FSM, 0);
		return 0;
	    }

	    memcpy(&data, p->data, len - sizeof(p->header));

	    if (data.version != BGP_VERSION)
	    {
		LOG(1, 0, 0, "Bad version (%d) sent by BGP peer %s\n",
		    (int) data.version, peer->name);

		bgp_send_notification(peer, BGP_ERR_OPEN, BGP_ERR_OPN_VERSION);
		return 0;
	    }

	    if (ntohs(data.as) != peer->as)
	    {
		LOG(1, 0, 0, "Bad AS sent by BGP peer %s (got %d, "
		    "expected %d)\n", peer->name, (int) htons(data.as),
		    (int) peer->as);

		bgp_send_notification(peer, BGP_ERR_OPEN, BGP_ERR_OPN_BAD_AS);
		return 0;
	    }

	    if ((hold = ntohs(data.hold_time)) < 3)
	    {
		LOG(1, 0, 0, "Bad hold time (%d) from BGP peer %s\n",
		    hold, peer->name);

		bgp_send_notification(peer, BGP_ERR_OPEN, BGP_ERR_OPN_HOLD_TIME);
		return 0;
	    }

	    /* pick lowest hold time */
	    if (hold < peer->hold)
	    	peer->hold = hold;

	    /* adjust our keepalive based on negotiated hold value */
	    if (peer->keepalive * 3 > peer->hold)
		peer->keepalive = peer->hold / 3;

	    /* next transition requires an exchange of keepalives */
	    bgp_send_keepalive(peer);

	    /* FIXME: may need to check for optional params */
	}

	break;

    case BGP_MSG_KEEPALIVE:
	if (peer->state == OpenConfirm)
	{
	    peer->state = peer->next_state = Established;
	    peer->state_time = time_now;
	    peer->keepalive_time = time_now + peer->keepalive;
	    peer->update_routes = 1;
	    peer->retry_count = 0;
	    peer->retry_time = 0;

	    LOG(4, 0, 0, "BGP peer %s: state Established\n", peer->name);
	}

	break;

    case BGP_MSG_NOTIFICATION:
	if (len > sizeof(p->header))
	{
	    struct bgp_data_notification *notification =
		(struct bgp_data_notification *) p->data;

	    if (notification->error_code == BGP_ERR_CEASE)
	    {
		LOG(4, 0, 0, "BGP peer %s sent CEASE\n", peer->name);
		bgp_restart(peer);
		return 0;
	    }

	    /* FIXME: should handle more notifications */
	    LOG(4, 0, 0, "BGP peer %s sent unhandled NOTIFICATION %d\n",
		peer->name, (int) notification->error_code);
	}

	break;
    }

    /* reset timer */
    peer->expire_time = time_now + peer->hold;

    /* see if there's another message in the same packet/buffer */
    if (peer->inbuf->done > len)
    {
	peer->inbuf->done -= len;
	memmove(p, (char *) p + len, peer->inbuf->done);
    }
    else
    {
	peer->inbuf->packet.header.len = 0;
	peer->inbuf->done = 0;
    }

    return peer->inbuf->done;
}

/* send/buffer OPEN message */
static int bgp_send_open(struct bgp_peer *peer)
{
    struct bgp_data_open data;
    uint16_t len = sizeof(peer->outbuf->packet.header);

    memset(peer->outbuf->packet.header.marker, 0xff,
	sizeof(peer->outbuf->packet.header.marker));

    peer->outbuf->packet.header.type = BGP_MSG_OPEN;

    data.version = BGP_VERSION;
    data.as = htons(our_as);
    data.hold_time = htons(peer->hold);
    data.identifier = my_address;
    data.opt_len = 0;

    memcpy(peer->outbuf->packet.data, &data, BGP_DATA_OPEN_SIZE);
    len += BGP_DATA_OPEN_SIZE;

    peer->outbuf->packet.header.len = htons(len);
    peer->outbuf->done = 0;
    peer->next_state = OpenSent;

    return bgp_write(peer);
}

/* send/buffer KEEPALIVE message */
static int bgp_send_keepalive(struct bgp_peer *peer)
{
    memset(peer->outbuf->packet.header.marker, 0xff,
	sizeof(peer->outbuf->packet.header.marker));

    peer->outbuf->packet.header.type = BGP_MSG_KEEPALIVE;
    peer->outbuf->packet.header.len =
	htons(sizeof(peer->outbuf->packet.header));

    peer->outbuf->done = 0;
    peer->next_state = (peer->state == OpenSent) ? OpenConfirm : peer->state;

    return bgp_write(peer);
}

/* send/buffer UPDATE message */
static int bgp_send_update(struct bgp_peer *peer)
{
    uint16_t unf_len = 0;
    uint16_t attr_len;
    uint16_t len = sizeof(peer->outbuf->packet.header);
    struct bgp_route_list *have = peer->routes;
    struct bgp_route_list *want = peer->routing ? bgp_routes : 0;
    struct bgp_route_list *e = 0;
    struct bgp_route_list *add = 0;
    int s;

    char *data = (char *) &peer->outbuf->packet.data;

    /* need leave room for attr_len, bgp_path_attrs and one prefix */
    char *max = (char *) &peer->outbuf->packet.data
	+ sizeof(peer->outbuf->packet.data)
	- sizeof(attr_len) - peer->path_attr_len - sizeof(struct bgp_ip_prefix);

    /* skip over unf_len */
    data += sizeof(unf_len);
    len += sizeof(unf_len);

    memset(peer->outbuf->packet.header.marker, 0xff,
	sizeof(peer->outbuf->packet.header.marker));

    peer->outbuf->packet.header.type = BGP_MSG_UPDATE;

    peer->update_routes = 0; /* tentatively clear */

    /* find differences */
    while ((have || want) && data < (max - sizeof(struct bgp_ip_prefix)))
    {
	if (have)
	    s = want
		? memcmp(&have->dest, &want->dest, sizeof(have->dest))
	    	: -1;
	else
	    s = 1;

	if (s < 0) /* found one to delete */
	{
	    struct bgp_route_list *tmp = have;
	    have = have->next;

	    s = BGP_IP_PREFIX_SIZE(tmp->dest);
	    memcpy(data, &tmp->dest, s);
	    data += s;
	    unf_len += s;
	    len += s;

	    LOG(5, 0, 0, "Withdrawing route %s/%d from BGP peer %s\n",
		fmtaddr(tmp->dest.prefix, 0), tmp->dest.len, peer->name);

	    free(tmp);

	    if (e)
		e->next = have;
	    else
	    	peer->routes = have;
	}
	else
	{
	    if (!s) /* same */
	    {
		e = have; /* stash the last found to relink above */
		have = have->next;
		want = want->next;
	    }
	    else if (s > 0) /* addition reqd. */
	    {
		if (add)
		{
		    peer->update_routes = 1; /* only one add per packet */
		    if (!have)
		    	break;
		}
		else
		    add = want;

		if (want)
		    want = want->next;
	    }
	}
    }

    if (have || want)
	peer->update_routes = 1; /* more to do */

    /* anything changed? */
    if (!(unf_len || add))
	return 1;

    /* go back and insert unf_len */
    unf_len = htons(unf_len);
    memcpy(&peer->outbuf->packet.data, &unf_len, sizeof(unf_len));

    if (add)
    {
	if (!(e = malloc(sizeof(*e))))
	{
	    LOG(0, 0, 0, "Can't allocate route for %s/%d (%s)\n",
		fmtaddr(add->dest.prefix, 0), add->dest.len, strerror(errno));

	    return 0;
	}

	memcpy(e, add, sizeof(*e));
	e->next = 0;
	peer->routes = bgp_insert_route(peer->routes, e);

	attr_len = htons(peer->path_attr_len);
	memcpy(data, &attr_len, sizeof(attr_len));
	data += sizeof(attr_len);
	len += sizeof(attr_len);

	memcpy(data, peer->path_attrs, peer->path_attr_len);
	data += peer->path_attr_len;
	len += peer->path_attr_len;

	s = BGP_IP_PREFIX_SIZE(add->dest);
	memcpy(data, &add->dest, s);
	data += s;
	len += s;

	LOG(5, 0, 0, "Advertising route %s/%d to BGP peer %s\n",
	    fmtaddr(add->dest.prefix, 0), add->dest.len, peer->name);
    }
    else
    {
	attr_len = 0;
	memcpy(data, &attr_len, sizeof(attr_len));
	data += sizeof(attr_len);
	len += sizeof(attr_len);
    }

    peer->outbuf->packet.header.len = htons(len);
    peer->outbuf->done = 0;

    return bgp_write(peer);
}

/* send/buffer NOTIFICATION message */
static int bgp_send_notification(struct bgp_peer *peer, uint8_t code,
    uint8_t subcode)
{
    struct bgp_data_notification data;
    uint16_t len = 0;

    data.error_code = code;
    len += sizeof(data.error_code);

    data.error_subcode = subcode;
    len += sizeof(data.error_code);

    memset(peer->outbuf->packet.header.marker, 0xff,
	sizeof(peer->outbuf->packet.header.marker));

    peer->outbuf->packet.header.type = BGP_MSG_NOTIFICATION;
    peer->outbuf->packet.header.len =
	htons(sizeof(peer->outbuf->packet.header) + len);

    memcpy(peer->outbuf->packet.data, &data, len);

    peer->outbuf->done = 0;
    peer->next_state = code == BGP_ERR_CEASE ? Disabled : Idle;

    /* we're dying; ignore any pending input */
    peer->inbuf->packet.header.len = 0;
    peer->inbuf->done = 0;

    return bgp_write(peer);
}
