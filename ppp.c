// L2TPNS PPP Stuff

char const *cvs_id_ppp = "$Id: ppp.c,v 1.32 2004-11-28 20:10:04 bodea Exp $";

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include "l2tpns.h"
#include "constants.h"
#include "plugin.h"
#include "util.h"
#include "tbf.h"
#include "cluster.h"

extern tunnelt *tunnel;
extern sessiont *session;
extern radiust *radius;
extern int tunfd;
extern char hostname[];
extern u32 eth_tx;
extern time_t time_now;
extern configt *config;

static void initccp(tunnelidt t, sessionidt s);

// Process PAP messages
void processpap(tunnelidt t, sessionidt s, u8 *p, u16 l)
{
	char user[129];
	char pass[129];
	u16 hl;

	CSTAT(call_processpap);

	LOG_HEX(5, "PAP", p, l);
	if (l < 4)
	{
		LOG(1, 0, s, t, "Short PAP %u bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	if ((hl = ntohs(*(u16 *) (p + 2))) > l)
	{
		LOG(1, 0, s, t, "Length mismatch PAP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		return ;
	}
	l = hl;

	if (*p != 1)
	{
		LOG(1, 0, s, t, "Unexpected PAP code %d\n", *p);
		STAT(tunnel_rx_errors);
		return ;
	}

	{
		u8 *b = p;
		b += 4;
		if (*b && *b < sizeof(user))
			memcpy(user, b + 1, *b);
		user[*b] = 0;
		b += 1 + *b;
		if (*b && *b < sizeof(pass))
			memcpy(pass, b + 1, *b);
		pass[*b] = 0;
		LOG(3, 0, s, t, "PAP login %s/%s\n", user, pass);
	}
	if (session[s].ip || !session[s].radius)
	{
		// respond now, either no RADIUS available or already authenticated
		u8 b[MAXCONTROL];
		u8 id = p[1];
		u8 *p = makeppp(b, sizeof(b), 0, 0, t, s, PPPPAP);
		if (!p) return;

		if (session[s].ip)
			*p = 2;			// ACK
		else
			*p = 3;			// cant authorise
		p[1] = id;
		*(u16 *) (p + 2) = htons(5);	// length
		p[4] = 0;			// no message
		if (session[s].ip)
		{
			LOG(3, session[s].ip, s, t, "Already an IP allocated: %s (%d)\n", inet_toa(htonl(session[s].ip)), session[s].ip_pool_index);
			session[s].flags &= ~SF_IPCP_ACKED;
		}
		else
		{
			LOG(1, 0, s, t, "No radius session available to authenticate session...\n");
		}
		LOG(3, 0, s, t, "Fallback response to PAP (%s)\n", (session[s].ip) ? "ACK" : "NAK");
		tunnelsend(b, 5 + (p - b), t); // send it
	}
	else
	{
		// set up RADIUS request
		u16 r = session[s].radius;

		// Run PRE_AUTH plugins
		struct param_pre_auth packet = { &tunnel[t], &session[s], strdup(user), strdup(pass), PPPPAP, 1 };
		run_plugins(PLUGIN_PRE_AUTH, &packet);
		if (!packet.continue_auth)
		{
			LOG(3, 0, s, t, "A plugin rejected PRE_AUTH\n");
			if (packet.username) free(packet.username);
			if (packet.password) free(packet.password);
			return;
		}

		strncpy(session[s].user, packet.username, sizeof(session[s].user) - 1);
		strncpy(radius[r].pass, packet.password, sizeof(radius[r].pass) - 1);

		free(packet.username);
		free(packet.password);

		radius[r].id = p[1];
		LOG(3, 0, s, t, "Sending login for %s/%s to radius\n", user, pass);
		radiussend(r, RADIUSAUTH);
	}
}

// Process CHAP messages
void processchap(tunnelidt t, sessionidt s, u8 *p, u16 l)
{
	u16 r;
	u16 hl;

	CSTAT(call_processchap);

	LOG_HEX(5, "CHAP", p, l);
	r = session[s].radius;
	if (!r)
	{
		LOG(1, 0, s, t, "Unexpected CHAP message\n");

// FIXME: Need to drop the session here.

		STAT(tunnel_rx_errors);
		return;
	}

	if (l < 4)
	{
		LOG(1, 0, s, t, "Short CHAP %u bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	if ((hl = ntohs(*(u16 *) (p + 2))) > l)
	{
		LOG(1, 0, s, t, "Length mismatch CHAP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		return ;
	}
	l = hl;

	if (*p != 2)
	{
		LOG(1, 0, s, t, "Unexpected CHAP response code %d\n", *p);
		STAT(tunnel_rx_errors);
		return;
	}
	if (p[1] != radius[r].id)
	{
		LOG(1, 0, s, t, "Wrong CHAP response ID %d (should be %d) (%d)\n", p[1], radius[r].id, r);
		STAT(tunnel_rx_errors);
		return ;
	}

	if (l < 5 || p[4] != 16)
	{
		LOG(1, 0, s, t, "Bad CHAP response length %d\n", l < 5 ? -1 : p[4]);
		STAT(tunnel_rx_errors);
		return ;
	}

	l -= 5;
	p += 5;
	if (l < 16 || l - 16 >= sizeof(session[s].user))
	{
		LOG(1, 0, s, t, "CHAP user too long %d\n", l - 16);
		STAT(tunnel_rx_errors);
		return ;
	}

	// Run PRE_AUTH plugins
	{
		struct param_pre_auth packet = { &tunnel[t], &session[s], NULL, NULL, PPPCHAP, 1 };

		packet.password = calloc(17, 1);
		memcpy(packet.password, p, 16);

		p += 16;
		l -= 16;

		packet.username = calloc(l + 1, 1);
		memcpy(packet.username, p, l);

		run_plugins(PLUGIN_PRE_AUTH, &packet);
		if (!packet.continue_auth)
		{
			LOG(3, 0, s, t, "A plugin rejected PRE_AUTH\n");
			if (packet.username) free(packet.username);
			if (packet.password) free(packet.password);
			return;
		}

		strncpy(session[s].user, packet.username, sizeof(session[s].user) - 1);
		memcpy(radius[r].pass, packet.password, 16);

		free(packet.username);
		free(packet.password);
	}

	radius[r].chap = 1;
	LOG(3, 0, s, t, "CHAP login %s\n", session[s].user);
	radiussend(r, RADIUSAUTH);
}

static char *ppp_lcp_types[] = {
	NULL,
	"ConfigReq",
	"ConfigAck",
	"ConfigNak",
	"ConfigRej",
	"TerminateReq",
	"TerminateAck",
	"CodeRej",
	"ProtocolRej",
	"EchoReq",
	"EchoReply",
	"DiscardRequest",
	"IdentRequest",
};

static void dumplcp(u8 *p, int l)
{
	int x = l - 4;
	u8 *o = (p + 4);

	LOG_HEX(5, "PPP LCP Packet", p, l);
	LOG(4, 0, 0, 0, "PPP LCP Packet type %d (%s len %d)\n", *p, ppp_lcp_types[(int)*p], ntohs( ((u16 *) p)[1]) );
	LOG(4, 0, 0, 0, "Length: %d\n", l);
	if (*p != ConfigReq && *p != ConfigRej && *p != ConfigAck)
		return;

	while (x > 2)
	{
		int type = o[0];
		int length = o[1];
		if (length < 2)
		{
			LOG(4, 0, 0, 0, "	Option length is %d...\n", length);
			break;
		}
		if (type == 0)
		{
			LOG(4, 0, 0, 0, "	Option type is 0...\n");
			x -= length;
			o += length;
			continue;
		}
		switch (type)
		{
			case 1: // Maximum-Receive-Unit
				if (length == 4)
					LOG(4, 0, 0, 0, "    %s %d\n", lcp_types[type], ntohs(*(u16 *)(o + 2)));
				else
					LOG(4, 0, 0, 0, "    %s odd length %d\n", lcp_types[type], length);
				break;
			case 2: // Async-Control-Character-Map
				if (length == 6)
				{
					u32 asyncmap = ntohl(*(u32 *)(o + 2));
					LOG(4, 0, 0, 0, "    %s %x\n", lcp_types[type], asyncmap);
				}
				else
					LOG(4, 0, 0, 0, "   %s odd length %d\n", lcp_types[type], length);
				break;
			case 3: // Authentication-Protocol
				if (length == 4)
				{
					int proto = ntohs(*(u16 *)(o + 2));
					LOG(4, 0, 0, 0, "   %s 0x%x (%s)\n", lcp_types[type], proto,
						proto == PPPCHAP ? "CHAP" :
						proto == PPPPAP  ? "PAP"  : "UNKNOWN");
				}
				else
					LOG(4, 0, 0, 0, "   %s odd length %d\n", lcp_types[type], length);
				break;
			case 4: // Quality-Protocol
				{
					u32 qp = ntohl(*(u32 *)(o + 2));
					LOG(4, 0, 0, 0, "    %s %x\n", lcp_types[type], qp);
				}
				break;
			case 5: // Magic-Number
				if (length == 6)
				{
					u32 magicno = ntohl(*(u32 *)(o + 2));
					LOG(4, 0, 0, 0, "    %s %x\n", lcp_types[type], magicno);
				}
				else
					LOG(4, 0, 0, 0, "   %s odd length %d\n", lcp_types[type], length);
				break;
			case 7: // Protocol-Field-Compression
			case 8: // Address-And-Control-Field-Compression
				LOG(4, 0, 0, 0, "    %s\n", lcp_types[type]);
				break;
			default:
				LOG(2, 0, 0, 0, "    Unknown PPP LCP Option type %d\n", type);
				break;
		}
		x -= length;
		o += length;
	}
}

// Process LCP messages
void processlcp(tunnelidt t, sessionidt s, u8 *p, u16 l)
{
	u8 b[MAXCONTROL];
	u8 *q = NULL;
	u32 magicno = 0;
	u16 hl;

	CSTAT(call_processlcp);

	LOG_HEX(5, "LCP", p, l);
	if (l < 4)
	{
		LOG(1, session[s].ip, s, t, "Short LCP %d bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	if ((hl = ntohs(*(u16 *) (p + 2))) > l)
	{
		LOG(1, 0, s, t, "Length mismatch LCP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		return ;
	}
	l = hl;

	if (*p == ConfigAck)
	{
		LOG(3, session[s].ip, s, t, "LCP: Discarding ConfigAck\n");
		session[s].flags |= SF_LCP_ACKED;
	}
	else if (*p == ConfigReq)
	{
		int x = l - 4;
		u8 *o = (p + 4);
		u8 response = 0;

		LOG(3, session[s].ip, s, t, "LCP: ConfigReq (%d bytes)...\n", l);
		if (config->debug > 3) dumplcp(p, l);

		while (x > 2)
		{
			int type = o[0];
			int length = o[1];
			if (length == 0 || type == 0 || x < length) break;
			switch (type)
			{
				case 1: // Maximum-Receive-Unit
					session[s].mru = ntohs(*(u16 *)(o + 2));
					break;

				case 2: // Async-Control-Character-Map
					if (!ntohl(*(u32 *)(o + 2))) // all bits zero is OK
						break;

					if (response && response != ConfigNak) // rej already queued
						break;

					LOG(2, session[s].ip, s, t, "    Remote requesting asyncmap.  Rejecting.\n");
					if (!response)
					{
						q = makeppp(b, sizeof(b), NULL, 0, t, s, PPPLCP);
						if (!q) break;
						response = *q++ = ConfigNak;
					}

					if ((q - b + 11) > sizeof(b))
					{
						LOG(2, session[s].ip, s, t, "LCP overflow for asyncmap ConfigNak.\n");
						break;
					}

					*q++ = type;
					*q++ = 6;
					memset(q, 0, 4); // asyncmap 0
					q += 4;
					break;

				case 3: // Authentication-Protocol
					{
						int proto = ntohs(*(u16 *)(o + 2));
						char proto_name[] = "0x0000";
						if (proto == PPPPAP)
							break;

						if (response && response != ConfigNak) // rej already queued
							break;

						if (proto == PPPCHAP)
							strcpy(proto_name, "CHAP");
						else
							sprintf(proto_name, "%#4.4x", proto);

						LOG(2, session[s].ip, s, t, "    Remote requesting %s authentication.  Rejecting.\n", proto_name);

						if (!response)
						{
							q = makeppp(b, sizeof(b), NULL, 0, t, s, PPPLCP);
							if (!q) break;
							response = *q++ = ConfigNak;
						}

						if ((q - b + length) > sizeof(b))
						{
							LOG(2, session[s].ip, s, t, "LCP overflow for %s ConfigNak.\n", proto_name);
							break;
						}

						memcpy(q, o, length);
						*(u16 *)(q += 2) = htons(PPPPAP); // NAK -> Use PAP instead
						q += length;
					}
					break;

				case 5: // Magic-Number
					magicno = ntohl(*(u32 *)(o + 2));
					break;

				case 4: // Quality-Protocol
				case 7: // Protocol-Field-Compression
				case 8: // Address-And-Control-Field-Compression
					break;

				default: // Reject any unknown options
					LOG(2, session[s].ip, s, t, "    Rejecting PPP LCP Option type %d\n", type);
					if (!response || response != ConfigRej) // drop nak in favour of rej
					{
						q = makeppp(b, sizeof(b), NULL, 0, t, s, PPPLCP);
						if (!q) return;
						response = *q++ = ConfigRej;
					}

					if ((q - b + length) > sizeof(b))
					{
						LOG(2, session[s].ip, s, t, "LCP overflow for ConfigRej (type=%d).\n", type);
						break;
					}

					memcpy(q, o, length);
					q += length;
			}
			x -= length;
			o += length;
		}

		if (!response)
		{
			// Send back a ConfigAck
			q = makeppp(b, sizeof(b), p, l, t, s, PPPLCP);
			if (!q) return;
			response = *q = ConfigAck;
		}

		LOG(3, session[s].ip, s, t, "Sending %s\n", ppp_lcp_types[response]);
		tunnelsend(b, l + (q - b), t);

		if (!(session[s].flags & SF_LCP_ACKED))
			initlcp(t, s);
	}
	else if (*p == ConfigNak)
	{
		LOG(1, session[s].ip, s, t, "Remote end sent a ConfigNak.  Ignoring\n");
		if (config->debug > 3) dumplcp(p, l);
		return ;
	}
	else if (*p == TerminateReq)
	{
		LOG(3, session[s].ip, s, t, "LCP: Received TerminateReq.  Sending TerminateAck\n");
		*p = TerminateAck;	// close
		q = makeppp(b, sizeof(b),  p, l, t, s, PPPLCP);
		if (!q) return;
		tunnelsend(b, l + (q - b), t); // send it
		sessionshutdown(s, "Remote end closed connection.");
	}
	else if (*p == TerminateAck)
	{
		sessionshutdown(s, "Connection closed.");
	}
	else if (*p == EchoReq)
	{
		LOG(5, session[s].ip, s, t, "LCP: Received EchoReq.  Sending EchoReply\n");
		*p = EchoReply;		// reply
		*(u32 *) (p + 4) = htonl(session[s].magic); // our magic number
		q = makeppp(b, sizeof(b), p, l, t, s, PPPLCP);
		if (!q) return;
		tunnelsend(b, l + (q - b), t); // send it
	}
	else if (*p == EchoReply)
	{
		// Ignore it, last_packet time is set earlier than this.
	}
	else if (*p == IdentRequest)
	{
		*p = CodeRej;
		if (l > MAXCONTROL)
		{
			LOG(1, 0, s, t, "Truncated Ident Packet (length=%d) to 1400 bytes\n", l);
			l = 1400;
		}
		q = makeppp(b, sizeof(b), p, l, t, s, PPPLCP);
		if (!q) return;
		LOG_HEX(5, "LCPIdentRej", q, l + 4);
		tunnelsend(b, 12 + 4 + l, t);
	}
	else
	{
		LOG(1, session[s].ip, s, t, "Unexpected LCP code %d\n", *p);
		STAT(tunnel_rx_errors);
		return ;
	}
}

// find a PPP option, returns point to option, or 0 if not found
static u8 *findppp(u8 *b, u8 mtype)
{
	u16 l = ntohs(*(u16 *) (b + 2));
	if (l < 4)
		return 0;
	b += 4;
	l -= 4;
	while (l)
	{
		if (l < b[1] || !b[1])
			return 0;		// faulty
		if (*b == mtype)
			return b;
		l -= b[1];
		b += b[1];
	}
	return 0;
}

// Process IPCP messages
void processipcp(tunnelidt t, sessionidt s, u8 *p, u16 l)
{
	u16 hl;

	CSTAT(call_processipcp);

	LOG_HEX(5, "IPCP", p, l);
	if (l < 5)
	{
		LOG(1, 0, s, t, "Short IPCP %d bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	if ((hl = ntohs(*(u16 *) (p + 2))) > l)
	{
		LOG(1, 0, s, t, "Length mismatch IPCP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		return ;
	}
	l = hl;

	if (*p == ConfigAck)
	{
		// happy with our IPCP
		u16 r = session[s].radius;
		if ((!r || radius[r].state == RADIUSIPCP) && !session[s].walled_garden)
		{
			if (!r)
				r = radiusnew(s);
			if (r)
				radiussend(r, RADIUSSTART); // send radius start, having got IPCP at last
		}
		session[s].flags |= SF_IPCP_ACKED;

		LOG(3, session[s].ip, s, t, "IPCP Acked, session is now active\n");

		// clear LCP_ACKED/CCP_ACKED flag for possible fast renegotiaion for routers
		session[s].flags &= ~(SF_LCP_ACKED|SF_CCP_ACKED);

		return;
	}
	if (*p != ConfigReq)
	{
		LOG(1, 0, s, t, "Unexpected IPCP code %d\n", *p);
		STAT(tunnel_rx_errors);
		return ;
	}
	LOG(4, session[s].ip, s, t, "IPCP ConfigReq received\n");

	if (!session[s].ip)
	{
		LOG(3, 0, s, t, "Waiting on radius reply\n");
		return;			// have to wait on RADIUS reply
	}
	// form a config reply quoting the IP in the session
	{
		u8 b[MAXCONTROL];
		u8 *i,
		*q;

		q = p + 4;
		i = p + l;
		while (q < i && q[1])
		{
			if (*q != 0x81 && *q != 0x83 && *q != 3)
				break;
			q += q[1];
		}
		if (q < i)
		{
			// reject
			u16 n = 4;
			i = p + l;
			if (!(q = makeppp(b, sizeof(b), p, l, t, s, PPPIPCP)))
				return;

			*q = ConfigRej;
			p += 4;
			while (p < i && p[1])
			{
				if (*p != 0x81 && *p != 0x83 && *p != 3)
				{
					LOG(2, 0, s, t, "IPCP reject %d\n", *p);
					memcpy(q + n, p, p[1]);
					n += p[1];
				}
				p += p[1];
			}
			*(u16 *) (q + 2) = htons(n);
			LOG(4, session[s].ip, s, t, "Sending ConfigRej\n");
			tunnelsend(b, n + (q - b), t); // send it
		}
		else
		{
			LOG(4, session[s].ip, s, t, "Sending ConfigAck\n");
			*p = ConfigAck;
			if ((i = findppp(p, 0x81))) // Primary DNS address
			{
				if (*(u32 *) (i + 2) != htonl(session[s].dns1))
				{
					*(u32 *) (i + 2) = htonl(session[s].dns1);
					*p = ConfigNak;
					LOG(5, session[s].ip, s, t, "   DNS1 = %s\n", inet_toa(session[s].dns1));
				}
			}
			if ((i = findppp(p, 0x83))) // Secondary DNS address (TBA, is it)
			{
				if (*(u32 *) (i + 2) != htonl(session[s].dns2))
				{
					*(u32 *) (i + 2) = htonl(session[s].dns2);
					*p = ConfigNak;
					LOG(5, session[s].ip, s, t, "   DNS2 = %s\n", inet_toa(session[s].dns2));
				}
			}
			i = findppp(p, 3);		// IP address
			if (!i || i[1] != 6)
			{
				LOG(1, 0, s, t, "No IP in IPCP request\n");
				STAT(tunnel_rx_errors);
				return ;
			}
			if (*(u32 *) (i + 2) != htonl(session[s].ip))
			{
				*(u32 *) (i + 2) = htonl(session[s].ip);
				*p = ConfigNak;
				LOG(4, session[s].ip, s, t, " No, a ConfigNak, client is requesting IP - sending %s\n",
						inet_toa(htonl(session[s].ip)));
			}
			if (!(q = makeppp(b, sizeof(b), p, l, t, s, PPPIPCP)))
				return;

			tunnelsend(b, l + (q - b), t); // send it
		}
	}
}

// process IP packet received
//
// This MUST be called with at least 4 byte behind 'p'.
// (i.e. this routine writes to p[-4]).
void processipin(tunnelidt t, sessionidt s, u8 *p, u16 l)
{
	ipt ip;

	CSTAT(call_processipin);

	LOG_HEX(5, "IP", p, l);

	ip = ntohl(*(u32 *)(p + 12));

	if (l > MAXETHER)
	{
		LOG(1, ip, s, t, "IP packet too long %d\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	// no spoof (do sessionbyip to handled statically routed subnets)
	if (ip != session[s].ip && sessionbyip(htonl(ip)) != s)
	{
		LOG(5, ip, s, t, "Dropping packet with spoofed IP %s\n", inet_toa(htonl(ip)));
		return;
	}

	// run access-list if any
	if (session[s].filter_in && !ip_filter(p, l, session[s].filter_in - 1))
		return;

	// Add on the tun header
	p -= 4;
	*(u32 *)p = htonl(0x00000800);
	l += 4;

	if (session[s].tbf_in && !config->cluster_iam_master) { // Are we throttled and a slave?
		master_throttle_packet(session[s].tbf_in, p, l); // Pass it to the master for handling.
		return;
	}

	if (session[s].tbf_in && config->cluster_iam_master) { // Are we throttled and a master?? actually handle the throttled packets.
		tbf_queue_packet(session[s].tbf_in, p, l);
		return;
	}

	// send to ethernet
	if (tun_write(p, l) < 0)
	{
		STAT(tun_tx_errors);
		LOG(0, 0, s, t, "Error writing %d bytes to TUN device: %s (tunfd=%d, p=%p)\n",
			l, strerror(errno), tunfd, p);

		return;
	}

	if (session[s].snoop_ip && session[s].snoop_port)
	{
		// Snooping this session
		snoop_send_packet(p + 4, l - 4, session[s].snoop_ip, session[s].snoop_port);
	}

	session[s].cin += l - 4;
	session[s].total_cin += l - 4;
	sess_count[s].cin += l - 4;

	session[s].pin++;
	eth_tx += l - 4;

	STAT(tun_tx_packets);
	INC_STAT(tun_tx_bytes, l - 4);
}

//
// Helper routine for the TBF filters.
// Used to send queued data in from the user.
//
void send_ipin(sessionidt s, u8 *buf, int len)
{
	LOG_HEX(5, "IP in throttled", buf, len);

	if (write(tunfd, buf, len) < 0)
	{
		STAT(tun_tx_errors);
		LOG(0, 0, 0, 0, "Error writing %d bytes to TUN device: %s (tunfd=%d, p=%p)\n",
			len, strerror(errno), tunfd, buf);

		return;
	}

	if (session[s].snoop_ip && session[s].snoop_port)
	{
		// Snooping this session
		snoop_send_packet(buf + 4, len - 4, session[s].snoop_ip, session[s].snoop_port);
	}

	// Increment packet counters
	session[s].cin += len - 4;
	session[s].total_cin += len - 4;
	sess_count[s].cin += len - 4;

	session[s].pin++;
	eth_tx += len - 4;

	STAT(tun_tx_packets);
	INC_STAT(tun_tx_bytes, len - 4);
}


// Process CCP messages
void processccp(tunnelidt t, sessionidt s, u8 *p, u16 l)
{
	u8 b[MAXCONTROL];
	u8 *q;

	CSTAT(call_processccp);

	LOG_HEX(5, "CCP", p, l);
	switch (l > 1 ? *p : 0)
	{
	case ConfigAck:
		session[s].flags |= SF_CCP_ACKED;
		return;

	case ConfigReq:
		if (l < 6) // accept no compression
		{
			*p = ConfigAck;
			break;
		}

		// compression requested--reject
		*p = ConfigRej;

		// send CCP request for no compression for our end if not negotiated
		if (!(session[s].flags & SF_CCP_ACKED))
			initccp(t, s);

		break;

	case TerminateReq:
	    	*p = TerminateAck;
		break;

	default:
		if (l > 1)
			LOG(1, 0, s, t, "Unexpected CCP request code %d\n", *p);
		else
			LOG(1, 0, s, t, "Short CCP packet\n");

		STAT(tunnel_rx_errors);
		return;
	}

	if (!(q = makeppp(b, sizeof(b), p, l, t, s, PPPCCP)))
		return;

	tunnelsend(b, l + (q - b), t); // send it
}

// send a CHAP PP packet
void sendchap(tunnelidt t, sessionidt s)
{
	u8 b[MAXCONTROL];
	u16 r = session[s].radius;
	u8 *q;

	CSTAT(call_sendchap);

	if (!r)
	{
		LOG(1, 0, s, t, "No RADIUS to send challenge\n");
		STAT(tunnel_tx_errors);
		return ;
	}
	LOG(1, 0, s, t, "Send CHAP challenge\n");
	{
		// new challenge
		int n;
		for (n = 0; n < 15; n++)
			radius[r].auth[n] = rand();
	}
	radius[r].chap = 1;		// CHAP not PAP
	radius[r].id++;
	if (radius[r].state != RADIUSCHAP)
		radius[r].try = 0;
	radius[r].state = RADIUSCHAP;
	radius[r].retry = backoff(radius[r].try++);
	if (radius[r].try > 5)
	{
		sessionshutdown(s, "Timeout CHAP");
		STAT(tunnel_tx_errors);
		return ;
	}
	q = makeppp(b, sizeof(b), 0, 0, t, s, PPPCHAP);
	if (!q) return;

	*q = 1;					// challenge
	q[1] = radius[r].id;			// ID
	q[4] = 16;				// length
	memcpy(q + 5, radius[r].auth, 16);	// challenge
	strcpy(q + 21, hostname);		// our name
	*(u16 *) (q + 2) = htons(strlen(hostname) + 21); // length
	tunnelsend(b, strlen(hostname) + 21 + (q - b), t); // send it
}

// fill in a L2TP message with a PPP frame,
// copies existing PPP message and changes magic number if seen
// returns start of PPP frame
u8 *makeppp(u8 *b, int size, u8 *p, int l, tunnelidt t, sessionidt s, u16 mtype)
{
	if (size < 12) // Need more space than this!!
	{
		static int backtrace_count = 0;
		LOG(0, session[s].ip, s, t, "makeppp buffer too small for L2TP header (size=%d)\n", size);
		log_backtrace(backtrace_count, 5)
		return NULL;
	}

	*(u16 *) (b + 0) = htons(0x0002); // L2TP with no options
	*(u16 *) (b + 2) = htons(tunnel[t].far); // tunnel
	*(u16 *) (b + 4) = htons(session[s].far); // session
	b += 6;
	if (mtype == PPPLCP || !(session[s].l2tp_flags & SESSIONACFC))
	{
		*(u16 *) b = htons(0xFF03); // HDLC header
		b += 2;
	}
	if (mtype < 0x100 && session[s].l2tp_flags & SESSIONPFC)
		*b++ = mtype;
	else
	{
		*(u16 *) b = htons(mtype);
		b += 2;
	}

	if (l + 12 > size)
	{
		static int backtrace_count = 0;
		LOG(2, session[s].ip, s, t, "makeppp would overflow buffer (size=%d, header+payload=%d)\n", size, l + 12);
		log_backtrace(backtrace_count, 5)
		return NULL;
	}

	if (p && l)
		memcpy(b, p, l);

	return b;
}

// Send initial LCP ConfigReq for PAP, set magic no.
void initlcp(tunnelidt t, sessionidt s)
{
	char b[500], *q;

	if (!(q = makeppp(b, sizeof(b), NULL, 0, t, s, PPPLCP)))
		return;

	LOG(4, 0, s, t, "Sending LCP ConfigReq for PAP\n");
	*q = ConfigReq;
	*(u8 *)(q + 1) = (time_now % 255) + 1; // ID
	*(u16 *)(q + 2) = htons(14); // Length
	*(u8 *)(q + 4) = 5;
	*(u8 *)(q + 5) = 6;
	*(u32 *)(q + 6) = htonl(session[s].magic);
	*(u8 *)(q + 10) = 3;
	*(u8 *)(q + 11) = 4;
	*(u16 *)(q + 12) = htons(PPPPAP); // PAP

	LOG_HEX(5, "PPPLCP", q, 14);
	tunnelsend(b, (q - b) + 14, t);
}

// Send CCP request for no compression
static void initccp(tunnelidt t, sessionidt s)
{
	char b[500], *q;

	if (!(q = makeppp(b, sizeof(b), NULL, 0, t, s, PPPCCP)))
		return;

	LOG(4, 0, s, t, "Sending CCP ConfigReq for no compression\n");
	*q = ConfigReq;
	*(u8 *)(q + 1) = (time_now % 255) + 1; // ID
	*(u16 *)(q + 2) = htons(4); // Length

	LOG_HEX(5, "PPPCCP", q, 4);
	tunnelsend(b, (q - b) + 4 , t);
}
