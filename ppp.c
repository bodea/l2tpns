// L2TPNS PPP Stuff

char const *cvs_id_ppp = "$Id: ppp.c,v 1.13 2004-08-26 04:44:26 fred_nerk Exp $";

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
extern struct configt *config;

void sendccp(tunnelidt t, sessionidt s);

// Process PAP messages
void processpap(tunnelidt t, sessionidt s, u8 * p, u16 l)
{
	char user[129];
	char pass[129];


	CSTAT(call_processpap);

	log_hex(5, "PAP", p, l);
	if (l < 4)
	{
		log(1, 0, s, t, "Short PAP %u bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (*p != 1)
	{
		log(1, 0, s, t, "Unexpected PAP code %d\n", *p);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (ntohs(*(u16 *) (p + 2)) > l)
	{
		log(1, 0, s, t, "Length mismatch PAP %d/%d\n", ntohs(*(u16 *) (p + 2)), l);
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
		log(3, 0, s, t, "PAP login %s/%s\n", user, pass);
	}
	if (session[s].ip || !session[s].radius)
	{
		// respond now, either no RADIUS available or already authenticated
		u8 b[MAXCONTROL];
		u8 id = p[1];
		u8 *p = makeppp(b, sizeof(b), 0, 0, t, s, PPPPAP);
		if (!p) {	// Failed to make ppp header!
			log(1,0,0,0, "Failed to make PPP header in process pap!\n");
			return;
		}
		if (session[s].ip)
			*p = 2;			// ACK
		else
			*p = 3;			// cant authorise
		p[1] = id;
		*(u16 *) (p + 2) = htons(5);	// length
		p[4] = 0;			// no message
		if (session[s].ip)
		{
			log(3, session[s].ip, s, t, "%d Already an IP allocated: %s (%d)\n", getpid(), inet_toa(htonl(session[s].ip)), session[s].ip_pool_index);
			session[s].flags &= ~SF_IPCP_ACKED;
		}
		else
		{
			log(1, 0, s, t, "No radius session available to authenticate session...\n");
		}
		log(3, 0, s, t, "Fallback response to PAP (%s)\n", (session[s].ip) ? "ACK" : "NAK");
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
			log(3, 0, s, t, "A plugin rejected PRE_AUTH\n");
			if (packet.username) free(packet.username);
			if (packet.password) free(packet.password);
			return;
		}

		strncpy(session[s].user, packet.username, sizeof(session[s].user) - 1);
		strncpy(radius[r].pass, packet.password, sizeof(radius[r].pass) - 1);

		free(packet.username);
		free(packet.password);

		radius[r].id = p[1];
		log(3, 0, s, t, "Sending login for %s/%s to radius\n", user, pass);
		radiussend(r, RADIUSAUTH);
	}
}

// Process CHAP messages
void processchap(tunnelidt t, sessionidt s, u8 * p, u16 l)
{
	u16 r;
	u16 len;


	CSTAT(call_processchap);

	log_hex(5, "CHAP", p, l);
	r = session[s].radius;
	if (!r)
	{
		log(1, 0, s, t, "Unexpected CHAP message\n");

// FIXME: Need to drop the session here.

		STAT(tunnel_rx_errors);
		return;
	}
	if (*p != 2)
	{
		log(1, 0, s, t, "Unexpected CHAP response code %d\n", *p);
		STAT(tunnel_rx_errors);
		return;
	}
	if (p[1] != radius[r].id)
	{
		log(1, 0, s, t, "Wrong CHAP response ID %d (should be %d) (%d)\n", p[1], radius[r].id, r);
		STAT(tunnel_rx_errors);
		return ;
	}
	len = ntohs(*(u16 *) (p + 2));
	if (len > l)
	{
		log(1, 0, s, t, "Bad CHAP length %d\n", len);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (p[4] != 16)
	{
		log(1, 0, s, t, "Bad CHAP response length %d\n", p[4]);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (len - 21 >= sizeof(session[s].user))
	{
		log(1, 0, s, t, "CHAP user too long %d\n", len - 21);
		STAT(tunnel_rx_errors);
		return ;
	}

	// Run PRE_AUTH plugins
	{
		struct param_pre_auth packet = { &tunnel[t], &session[s], NULL, NULL, PPPCHAP, 1 };

		packet.username = calloc(len-20, 1);
		packet.password = calloc(16, 1);
		memcpy(packet.username, p + 21, len - 21);
		memcpy(packet.password, p + 5, 16);

		run_plugins(PLUGIN_PRE_AUTH, &packet);
		if (!packet.continue_auth)
		{
			log(3, 0, s, t, "A plugin rejected PRE_AUTH\n");
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
	log(3, 0, s, t, "CHAP login %s\n", session[s].user);
	radiussend(r, RADIUSAUTH);
}

char *ppp_lcp_types[] = {
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

void dumplcp(u8 *p, int l)
{
	signed int x = l - 4;
	u8 *o = (p + 4);

	log_hex(5, "PPP LCP Packet", p, l);
	log(4, 0, 0, 0, "PPP LCP Packet type %d (%s len %d)\n", *p, ppp_lcp_types[(int)*p], ntohs( ((u16 *) p)[1]) );
	log(4, 0, 0, 0, "Length: %d\n", l);
	if (*p != ConfigReq && *p != ConfigRej && *p != ConfigAck)
		return;

	while (x > 2)
	{
		int type = o[0];
		int length = o[1];
		if (length < 2)
		{
			log(4, 0, 0, 0, "	Option length is %d...\n", length);
			break;
		}
		if (type == 0)
		{
			log(4, 0, 0, 0, "	Option type is 0...\n");
			x -= length;
			o += length;
			continue;
		}
		switch (type)
		{
			case 1: // Maximum-Receive-Unit
				if (length == 4)
					log(4, 0, 0, 0, "    %s %d\n", lcp_types[type], ntohs(*(u16 *)(o + 2)));
				else
					log(4, 0, 0, 0, "    %s odd length %d\n", lcp_types[type], length);
				break;
			case 3: // Authentication-Protocol
				{
					if (length == 4)
					{
						int proto = ntohs(*(u16 *)(o + 2));
						log(4, 0, 0, 0, "   %s 0x%x (%s)\n", lcp_types[type], proto,
							proto == 0xC223 ? "CHAP" :
							proto == 0xC023 ? "PAP"  : "UNKNOWN");
					}
					else
						log(4, 0, 0, 0, "   %s odd length %d\n", lcp_types[type], length);
					break;
				}
			case 4: // Quality-Protocol
				{
					u32 qp = ntohl(*(u32 *)(o + 2));
					log(4, 0, 0, 0, "    %s %x\n", lcp_types[type], qp);
					break;
				}
			case 5: // Magic-Number
				{
					if (length == 6)
					{
						u32 magicno = ntohl(*(u32 *)(o + 2));
						log(4, 0, 0, 0, "    %s %x\n", lcp_types[type], magicno);
					}
					else
						log(4, 0, 0, 0, "   %s odd length %d\n", lcp_types[type], length);
					break;
				}
			case 7: // Protocol-Field-Compression
				{
					log(4, 0, 0, 0, "    %s\n", lcp_types[type]);
					break;
				}
			case 8: // Address-And-Control-Field-Compression
				{
					log(4, 0, 0, 0, "    %s\n", lcp_types[type]);
					break;
				}
			default:
				log(2, 0, 0, 0, "    Unknown PPP LCP Option type %d\n", type);
				break;
		}
		x -= length;
		o += length;
	}
}

// Process LCP messages
void processlcp(tunnelidt t, sessionidt s, u8 * p, u16 l)
{
	u8 b[MAXCONTROL];
	u8 *q = NULL;
	u32  magicno = 0;


	CSTAT(call_processlcp);

	log_hex(5, "LCP", p, l);
	if (l < 4)
	{
		log(1, session[s].ip, s, t, "Short LCP %d bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (*p == ConfigAck)
	{
		log(3, session[s].ip, s, t, "LCP: Discarding ConfigAck\n");
		session[s].flags |= SESSIONLCPACK;
	}
	else if (*p == ConfigReq)
	{
		signed int x = l - 4;
		u8 *o = (p + 4);

		log(3, session[s].ip, s, t, "LCP: ConfigReq (%d bytes)...\n", l);
		dumplcp(p, l);

		while (x > 2)
		{
			int type = o[0];
			int length = o[1];
			if (length == 0 || type == 0) break;
			switch (type)
			{
				case 1: // Maximum-Receive-Unit
					session[s].mru = ntohs(*(u16 *)(o + 2));
					break;
				case 2: // asyncmap
					log_hex(2, "PPP LCP Packet", p, l);
					log(2, 0, 0, 0, "PPP LCP Packet type %d (%s len %d)\n", *p, ppp_lcp_types[(int)*p], ntohs( ((u16 *) p)[1]) );
					break;
				case 3: // Authentication-Protocol
					{
						int proto = ntohs(*(u16 *)(o + 2));
						if (proto == 0xC223)
						{
							log(2, session[s].ip, s, t, "    Remote end is trying to do CHAP. Rejecting it.\n");

							if (!q)
							{
								q = makeppp(b, sizeof(b), p, l, t, s, PPPLCP);
								if (!q) {
									log(2, session[s].ip, s, t, " Failed to send packet.\n");
									break;
								}
								*q++ = ConfigNak;
							}
							memcpy(q, o, length);
							*(u16 *)(q += 2) = htons(0xC023); // NAK -> Use PAP instead
							q += length;
						}
						break;
					}
				case 5: // Magic-Number
					{
						magicno = ntohl(*(u32 *)(o + 2));
						break;
					}
				case 4: // Quality-Protocol
				case 7: // Protocol-Field-Compression
				case 8: // Address-And-Control-Field-Compression
						break;
				case 13: // CallBack option for LCP extention of win2000/routers L2TP client
				case 17:
				case 18:
				{
					// Reject LCP CallBack
					log(2, session[s].ip, s, t, "    PPP LCP Option type %d, len=%d\n", type, length);
					memcpy(p + 4, o, length);
					*(u16 *)(p + 2) = htons(length + 4);
					*p = ConfigRej;
					q = makeppp(b,sizeof(b), p, length + 4, t, s, PPPLCP);
					tunnelsend(b, 12 + length + 4, t);
					return;
					}

				default:
					// Reject Unknown LCP Option to stop to send it again
					log(2, session[s].ip, s, t, "    Unknown PPP LCP Option type %d\n", type);
					memcpy(p + 4, o, length);
					*(u16 *)(p + 2) = htons(length + 4);
					*p = ConfigRej;
					q = makeppp(b,sizeof(b), p, length + 4, t, s, PPPLCP);
					tunnelsend(b, 12 + length + 4, t);
					return;
			}
			x -= length;
			o += length;
		}

		if (!q)
		{
			// Send back a ConfigAck
			log(3, session[s].ip, s, t, "ConfigReq accepted, sending as Ack\n");
			// for  win2k L2TP clientis  and LCP renegotiation of alive session 
			if (magicno || l == 4) initlcp(t, s);
			q = makeppp(b, sizeof(b), p, l, t, s, PPPLCP);
			if (!q)
			{
				log(3, session[s].ip, s, t, " failed to create packet.\n");
				return;
			}
			*q = ConfigAck;
			tunnelsend(b, l + (q - b), t);
		}
		else
		{
			// Already built a ConfigNak... send it
			log(3, session[s].ip, s, t, "Sending ConfigNak\n");
			tunnelsend(b, l + (q - b), t);
		}

		if (!(session[s].flags & SESSIONLCPACK))
			initlcp(t, s);
	}
	else if (*p == ConfigNak)
	{
		log(1, session[s].ip, s, t, "Remote end sent a ConfigNak. Ignoring\n");
		dumplcp(p, l);
		return ;
	}
	else if (*p == TerminateReq)
	{
		*p = TerminateAck;	// close
		q = makeppp(b, sizeof(b),  p, l, t, s, PPPLCP);
		if (!q) {
			log(3, session[s].ip, s, t, "Failed to create PPP packet in processlcp.\n");
			return;
		}
		log(3, session[s].ip, s, t, "LCP: Received TerminateReq. Sending TerminateAck\n");
		sessionshutdown(s, "Remote end closed connection.");
		tunnelsend(b, l + (q - b), t); // send it
	}
	else if (*p == TerminateAck)
	{
		sessionshutdown(s, "Connection closed.");
	}
	else if (*p == EchoReq)
	{
		*p = EchoReply;		// reply
		*(u32 *) (p + 4) = htonl(session[s].magic); // our magic number
		q = makeppp(b, sizeof(b), p, l, t, s, PPPLCP);
		if (!q) {
			log(3, session[s].ip, s, t, " failed to send EchoReply.\n");
			return;
		}
		log(5, session[s].ip, s, t, "LCP: Received EchoReq. Sending EchoReply\n");
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
			log(1, 0, s, t, "Truncated Ident Packet (length=%d) to 1400 bytes\n", l);
			l = 1400;
		}
		q = makeppp(b, sizeof(b), p, l, t, s, PPPLCP);
		if (!q)
		{
			log(3, session[s].ip, s, t, "Failed to create IdentRej.\n");
			return;
		}
		log_hex(5, "LCPIdentRej", q, l + 4);
		tunnelsend(b, 12 + 4 + l, t);
	}
	else
	{
		log(1, session[s].ip, s, t, "Unexpected LCP code %d\n", *p);
		STAT(tunnel_rx_errors);
		return ;
	}
}

// Process IPCP messages
void processipcp(tunnelidt t, sessionidt s, u8 * p, u16 l)
{

	CSTAT(call_processipcp);

	log_hex(5, "IPCP", p, l);
	if (l < 5)
	{
		log(1, 0, s, t, "Short IPCP %d bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (*p == ConfigAck)
	{
		// happy with our IPCP
		u16 r = session[s].radius;
		if ((!r || radius[r].state == RADIUSIPCP) && !session[s].walled_garden) {
			if (!r)
				r = radiusnew(s);
			if (r)
				radiussend(r, RADIUSSTART); // send radius start, having got IPCP at last
		}
		session[s].flags |= SF_IPCP_ACKED;

		log(3, session[s].ip, s, t, "IPCP Acked, session is now active\n");
		return;
	}
	if (*p != ConfigReq)
	{
		log(1, 0, s, t, "Unexpected IPCP code %d\n", *p);
		STAT(tunnel_rx_errors);
		return ;
	}
	log(4, session[s].ip, s, t, "IPCP ConfigReq received\n");
	if (ntohs(*(u16 *) (p + 2)) > l)
	{
		log(1, 0, s, t, "Length mismatch IPCP %d/%d\n", ntohs(*(u16 *) (p + 2)), l);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (!session[s].ip)
	{
		log(3, 0, s, t, "Waiting on radius reply\n");
		return;			// have to wait on RADIUS reply
	}
	// form a config reply quoting the IP in the session
	{
		u8 b[MAXCONTROL];
		u8 *i,
		*q;

		l = ntohs(*(u16 *) (p + 2)); // We must use length from IPCP len field
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
			{
				log(2, 0, s, t, "Failed to send IPCP ConfigRej\n");
				return;
			}
			*q = ConfigRej;
			p += 4;
			while (p < i && p[1])
			{
				if (*p != 0x81 && *p != 0x83 && *p != 3)
				{
					log(2, 0, s, t, "IPCP reject %d\n", *p);
					memcpy(q + n, p, p[1]);
					n += p[1];
				}
				p += p[1];
			}
			*(u16 *) (q + 2) = htons(n);
			log(4, session[s].ip, s, t, "Sending ConfigRej\n");
			tunnelsend(b, n + (q - b), t); // send it
		}
		else
		{
			log(4, session[s].ip, s, t, "Sending ConfigAck\n");
			*p = ConfigAck;
			if ((i = findppp(p, 0x81))) // Primary DNS address
			{
				if (*(u32 *) (i + 2) != htonl(session[s].dns1))
				{
					*(u32 *) (i + 2) = htonl(session[s].dns1);
					*p = ConfigNak;
					log(5, session[s].ip, s, t, "   DNS1 = %s\n", inet_toa(session[s].dns1));
				}
			}
			if ((i = findppp(p, 0x83))) // Secondary DNS address (TBA, is it)
			{
				if (*(u32 *) (i + 2) != htonl(session[s].dns2))
				{
					*(u32 *) (i + 2) = htonl(session[s].dns2);
					*p = ConfigNak;
					log(5, session[s].ip, s, t, "   DNS2 = %s\n", inet_toa(session[s].dns1));
				}
			}
			i = findppp(p, 3);		// IP address
			if (!i || i[1] != 6)
			{
				log(1, 0, s, t, "No IP in IPCP request\n");
				STAT(tunnel_rx_errors);
				return ;
			}
			if (*(u32 *) (i + 2) != htonl(session[s].ip))
			{
				*(u32 *) (i + 2) = htonl(session[s].ip);
				*p = ConfigNak;
				log(4, session[s].ip, s, t, " No, a ConfigNak, client is requesting IP - sending %s\n",
						inet_toa(htonl(session[s].ip)));
			}
			if (!(q = makeppp(b, sizeof(b), p, l, t, s, PPPIPCP)))
			{
				log(2, 0, s, t, " Failed to send IPCP packet.\n");
				return;
			}
			tunnelsend(b, l + (q - b), t); // send it
		}
	}
}

// process IP packet received
//
// This MUST be called with at least 4 byte behind 'p'.
// (i.e. this routine writes to p[-4]).
void processipin(tunnelidt t, sessionidt s, u8 * p, u16 l)
{
	ipt ip;


	CSTAT(call_processipin);

	log_hex(5, "IP", p, l);

	ip = ntohl(*(u32 *)(p + 12));

	if (l > MAXETHER)
	{
		log(1, ip, s, t, "IP packet too long %d\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	// no spoof (do sessionbyip to handled statically routed subnets)
	if (ip != session[s].ip && sessionbyip(htonl(ip)) != s)
	{
		log(5, ip, s, t, "Dropping packet with spoofed IP %s\n", inet_toa(htonl(ip)));
		return;
	}

	// Add on the tun header
	p -= 4;
	*(u32 *)p = htonl(0x00000800);
	l += 4;

	if (session[s].tbf_in && !config->cluster_iam_master) { // Are we throttled and a slave?
		master_throttle_packet(session[s].tbf_in, p, l); // Pass it to the master for handling.
		return;
	}

	session[s].cin += l - 4;
	session[s].total_cin += l - 4;
	sess_count[s].cin += l - 4;

	session[s].pin++;
	eth_tx += l - 4;

	if (session[s].snoop_ip && session[s].snoop_port)
	{
		// Snooping this session, send it to ASIO
		snoop_send_packet(p, l, session[s].snoop_ip, session[s].snoop_port);
	}
	STAT(tun_tx_packets);
	INC_STAT(tun_tx_bytes, l);

	if (session[s].tbf_in && config->cluster_iam_master) { // Are we throttled and a master?? actually handle the throttled packets.
		tbf_queue_packet(session[s].tbf_in, p, l);
		return;
	}

	// send to ethernet
	if (tun_write(p, l) < 0)
	{
		STAT(tun_tx_errors);
		log(0, 0, s, t, "Error writing %d bytes to TUN device: %s (tunfd=%d, p=%p)\n",
			l, strerror(errno), tunfd, p);
	}

}

//
// Helper routine for the TBF filters.
// Used to send queued data in from the user.
//
void send_ipin(sessionidt s, u8 *buf, int len)
{
	log_hex(5, "IP in throttled", buf, len);
	if (write(tunfd, buf, len) < 0)
	{
		STAT(tun_tx_errors);
		log(0, 0, 0, 0, "Error writing %d bytes to TUN device: %s (tunfd=%d, p=%p)\n",
			len, strerror(errno), tunfd, buf);
	}

	// Increment packet counters
	session[s].cin += len - 4;
	session[s].total_cin += len - 4;
	sess_count[s].cin += len - 4;

	session[s].pin++;
	eth_tx += len - 4;
}


// Process LCP messages
void processccp(tunnelidt t, sessionidt s, u8 * p, u16 l)
{

	CSTAT(call_processccp);

	log_hex(5, "CCP", p, l);
	if (l < 2 || (*p != ConfigReq && *p != TerminateReq))
	{
		log(1, 0, s, t, "Unexpecetd CCP request code %d\n", *p);
		STAT(tunnel_rx_errors);
		return ;
	}
	// reject
	{
		u8 b[MAXCONTROL];
		u8 *q;
		if (*p == ConfigReq)
		{
			if (l < 6)
			{
				*p = ConfigAck;		// accept no compression
			}
			else
			{
				*p = ConfigRej;		// reject
				sendccp(t, s);
			}
		}
		else
			*p = TerminateAck;		// close
		if (!(q = makeppp(b, sizeof(b), p, l, t, s, PPPCCP)))
		{
			log(1,0,0,0, "Failed to send CCP packet.\n");	
			return;
		}
		tunnelsend(b, l + (q - b), t); // send it
	}
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
		log(1, 0, s, t, "No RADIUS to send challenge\n");
		STAT(tunnel_tx_errors);
		return ;
	}
	log(1, 0, s, t, "Send CHAP challenge\n");
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
	if (!q) {
		log(1, 0, s, t, "failed to send CHAP challenge.\n");
		return;
	}
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
u8 *makeppp(u8 * b, int size, u8 * p, int l, tunnelidt t, sessionidt s, u16 mtype)
{

	if (size < 12)
		return NULL;	// Need more space than this!!

	*(u16 *) (b + 0) = htons(0x0002); // L2TP with no options
	*(u16 *) (b + 2) = htons(tunnel[t].far); // tunnel
	*(u16 *) (b + 4) = htons(session[s].far); // session
	b += 6;
	if (mtype && !(session[s].l2tp_flags & SESSIONACFC))
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

	if (l + 12 > size) {
		log(3,0,0,0, "Would have overflowed the buffer in makeppp: size %d, len %d.\n", size, l);
		return NULL;	// Run out of room to hold the packet!
	}
	if (p && l)
		memcpy(b, p, l);
	return b;
}

// find a PPP option, returns point to option, or 0 if not found
u8 *findppp(u8 * b, u8 mtype)
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

// Send initial LCP ConfigReq
void initlcp(tunnelidt t, sessionidt s)
{
	char b[500] = {0}, *q;

	q = makeppp(b, sizeof(b), NULL, 0, t, s, PPPLCP);
	if (!q) {
		log(1, 0, s, t, "Failed to send LCP ConfigReq.\n");
		return;
	}
	log(4, 0, s, t, "Sending LCP ConfigReq for PAP\n");
	*q = ConfigReq;
	*(u8 *)(q + 1) = (time_now % 255) + 1; // ID
	*(u16 *)(q + 2) = htons(14); // Length
	*(u8 *)(q + 4) = 5;
	*(u8 *)(q + 5) = 6;
	*(u32 *)(q + 6) = htonl(session[s].magic);
	*(u8 *)(q + 10) = 3;
	*(u8 *)(q + 11) = 4;
	*(u16 *)(q + 12) = htons(0xC023); // PAP
	tunnelsend(b, 12 + 14, t);
}

// Send CCP reply
void sendccp(tunnelidt t, sessionidt s)
{
	char *q, b[500] = {0};

	q = makeppp(b, sizeof(b), NULL, 0, t, s, PPPCCP);
	*q = ConfigReq;
	*(u8 *)(q + 1) = (time_now % 255) + 1; // ID
	*(u16 *)(q + 2) = htons(4); // Length
	log_hex(5, "PPPCCP", q, 4);
	tunnelsend(b, (q - b) + 4 , t);
}

