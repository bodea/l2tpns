// L2TPNS PPP Stuff
// $Id: ppp.c,v 1.1 2003-12-16 07:07:39 fred_nerk Exp $

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include "l2tpns.h"
#include "constants.h"
#include "plugin.h"
#include "util.h"

extern char debug;
extern tunnelt *tunnel;
extern sessiont *session;
extern radiust *radius;
extern u16 tapmac[3];
extern int tapfd;
extern char hostname[1000];
extern struct Tstats *_statistics;
extern unsigned long eth_tx;
extern time_t time_now;

// Process PAP messages
void processpap(tunnelidt t, sessionidt s, u8 * p, u16 l)
{
	char user[129];
	char pass[129];

#ifdef STAT_CALLS
	STAT(call_processpap);
#endif
	log_hex(5, "PAP", p, l);
	if (l < 4)
	{
		log(1, 0, s, t, "Short PAP %u bytes", l);
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
		u8 *p = makeppp(b, 0, 0, t, s, PPPPAP);
		if (session[s].ip)
			*p = 2;              // ACK
		else
			*p = 3;              // cant authorise
		p[1] = id;
		*(u16 *) (p + 2) = htons(5); // length
		p[4] = 0;               // no message
		if (session[s].ip)
		{
		    log(3, session[s].ip, s, t, "%d Already an IP allocated: %s (%d)\n", getpid(), inet_toa(htonl(session[s].ip)), session[s].ip);
		}
		else
		{
		    log(1, 0, s, t, "No radius session available to authenticate session...\n");
		}
		log(3, 0, s, t, "Fallback response to PAP (%s)\n", (session[s].ip) ? "ACK" : "NAK");
		tunnelsend(b, 5 + (p - b), t); // send it
	}
	else
	{                          // set up RADIUS request
		u8 r = session[s].radius;

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

		strncpy(session[s].user, packet.username, sizeof(session[s].user));
		strncpy(radius[r].pass, packet.password, sizeof(radius[r].pass));

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
	u8 r;
	u16 len;

#ifdef STAT_CALLS
	STAT(call_processchap);
#endif
	log_hex(5, "CHAP", p, l);
	r = session[s].radius;
	if (!r)
	{
		log(1, 0, s, t, "Unexpected CHAP message\n");
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

		strncpy(session[s].user, packet.username, sizeof(session[s].user));
		memcpy(radius[r].pass, packet.password, 16);

		free(packet.username);
		free(packet.password);
	}

	radius[r].chap = 1;
	radiussend(r, RADIUSAUTH);
	log(3, 0, s, t, "CHAP login %s\n", session[s].user);
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
};

void dumplcp(char *p, int l)
{
	signed int x = l - 3;
	char *o = (p + 3);

	log_hex(5, "PPP LCP Packet", p, l);
	log(4, 0, 0, 0, "PPP LCP Packet type %d (%s)\n", *p, ppp_lcp_types[(int)*p]);
	log(4, 0, 0, 0, "Length: %d\n", l);
	if (*p != ConfigReq && *p != ConfigRej && *p != ConfigAck)
		return;

	while (x > 2)
	{
		int type = *(u8 *)(o);
		int length = *(u8 *)(o + 1);
		if (length == 0)
		{
			log(4, 0, 0, 0, "	Option length is 0...\n");
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
				log(4, 0, 0, 0, "    %s %d\n", lcp_types[type], ntohs(*(u16 *)(o + 2)));
				break;
			case 3: // Authentication-Protocol
				{
					int proto = ntohs(*(u16 *)(o + 2));
					log(4, 0, 0, 0, "    %s %s\n", lcp_types[type],
							proto == 0xC223 ? "CHAP" : "PAP");
					break;
				}
			case 5: // Magic-Number
				{
					u32 magicno = ntohl(*(u32 *)(o + 2));
					log(4, 0, 0, 0, "    %s %x\n", lcp_types[type], magicno);
					break;
				}
			case 4: // Quality-Protocol
				{
					u32 qp = ntohl(*(u32 *)(o + 2));
					log(4, 0, 0, 0, "    %s %x\n", lcp_types[type], qp);
					break;
				}
			case 7: // Protocol-Field-Compression
				{
					u32 pfc = ntohl(*(u32 *)(o + 2));
					log(4, 0, 0, 0, "    %s %x\n", lcp_types[type], pfc);
					break;
				}
			case 8: // Address-And-Control-Field-Compression
				{
					u32 afc = ntohl(*(u32 *)(o + 2));
					log(4, 0, 0, 0, "    %s %x\n", lcp_types[type], afc);
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

#ifdef STAT_CALLS
	STAT(call_processlcp);
#endif
	log_hex(5, "LCP", p, l);
	if (l < 4)
	{
		log(1, session[s].ip, s, t, "Short LCP %d bytes", l);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (*p == ConfigAck)
	{
		log(3, session[s].ip, s, t, "LCP: Discarding ConfigAck\n");
	}
	else if (*p == ConfigReq)
	{
		signed int x = l - 1;
		char *o = (p + 1);

		log(3, session[s].ip, s, t, "LCP: ConfigReq (%d bytes)...\n", l);

		while (x > 2)
		{
			int type = *(u8 *)(o);
			int length = *(u8 *)(o + 1);
			if (length == 0 || type == 0) break;
			switch (type)
			{
				case 1: // Maximum-Receive-Unit
					session[s].mru = ntohs(*(u16 *)(o + 2));
					break;
				case 3: // Authentication-Protocol
					{
						int proto = ntohs(*(u16 *)(o + 2));
						if (proto == 0xC223)
						{
							log(2, session[s].ip, s, t, "    Remote end is trying to do CHAP. Rejecting it.\n");

							if (!q)
							{
								q = makeppp(b, p, l, t, s, PPPLCP);
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
//						u32 magicno = ntohl(*(u32 *)(o + 2));
						break;
					}
				case 4: // Quality-Protocol
					{
//						u32 qp = ntohl(*(u32 *)(o + 2));
						break;
					}
				case 7: // Protocol-Field-Compression
					{
//						u32 pfc = ntohl(*(u32 *)(o + 2));
						break;
					}
				case 8: // Address-And-Control-Field-Compression
					{
//						u32 afc = ntohl(*(u32 *)(o + 2));
						break;
					}
				default:
					log(2, session[s].ip, s, t, "    Unknown PPP LCP Option type %d\n", type);
					break;
			}
			x -= length;
			o += length;
		}

		if (!q)
		{
			// Send back a ConfigAck
			log(3, session[s].ip, s, t, "ConfigReq accepted, sending as Ack\n");
			q = makeppp(b, p, l, t, s, PPPLCP);
			*q = ConfigAck;
			tunnelsend(b, l + (q - b), t);
		}
		else
		{
			// Already built a ConfigNak... send it
			log(3, session[s].ip, s, t, "Sending ConfigNak\n");
			tunnelsend(b, l + (q - b), t);

			log(3, session[s].ip, s, t, "Sending ConfigReq, requesting PAP login\n");
			q = makeppp(b, NULL, 0, t, s, PPPLCP);
			*q++ = ConfigReq;
			*(u8 *)(q++) = 3;
			*(u8 *)(q++) = 4;
			*(u16 *)(q += 2) = htons(0xC023);
			tunnelsend(b, l + (q - b), t);
		}
	}
	else if (*p == ConfigNak)
	{
		log(1, session[s].ip, s, t, "Remote end sent a ConfigNak. Ignoring\n");
		dumplcp(p, l);
		return ;
	}
	else if (*p == TerminateReq)
	{
		*p = TerminateAck;     // close
		q = makeppp(b, p, l, t, s, PPPLCP);
		log(3, session[s].ip, s, t, "LCP: Received TerminateReq. Sending TerminateAck\n");
		sessionshutdown(s, "Remote end closed connection.");
		tunnelsend(b, l + (q - b), t); // send it
	}
	else if (*p == TerminateReq)
	{
		sessionshutdown(s, "Remote end closed connection.");
	}
	else if (*p == EchoReq)
	{
		*p = EchoReply;      // reply
		*(u32 *) (p + 4) = htonl(session[s].magic); // our magic number
		q = makeppp(b, p, l, t, s, PPPLCP);
		log(3, session[s].ip, s, t, "LCP: Received EchoReq. Sending EchoReply\n");
		tunnelsend(b, l + (q - b), t); // send it
	}
	else if (*p == EchoReply)
	{
		// Ignore it, last_packet time is set earlier than this.
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
#ifdef STAT_CALLS
	STAT(call_processipcp);
#endif
	log_hex(5, "IPCP", p, l);
	if (l < 5)
	{
		log(1, 0, s, t, "Short IPCP %d bytes", l);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (*p == ConfigAck)
	{                          // happy with our IPCP
		u8 r = session[s].radius;
		if ((!r || radius[r].state == RADIUSIPCP) && !session[s].walled_garden)
			if (!r)
				r = radiusnew(s);
			if (r)
				radiussend(r, RADIUSSTART); // send radius start, having got IPCP at last
		return ;                 // done
	}
	if (*p != ConfigReq)
	{
		log(1, 0, s, t, "Unexpected IPCP code %d\n", *p);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (ntohs(*(u16 *) (p + 2)) > l)
	{
		log(1, 0, s, t, "Length mismatch IPCP %d/%d\n", ntohs(*(u16 *) (p + 2)), l);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (!session[s].ip)
	{
		log(3, 0, s, t, "Waiting on radius reply\n");
		return ;                   // have to wait on RADIUS eply
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
		{                       // reject
			u16 n = 4;
			i = p + l;
			q = makeppp(b, p, l, t, s, PPPIPCP);
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
			tunnelsend(b, n + (q - b), t); // send it
		}
		else
		{
			*p = ConfigAck;
			i = findppp(p, 0x81); // Primary DNS address
			if (i)
			{
				if (*(u32 *) (i + 2) != htonl(session[s].dns1))
				{
					*(u32 *) (i + 2) = htonl(session[s].dns1);
					*p = ConfigNak;
				}
			}
			i = findppp(p, 0x83); // Secondary DNS address (TBA, is it)
			if (i)
			{
				if (*(u32 *) (i + 2) != htonl(session[s].dns2))
				{
					*(u32 *) (i + 2) = htonl(session[s].dns2);
					*p = ConfigNak;
				}
			}
			i = findppp(p, 3);   // IP address
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
			}
			q = makeppp(b, p, l, t, s, PPPIPCP);
			tunnelsend(b, l + (q - b), t); // send it
		}
	}
}

// process IP packet received
void processipin(tunnelidt t, sessionidt s, u8 * p, u16 l)
{
#ifdef STAT_CALLS
	STAT(call_processipin);
#endif
	log_hex(5, "IP", p, l);

	if (l > MAXETHER)
	{
		log(1, *(u32 *)(p + 12), s, t, "IP packet too long %d\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	session[s].cin += l;
	session[s].pin++;
	eth_tx += l;

	// Add on the tun header
	p -= 4;
	*(u32 *)p = htonl(0x00000800);
	l += 4;

	// Plugin hook
	{
		struct param_packet_rx packet = { &tunnel[t], &session[s], p, l };
		run_plugins(PLUGIN_PACKET_TX, &packet);
	}

	// send to ethernet
	if (write(tapfd, p, l) < 0)
	{
		STAT(tap_tx_errors);
		log(0, 0, s, t, "Error writing %d bytes to TAP device: %s (tapfd=%d, p=%p)\n",
			l, strerror(errno), tapfd, p);
	}

	if (session[s].snoop)
	{
		// Snooping this session, send it to ASIO
		snoop_send_packet(p, l);
	}
	STAT(tap_tx_packets);
	INC_STAT(tap_tx_bytes, l);
}

// Process LCP messages
void processccp(tunnelidt t, sessionidt s, u8 * p, u16 l)
{
#ifdef STAT_CALLS
	STAT(call_processccp);
#endif
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
				*p = ConfigRej;        // reject
			}
		}
		else
			*p = TerminateAck;     // close
		q = makeppp(b, p, l, t, s, PPPCCP);
		tunnelsend(b, l + (q - b), t); // send it
	}
}

// send a CHAP PP packet
void sendchap(tunnelidt t, sessionidt s)
{
	u8 b[MAXCONTROL];
	u8 r = session[s].radius;
	u8 *q;
#ifdef STAT_CALLS
	STAT(call_sendchap);
#endif
	if (!r)
	{
		log(1, 0, s, t, "No RADIUS to send challenge\n");
		STAT(tunnel_tx_errors);
		return ;
	}
	log(1, 0, s, t, "Send CHAP challenge\n");
	{                            // new challenge
		int n;
		for (n = 0; n < 15; n++)
			radius[r].auth[n] = rand();
	}
	radius[r].chap = 1;          // CHAP not PAP
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
	q = makeppp(b, 0, 0, t, s, PPPCHAP);
	*q = 1;                      // challenhe
	q[1] = radius[r].id;         // ID
	q[4] = 16;                   // length
	memcpy(q + 5, radius[r].auth, 16); // challenge
	strcpy(q + 21, hostname);    // our name
	*(u16 *) (q + 2) = htons(strlen(hostname) + 21); // length
	tunnelsend(b, strlen(hostname) + 21 + (q - b), t); // send it
}

// fill in a L2TP message with a PPP frame,
// copies existing PPP message and changes magic number if seen
// returns start of PPP frame
u8 *makeppp(u8 * b, u8 * p, int l, tunnelidt t, sessionidt s, u16 mtype)
{
	*(u16 *) (b + 0) = htons(0x0002); // L2TP with no options
	*(u16 *) (b + 2) = htons(tunnel[t].far); // tunnel
	*(u16 *) (b + 4) = htons(session[s].far); // session
	b += 6;
	if (mtype != PPPLCP && !(session[s].flags & SESSIONACFC))
	{
		*(u16 *) b = htons(0xFF03); // HDLC header
		b += 2;
	}
	if (mtype < 0x100 && session[s].flags & SESSIONPFC)
		*b++ = mtype;
	else
	{
		*(u16 *) b = htons(mtype);
		b += 2;
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
			return 0;            // faulty
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

	q = makeppp(b, NULL, 0, t, s, PPPLCP);
	log(4, 0, s, t, "Sending LCP ConfigReq for PAP\n");
	*q = ConfigReq;
	*(u8 *)(q + 1) = (time_now % 255) + 1; // ID
	*(u16 *)(q + 2) = htons(8); // Length
	*(u8 *)(q + 4) = 3;
	*(u8 *)(q + 5) = 4;
	*(u16 *)(q + 6) = htons(0xC023); // PAP
	tunnelsend(b, 12 + 8, t);
}

