// L2TPNS PPP Stuff

char const *cvs_id_ppp = "$Id: ppp.c,v 1.43 2005-01-25 04:38:49 bodea Exp $";

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
extern uint32_t eth_tx;
extern time_t time_now;
extern configt *config;

static void initccp(tunnelidt t, sessionidt s);

// Process PAP messages
void processpap(tunnelidt t, sessionidt s, uint8_t *p, uint16_t l)
{
	char user[129];
	char pass[129];
	uint16_t hl;

	CSTAT(processpap);

	LOG_HEX(5, "PAP", p, l);
	if (l < 4)
	{
		LOG(1, s, t, "Short PAP %u bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, s, t, "Length mismatch PAP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		return ;
	}
	l = hl;

	if (*p != 1)
	{
		LOG(1, s, t, "Unexpected PAP code %d\n", *p);
		STAT(tunnel_rx_errors);
		return ;
	}

	{
		uint8_t *b = p;
		b += 4;
		if (*b && *b < sizeof(user))
			memcpy(user, b + 1, *b);
		user[*b] = 0;
		b += 1 + *b;
		if (*b && *b < sizeof(pass))
			memcpy(pass, b + 1, *b);
		pass[*b] = 0;
		LOG(3, s, t, "PAP login %s/%s\n", user, pass);
	}
	if (session[s].ip || !session[s].radius)
	{
		// respond now, either no RADIUS available or already authenticated
		uint8_t b[MAXCONTROL];
		uint8_t id = p[1];
		uint8_t *p = makeppp(b, sizeof(b), 0, 0, t, s, PPPPAP);
		if (!p) return;

		if (session[s].ip)
			*p = 2;				// ACK
		else
			*p = 3;				// cant authorise
		p[1] = id;
		*(uint16_t *) (p + 2) = htons(5);	// length
		p[4] = 0;				// no message
		if (session[s].ip)
		{
			LOG(3, s, t, "Already an IP allocated: %s (%d)\n",
				fmtaddr(htonl(session[s].ip), 0), session[s].ip_pool_index);

			session[s].flags &= ~SF_IPCP_ACKED;
		}
		else
		{
			LOG(1, s, t, "No radius session available to authenticate session...\n");
		}
		LOG(3, s, t, "Fallback response to PAP (%s)\n", (session[s].ip) ? "ACK" : "NAK");
		tunnelsend(b, 5 + (p - b), t); // send it
	}
	else
	{
		// set up RADIUS request
		uint16_t r = session[s].radius;

		// Run PRE_AUTH plugins
		struct param_pre_auth packet = { &tunnel[t], &session[s], strdup(user), strdup(pass), PPPPAP, 1 };
		run_plugins(PLUGIN_PRE_AUTH, &packet);
		if (!packet.continue_auth)
		{
			LOG(3, s, t, "A plugin rejected PRE_AUTH\n");
			if (packet.username) free(packet.username);
			if (packet.password) free(packet.password);
			return;
		}

		strncpy(session[s].user, packet.username, sizeof(session[s].user) - 1);
		strncpy(radius[r].pass, packet.password, sizeof(radius[r].pass) - 1);

		free(packet.username);
		free(packet.password);

		radius[r].id = p[1];
		LOG(3, s, t, "Sending login for %s/%s to radius\n", user, pass);
		radiussend(r, RADIUSAUTH);
	}
}

// Process CHAP messages
void processchap(tunnelidt t, sessionidt s, uint8_t *p, uint16_t l)
{
	uint16_t r;
	uint16_t hl;

	CSTAT(processchap);

	LOG_HEX(5, "CHAP", p, l);
	r = session[s].radius;
	if (!r)
	{
		LOG(1, s, t, "Unexpected CHAP message\n");
		STAT(tunnel_rx_errors);
		return;
	}

	if (l < 4)
	{
		LOG(1, s, t, "Short CHAP %u bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, s, t, "Length mismatch CHAP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		return ;
	}
	l = hl;

	if (*p != 2)
	{
		LOG(1, s, t, "Unexpected CHAP response code %d\n", *p);
		STAT(tunnel_rx_errors);
		return;
	}
	if (p[1] != radius[r].id)
	{
		LOG(1, s, t, "Wrong CHAP response ID %d (should be %d) (%d)\n", p[1], radius[r].id, r);
		STAT(tunnel_rx_errors);
		return ;
	}

	if (l < 5 || p[4] != 16)
	{
		LOG(1, s, t, "Bad CHAP response length %d\n", l < 5 ? -1 : p[4]);
		STAT(tunnel_rx_errors);
		return ;
	}

	l -= 5;
	p += 5;
	if (l < 16 || l - 16 >= sizeof(session[s].user))
	{
		LOG(1, s, t, "CHAP user too long %d\n", l - 16);
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
			LOG(3, s, t, "A plugin rejected PRE_AUTH\n");
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
	LOG(3, s, t, "CHAP login %s\n", session[s].user);
	radiussend(r, RADIUSAUTH);
}

static void dumplcp(uint8_t *p, int l)
{
	int x = l - 4;
	uint8_t *o = (p + 4);

	LOG_HEX(5, "PPP LCP Packet", p, l);
	LOG(4, 0, 0, "PPP LCP Packet type %d (%s len %d)\n", *p, ppp_lcp_type((int)*p), ntohs( ((uint16_t *) p)[1]) );
	LOG(4, 0, 0, "Length: %d\n", l);
	if (*p != ConfigReq && *p != ConfigRej && *p != ConfigAck)
		return;

	while (x > 2)
	{
		int type = o[0];
		int length = o[1];
		if (length < 2)
		{
			LOG(4, 0, 0, "	Option length is %d...\n", length);
			break;
		}
		if (type == 0)
		{
			LOG(4, 0, 0, "	Option type is 0...\n");
			x -= length;
			o += length;
			continue;
		}
		switch (type)
		{
			case 1: // Maximum-Receive-Unit
				if (length == 4)
					LOG(4, 0, 0, "    %s %d\n", lcp_type(type), ntohs(*(uint16_t *)(o + 2)));
				else
					LOG(4, 0, 0, "    %s odd length %d\n", lcp_type(type), length);
				break;
			case 2: // Async-Control-Character-Map
				if (length == 6)
				{
					uint32_t asyncmap = ntohl(*(uint32_t *)(o + 2));
					LOG(4, 0, 0, "    %s %x\n", lcp_type(type), asyncmap);
				}
				else
					LOG(4, 0, 0, "   %s odd length %d\n", lcp_type(type), length);
				break;
			case 3: // Authentication-Protocol
				if (length == 4)
				{
					int proto = ntohs(*(uint16_t *)(o + 2));
					LOG(4, 0, 0, "   %s 0x%x (%s)\n", lcp_type(type), proto,
						proto == PPPCHAP ? "CHAP" :
						proto == PPPPAP  ? "PAP"  : "UNKNOWN");
				}
				else
					LOG(4, 0, 0, "   %s odd length %d\n", lcp_type(type), length);
				break;
			case 4: // Quality-Protocol
				{
					uint32_t qp = ntohl(*(uint32_t *)(o + 2));
					LOG(4, 0, 0, "    %s %x\n", lcp_type(type), qp);
				}
				break;
			case 5: // Magic-Number
				if (length == 6)
				{
					uint32_t magicno = ntohl(*(uint32_t *)(o + 2));
					LOG(4, 0, 0, "    %s %x\n", lcp_type(type), magicno);
				}
				else
					LOG(4, 0, 0, "   %s odd length %d\n", lcp_type(type), length);
				break;
			case 7: // Protocol-Field-Compression
			case 8: // Address-And-Control-Field-Compression
				LOG(4, 0, 0, "    %s\n", lcp_type(type));
				break;
			default:
				LOG(2, 0, 0, "    Unknown PPP LCP Option type %d\n", type);
				break;
		}
		x -= length;
		o += length;
	}
}

// Process LCP messages
void processlcp(tunnelidt t, sessionidt s, uint8_t *p, uint16_t l)
{
	uint8_t b[MAXCONTROL];
	uint8_t *q = NULL;
	uint32_t magicno = 0;
	uint16_t hl;

	CSTAT(processlcp);

	LOG_HEX(5, "LCP", p, l);
	if (l < 4)
	{
		LOG(1, s, t, "Short LCP %d bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, s, t, "Length mismatch LCP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		return ;
	}
	l = hl;

	if (*p == ConfigAck)
	{
		LOG(3, s, t, "LCP: Discarding ConfigAck\n");
		session[s].flags |= SF_LCP_ACKED;
	}
	else if (*p == ConfigReq)
	{
		int x = l - 4;
		uint8_t *o = (p + 4);
		uint8_t *response = 0;

		LOG(3, s, t, "LCP: ConfigReq (%d bytes)...\n", l);
		if (config->debug > 3) dumplcp(p, l);

		while (x > 2)
		{
			int type = o[0];
			int length = o[1];

			if (length == 0 || type == 0 || x < length) break;
			switch (type)
			{
				case 1: // Maximum-Receive-Unit
					session[s].mru = ntohs(*(uint16_t *)(o + 2));
					break;

				case 2: // Async-Control-Character-Map
					if (!ntohl(*(uint32_t *)(o + 2))) // all bits zero is OK
						break;

					if (response && *response != ConfigNak) // rej already queued
						break;

					LOG(2, s, t, "    Remote requesting asyncmap.  Rejecting.\n");
					if (!response)
					{
						q = response = makeppp(b, sizeof(b), p, 2, t, s, PPPLCP);
						if (!q) break;
						*q = ConfigNak;
						q += 4;
					}

					if ((q - b + 11) > sizeof(b))
					{
						LOG(2, s, t, "LCP overflow for asyncmap ConfigNak.\n");
						break;
					}

					*q++ = type;
					*q++ = 6;
					memset(q, 0, 4); // asyncmap 0
					q += 4;
					*((uint16_t *) (response + 2)) = htons(q - response); // LCP header length
					break;

				case 3: // Authentication-Protocol
					{
						int proto = ntohs(*(uint16_t *)(o + 2));
						char proto_name[] = "0x0000";
						if (proto == PPPPAP)
							break;

						if (response && *response != ConfigNak) // rej already queued
							break;

						if (proto == PPPCHAP)
							strcpy(proto_name, "CHAP");
						else
							sprintf(proto_name, "%#4.4x", proto);

						LOG(2, s, t, "    Remote requesting %s authentication.  Rejecting.\n", proto_name);

						if (!response)
						{
							q = response = makeppp(b, sizeof(b), p, 2, t, s, PPPLCP);
							if (!q) break;
							*q = ConfigNak;
							q += 4;
						}

						if ((q - b + length) > sizeof(b))
						{
							LOG(2, s, t, "LCP overflow for %s ConfigNak.\n", proto_name);
							break;
						}

						memcpy(q, o, length);
						*(uint16_t *)(q += 2) = htons(PPPPAP); // NAK -> Use PAP instead
						q += length;
						*((uint16_t *) (response + 2)) = htons(q - response);
					}
					break;

				case 5: // Magic-Number
					magicno = ntohl(*(uint32_t *)(o + 2));
					break;

				case 4: // Quality-Protocol
				case 7: // Protocol-Field-Compression
				case 8: // Address-And-Control-Field-Compression
					break;

				default: // Reject any unknown options
					LOG(2, s, t, "    Rejecting PPP LCP Option type %d\n", type);
					if (!response || *response != ConfigRej) // drop nak in favour of rej
					{
						q = response = makeppp(b, sizeof(b), p, 2, t, s, PPPLCP);
						if (!q) break;
						*q = ConfigRej;
						q += 4;
					}

					if ((q - b + length) > sizeof(b))
					{
						LOG(2, s, t, "LCP overflow for ConfigRej (type=%d).\n", type);
						break;
					}

					memcpy(q, o, length);
					q += length;
					*((uint16_t *) (response + 2)) = htons(q - response); // LCP header length
			}
			x -= length;
			o += length;
		}

		if (!response)
		{
			// Send back a ConfigAck
			q = response = makeppp(b, sizeof(b), p, l, t, s, PPPLCP);
			if (!q) return;
			*q = ConfigAck;
		}

		LOG(3, s, t, "Sending %s\n", ppp_lcp_type(*response));
		tunnelsend(b, l + (q - b), t);

		if (!(session[s].flags & SF_LCP_ACKED))
			initlcp(t, s);
	}
	else if (*p == ConfigNak)
	{
		LOG(1, s, t, "Remote end sent a ConfigNak.  Ignoring\n");
		if (config->debug > 3) dumplcp(p, l);
		return ;
	}
	else if (*p == TerminateReq)
	{
		LOG(3, s, t, "LCP: Received TerminateReq.  Sending TerminateAck\n");
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
	else if (*p == ProtocolRej)
	{
		if (*(uint16_t *) (p+4) == htons(PPPIPV6CP))
		{
			LOG(3, s, t, "IPv6 rejected\n");
			session[s].flags |= SF_IPV6_NACKED;
		}
		else
		{
			LOG(1, s, t, "Unexpected LCP protocol reject 0x%X\n",
				ntohs(*(uint16_t *) (p+4)));
			STAT(tunnel_rx_errors);
		}
	}
	else if (*p == EchoReq)
	{
		LOG(5, s, t, "LCP: Received EchoReq.  Sending EchoReply\n");
		*p = EchoReply;		// reply
		*(uint32_t *) (p + 4) = htonl(session[s].magic); // our magic number
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
			LOG(1, s, t, "Truncated Ident Packet (length=%d) to 1400 bytes\n", l);
			l = 1400;
		}
		q = makeppp(b, sizeof(b), p, l, t, s, PPPLCP);
		if (!q) return;
		LOG_HEX(5, "LCPIdentRej", q, l + 4);
		tunnelsend(b, 12 + 4 + l, t);
	}
	else
	{
		LOG(1, s, t, "Unexpected LCP code %d\n", *p);
		STAT(tunnel_rx_errors);
		return ;
	}
}

// find a PPP option, returns point to option, or 0 if not found
static uint8_t *findppp(uint8_t *b, uint8_t mtype)
{
	uint16_t l = ntohs(*(uint16_t *) (b + 2));
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
void processipcp(tunnelidt t, sessionidt s, uint8_t *p, uint16_t l)
{
	uint16_t hl;

	CSTAT(processipcp);

	LOG_HEX(5, "IPCP", p, l);
	if (l < 5)
	{
		LOG(1, s, t, "Short IPCP %d bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, s, t, "Length mismatch IPCP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		return ;
	}
	l = hl;

	if (*p == ConfigAck)
	{
		// happy with our IPCP
		uint16_t r = session[s].radius;
		if ((!r || radius[r].state == RADIUSIPCP) && !session[s].walled_garden)
		{
			if (!r)
				r = radiusnew(s);
			if (r)
				radiussend(r, RADIUSSTART); // send radius start, having got IPCP at last
		}
		session[s].flags |= SF_IPCP_ACKED;

		LOG(3, s, t, "IPCP Acked, session is now active\n");

		// clear LCP_ACKED/CCP_ACKED flag for possible fast renegotiaion for routers
		session[s].flags &= ~(SF_LCP_ACKED|SF_CCP_ACKED);

		return;
	}
	if (*p != ConfigReq)
	{
		LOG(1, s, t, "Unexpected IPCP code %d\n", *p);
		STAT(tunnel_rx_errors);
		return ;
	}
	LOG(4, s, t, "IPCP ConfigReq received\n");

	if (!session[s].ip)
	{
		LOG(3, s, t, "Waiting on radius reply\n");
		return;			// have to wait on RADIUS reply
	}
	// form a config reply quoting the IP in the session
	{
		uint8_t b[MAXCONTROL];
		uint8_t *i, *q;

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
			uint16_t n = 4;
			i = p + l;
			if (!(q = makeppp(b, sizeof(b), p, l, t, s, PPPIPCP)))
				return;

			*q = ConfigRej;
			p += 4;
			while (p < i && p[1])
			{
				if (*p != 0x81 && *p != 0x83 && *p != 3)
				{
					LOG(2, s, t, "IPCP reject %d\n", *p);
					memcpy(q + n, p, p[1]);
					n += p[1];
				}
				p += p[1];
			}
			*(uint16_t *) (q + 2) = htons(n);
			LOG(4, s, t, "Sending ConfigRej\n");
			tunnelsend(b, n + (q - b), t); // send it
		}
		else
		{
			LOG(4, s, t, "Sending ConfigAck\n");
			*p = ConfigAck;
			if ((i = findppp(p, 0x81))) // Primary DNS address
			{
				if (*(uint32_t *) (i + 2) != htonl(session[s].dns1))
				{
					*(uint32_t *) (i + 2) = htonl(session[s].dns1);
					*p = ConfigNak;
					LOG(5, s, t, "   DNS1 = %s\n",
						fmtaddr(htonl(session[s].dns1), 0));
				}
			}
			if ((i = findppp(p, 0x83))) // Secondary DNS address (TBA, is it)
			{
				if (*(uint32_t *) (i + 2) != htonl(session[s].dns2))
				{
					*(uint32_t *) (i + 2) = htonl(session[s].dns2);
					*p = ConfigNak;
					LOG(5, s, t, "   DNS2 = %s\n",
						fmtaddr(htonl(session[s].dns2), 0));
				}
			}
			i = findppp(p, 3);		// IP address
			if (!i || i[1] != 6)
			{
				LOG(1, s, t, "No IP in IPCP request\n");
				STAT(tunnel_rx_errors);
				return ;
			}
			if (*(uint32_t *) (i + 2) != htonl(session[s].ip))
			{
				*(uint32_t *) (i + 2) = htonl(session[s].ip);
				*p = ConfigNak;
				LOG(4, s, t, " No, a ConfigNak, client is requesting IP - sending %s\n",
						fmtaddr(htonl(session[s].ip), 0));
			}
			if (!(q = makeppp(b, sizeof(b), p, l, t, s, PPPIPCP)))
				return;

			tunnelsend(b, l + (q - b), t); // send it
		}
	}
}

// Process IPV6CP messages
void processipv6cp(tunnelidt t, sessionidt s, uint8_t *p, uint16_t l)
{

	CSTAT(processipv6cp);

	LOG_HEX(5, "IPV6CP", p, l);
	if (l < 4)
	{
		LOG(1, s, t, "Short IPV6CP %d bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (*p == ConfigAck)
	{
		// happy with our IPV6CP
		session[s].flags |= SF_IPV6CP_ACKED;

		LOG(3, s, t, "IPV6CP Acked, IPv6 is now active\n");
		// Add a routed block if configured.
		if (session[s].ipv6prefixlen)
		{
			route6set(s, session[s].ipv6route, session[s].ipv6prefixlen, 1);
			session[s].flags |= SF_IPV6_ROUTED;
		}

		// Send an initial RA (TODO: Should we send these regularly?)
		send_ipv6_ra(t, s, NULL);
		return;
	}
	if (*p != ConfigReq)
	{
		LOG(1, s, t, "Unexpected IPV6CP code %d\n", *p);
		STAT(tunnel_rx_errors);
		return;
	}

	LOG(4, s, t, "IPV6CP ConfigReq received\n");
	if (ntohs(*(uint16_t *) (p + 2)) > l)
	{
		LOG(1, s, t, "Length mismatch IPV6CP %d/%d\n", ntohs(*(uint16_t *) (p + 2)), l);
		STAT(tunnel_rx_errors);
		return ;
	}
	if (!session[s].ip)
	{
		LOG(3, s, t, "Waiting on radius reply\n");
		return;			// have to wait on RADIUS reply
	}
	// form a config reply quoting the IP in the session
	{
		uint8_t b[MAXCONTROL];
		uint8_t *i,
		*q;

		l = ntohs(*(uint16_t *) (p + 2)); // We must use length from IPV6CP len field
		q = p + 4;
		i = p + l;
		while (q < i && q[1])
		{
			if (*q != 1)
				break;
			q += q[1];
		}
		if (q < i)
		{
			// reject
			uint16_t n = 4;
			i = p + l;
			if (!(q = makeppp(b, sizeof(b), p, l, t, s, PPPIPV6CP)))
			{
				LOG(2, s, t, "Failed to send IPV6CP ConfigRej\n");
				return;
			}
			*q = ConfigRej;
			p += 4;
			while (p < i && p[1])
			{
				if (*p != 1)
				{
					LOG(2, s, t, "IPV6CP reject %d\n", *p);
					memcpy(q + n, p, p[1]);
					n += p[1];
				}
				p += p[1];
			}
			*(uint16_t *) (q + 2) = htons(n);
			LOG(4, s, t, "Sending ConfigRej\n");
			tunnelsend(b, n + (q - b), t); // send it
		}
		else
		{
			LOG(4, s, t, "Sending ConfigAck\n");
			*p = ConfigAck;
			i = findppp(p, 1);		// IP address
			if (!i || i[1] != 10)
			{
				LOG(1, s, t, "No IP in IPV6CP request\n");
				STAT(tunnel_rx_errors);
				return ;
			}
			if ((*(uint32_t *) (i + 2) != htonl(session[s].ip)) || 
					(*(uint32_t *) (i + 6) != 0))
			{
				*(uint32_t *) (i + 2) = htonl(session[s].ip);
				*(uint32_t *) (i + 6) = 0;
				*p = ConfigNak;
				LOG(4, s, t,
					" No, a ConfigNak, client is "
					"requesting IP - sending %s\n",
					fmtaddr(htonl(session[s].ip), 0));
			}
			if (!(q = makeppp(b, sizeof(b), p, l, t, s, PPPIPV6CP)))
			{
				LOG(2, s, t, " Failed to send IPV6CP packet.\n");
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
void processipin(tunnelidt t, sessionidt s, uint8_t *p, uint16_t l)
{
	in_addr_t ip;

	CSTAT(processipin);

	LOG_HEX(5, "IP", p, l);

	ip = ntohl(*(uint32_t *)(p + 12));

	if (l > MAXETHER)
	{
		LOG(1, s, t, "IP packet too long %d\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	// no spoof (do sessionbyip to handled statically routed subnets)
	if (ip != session[s].ip && sessionbyip(htonl(ip)) != s)
	{
		LOG(5, s, t, "Dropping packet with spoofed IP %s\n", fmtaddr(htonl(ip), 0));
		return;
	}

	// run access-list if any
	if (session[s].filter_in && !ip_filter(p, l, session[s].filter_in - 1))
		return;

	// Add on the tun header
	p -= 4;
	*(uint32_t *) p = htonl(PKTIP);
	l += 4;

	// Are we throttled and a slave?
	if (session[s].tbf_in && !config->cluster_iam_master) {
		// Pass it to the master for handling.
		master_throttle_packet(session[s].tbf_in, p, l);
		return;
	}

	// Are we throttled and a master??
	if (session[s].tbf_in && config->cluster_iam_master) {
		// Actually handle the throttled packets.
		tbf_queue_packet(session[s].tbf_in, p, l);
		return;
	}

	// send to ethernet
	if (tun_write(p, l) < 0)
	{
		STAT(tun_tx_errors);
		LOG(0, s, t, "Error writing %d bytes to TUN device: %s (tunfd=%d, p=%p)\n",
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
	sess_local[s].cin += l - 4;

	session[s].pin++;
	eth_tx += l - 4;

	STAT(tun_tx_packets);
	INC_STAT(tun_tx_bytes, l - 4);
}

// process IPv6 packet received
//
// This MUST be called with at least 4 byte behind 'p'.
// (i.e. this routine writes to p[-4]).
void processipv6in(tunnelidt t, sessionidt s, uint8_t *p, uint16_t l)
{
	struct in6_addr ip;
	in_addr_t ipv4;

	CSTAT(processipv6in);

	LOG_HEX(5, "IPv6", p, l);

	ip = *(struct in6_addr *) (p + 8);
	ipv4 = ntohl(*(uint32_t *)(p + 16));

	if (l > MAXETHER)
	{
		LOG(1, s, t, "IP packet too long %d\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	// no spoof
	if (ipv4 != session[s].ip && memcmp(&config->ipv6_prefix, &ip, 8) && sessionbyipv6(ip) != s)
	{
		char str[INET6_ADDRSTRLEN];
		LOG(5, s, t, "Dropping packet with spoofed IP %s\n",
				inet_ntop(AF_INET6, &ip, str, INET6_ADDRSTRLEN));
		return;
	}

	// Check if it's a Router Solicition message.
	if (*(p + 6) == 58 && *(p + 7) == 255 && *(p + 24) == 0xFF && *(p + 25) == 2 &&
			*(uint32_t *)(p + 26) == 0 && *(uint32_t *)(p + 30) == 0 &&
			*(uint32_t *)(p + 34) == 0 &&
			*(p + 38) == 0 && *(p + 39) == 2 && *(p + 40) == 133) {
		LOG(3, s, t, "Got IPv6 RS\n");
		send_ipv6_ra(t, s, &ip);
		return;
	}

	// Add on the tun header
	p -= 4;
	*(uint32_t *) p = htonl(PKTIPV6);
	l += 4;

	// Are we throttled and a slave?
	if (session[s].tbf_in && !config->cluster_iam_master) {
		// Pass it to the master for handling.
		master_throttle_packet(session[s].tbf_in, p, l);
		return;
	}

	// Are we throttled and a master??
	if (session[s].tbf_in && config->cluster_iam_master) {
		// Actually handle the throttled packets.
		tbf_queue_packet(session[s].tbf_in, p, l);
		return;
	}

	// send to ethernet
	if (tun_write(p, l) < 0)
	{
		STAT(tun_tx_errors);
		LOG(0, s, t, "Error writing %d bytes to TUN device: %s (tunfd=%d, p=%p)\n",
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
	sess_local[s].cin += l - 4;

	session[s].pin++;
	eth_tx += l - 4;

	STAT(tun_tx_packets);
	INC_STAT(tun_tx_bytes, l - 4);
}

//
// Helper routine for the TBF filters.
// Used to send queued data in from the user.
//
void send_ipin(sessionidt s, uint8_t *buf, int len)
{
	LOG_HEX(5, "IP in throttled", buf, len);

	if (write(tunfd, buf, len) < 0)
	{
		STAT(tun_tx_errors);
		LOG(0, 0, 0, "Error writing %d bytes to TUN device: %s (tunfd=%d, p=%p)\n",
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
	sess_local[s].cin += len - 4;

	session[s].pin++;
	eth_tx += len - 4;

	STAT(tun_tx_packets);
	INC_STAT(tun_tx_bytes, len - 4);
}


// Process CCP messages
void processccp(tunnelidt t, sessionidt s, uint8_t *p, uint16_t l)
{
	uint8_t b[MAXCONTROL];
	uint8_t *q;

	CSTAT(processccp);

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
			LOG(1, s, t, "Unexpected CCP request code %d\n", *p);
		else
			LOG(1, s, t, "Short CCP packet\n");

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
	uint8_t b[MAXCONTROL];
	uint16_t r = session[s].radius;
	uint8_t *q;

	CSTAT(sendchap);

	if (!r)
	{
		LOG(1, s, t, "No RADIUS to send challenge\n");
		STAT(tunnel_tx_errors);
		return;
	}

	LOG(1, s, t, "Send CHAP challenge\n");

	// new challenge
	random_data(radius[r].auth, sizeof(radius[r].auth));
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
	*(uint16_t *) (q + 2) = htons(strlen(hostname) + 21); // length
	tunnelsend(b, strlen(hostname) + 21 + (q - b), t); // send it
}

// fill in a L2TP message with a PPP frame,
// copies existing PPP message and changes magic number if seen
// returns start of PPP frame
uint8_t *makeppp(uint8_t *b, int size, uint8_t *p, int l, tunnelidt t, sessionidt s, uint16_t mtype)
{
	if (size < 12) // Need more space than this!!
	{
		static int backtrace_count = 0;
		LOG(0, s, t, "makeppp buffer too small for L2TP header (size=%d)\n", size);
		log_backtrace(backtrace_count, 5)
		return NULL;
	}

	*(uint16_t *) (b + 0) = htons(0x0002); // L2TP with no options
	*(uint16_t *) (b + 2) = htons(tunnel[t].far); // tunnel
	*(uint16_t *) (b + 4) = htons(session[s].far); // session
	b += 6;
	if (mtype == PPPLCP || !(session[s].l2tp_flags & SESSIONACFC))
	{
		*(uint16_t *) b = htons(0xFF03); // HDLC header
		b += 2;
	}
	if (mtype < 0x100 && session[s].l2tp_flags & SESSIONPFC)
		*b++ = mtype;
	else
	{
		*(uint16_t *) b = htons(mtype);
		b += 2;
	}

	if (l + 12 > size)
	{
		static int backtrace_count = 0;
		LOG(2, s, t, "makeppp would overflow buffer (size=%d, header+payload=%d)\n", size, l + 12);
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

	LOG(4, s, t, "Sending LCP ConfigReq for PAP\n");
	*q = ConfigReq;
	*(uint8_t *)(q + 1) = (time_now % 255) + 1; // ID
	*(uint16_t *)(q + 2) = htons(14); // Length
	*(uint8_t *)(q + 4) = 5;
	*(uint8_t *)(q + 5) = 6;
	*(uint32_t *)(q + 6) = htonl(session[s].magic);
	*(uint8_t *)(q + 10) = 3;
	*(uint8_t *)(q + 11) = 4;
	*(uint16_t *)(q + 12) = htons(PPPPAP); // PAP

	LOG_HEX(5, "PPPLCP", q, 14);
	tunnelsend(b, (q - b) + 14, t);
}

// Send CCP request for no compression
static void initccp(tunnelidt t, sessionidt s)
{
	char b[500], *q;

	if (!(q = makeppp(b, sizeof(b), NULL, 0, t, s, PPPCCP)))
		return;

	LOG(4, s, t, "Sending CCP ConfigReq for no compression\n");
	*q = ConfigReq;
	*(uint8_t *)(q + 1) = (time_now % 255) + 1; // ID
	*(uint16_t *)(q + 2) = htons(4); // Length

	LOG_HEX(5, "PPPCCP", q, 4);
	tunnelsend(b, (q - b) + 4 , t);
}
