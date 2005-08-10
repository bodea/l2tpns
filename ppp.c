// L2TPNS PPP Stuff

char const *cvs_id_ppp = "$Id: ppp.c,v 1.68 2005-08-10 11:25:56 bodea Exp $";

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

static int add_lcp_auth(uint8_t *b, int size, int authtype);

// Process PAP messages
void processpap(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l)
{
	char user[MAXUSER];
	char pass[MAXPASS];
	uint16_t hl;
	uint16_t r;

	CSTAT(processpap);

	LOG_HEX(5, "PAP", p, l);
	if (l < 4)
	{
		LOG(1, s, t, "Short PAP %u bytes\n", l);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "Short PAP packet.", 3, 0);
		return;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, s, t, "Length mismatch PAP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "PAP length mismatch.", 3, 0);
		return;
	}
	l = hl;

	if (*p != 1)
	{
		LOG(1, s, t, "Unexpected PAP code %d\n", *p);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "Unexpected PAP code.", 3, 0);
		return;
	}

	if (session[s].ppp.phase != Authenticate)
	{
	    	LOG(2, s, t, "PAP ignored in %s phase\n", ppp_phase(session[s].ppp.phase));
		return;
	}

	{
		uint8_t *b = p;
		b += 4;
		user[0] = pass[0] = 0;
		if (*b && *b < sizeof(user))
		{
			memcpy(user, b + 1, *b);
			user[*b] = 0;
			b += 1 + *b;
			if (*b && *b < sizeof(pass))
			{
				memcpy(pass, b + 1, *b);
				pass[*b] = 0;
			}
		}
		LOG(3, s, t, "PAP login %s/%s\n", user, pass);
	}

	r = radiusnew(s);
	if (session[s].ip || !r)
	{
		// respond now, either no RADIUS available or already authenticated
		uint8_t b[MAXCONTROL];
		uint8_t id = p[1];
		uint8_t *p = makeppp(b, sizeof(b), 0, 0, s, t, PPPPAP);
		if (!p) return;

		if (session[s].ip)
			*p = 2;				// ACK
		else
			*p = 3;				// cant authorise
		p[1] = id;
		*(uint16_t *) (p + 2) = htons(5);	// length
		p[4] = 0;				// no message
		tunnelsend(b, 5 + (p - b), t);		// send it

		if (session[s].ip)
		{
			LOG(3, s, t, "Already an IP allocated: %s (%d)\n",
				fmtaddr(htonl(session[s].ip), 0), session[s].ip_pool_index);
		}
		else
		{
			LOG(1, s, t, "No RADIUS session available to authenticate session...\n");
			sessionshutdown(s, "No free RADIUS sessions.", 4, 0);
		}
	}
	else
	{
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
		LOG(3, s, t, "Sending login for %s/%s to RADIUS\n", user, pass);
		radiussend(r, RADIUSAUTH);
	}
}

// Process CHAP messages
void processchap(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l)
{
	uint16_t r;
	uint16_t hl;

	CSTAT(processchap);

	LOG_HEX(5, "CHAP", p, l);
	r = sess_local[s].radius;
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
		sessionshutdown(s, "Short CHAP packet.", 3, 0);
		return;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, s, t, "Length mismatch CHAP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "CHAP length mismatch.", 3, 0);
		return;
	}
	l = hl;

	if (*p != 2)
	{
		LOG(1, s, t, "Unexpected CHAP response code %d\n", *p);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "CHAP length mismatch.", 3, 0);
		return;
	}

	if (session[s].ppp.phase != Authenticate)
	{
	    	LOG(2, s, t, "CHAP ignored in %s phase\n", ppp_phase(session[s].ppp.phase));
		return;
	}

	if (p[1] != radius[r].id)
	{
		LOG(1, s, t, "Wrong CHAP response ID %d (should be %d) (%d)\n", p[1], radius[r].id, r);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "Unexpected CHAP response ID.", 3, 0);
		return;
	}

	if (l < 5 || p[4] != 16)
	{
		LOG(1, s, t, "Bad CHAP response length %d\n", l < 5 ? -1 : p[4]);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "Bad CHAP response length.", 3, 0);
		return;
	}

	l -= 5;
	p += 5;
	if (l < 16 || l - 16 >= sizeof(session[s].user))
	{
		LOG(1, s, t, "CHAP user too long %d\n", l - 16);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "CHAP username too long.", 3, 0);
		return;
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
	LOG(4, 0, 0, "PPP LCP Packet type %d (%s len %d)\n", *p, ppp_code((int)*p), ntohs( ((uint16_t *) p)[1]) );
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
					LOG(4, 0, 0, "    %s %d\n", ppp_lcp_option(type), ntohs(*(uint16_t *)(o + 2)));
				else
					LOG(4, 0, 0, "    %s odd length %d\n", ppp_lcp_option(type), length);
				break;
			case 2: // Async-Control-Character-Map
				if (length == 6)
				{
					uint32_t asyncmap = ntohl(*(uint32_t *)(o + 2));
					LOG(4, 0, 0, "    %s %x\n", ppp_lcp_option(type), asyncmap);
				}
				else
					LOG(4, 0, 0, "    %s odd length %d\n", ppp_lcp_option(type), length);
				break;
			case 3: // Authentication-Protocol
				if (length == 4)
				{
					int proto = ntohs(*(uint16_t *)(o + 2));
					LOG(4, 0, 0, "    %s 0x%x (%s)\n", ppp_lcp_option(type), proto,
						proto == PPPPAP  ? "PAP"  : "UNSUPPORTED");
				}
				else if (length == 5)
				{
					int proto = ntohs(*(uint16_t *)(o + 2));
					int algo = *(uint8_t *)(o + 4);
					LOG(4, 0, 0, "    %s 0x%x 0x%x (%s)\n", ppp_lcp_option(type), proto, algo,
						(proto == PPPCHAP && algo == 5) ? "CHAP MD5"  : "UNSUPPORTED");
				}
				else
					LOG(4, 0, 0, "    %s odd length %d\n", ppp_lcp_option(type), length);
				break;
			case 4: // Quality-Protocol
				{
					uint32_t qp = ntohl(*(uint32_t *)(o + 2));
					LOG(4, 0, 0, "    %s %x\n", ppp_lcp_option(type), qp);
				}
				break;
			case 5: // Magic-Number
				if (length == 6)
				{
					uint32_t magicno = ntohl(*(uint32_t *)(o + 2));
					LOG(4, 0, 0, "    %s %x\n", ppp_lcp_option(type), magicno);
				}
				else
					LOG(4, 0, 0, "    %s odd length %d\n", ppp_lcp_option(type), length);
				break;
			case 7: // Protocol-Field-Compression
			case 8: // Address-And-Control-Field-Compression
				LOG(4, 0, 0, "    %s\n", ppp_lcp_option(type));
				break;
			default:
				LOG(2, 0, 0, "    Unknown PPP LCP Option type %d\n", type);
				break;
		}
		x -= length;
		o += length;
	}
}

void lcp_open(sessionidt s, tunnelidt t)
{
	// transition to Authentication or Network phase: 
	session[s].ppp.phase = sess_local[s].lcp_authtype ? Authenticate : Network;

	// LCP now Opened
	change_state(s, lcp, Opened);

	if (session[s].ppp.phase == Authenticate)
	{
		if (sess_local[s].lcp_authtype == AUTHCHAP)
			sendchap(s, t);
	}
	else
	{
		// This-Layer-Up
		sendipcp(s, t);
		change_state(s, ipcp, RequestSent);
		// move to passive state for IPv6 (if configured), CCP
		if (config->ipv6_prefix.s6_addr[0])
			change_state(s, ipv6cp, Stopped);
		else
			change_state(s, ipv6cp, Closed);

		change_state(s, ccp, Stopped);
	}
}

static void lcp_restart(sessionidt s)
{
	session[s].ppp.phase = Establish;
	// This-Layer-Down
	change_state(s, ipcp, Dead);
	change_state(s, ipv6cp, Dead);
	change_state(s, ccp, Dead);
}

static uint8_t *ppp_rej(sessionidt s, uint8_t *buf, size_t blen, uint16_t mtype,
	uint8_t **response, uint8_t *queued, uint8_t *packet, uint8_t *option)
{
	if (!*response || **response != ConfigRej)
	{
		queued = *response = makeppp(buf, blen, packet, 2, s, session[s].tunnel, mtype);
		if (!queued)
			return 0;

		*queued = ConfigRej;
		queued += 4;
	}

	if ((queued - buf + option[1]) > blen)
	{
		LOG(2, s, session[s].tunnel, "PPP overflow for ConfigRej (proto %u, option %u).\n", mtype, *option);
		return 0;
	}

	memcpy(queued, option, option[1]);
	return queued + option[1];
}

static uint8_t *ppp_nak(sessionidt s, uint8_t *buf, size_t blen, uint16_t mtype,
	uint8_t **response, uint8_t *queued, uint8_t *packet, uint8_t *option,
	uint8_t *value, size_t vlen)
{
    	int *nak_sent;
	switch (mtype)
	{
	case PPPLCP:	nak_sent = &sess_local[s].lcp.nak_sent;    break;
	case PPPIPCP:	nak_sent = &sess_local[s].ipcp.nak_sent;   break;
	case PPPIPV6CP:	nak_sent = &sess_local[s].ipv6cp.nak_sent; break;
	default:	return 0; // ?
	}

	if (*response && **response != ConfigNak)
	{
	    	if (*nak_sent < config->ppp_max_failure) // reject queued
			return queued;

		return ppp_rej(s, buf, blen, mtype, response, 0, packet, option);
	}

	if (!*response)
	{
	    	if (*nak_sent >= config->ppp_max_failure)
			return ppp_rej(s, buf, blen, mtype, response, 0, packet, option);

		queued = *response = makeppp(buf, blen, packet, 2, s, session[s].tunnel, mtype);
		if (!queued)
			return 0;

		*nak_sent++;
		*queued = ConfigNak;
		queued += 4;
	}

	if ((queued - buf + vlen + 2) > blen)
	{
		LOG(2, s, session[s].tunnel, "PPP overflow for ConfigNak (proto %u, option %u).\n", mtype, *option);
		return 0;
	}

	*queued++ = *option;
	*queued++ = vlen + 2;
	memcpy(queued, value, vlen);
	return queued + vlen;
}

// Process LCP messages
void processlcp(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l)
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

	if (session[s].die) // going down...
		return;

	if (*p == ConfigAck)
	{
		int x = l - 4;
		uint8_t *o = (p + 4);
		int authtype = 0;

		LOG(3, s, t, "LCP: ConfigAck (%d bytes)...\n", l);
		if (config->debug > 3) dumplcp(p, l);

		while (x > 2)
		{
			int type = o[0];
			int length = o[1];

			if (length == 0 || type == 0 || x < length) break;
			switch (type)
			{
				case 3: // Authentication-Protocol
					{
						int proto = ntohs(*(uint16_t *)(o + 2));
						if (proto == PPPPAP)
							authtype = AUTHPAP;
						else if (proto == PPPCHAP && *(o + 4) == 5)
							authtype = AUTHCHAP;
					}

					break;
			}
			x -= length;
			o += length;
		}

		if (!session[s].ip && authtype)
			sess_local[s].lcp_authtype = authtype;

		switch (session[s].ppp.lcp)
		{
		case RequestSent:
		    	initialise_restart_count(s, lcp);
			change_state(s, lcp, AckReceived);
			break;

		case AckReceived:
		case Opened:
		    	LOG(2, s, t, "LCP: ConfigAck in state %s?  Sending ConfigReq\n", ppp_state(session[s].ppp.lcp));
			if (session[s].ppp.lcp == Opened)
				lcp_restart(s);

			sendlcp(s, t, sess_local[s].lcp_authtype);
			change_state(s, lcp, RequestSent);
			break;

		case AckSent:
			lcp_open(s, t);
			break;

		default:
		    	LOG(2, s, t, "LCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.lcp));
		}
	}
	else if (*p == ConfigReq)
	{
		int x = l - 4;
		uint8_t *o = (p + 4);
		uint8_t *response = 0;
		static uint8_t asyncmap[4] = { 0, 0, 0, 0 }; // all zero
		static uint8_t authproto[5];

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

					LOG(2, s, t, "    Remote requesting asyncmap.  Rejecting.\n");
					q = ppp_nak(s, b, sizeof(b), PPPLCP, &response, q, p, o, asyncmap, sizeof(asyncmap));
					break;

				case 3: // Authentication-Protocol
					{
						int proto = ntohs(*(uint16_t *)(o + 2));
						char proto_name[] = "0x0000";
						int alen;

						if (proto == PPPPAP)
						{
							if (config->radius_authtypes & AUTHPAP)
							{
								sess_local[s].lcp_authtype = AUTHPAP;
								break;
							}

							strcpy(proto_name, "PAP");
						}
						else if (proto == PPPCHAP)
						{
							if (config->radius_authtypes & AUTHCHAP
							    && *(o + 4) == 5) // MD5
							{
								sess_local[s].lcp_authtype = AUTHCHAP;
								break;
							}

							strcpy(proto_name, "CHAP");
						}
						else
							sprintf(proto_name, "%#4.4x", proto);

						LOG(2, s, t, "    Remote requesting %s authentication.  Rejecting.\n", proto_name);

						alen = add_lcp_auth(authproto, sizeof(authproto), config->radius_authprefer);
						if (alen < 2) break; // paranoia

						q = ppp_nak(s, b, sizeof(b), PPPLCP, &response, q, p, o, authproto + 2, alen - 2);
						if (q && *response == ConfigNak &&
							config->radius_authtypes != config->radius_authprefer)
						{
							// alternate type
						    	alen = add_lcp_auth(authproto, sizeof(authproto), config->radius_authtypes & ~config->radius_authprefer);
							if (alen < 2) break;
							q = ppp_nak(s, b, sizeof(b), PPPLCP, &response, q, p, o, authproto + 2, alen - 2);
						}

						break;
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
					q = ppp_rej(s, b, sizeof(b), PPPLCP, &response, q, p, o);
			}
			x -= length;
			o += length;
		}

		if (response)
		{
			l = q - response; // LCP packet length
			*((uint16_t *) (response + 2)) = htons(l); // update header
		}
		else
		{
			// Send packet back as ConfigAck
			response = makeppp(b, sizeof(b), p, l, s, t, PPPLCP);
			if (!response) return;
			*response = ConfigAck;
		}

		switch (session[s].ppp.lcp)
		{
		case Closed:
			response = makeppp(b, sizeof(b), p, 2, s, t, PPPLCP);
			if (!response) return;
			*response = TerminateAck;
			*((uint16_t *) (response + 2)) = htons(l = 4);
			break;

		case Stopped:
		    	initialise_restart_count(s, lcp);
			sendlcp(s, t, sess_local[s].lcp_authtype);
			if (*response == ConfigAck)
				change_state(s, lcp, AckSent);
			else
				change_state(s, lcp, RequestSent);

			break;

		case RequestSent:
			if (*response == ConfigAck)
				change_state(s, lcp, AckSent);

			break;

		case AckReceived:
			if (*response == ConfigAck)
				lcp_open(s, t);

			break;

		case Opened:
		    	lcp_restart(s);
			sendlcp(s, t, sess_local[s].lcp_authtype);
			/* fallthrough */

		case AckSent:
			if (*response == ConfigAck)
				change_state(s, lcp, AckSent);
			else
				change_state(s, lcp, RequestSent);

			break;

		default:
		    	LOG(2, s, t, "LCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.lcp));
			return;
		}

		LOG(3, s, t, "LCP: Sending %s\n", ppp_code(*response));
		tunnelsend(b, l + (response - b), t);
	}
	else if (*p == ConfigNak)
	{
		int x = l - 4;
		uint8_t *o = (p + 4);
		int authtype = -1;

		LOG(3, s, t, "LCP: ConfigNak (%d bytes)...\n", l);
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
					LOG(3, s, t, "    Remote requested MRU of %u\n", session[s].mru);
					break;

				case 3: // Authentication-Protocol
					if (authtype > 0)
						break;

					{
						int proto = ntohs(*(uint16_t *)(o + 2));
						if (proto == PPPPAP)
						{
							authtype = config->radius_authtypes & AUTHPAP;
							LOG(3, s, t, "    Remote requested PAP authentication...%sing\n",
								authtype ? "accept" : "reject");
						}
						else if (proto == PPPCHAP && *(o + 4) == 5)
						{
							authtype = config->radius_authtypes & AUTHCHAP;
							LOG(3, s, t, "    Remote requested CHAP authentication...%sing\n",
								authtype ? "accept" : "reject");
						}
						else
						{
							LOG(3, s, t, "    Rejecting unsupported authentication %#4x\n",
								proto);
						}
					}

					break;

				default:
				    	LOG(2, s, t, "    Remote NAKed LCP type %u?\n", type);
					break;
			}
			x -= length;
			o += length;
		}

		if (!authtype)
		{
			sessionshutdown(s, "Unsupported authentication.", 3, 0);
			return;
		}

		if (authtype > 0)
			sess_local[s].lcp_authtype = authtype;

		switch (session[s].ppp.lcp)
		{
		case Closed:
		case Stopped:
		    	{
				uint8_t *response = makeppp(b, sizeof(b), p, 2, s, t, PPPLCP);
				if (!response) return;
				*response = TerminateAck;
				*((uint16_t *) (response + 2)) = htons(l = 4);
				tunnelsend(b, l + (response - b), t);
			}
			break;

		case RequestSent:
		case AckSent:
		    	initialise_restart_count(s, lcp);
			sendlcp(s, t, sess_local[s].lcp_authtype);
			break;

		case AckReceived:
		    	LOG(2, s, t, "LCP: ConfigNak in state %s?  Sending ConfigReq\n", ppp_state(session[s].ppp.lcp));
			sendlcp(s, t, sess_local[s].lcp_authtype);
			break;

		case Opened:
		    	lcp_restart(s);
			sendlcp(s, t, sess_local[s].lcp_authtype);
			break;

		default:
		    	LOG(2, s, t, "LCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.lcp));
			return;
		}
	}
	else if (*p == TerminateReq)
	{
		LOG(3, s, t, "LCP: Received TerminateReq.  Sending TerminateAck\n");
		*p = TerminateAck;	// close
		q = makeppp(b, sizeof(b),  p, l, s, t, PPPLCP);
		if (!q) return;
		tunnelsend(b, l + (q - b), t); // send it
		sessionshutdown(s, "Remote end closed connection.", 3, 0);
	}
	else if (*p == TerminateAck)
	{
		sessionshutdown(s, "Connection closed.", 3, 0);
	}
	else if (*p == ProtocolRej)
	{
		if (*(uint16_t *) (p+4) == htons(PPPIPV6CP))
		{
			LOG(3, s, t, "IPv6 rejected\n");
			change_state(s, ipv6cp, Closed);
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
		q = makeppp(b, sizeof(b), p, l, s, t, PPPLCP);
		if (!q) return;
		tunnelsend(b, l + (q - b), t); // send it
	}
	else if (*p == EchoReply)
	{
		// Ignore it, last_packet time is set earlier than this.
	}
	else
	{
		int code = *p;
		int mru = session[s].mru;
		if (!mru)
			mru = DEFAULT_MRU;

		if (l > mru) l = mru;

		*p = CodeRej;
		q = makeppp(b, sizeof(b), p, l, s, t, PPPLCP);
		if (!q) return;

		LOG(3, s, t, "Unexpected LCP code %s\n", ppp_code(code));
		tunnelsend(b, l + (q - b), t);
	}
}

static void ipcp_open(sessionidt s, tunnelidt t)
{
	LOG(3, s, t, "IPCP: Opened, session is now active\n");

	change_state(s, ipcp, Opened);

	if (!session[s].walled_garden)
	{
		uint16_t r = radiusnew(s);
		if (r)
			radiussend(r, RADIUSSTART); // send radius start
	}

	// start IPv6 if configured and still in passive state
	if (session[s].ppp.ipv6cp == Stopped)
	{
		sendipv6cp(s, t);
		change_state(s, ipv6cp, RequestSent);
	}
}

// Process IPCP messages
void processipcp(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l)
{
	uint8_t b[MAXCONTROL];
	uint8_t *q = 0;
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

	if (session[s].ppp.phase < Network)
	{
	    	LOG(2, s, t, "IPCP %s ignored in %s phase\n", ppp_code(*p), ppp_phase(session[s].ppp.phase));
		return;
	}

	if (*p == ConfigAck)
	{
		switch (session[s].ppp.ipcp)
		{
		case RequestSent:
		    	initialise_restart_count(s, ipcp);
			change_state(s, ipcp, AckReceived);
			break;

		case AckReceived:
		case Opened:
		    	LOG(2, s, t, "IPCP: ConfigAck in state %s?  Sending ConfigReq\n", ppp_state(session[s].ppp.ipcp));
			sendipcp(s, t);
			change_state(s, ipcp, RequestSent);
			break;

		case AckSent:
			ipcp_open(s, t);
			break;

		default:
		    	LOG(2, s, t, "IPCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.ipcp));
		}
	}
	else if (*p == ConfigReq)
	{
		uint8_t *response = 0;
		uint8_t *o = p + 4;
		int length = l - 4;
		int gotip = 0;
		in_addr_t addr;

		LOG(3, s, t, "IPCP: ConfigReq received\n");

		while (length > 2)
		{
			switch (*o)
			{
			case 3: // ip address
				gotip++; // seen address
				if (o[1] != 6 || o[1] > length) return;

				addr = htonl(session[s].ip);
				if (memcmp(o + 2, &addr, (sizeof addr)))
				{
					q = ppp_nak(s, b, sizeof(b), PPPIPCP, &response, q, p, o, (uint8_t *) &addr, sizeof(addr));
					if (!q || *response == ConfigRej)
					{
						sessionshutdown(s, "Can't negotiate IPCP.", 3, 0);
						return;
					}
				}

				break;

			case 129: // primary DNS
				if (o[1] != 6 || o[1] > length) return;

				addr = htonl(session[s].dns1);
				if (memcmp(o + 2, &addr, (sizeof addr)))
				{
					q = ppp_nak(s, b, sizeof(b), PPPIPCP, &response, q, p, o, (uint8_t *) &addr, sizeof(addr));
					if (!q) return;
				}

				break;

			case 131: // secondary DNS
				if (o[1] != 6 || o[1] > length) return;

				addr = htonl(session[s].dns1);
				if (memcmp(o + 2, &addr, sizeof(addr)))
				{
					q = ppp_nak(s, b, sizeof(b), PPPIPCP, &response, q, p, o, (uint8_t *) &addr, sizeof(addr));
					if (!q) return;
				}

				break;

			default:
				LOG(2, s, t, "    Rejecting PPP IPCP Option type %d\n", *o);
				q = ppp_rej(s, b, sizeof(b), PPPIPCP, &response, q, p, o);
				if (!q) return;
			}

			length -= o[1];
			o += o[1];
		}

		if (response)
		{
			l = q - response; // IPCP packet length
			*((uint16_t *) (response + 2)) = htons(l); // update header
		}
		else if (gotip)
		{
			// Send packet back as ConfigAck
			response = makeppp(b, sizeof(b), p, l, s, t, PPPIPCP);
			if (!response) return;
			*response = ConfigAck;
		}
		else
		{
			LOG(1, s, t, "No IP in IPCP request\n");
			STAT(tunnel_rx_errors);
			return;
		}

		switch (session[s].ppp.ipcp)
		{
		case Closed:
			response = makeppp(b, sizeof(b), p, 2, s, t, PPPIPCP);
			if (!response) return;
			*response = TerminateAck;
			*((uint16_t *) (response + 2)) = htons(l = 4);
			break;

		case Stopped:
		    	initialise_restart_count(s, ipcp);
			sendipcp(s, t);
			if (*response == ConfigAck)
				change_state(s, ipcp, AckSent);
			else
				change_state(s, ipcp, RequestSent);

			break;

		case RequestSent:
			if (*response == ConfigAck)
				change_state(s, ipcp, AckSent);

			break;

		case AckReceived:
			if (*response == ConfigAck)
				ipcp_open(s, t);

			break;

		case Opened:
		    	initialise_restart_count(s, ipcp);
			sendipcp(s, t);
			/* fallthrough */

		case AckSent:
			if (*response == ConfigAck)
				change_state(s, ipcp, AckSent);
			else
				change_state(s, ipcp, RequestSent);

			break;

		default:
		    	LOG(2, s, t, "IPCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.ipcp));
			return;
		}

		LOG(3, s, t, "IPCP: Sending %s\n", ppp_code(*response));
		tunnelsend(b, l + (response - b), t);
	}
	else if (*p == TerminateReq)
	{
		LOG(3, s, t, "IPCP: Received TerminateReq.  Sending TerminateAck\n");
		*p = TerminateAck;
		q = makeppp(b, sizeof(b), p, l, s, t, PPPIPCP);
		if (!q) return;
		tunnelsend(b, l + (q - b), t);
		change_state(s, ipcp, Stopped);
	}
	else
	{
		int code = *p;
		int mru = session[s].mru;
		if (!mru)
			mru = DEFAULT_MRU;

		if (l > mru) l = mru;

		*p = CodeRej;
		q = makeppp(b, sizeof(b), p, l, s, t, PPPIPCP);
		if (!q) return;

		LOG(3, s, t, "Unexpected IPCP code %s\n", ppp_code(code));
		tunnelsend(b, l + (q - b), t);
	}
}

static void ipv6cp_open(sessionidt s, tunnelidt t)
{
	LOG(3, s, t, "IPV6CP: Opened\n");

	change_state(s, ipv6cp, Opened);
	if (session[s].ipv6prefixlen)
		route6set(s, session[s].ipv6route, session[s].ipv6prefixlen, 1);

	// Send an initial RA (TODO: Should we send these regularly?)
	send_ipv6_ra(s, t, NULL);
}

// Process IPV6CP messages
void processipv6cp(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l)
{
	uint8_t b[MAXCONTROL];
	uint8_t *q = 0;
	uint16_t hl;

	CSTAT(processipv6cp);

	LOG_HEX(5, "IPV6CP", p, l);
	if (l < 4)
	{
		LOG(1, s, t, "Short IPV6CP %d bytes\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, s, t, "Length mismatch IPV6CP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		return ;
	}
	l = hl;

	if (session[s].ppp.phase < Network)
	{
	    	LOG(2, s, t, "IPV6CP %s ignored in %s phase\n", ppp_code(*p), ppp_phase(session[s].ppp.phase));
		return;
	}

	if (!config->ipv6_prefix.s6_addr[0])
	{
	    	LOG(2, s, t, "IPV6CP: %s rejected (not configured)\n", ppp_code(*p));
		*p = ProtocolRej;
		q = makeppp(b, sizeof(b),  p, l, s, t, PPPIPV6CP);
		if (!q) return;
		tunnelsend(b, l + (q - b), t);
		return;
	}

	if (!session[s].ip)
	{
		LOG(3, s, t, "IPV6CP: no IPv4 address (IPCP in state %s)\n", ppp_state(session[s].ppp.ipcp));
		return; // need IPCP to complete...
	}

	if (*p == ConfigAck)
	{
		switch (session[s].ppp.ipv6cp)
		{
		case RequestSent:
		    	initialise_restart_count(s, ipv6cp);
			change_state(s, ipv6cp, AckReceived);
			break;

		case AckReceived:
		case Opened:
		    	LOG(2, s, t, "IPV6CP: ConfigAck in state %s?  Sending ConfigReq\n", ppp_state(session[s].ppp.ipv6cp));
			sendipv6cp(s, t);
			change_state(s, ipv6cp, RequestSent);
			break;

		case AckSent:
			ipv6cp_open(s, t);
			break;

		default:
		    	LOG(2, s, t, "IPV6CP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.ipv6cp));
		}
	}
	else if (*p == ConfigReq)
	{
		uint8_t *response = 0;
		uint8_t *o = p + 4;
		int length = l - 4;
		int gotip = 0;
		uint8_t ident[8];

		LOG(3, s, t, "IPV6CP: ConfigReq received\n");

		while (length > 2)
		{
			switch (*o)
			{
			case 1: // interface identifier
				gotip++; // seen address
				if (o[1] != 10 || o[1] > length) return;

				*(uint32_t *) ident = htonl(session[s].ip);
				*(uint32_t *) (ident + 4) = 0;

				if (memcmp(o + 2, ident, sizeof(ident)))
				{
					q = ppp_nak(s, b, sizeof(b), PPPIPV6CP, &response, q, p, o, ident, sizeof(ident));
					if (!q) return;
				}

				break;

			default:
				LOG(2, s, t, "    Rejecting PPP IPV6CP Option type %d\n", *o);
				q = ppp_rej(s, b, sizeof(b), PPPIPV6CP, &response, q, p, o);
				if (!q) return;
			}

			length -= o[1];
			o += o[1];
		}

		if (response)
		{
			l = q - response; // IPV6CP packet length
			*((uint16_t *) (response + 2)) = htons(l); // update header
		}
		else if (gotip)
		{
			// Send packet back as ConfigAck
			response = makeppp(b, sizeof(b), p, l, s, t, PPPIPV6CP);
			if (!response) return;
			*response = ConfigAck;
		}
		else
		{
			LOG(1, s, t, "No interface identifier in IPV6CP request\n");
			STAT(tunnel_rx_errors);
			return;
		}

		switch (session[s].ppp.ipv6cp)
		{
		case Closed:
			response = makeppp(b, sizeof(b), p, 2, s, t, PPPIPV6CP);
			if (!response) return;
			*response = TerminateAck;
			*((uint16_t *) (response + 2)) = htons(l = 4);
			break;

		case Stopped:
		    	initialise_restart_count(s, ipv6cp);
			sendipv6cp(s, t);
			if (*response == ConfigAck)
				change_state(s, ipv6cp, AckSent);
			else
				change_state(s, ipv6cp, RequestSent);

			break;

		case RequestSent:
			if (*response == ConfigAck)
				change_state(s, ipv6cp, AckSent);

			break;

		case AckReceived:
			if (*response == ConfigAck)
				ipv6cp_open(s, t);

			break;

		case Opened:
		    	initialise_restart_count(s, ipv6cp);
			sendipv6cp(s, t);
			/* fallthrough */

		case AckSent:
			if (*response == ConfigAck)
				change_state(s, ipv6cp, AckSent);
			else
				change_state(s, ipv6cp, RequestSent);

			break;

		default:
		    	LOG(2, s, t, "IPV6CP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.ipv6cp));
			return;
		}

		LOG(3, s, t, "IPV6CP: Sending %s\n", ppp_code(*response));
		tunnelsend(b, l + (response - b), t);
	}
	else if (*p == TerminateReq)
	{
		LOG(3, s, t, "IPV6CP: Received TerminateReq.  Sending TerminateAck\n");
		*p = TerminateAck;
		q = makeppp(b, sizeof(b),  p, l, s, t, PPPIPV6CP);
		if (!q) return;
		tunnelsend(b, l + (q - b), t);
		change_state(s, ipv6cp, Stopped);
	}
	else
	{
		int code = *p;
		int mru = session[s].mru;
		if (!mru)
			mru = DEFAULT_MRU;

		if (l > mru) l = mru;

		*p = CodeRej;
		q = makeppp(b, sizeof(b), p, l, s, t, PPPIPV6CP);
		if (!q) return;

		LOG(3, s, t, "Unexpected IPV6CP code %s\n", ppp_code(code));
		tunnelsend(b, l + (q - b), t);
	}
}

// process IP packet received
//
// This MUST be called with at least 4 byte behind 'p'.
// (i.e. this routine writes to p[-4]).
void processipin(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l)
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

	if (session[s].ppp.phase != Network || session[s].ppp.ipcp != Opened)
		return;

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

	p += 4;
	l -= 4;

	if (session[s].snoop_ip && session[s].snoop_port)
	{
		// Snooping this session
		snoop_send_packet(p, l, session[s].snoop_ip, session[s].snoop_port);
	}

	increment_counter(&session[s].cin, &session[s].cin_wrap, l);
	session[s].cin_delta += l;
	session[s].pin++;

	sess_local[s].cin += l;
	sess_local[s].pin++;

	eth_tx += l;

	STAT(tun_tx_packets);
	INC_STAT(tun_tx_bytes, l);
}

// process IPv6 packet received
//
// This MUST be called with at least 4 byte behind 'p'.
// (i.e. this routine writes to p[-4]).
void processipv6in(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l)
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

	if (session[s].ppp.phase != Network || session[s].ppp.ipv6cp != Opened)
		return;

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
		send_ipv6_ra(s, t, &ip);
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

	p += 4;
	l -= 4;

	if (session[s].snoop_ip && session[s].snoop_port)
	{
		// Snooping this session
		snoop_send_packet(p, l, session[s].snoop_ip, session[s].snoop_port);
	}

	increment_counter(&session[s].cin, &session[s].cin_wrap, l);
	session[s].cin_delta += l;
	session[s].pin++;

	sess_local[s].cin += l;
	sess_local[s].pin++;

	eth_tx += l;

	STAT(tun_tx_packets);
	INC_STAT(tun_tx_bytes, l);
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

	buf += 4;
	len -= 4;

	if (session[s].snoop_ip && session[s].snoop_port)
	{
		// Snooping this session
		snoop_send_packet(buf, len, session[s].snoop_ip, session[s].snoop_port);
	}

	// Increment packet counters
	increment_counter(&session[s].cin, &session[s].cin_wrap, len);
	session[s].cin_delta += len;
	session[s].pin++;

	sess_local[s].cin += len;
	sess_local[s].pin++;

	eth_tx += len;

	STAT(tun_tx_packets);
	INC_STAT(tun_tx_bytes, len - 4);
}


// Process CCP messages
void processccp(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l)
{
	uint8_t b[MAXCONTROL];
	uint8_t *q;

	CSTAT(processccp);

	LOG_HEX(5, "CCP", p, l);

	if (session[s].ppp.phase < Network)
	{
	    	LOG(2, s, t, "CCP %s ignored in %s phase\n", ppp_code(*p), ppp_phase(session[s].ppp.phase));
		return;
	}

	if (l < 1)
	{
		LOG(1, s, t, "Short CCP packet\n");
		STAT(tunnel_rx_errors);
	}

	if (*p == ConfigAck)
	{
		switch (session[s].ppp.ccp)
		{
		case RequestSent:
		    	initialise_restart_count(s, ccp);
			change_state(s, ccp, AckReceived);
			break;

		case AckReceived:
		case Opened:
		    	LOG(2, s, t, "CCP: ConfigAck in state %s?  Sending ConfigReq\n", ppp_state(session[s].ppp.ccp));
			sendccp(s, t);
			change_state(s, ccp, RequestSent);
			break;

		case AckSent:
			LOG(3, s, t, "CCP: Opened\n");
			change_state(s, ccp, Opened);
			break;

		default:
		    	LOG(2, s, t, "CCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.ccp));
		}
	}
	else if (*p == ConfigReq)
	{
		if (l < 6) // accept no compression
			*p = ConfigAck;
		else // compression requested--reject
			*p = ConfigRej;

		q = makeppp(b, sizeof(b), p, l, s, t, PPPCCP);
		if (!q) return;

		switch (session[s].ppp.ccp)
		{
		case Closed:
			q = makeppp(b, sizeof(b), p, 2, s, t, PPPCCP);
			if (!q) return;
			*q = TerminateAck;
			*((uint16_t *) (q + 2)) = htons(l = 4);
			break;

		case Stopped:
		    	initialise_restart_count(s, ccp);
			sendccp(s, t);
			if (*q == ConfigAck)
				change_state(s, ccp, AckSent);
			else
				change_state(s, ccp, RequestSent);

			break;

		case RequestSent:
			if (*q == ConfigAck)
				change_state(s, ccp, AckSent);

			break;

		case AckReceived:
			if (*q == ConfigAck)
				change_state(s, ccp, Opened);

			break;

		case Opened:
		    	initialise_restart_count(s, ccp);
			sendccp(s, t);
			/* fallthrough */

		case AckSent:
			if (*q == ConfigAck)
				change_state(s, ccp, AckSent);
			else
				change_state(s, ccp, RequestSent);

			break;

		default:
		    	LOG(2, s, t, "CCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.ccp));
			return;
		}

		LOG(3, s, t, "CCP: Sending %s\n", ppp_code(*q));
		tunnelsend(b, l + (q - b), t);
	}
	else if (*p == TerminateReq)
	{
		LOG(3, s, t, "CCP: Received TerminateReq.  Sending TerminateAck\n");
		*p = TerminateAck;
		q = makeppp(b, sizeof(b),  p, l, s, t, PPPCCP);
		if (!q) return;
		tunnelsend(b, l + (q - b), t);
		change_state(s, ccp, Stopped);
	}
	else
	{
		int code = *p;
		int mru = session[s].mru;
		if (!mru)
			mru = DEFAULT_MRU;

		if (l > mru) l = mru;

		*p = CodeRej;
		q = makeppp(b, sizeof(b), p, l, s, t, PPPCCP);
		if (!q) return;

		LOG(3, s, t, "Unexpected CCP code %s\n", ppp_code(code));
		tunnelsend(b, l + (q - b), t);
	}
}

// send a CHAP challenge
void sendchap(sessionidt s, tunnelidt t)
{
	uint8_t b[MAXCONTROL];
	uint16_t r;
	uint8_t *q;

	CSTAT(sendchap);

	r = radiusnew(s);
	if (!r)
	{
		LOG(1, s, t, "No RADIUS to send challenge\n");
		STAT(tunnel_tx_errors);
		return;
	}

	LOG(1, s, t, "Send CHAP challenge\n");

	radius[r].chap = 1;		// CHAP not PAP
	radius[r].id++;
	if (radius[r].state != RADIUSCHAP)
		radius[r].try = 0;

	radius[r].state = RADIUSCHAP;
	radius[r].retry = backoff(radius[r].try++);
	if (radius[r].try > 5)
	{
		sessionshutdown(s, "CHAP timeout.", 3, 0);
		STAT(tunnel_tx_errors);
		return ;
	}
	q = makeppp(b, sizeof(b), 0, 0, s, t, PPPCHAP);
	if (!q) return;

	*q = 1;					// challenge
	q[1] = radius[r].id;			// ID
	q[4] = 16;				// value size (size of challenge)
	memcpy(q + 5, radius[r].auth, 16);	// challenge
	strcpy((char *) q + 21, hostname);	// our name
	*(uint16_t *) (q + 2) = htons(strlen(hostname) + 21); // length
	tunnelsend(b, strlen(hostname) + 21 + (q - b), t); // send it
}

// fill in a L2TP message with a PPP frame,
// copies existing PPP message and changes magic number if seen
// returns start of PPP frame
uint8_t *makeppp(uint8_t *b, int size, uint8_t *p, int l, sessionidt s, tunnelidt t, uint16_t mtype)
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

static int add_lcp_auth(uint8_t *b, int size, int authtype)
{
	int len = 0;
	if ((authtype == AUTHCHAP && size < 5) || size < 4)
		return 0;

	*b++ = 3; // Authentication-Protocol
	if (authtype == AUTHCHAP)
	{
		len = *b++ = 5; // length
		*(uint16_t *) b = htons(PPPCHAP); b += 2;
		*b++ = 5; // MD5
	}
	else if (authtype == AUTHPAP)
	{
		len = *b++ = 4; // length
		*(uint16_t *) b = htons(PPPPAP); b += 2;
	}
	else
	{
		LOG(0, 0, 0, "add_lcp_auth called with unsupported auth type %d\n", authtype);
	}

	return len;
}

// Send initial LCP ConfigReq for MRU, authentication type and magic no
void sendlcp(sessionidt s, tunnelidt t, int authtype)
{
	uint8_t b[500], *q, *l;

	if (!(q = makeppp(b, sizeof(b), NULL, 0, s, t, PPPLCP)))
		return;

	LOG(4, s, t, "Sending LCP ConfigReq%s%s\n",
	    authtype ? " for " : "",
	    authtype ? (authtype == AUTHCHAP ? "CHAP" : "PAP") : "");

	if (!session[s].mru)
		session[s].mru = DEFAULT_MRU;

	l = q;
	*l++ = ConfigReq;
	*l++ = (time_now % 255) + 1; // ID

	l += 2; //Save space for length

	*l++ = 1; *l++ = 4; // Maximum-Receive-Unit (length 4)
	*(uint16_t *) l = htons(session[s].mru); l += 2;

	if (authtype)
		l += add_lcp_auth(l, sizeof(b) - (l - b), authtype);

	*l++ = 5; *l++ = 6; // Magic-Number (length 6)
	*(uint32_t *) l = htonl(session[s].magic);
	l += 4;

	*(uint16_t *)(q + 2) = htons(l - q); // Length

	LOG_HEX(5, "PPPLCP", q, l - q);
	tunnelsend(b, (l - b), t);
}

// Send CCP request for no compression
void sendccp(sessionidt s, tunnelidt t)
{
	uint8_t b[500], *q;

	if (!(q = makeppp(b, sizeof(b), NULL, 0, s, t, PPPCCP)))
		return;

	LOG(4, s, t, "Sending CCP ConfigReq for no compression\n");
	*q = ConfigReq;
	*(uint8_t *)(q + 1) = (time_now % 255) + 1; // ID
	*(uint16_t *)(q + 2) = htons(4); // Length

	LOG_HEX(5, "PPPCCP", q, 4);
	tunnelsend(b, (q - b) + 4 , t);
}
