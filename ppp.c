// L2TPNS PPP Stuff

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
extern bundlet *bundle;
extern fragmentationt *frag;
extern sessiont *session;
extern radiust *radius;
extern int tunfd;
extern char hostname[];
extern uint32_t eth_tx;
extern time_t time_now;
extern configt *config;

static int add_lcp_auth(uint8_t *b, int size, int authtype);
static bundleidt new_bundle(void);
static int epdiscmp(epdist, epdist);
static void setepdis(epdist *, epdist);
static void ipcp_open(sessionidt s, tunnelidt t);

static int first_session_in_bundle(sessionidt s)
{
	bundleidt i;
	for (i = 1; i < MAXBUNDLE; i++)
		if (bundle[i].state != BUNDLEFREE)
			if (epdiscmp(session[s].epdis,bundle[i].epdis) && !strcmp(session[s].user, bundle[i].user))
				return 0;
	return 1;	
}

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
		sessionshutdown(s, "Short PAP packet.", CDN_ADMIN_DISC, TERM_USER_ERROR);
		return;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, s, t, "Length mismatch PAP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "PAP length mismatch.", CDN_ADMIN_DISC, TERM_USER_ERROR);
		return;
	}
	l = hl;

	if (*p != 1)
	{
		LOG(1, s, t, "Unexpected PAP code %d\n", *p);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "Unexpected PAP code.", CDN_ADMIN_DISC, TERM_USER_ERROR);
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

	if (session[s].ip || !(r = radiusnew(s)))
	{
		// respond now, either no RADIUS available or already authenticated
		uint8_t b[MAXETHER];
		uint8_t id = p[1];
		uint8_t *p = makeppp(b, sizeof(b), 0, 0, s, t, PPPPAP, 0, 0, 0);
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
			sessionshutdown(s, "No free RADIUS sessions.", CDN_UNAVAILABLE, TERM_SERVICE_UNAVAILABLE);
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
		if ((session[s].mrru) && (!first_session_in_bundle(s)))
			radiussend(r, RADIUSJUSTAUTH);
		else
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

	if (l < 4)
	{
		LOG(1, s, t, "Short CHAP %u bytes\n", l);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "Short CHAP packet.", CDN_ADMIN_DISC, TERM_USER_ERROR);
		return;
	}

	if ((hl = ntohs(*(uint16_t *) (p + 2))) > l)
	{
		LOG(1, s, t, "Length mismatch CHAP %u/%u\n", hl, l);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "CHAP length mismatch.", CDN_ADMIN_DISC, TERM_USER_ERROR);
		return;
	}
	l = hl;

	if (*p != 2)
	{
		LOG(1, s, t, "Unexpected CHAP response code %d\n", *p);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "CHAP length mismatch.", CDN_ADMIN_DISC, TERM_USER_ERROR);
		return;
	}

	if (session[s].ppp.phase != Authenticate)
	{
	    	LOG(2, s, t, "CHAP ignored in %s phase\n", ppp_phase(session[s].ppp.phase));
		return;
	}

	r = sess_local[s].radius;
	if (!r)
	{
		LOG(3, s, t, "Unexpected CHAP message\n");

		// Some modems (Netgear DM602, possibly others) persist in using CHAP even
		// after ACKing our ConfigReq for PAP.
		if (sess_local[s].lcp_authtype == AUTHPAP && config->radius_authtypes & AUTHCHAP)
		{
			sess_local[s].lcp_authtype = AUTHCHAP;
			sendchap(s, t);
		}
		return;
	}

	if (p[1] != radius[r].id)
	{
		LOG(1, s, t, "Wrong CHAP response ID %d (should be %d) (%d)\n", p[1], radius[r].id, r);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "Unexpected CHAP response ID.", CDN_ADMIN_DISC, TERM_USER_ERROR);
		return;
	}

	if (l < 5 || p[4] != 16)
	{
		LOG(1, s, t, "Bad CHAP response length %d\n", l < 5 ? -1 : p[4]);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "Bad CHAP response length.", CDN_ADMIN_DISC, TERM_USER_ERROR);
		return;
	}

	l -= 5;
	p += 5;
	if (l < 16 || l - 16 >= sizeof(session[s].user))
	{
		LOG(1, s, t, "CHAP user too long %d\n", l - 16);
		STAT(tunnel_rx_errors);
		sessionshutdown(s, "CHAP username too long.", CDN_ADMIN_DISC, TERM_USER_ERROR);
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
	if ((session[s].mrru) && (!first_session_in_bundle(s)))
		radiussend(r, RADIUSJUSTAUTH);
	else
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
					int algo = *(o + 4);
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

	LOG(3, s, t, "LCP: Opened, phase %s\n", ppp_phase(session[s].ppp.phase));

	// LCP now Opened
	change_state(s, lcp, Opened);

	if (session[s].ppp.phase == Authenticate)
	{
		if (sess_local[s].lcp_authtype == AUTHCHAP)
			sendchap(s, t);
	}
	else
	{
		if(session[s].bundle == 0 || bundle[session[s].bundle].num_of_links == 1)
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
		else
		{
			sessionidt first_ses = bundle[session[s].bundle].members[0];
			LOG(3, s, t, "MPPP: Skipping IPCP negotiation for session:%d, first session of bundle is:%d\n",s,first_ses);
			ipcp_open(s, t);
                }
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

static uint8_t *ppp_conf_rej(sessionidt s, uint8_t *buf, size_t blen, uint16_t mtype,
	uint8_t **response, uint8_t *queued, uint8_t *packet, uint8_t *option)
{
	if (!*response || **response != ConfigRej)
	{
		queued = *response = makeppp(buf, blen, packet, 2, s, session[s].tunnel, mtype, 0, 0, 0);
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

static uint8_t *ppp_conf_nak(sessionidt s, uint8_t *buf, size_t blen, uint16_t mtype,
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

		return ppp_conf_rej(s, buf, blen, mtype, response, 0, packet, option);
	}

	if (!*response)
	{
	    	if (*nak_sent >= config->ppp_max_failure)
			return ppp_conf_rej(s, buf, blen, mtype, response, 0, packet, option);

		queued = *response = makeppp(buf, blen, packet, 2, s, session[s].tunnel, mtype, 0, 0, 0);
		if (!queued)
			return 0;

		(*nak_sent)++;
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

static void ppp_code_rej(sessionidt s, tunnelidt t, uint16_t proto,
	char *pname, uint8_t *p, uint16_t l, uint8_t *buf, size_t size)
{
	uint8_t *q;
	int mru = session[s].mru;
	if (mru < MINMTU) mru = MINMTU;
	if (mru > size) mru = size;

	l += 4;
	if (l > mru) l = mru;

	q = makeppp(buf, size, 0, 0, s, t, proto, 0, 0, 0);
	if (!q) return;

	*q = CodeRej;
	*(q + 1) = ++sess_local[s].lcp_ident;
	*(uint16_t *)(q + 2) = htons(l);
	memcpy(q + 4, p, l - 4);

	LOG(2, s, t, "Unexpected %s code %s\n", pname, ppp_code(*p));
	LOG(3, s, t, "%s: send %s\n", pname, ppp_code(*q));
	if (config->debug > 3) dumplcp(q, l);

	tunnelsend(buf, l + (q - buf), t);
}

// Process LCP messages
void processlcp(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l)
{
	uint8_t b[MAXETHER];
	uint8_t *q = NULL;
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

	LOG((*p == EchoReq || *p == EchoReply) ? 4 : 3, s, t,
		"LCP: recv %s\n", ppp_code(*p));

	if (config->debug > 3) dumplcp(p, l);

	if (*p == ConfigAck)
	{
		int x = l - 4;
		uint8_t *o = (p + 4);
		int authtype = 0;

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

			sendlcp(s, t);
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
		int changed = 0;

		while (x > 2)
		{
			int type = o[0];
			int length = o[1];

			if (length == 0 || type == 0 || x < length) break;
			switch (type)
			{
				case 1: // Maximum-Receive-Unit
					{
						uint16_t mru = ntohs(*(uint16_t *)(o + 2));
						if (mru >= MINMTU)
						{
							session[s].mru = mru;
							changed++;
							break;
						}

						LOG(3, s, t, "    Remote requesting MRU of %u.  Rejecting.\n", mru);
						mru = htons(MRU);
						q = ppp_conf_nak(s, b, sizeof(b), PPPLCP, &response, q, p, o, (uint8_t *) &mru, sizeof(mru));
					}
					break;

				case 2: // Async-Control-Character-Map
					if (!ntohl(*(uint32_t *)(o + 2))) // all bits zero is OK
						break;

					LOG(3, s, t, "    Remote requesting asyncmap.  Rejecting.\n");
					q = ppp_conf_nak(s, b, sizeof(b), PPPLCP, &response, q, p, o, asyncmap, sizeof(asyncmap));
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

						LOG(3, s, t, "    Remote requesting %s authentication.  Rejecting.\n", proto_name);

						alen = add_lcp_auth(authproto, sizeof(authproto), config->radius_authprefer);
						if (alen < 2) break; // paranoia

						q = ppp_conf_nak(s, b, sizeof(b), PPPLCP, &response, q, p, o, authproto + 2, alen - 2);
						if (q && *response == ConfigNak &&
							config->radius_authtypes != config->radius_authprefer)
						{
							// alternate type
						    	alen = add_lcp_auth(authproto, sizeof(authproto), config->radius_authtypes & ~config->radius_authprefer);
							if (alen < 2) break;
							q = ppp_conf_nak(s, b, sizeof(b), PPPLCP, &response, q, p, o, authproto + 2, alen - 2);
						}

						break;
					}
					break;

				case 4: // Quality-Protocol
				case 5: // Magic-Number
				case 7: // Protocol-Field-Compression
				case 8: // Address-And-Control-Field-Compression
					break;

				case 17: // Multilink Max-Receive-Reconstructed-Unit
					{
						uint16_t mrru = ntohs(*(uint16_t *)(o + 2));
						session[s].mrru = mrru;
						changed++;
						LOG(3, s, t, "    Received PPP LCP option MRRU: %d\n",mrru);
					}
					break;
					
				case 18: // Multilink Short Sequence Number Header Format
					{
						session[s].mssf = 1;
						changed++;
						LOG(3, s, t, "    Received PPP LCP option MSSN format\n");
					}
					break;
					
				case 19: // Multilink Endpoint Discriminator
					{
						uint8_t epdis_class = o[2];
						int addr;

						session[s].epdis.addr_class = epdis_class;
						session[s].epdis.length = length - 3;
						if (session[s].epdis.length > 20)
						{
							LOG(1, s, t, "Error: received EndDis Address Length more than 20: %d\n", session[s].epdis.length);
							session[s].epdis.length = 20;
						}

						for (addr = 0; addr < session[s].epdis.length; addr++)
							session[s].epdis.address[addr] = o[3+addr];

						changed++;

						switch (epdis_class)
						{
						case LOCALADDR:
							LOG(3, s, t, "    Received PPP LCP option Multilink EndDis Local Address Class: %d\n",epdis_class);
							break;
						case IPADDR:
							LOG(3, s, t, "    Received PPP LCP option Multilink EndDis IP Address Class: %d\n",epdis_class);
							break;
						case IEEEMACADDR:
							LOG(3, s, t, "    Received PPP LCP option Multilink EndDis IEEE MAC Address Class: %d\n",epdis_class);
							break;
						case PPPMAGIC:
							LOG(3, s, t, "    Received PPP LCP option Multilink EndDis PPP Magic No Class: %d\n",epdis_class);
							break;
						case PSNDN:
							LOG(3, s, t, "    Received PPP LCP option Multilink EndDis PSND No Class: %d\n",epdis_class);
							break;
						default:
							LOG(3, s, t, "    Received PPP LCP option Multilink EndDis NULL Class %d\n",epdis_class);
						}
					}
					break;

				default: // Reject any unknown options
					LOG(3, s, t, "    Rejecting unknown PPP LCP option %d\n", type);
					q = ppp_conf_rej(s, b, sizeof(b), PPPLCP, &response, q, p, o);
			}
			x -= length;
			o += length;
		}

		if (changed)
			cluster_send_session(s);

		if (response)
		{
			l = q - response; // LCP packet length
			*((uint16_t *) (response + 2)) = htons(l); // update header
		}
		else
		{
			// Send packet back as ConfigAck
			response = makeppp(b, sizeof(b), p, l, s, t, PPPLCP, 0, 0, 0);
			if (!response) return;
			*response = ConfigAck;
		}

		switch (session[s].ppp.lcp)
		{
		case Closed:
			response = makeppp(b, sizeof(b), p, 2, s, t, PPPLCP, 0, 0, 0);
			if (!response) return;
			*response = TerminateAck;
			*((uint16_t *) (response + 2)) = htons(l = 4);
			break;

		case Stopped:
		    	initialise_restart_count(s, lcp);
			sendlcp(s, t);
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
			sendlcp(s, t);
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

		LOG(3, s, t, "LCP: send %s\n", ppp_code(*response));
		if (config->debug > 3) dumplcp(response, l);

		tunnelsend(b, l + (response - b), t);
	}
	else if (*p == ConfigNak || *p == ConfigRej)
	{
		int x = l - 4;
		uint8_t *o = (p + 4);
		int authtype = -1;

		while (x > 2)
		{
			int type = o[0];
			int length = o[1];

			if (length == 0 || type == 0 || x < length) break;
			switch (type)
			{
				case 1: // Maximum-Receive-Unit
					if (*p == ConfigNak)
					{
						if (length < 4) break;
						sess_local[s].ppp_mru = ntohs(*(uint16_t *)(o + 2));
						LOG(3, s, t, "    Remote requested MRU of %u\n", sess_local[s].ppp_mru);
					}
					else
					{
						sess_local[s].ppp_mru = 0;
						LOG(3, s, t, "    Remote rejected MRU negotiation\n");
					}

					break;

				case 3: // Authentication-Protocol
					if (authtype > 0)
						break;

					if (*p == ConfigNak)
					{
						int proto;

						if (length < 4) break;
						proto = ntohs(*(uint16_t *)(o + 2));

						if (proto == PPPPAP)
						{
							authtype = config->radius_authtypes & AUTHPAP;
							LOG(3, s, t, "    Remote requested PAP authentication...%sing\n",
								authtype ? "accept" : "reject");
						}
						else if (proto == PPPCHAP && length > 4 && *(o + 4) == 5)
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
					else
					{
						LOG(2, s, t, "LCP: remote rejected auth negotiation\n");
					    	authtype = 0; // shutdown
					}

					break;

				case 5: // Magic-Number
					session[s].magic = 0;
					if (*p == ConfigNak)
					{
						if (length < 6) break;
						session[s].magic = ntohl(*(uint32_t *)(o + 2));
					}

					if (session[s].magic)
						LOG(3, s, t, "    Remote requested magic-no %x\n", session[s].magic);
					else
						LOG(3, s, t, "    Remote rejected magic-no\n");

					cluster_send_session(s);
					break;

				case 17: // Multilink Max-Receive-Reconstructed-Unit
				{
					if (*p == ConfigNak)
					{
						sess_local[s].mp_mrru = ntohs(*(uint16_t *)(o + 2));
						LOG(3, s, t, "    Remote requested MRRU of %u\n", sess_local[s].mp_mrru);
					}
					else
					{
						sess_local[s].mp_mrru = 0;
						LOG(3, s, t, "    Remote rejected MRRU negotiation\n");
					}
				}
				break;

				case 18: // Multilink Short Sequence Number Header Format
				{
					if (*p == ConfigNak)
					{
						sess_local[s].mp_mssf = 0;
						LOG(3, s, t, "    Remote requested Naked mssf\n");
					}
					else
					{
						sess_local[s].mp_mssf = 0;
						LOG(3, s, t, "    Remote rejected mssf\n");
					}
				}
				break;

				case 19: // Multilink Endpoint Discriminator
				{
					if (*p == ConfigNak)
					{
						LOG(2, s, t, "    Remote should not configNak Endpoint Dis!\n");
					}
					else
					{
						sess_local[s].mp_epdis = 0;
						LOG(3, s, t, "    Remote rejected Endpoint Discriminator\n");
					}
				}
				break;

				default:
				    	LOG(2, s, t, "LCP: remote sent %s for type %u?\n", ppp_code(*p), type);
					sessionshutdown(s, "Unable to negotiate LCP.", CDN_ADMIN_DISC, TERM_USER_ERROR);
					return;
			}
			x -= length;
			o += length;
		}

		if (!authtype)
		{
			sessionshutdown(s, "Unsupported authentication.", CDN_ADMIN_DISC, TERM_USER_ERROR);
			return;
		}

		if (authtype > 0)
			sess_local[s].lcp_authtype = authtype;

		switch (session[s].ppp.lcp)
		{
		case Closed:
		case Stopped:
		    	{
				uint8_t *response = makeppp(b, sizeof(b), p, 2, s, t, PPPLCP, 0, 0, 0);
				if (!response) return;
				*response = TerminateAck;
				*((uint16_t *) (response + 2)) = htons(l = 4);

				LOG(3, s, t, "LCP: send %s\n", ppp_code(*response));
				if (config->debug > 3) dumplcp(response, l);

				tunnelsend(b, l + (response - b), t);
			}
			break;

		case RequestSent:
		case AckSent:
		    	initialise_restart_count(s, lcp);
			sendlcp(s, t);
			break;

		case AckReceived:
		    	LOG(2, s, t, "LCP: ConfigNak in state %s?  Sending ConfigReq\n", ppp_state(session[s].ppp.lcp));
			sendlcp(s, t);
			break;

		case Opened:
		    	lcp_restart(s);
			sendlcp(s, t);
			break;

		default:
		    	LOG(2, s, t, "LCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.lcp));
			return;
		}
	}
	else if (*p == TerminateReq)
	{
		switch (session[s].ppp.lcp)
		{
		case Closed:
		case Stopped:
		case Closing:
		case Stopping:
		case RequestSent:
		case AckReceived:
		case AckSent:
		    	break;

		case Opened:
		    	lcp_restart(s);
		    	zero_restart_count(s, lcp);
			change_state(s, lcp, Closing);
			break;

		default:
		    	LOG(2, s, t, "LCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.lcp));
			return;
		}

		*p = TerminateAck;	// send ack
		q = makeppp(b, sizeof(b),  p, l, s, t, PPPLCP, 0, 0, 0);
		if (!q) return;

		LOG(3, s, t, "LCP: send %s\n", ppp_code(*q));
		if (config->debug > 3) dumplcp(q, l);

		tunnelsend(b, l + (q - b), t); // send it
	}
	else if (*p == ProtocolRej)
	{
	    	uint16_t proto = 0;

		if (l > 4)
		{
			proto = *(p+4);
			if (l > 5 && !(proto & 1))
			{
				proto <<= 8;
				proto |= *(p+5);
			}
		}

		if (proto == PPPIPV6CP)
		{
			LOG(3, s, t, "IPv6 rejected\n");
			change_state(s, ipv6cp, Closed);
		}
		else
		{
			LOG(3, s, t, "LCP protocol reject: 0x%04X\n", proto);
		}
	}
	else if (*p == EchoReq)
	{
		*p = EchoReply;		// reply
		*(uint32_t *) (p + 4) = htonl(session[s].magic); // our magic number
		q = makeppp(b, sizeof(b), p, l, s, t, PPPLCP, 0, 0, 0);
		if (!q) return;

		LOG(4, s, t, "LCP: send %s\n", ppp_code(*q));
		if (config->debug > 3) dumplcp(q, l);

		tunnelsend(b, l + (q - b), t); // send it
	}
	else if (*p == EchoReply)
	{
		// Ignore it, last_packet time is set earlier than this.
	}
	else if (*p != CodeRej)
	{
		ppp_code_rej(s, t, PPPLCP, "LCP", p, l, b, sizeof(b));
	}
}

int join_bundle(sessionidt s)
{
	// Search for a bundle to join
	bundleidt i;
	bundleidt b;
	for (i = 1; i < MAXBUNDLE; i++)
	{
		if (bundle[i].state != BUNDLEFREE)
		{
			if (epdiscmp(session[s].epdis,bundle[i].epdis) && !strcmp(session[s].user, bundle[i].user))
			{
				sessionidt first_ses = bundle[i].members[0];
				if (bundle[i].mssf != session[s].mssf)
				{
					// uniformity of sequence number format must be insured
					LOG(3, s, session[s].tunnel, "MPPP: unable to bundle session %d in bundle %d cause of different mssf\n", s, i);
					return -1;
				}
				session[s].bundle = i;
				session[s].ip = session[first_ses].ip;
				session[s].dns1 = session[first_ses].dns1;
				session[s].dns2 = session[first_ses].dns2;
				session[s].timeout = session[first_ses].timeout;

				if(session[s].epdis.length > 0)
					setepdis(&bundle[i].epdis, session[s].epdis);

				strcpy(bundle[i].user, session[s].user);
				bundle[i].members[bundle[i].num_of_links] = s;
				bundle[i].num_of_links++;
				LOG(3, s, session[s].tunnel, "MPPP: Bundling additional line in bundle (%d), lines:%d\n",i,bundle[i].num_of_links);
				return i;
			}
		}
	}

	// No previously created bundle was found for this session, so create a new one
	if (!(b = new_bundle())) return 0;

	session[s].bundle = b;
	bundle[b].mrru = session[s].mrru;
	bundle[b].mssf = session[s].mssf;
	// FIXME !!! to enable l2tpns reading mssf frames receiver_max_seq, sender_max_seq must be introduce
	// now session[s].mssf flag indecates that the receiver wish to receive frames in mssf, so max_seq (i.e. recv_max_seq) = 1<<24
	/*
	if (bundle[b].mssf)
		bundle[b].max_seq = 1 << 12;
	else */
		bundle[b].max_seq = 1 << 24;
	if(session[s].epdis.length > 0)
		setepdis(&bundle[b].epdis, session[s].epdis);

	strcpy(bundle[b].user, session[s].user);
	bundle[b].members[0] = s;
	bundle[b].timeout = session[s].timeout;
	LOG(3, s, session[s].tunnel, "MPPP: Created a new bundle (%d)\n", b);
	return b;
}

static int epdiscmp(epdist ep1, epdist ep2)
{
	int ad;
	if (ep1.length != ep2.length)
		return 0;

	if (ep1.addr_class != ep2.addr_class)
		return 0;

	for (ad = 0; ad < ep1.length; ad++)
		if (ep1.address[ad] != ep2.address[ad])
			return 0;

	return 1;
}

static void setepdis(epdist *ep1, epdist ep2)
{
	int ad;
	ep1->length = ep2.length;
	ep1->addr_class = ep2.addr_class;
	for (ad = 0; ad < ep2.length; ad++)
		ep1->address[ad] = ep2.address[ad];
}

static bundleidt new_bundle()
{
        bundleidt i;
        for (i = 1; i < MAXBUNDLE; i++)
        {
                if (bundle[i].state == BUNDLEFREE)
                {
                        LOG(4, 0, 0, "MPPP: Assigning bundle ID %d\n", i);
                        bundle[i].num_of_links = 1;
                        bundle[i].last_check = time_now;        // Initialize last_check value
                        bundle[i].state = BUNDLEOPEN;
                        bundle[i].current_ses = -1;     // This is to enforce the first session 0 to be used at first
			memset(&frag[i], 0, sizeof(fragmentationt));
                        if (i > config->cluster_highest_bundleid)
                                config->cluster_highest_bundleid = i;
                        return i;
                }
        }
        LOG(0, 0, 0, "MPPP: Can't find a free bundle! There shouldn't be this many in use!\n");
        return 0;
}

static void ipcp_open(sessionidt s, tunnelidt t)
{
	LOG(3, s, t, "IPCP: Opened, session is now active\n");

	change_state(s, ipcp, Opened);

	if (!(session[s].walled_garden || session[s].flags & SESSION_STARTED))
	{
		uint16_t r = radiusnew(s);
		if (r)
		{
			radiussend(r, RADIUSSTART); // send radius start

			// don't send further Start records if IPCP is restarted
			session[s].flags |= SESSION_STARTED;
			cluster_send_session(s);
		}
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
	uint8_t b[MAXETHER];
	uint8_t *q = 0;
	uint16_t hl;

	CSTAT(processipcp);

	LOG_HEX(5, "IPCP", p, l);
	if (l < 4)
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

	LOG(3, s, t, "IPCP: recv %s\n", ppp_code(*p));

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

		while (length > 2)
		{
			if (!o[1] || o[1] > length) return;

			switch (*o)
			{
			case 3: // ip address
				gotip++; // seen address
				if (o[1] != 6) return;

				addr = htonl(session[s].ip);
				if (memcmp(o + 2, &addr, (sizeof addr)))
				{
					uint8_t *oq = q;
					q = ppp_conf_nak(s, b, sizeof(b), PPPIPCP, &response, q, p, o, (uint8_t *) &addr, sizeof(addr));
					if (!q || (q != oq && *response == ConfigRej))
					{
						sessionshutdown(s, "Can't negotiate IPCP.", CDN_ADMIN_DISC, TERM_USER_ERROR);
						return;
					}
				}

				break;

			case 129: // primary DNS
				if (o[1] != 6) return;

				addr = htonl(session[s].dns1);
				if (memcmp(o + 2, &addr, (sizeof addr)))
				{
					q = ppp_conf_nak(s, b, sizeof(b), PPPIPCP, &response, q, p, o, (uint8_t *) &addr, sizeof(addr));
					if (!q) return;
				}

				break;

			case 131: // secondary DNS
				if (o[1] != 6) return;

				addr = htonl(session[s].dns2);
				if (memcmp(o + 2, &addr, sizeof(addr)))
				{
					q = ppp_conf_nak(s, b, sizeof(b), PPPIPCP, &response, q, p, o, (uint8_t *) &addr, sizeof(addr));
					if (!q) return;
				}

				break;

			default:
				LOG(2, s, t, "    Rejecting PPP IPCP Option type %d\n", *o);
				q = ppp_conf_rej(s, b, sizeof(b), PPPIPCP, &response, q, p, o);
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
			response = makeppp(b, sizeof(b), p, l, s, t, PPPIPCP, 0, 0, 0);
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
			response = makeppp(b, sizeof(b), p, 2, s, t, PPPIPCP, 0, 0, 0);
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

		LOG(3, s, t, "IPCP: send %s\n", ppp_code(*response));
		tunnelsend(b, l + (response - b), t);
	}
	else if (*p == TerminateReq)
	{
		switch (session[s].ppp.ipcp)
		{
		case Closed:
		case Stopped:
		case Closing:
		case Stopping:
		case RequestSent:
		case AckReceived:
		case AckSent:
		    	break;

		case Opened:
		    	zero_restart_count(s, ipcp);
			change_state(s, ipcp, Closing);
			break;

		default:
		    	LOG(2, s, t, "IPCP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.ipcp));
			return;
		}

		*p = TerminateAck;	// send ack
		q = makeppp(b, sizeof(b), p, l, s, t, PPPIPCP, 0, 0, 0);
		if (!q) return;

		LOG(3, s, t, "IPCP: send %s\n", ppp_code(*q));
		tunnelsend(b, l + (q - b), t); // send it
	}
	else if (*p != CodeRej)
	{
		ppp_code_rej(s, t, PPPIPCP, "IPCP", p, l, b, sizeof(b));
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
	uint8_t b[MAXETHER];
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

	LOG(3, s, t, "IPV6CP: recv %s\n", ppp_code(*p));

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

		while (length > 2)
		{
			if (!o[1] || o[1] > length) return;

			switch (*o)
			{
			case 1: // interface identifier
				gotip++; // seen address
				if (o[1] != 10) return;

				*(uint32_t *) ident = htonl(session[s].ip);
				*(uint32_t *) (ident + 4) = 0;

				if (memcmp(o + 2, ident, sizeof(ident)))
				{
					q = ppp_conf_nak(s, b, sizeof(b), PPPIPV6CP, &response, q, p, o, ident, sizeof(ident));
					if (!q) return;
				}

				break;

			default:
				LOG(2, s, t, "    Rejecting PPP IPV6CP Option type %d\n", *o);
				q = ppp_conf_rej(s, b, sizeof(b), PPPIPV6CP, &response, q, p, o);
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
			response = makeppp(b, sizeof(b), p, l, s, t, PPPIPV6CP, 0, 0, 0);
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
			response = makeppp(b, sizeof(b), p, 2, s, t, PPPIPV6CP, 0, 0, 0);
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

		LOG(3, s, t, "IPV6CP: send %s\n", ppp_code(*response));
		tunnelsend(b, l + (response - b), t);
	}
	else if (*p == TerminateReq)
	{
		switch (session[s].ppp.ipv6cp)
		{
		case Closed:
		case Stopped:
		case Closing:
		case Stopping:
		case RequestSent:
		case AckReceived:
		case AckSent:
		    	break;

		case Opened:
		    	zero_restart_count(s, ipv6cp);
			change_state(s, ipv6cp, Closing);
			break;

		default:
		    	LOG(2, s, t, "IPV6CP: ignoring %s in state %s\n", ppp_code(*p), ppp_state(session[s].ppp.ipv6cp));
			return;
		}

		*p = TerminateAck;	// send ack
		q = makeppp(b, sizeof(b),  p, l, s, t, PPPIPV6CP, 0, 0, 0);
		if (!q) return;

		LOG(3, s, t, "IPV6CP: send %s\n", ppp_code(*q));
		tunnelsend(b, l + (q - b), t); // send it
	}
	else if (*p != CodeRej)
	{
		ppp_code_rej(s, t, PPPIPV6CP, "IPV6CP", p, l, b, sizeof(b));
	}
}

static void update_sessions_in_stat(sessionidt s, uint16_t l)
{
	bundleidt b = session[s].bundle;
	if (!b)
	{
		increment_counter(&session[s].cin, &session[s].cin_wrap, l);
        	session[s].cin_delta += l;
       		session[s].pin++;

        	sess_local[s].cin += l;
        	sess_local[s].pin++;
	}
	else
	{
		int i = frag[b].re_frame_begin_index;
		int end = frag[b].re_frame_end_index;
		for (;;)
		{
			l = frag[b].fragment[i].length;
			s = frag[b].fragment[i].sid;
			increment_counter(&session[s].cin, &session[s].cin_wrap, l);
	                session[s].cin_delta += l;
       		        session[s].pin++;

                	sess_local[s].cin += l;
                	sess_local[s].pin++;
			if (i == end)
				return;
			i = (i + 1) & MAXFRAGNUM_MASK;
		}
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

	if (l < 20)
	{
		LOG(1, s, t, "IP packet too short %d\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	ip = ntohl(*(uint32_t *)(p + 12));

	if (l > MAXETHER)
	{
		LOG(1, s, t, "IP packet too long %d\n", l);
		STAT(tunnel_rx_errors);
		return ;
	}

	if (session[s].ppp.phase != Network || session[s].ppp.ipcp != Opened)
		return;

	if (!session[s].bundle || bundle[session[s].bundle].num_of_links < 2) // FIXME: 
	{
		// no spoof (do sessionbyip to handled statically routed subnets)
		if (ip != session[s].ip && sessionbyip(htonl(ip)) != s)
		{
			LOG(4, s, t, "Dropping packet with spoofed IP %s\n", fmtaddr(htonl(ip), 0));
			return;
		}
	}

	// run access-list if any
	if (session[s].filter_in && !ip_filter(p, l, session[s].filter_in - 1))
		return;

	// adjust MSS on SYN and SYN,ACK packets with options
	if ((ntohs(*(uint16_t *) (p + 6)) & 0x1fff) == 0 && p[9] == IPPROTO_TCP) // first tcp fragment
	{
		int ihl = (p[0] & 0xf) * 4; // length of IP header
		if (l >= ihl + 20 && (p[ihl + 13] & TCP_FLAG_SYN) && ((p[ihl + 12] >> 4) > 5))
			adjust_tcp_mss(s, t, p, l, p + ihl);
	}

	// Add on the tun header
	p -= 4;
	*(uint32_t *) p = htonl(PKTIP);
	l += 4;

	if (session[s].tbf_in)
	{
		// Are we throttling this session?
		if (config->cluster_iam_master)
			tbf_queue_packet(session[s].tbf_in, p, l);
		else
			master_throttle_packet(session[s].tbf_in, p, l);
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

	update_sessions_in_stat(s, l);

	eth_tx += l;

	STAT(tun_tx_packets);
	INC_STAT(tun_tx_bytes, l);
}

// process Multilink PPP packet received
void processmpin(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l)
{
        bundleidt b = session[s].bundle;
	bundlet * this_bundle = &bundle[b];
	uint32_t frag_offset, M_offset;
	uint16_t frag_index, M_index;
	fragmentationt *this_fragmentation = &frag[b];
	uint8_t begin_frame = (*p & MP_BEGIN);
        uint8_t end_frame = (*p & MP_END);
        uint32_t seq_num;
	uint8_t flags = *p;
	uint16_t begin_index, end_index;

	// Perform length checking
        if(l > MAXFRAGLEN)
        {
	       	LOG(2, s, t, "MPPP: discarding fragment larger than MAXFRAGLEN\n");
              	return;
        }

        if(!b)
        {
                LOG(2, s, t, "MPPP: Invalid bundle id: 0\n");
                return;
        }
	// FIXME !! session[s].mssf means that the receiver wants to receive frames in mssf not means the receiver will send frames in mssf
        /* if(session[s].mssf)
        {
                // Get 12 bit for seq number
                seq_num = ntohs((*(uint16_t *) p) & 0xFF0F);
                p += 2;
                l -= 2;
                // After this point the pointer should be advanced 2 bytes
                LOG(3, s, t, "MPPP: 12 bits, sequence number: %d\n",seq_num);
        }
        else */
        {
                // Get 24 bit for seq number
                seq_num = ntohl((*(uint32_t *) p) & 0xFFFFFF00);
                p += 4;
                l -= 4;
                // After this point the pointer should be advanced 4 bytes
                LOG(4, s, t, "MPPP: 24 bits sequence number:%d\n",seq_num);
        }

	// calculate this fragment's offset from the begin seq in the bundle
	frag_offset = (seq_num + this_bundle->max_seq - this_fragmentation->start_seq) & (this_bundle->max_seq-1);

	// discard this fragment if frag_offset is bigger that the fragmentation buffer size
	if (frag_offset >= MAXFRAGNUM)
        {
        	LOG(3, s, t, "MPPP: Index out of range, received more than MAXFRAGNUM fragment (lost frag) seq:%d, begin_seq:%d, bundle:%d, max:%d\n",seq_num, this_fragmentation->start_seq, b, this_bundle->max_seq);
                return;
        }
	
	// update M
	sess_local[s].last_seq = seq_num;
	if (seq_num < this_fragmentation->M)
		this_fragmentation->M = seq_num;
	else
	{
		uint32_t i, min = sess_local[(this_bundle->members[0])].last_seq;;
		for (i = 1; i < this_bundle->num_of_links; i++)
		{
			uint32_t s_seq = sess_local[(this_bundle->members[i])].last_seq; 
			if (s_seq < min)
				min = s_seq;
		}
		this_fragmentation->M = min;
	}

	LOG(4, s, t, "MPPP: Setting M to %d\n", this_fragmentation->M);	
	//calculate M's offset from the begin seq in the bundle
	M_offset = (this_fragmentation->M + this_bundle->max_seq - this_fragmentation->start_seq) & (this_bundle->max_seq-1);

	//caculate M's index in the fragment array
	M_index = (M_offset + this_fragmentation->start_index) & MAXFRAGNUM_MASK;
	
	//caculate received fragment's index in the fragment array
	frag_index = (frag_offset + this_fragmentation->start_index) & MAXFRAGNUM_MASK;

	//frame with a single fragment
	if (begin_frame && end_frame)
	{
		// process and reset fragmentation
                LOG(4, s, t, "MPPP: Both bits are set (Begin and End).\n");
		this_fragmentation->fragment[frag_index].length = l;
		this_fragmentation->fragment[frag_index].sid = s;
		this_fragmentation->fragment[frag_index].flags = flags;
		this_fragmentation->fragment[frag_index].seq = seq_num;
		this_fragmentation->re_frame_begin_index = frag_index;
		this_fragmentation->re_frame_end_index = frag_index;
		processmpframe(s, t, p, l, 0);
		this_fragmentation->fragment[frag_index].length = 0;
		this_fragmentation->fragment[frag_index].flags = 0;
		end_index = frag_index;
	}
	else
	{
		// insert the frame in it's place
		fragmentt *this_frag = &this_fragmentation->fragment[frag_index];
		this_frag->length = l;
		this_frag->sid = s;
		this_frag->flags = flags;
		this_frag->seq = seq_num;
                memcpy(this_frag->data, p, l);

		// try to assemble the frame that has the received fragment as a member		
		// get the beginning of this frame
		begin_index = end_index = frag_index;
		while (this_fragmentation->fragment[begin_index].length)
		{
			if (this_fragmentation->fragment[begin_index].flags & MP_BEGIN)
				break;
			begin_index = (begin_index ? (begin_index -1) : (MAXFRAGNUM -1)); 
		}

		// return if a lost fragment is found
		if (!(this_fragmentation->fragment[begin_index].length))
			return; // assembling frame failed
		// get the end of his frame
		while (this_fragmentation->fragment[end_index].length)
		{
			if (this_fragmentation->fragment[end_index].flags & MP_END)
				break;
			end_index = (end_index +1) & MAXFRAGNUM_MASK; 
		}

		// return if a lost fragment is found
		if (!(this_fragmentation->fragment[end_index].length))
			return; // assembling frame failed

		// assemble the packet
		//assemble frame, process it, reset fragmentation
		uint16_t cur_len = 4;   // This is set to 4 to leave 4 bytes for function processipin
		uint32_t i;

               	LOG(4, s, t, "MPPP: processing fragments from %d to %d\n", begin_index, end_index);
               	// Push to the receive buffer
		                        
		for (i = begin_index;; i = (i + 1) & MAXFRAGNUM_MASK)
                {
			this_frag = &this_fragmentation->fragment[i];
                        if(cur_len + this_frag->length > MAXETHER)
                        {
                                LOG(2, s, t, "MPPP: discarding reassembled frames larger than MAXETHER\n");				
                                break;
                        }
                        memcpy(this_fragmentation->reassembled_frame+cur_len, this_frag->data, this_frag->length);
			LOG(5, s, t, "MPPP: processing frame at %d, with len %d\n", i, this_frag->length);
                        cur_len += this_frag->length;
			if (i == end_index)
			{
				this_fragmentation->re_frame_len = cur_len;
				this_fragmentation->re_frame_begin_index = begin_index;
                		this_fragmentation->re_frame_end_index = end_index;
                		// Process the resassembled frame
                		LOG(5, s, t, "MPPP: Process the reassembled frame, len=%d\n",cur_len);
                		processmpframe(s, t, this_fragmentation->reassembled_frame, this_fragmentation->re_frame_len, 1);
				break;
			}
                }
                // Set reassembled frame length to zero after processing it
                this_fragmentation->re_frame_len = 0;
		for (i = begin_index;; i = (i + 1) & MAXFRAGNUM_MASK)
		{
			this_fragmentation->fragment[i].length = 0;      // Indicates that this fragment has been consumed
			this_fragmentation->fragment[i].flags = 0;
			if (i == end_index)
				break;
		}
	}
	//discard fragments received before the recently assembled frame
	begin_index = this_fragmentation->start_index;
	this_fragmentation->start_index = (end_index + 1) & MAXFRAGNUM_MASK;
        this_fragmentation->start_seq = (this_fragmentation->fragment[end_index].seq + 1) & (this_bundle->max_seq-1);
	//clear length and flags of the discarded fragments
	while (begin_index != this_fragmentation->start_index)
        {
                this_fragmentation->fragment[begin_index].flags = 0;
		this_fragmentation->fragment[begin_index].length = 0;
                begin_index = (begin_index + 1) & MAXFRAGNUM_MASK;
        }

	LOG(4, s, t, "MPPP after assembling: M index is =%d, start index is = %d, start seq=%d\n",M_index, this_fragmentation->start_index, this_fragmentation->start_seq);	
	return;
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

	update_sessions_in_stat(s, l);

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
	uint8_t b[MAXETHER];
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

	LOG(4, s, t, "CCP: recv %s\n", ppp_code(*p));
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

		q = makeppp(b, sizeof(b), p, l, s, t, PPPCCP, 0, 0, 0);
		if (!q) return;

		switch (session[s].ppp.ccp)
		{
		case Closed:
			q = makeppp(b, sizeof(b), p, 2, s, t, PPPCCP, 0, 0, 0);
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

		LOG(4, s, t, "CCP: send %s\n", ppp_code(*q));
		tunnelsend(b, l + (q - b), t);
	}
	else if (*p == TerminateReq)
	{
		*p = TerminateAck;
		q = makeppp(b, sizeof(b),  p, l, s, t, PPPCCP, 0, 0, 0);
		if (!q) return;
		LOG(3, s, t, "CCP: send %s\n", ppp_code(*q));
		tunnelsend(b, l + (q - b), t);
		change_state(s, ccp, Stopped);
	}
	else if (*p != CodeRej)
	{
		ppp_code_rej(s, t, PPPCCP, "CCP", p, l, b, sizeof(b));
	}
}

// send a CHAP challenge
void sendchap(sessionidt s, tunnelidt t)
{
	uint8_t b[MAXETHER];
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
		sessionshutdown(s, "CHAP timeout.", CDN_ADMIN_DISC, TERM_REAUTHENTICATION_FAILURE);
		STAT(tunnel_tx_errors);
		return ;
	}
	q = makeppp(b, sizeof(b), 0, 0, s, t, PPPCHAP, 0, 0, 0);
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
// returns start of PPP frame
uint8_t *makeppp(uint8_t *b, int size, uint8_t *p, int l, sessionidt s, tunnelidt t, uint16_t mtype, uint8_t prio, bundleidt bid, uint8_t mp_bits)
{
	uint16_t hdr = 0x0002; // L2TP with no options
	uint16_t type = mtype;
	uint8_t *start = b;

	if (size < 16) // Need more space than this!!
	{
		LOG(0, s, t, "makeppp buffer too small for L2TP header (size=%d)\n", size);
		return NULL;
	}

	if (prio) hdr |= 0x0100; // set priority bit

	*(uint16_t *) (b + 0) = htons(hdr);
	*(uint16_t *) (b + 2) = htons(tunnel[t].far); // tunnel
	*(uint16_t *) (b + 4) = htons(session[s].far); // session
	b += 6;

	// Check whether this session is part of multilink
	if (bid)
	{
		if (bundle[bid].num_of_links > 1)
			type = PPPMP; // Change PPP message type to the PPPMP
		else
			bid = 0;
	}

	if (type == PPPLCP || !(session[s].flags & SESSION_ACFC))
	{
		*(uint16_t *) b = htons(0xFF03); // HDLC header
		b += 2;
	}

	if (type < 0x100 && session[s].flags & SESSION_PFC)
	{
		*b++ = type;
	}
	else
	{
		*(uint16_t *) b = htons(type);
		b += 2;
	}

	if (bid)
	{
		// Set the sequence number and (B)egin (E)nd flags
		if (session[s].mssf)
		{
			// Set the multilink bits
			uint16_t bits_send = mp_bits;
			*(uint16_t *) b = htons((bundle[bid].seq_num_t & 0x0FFF)|bits_send);
			b += 2;
		}
		else
		{
			*(uint32_t *) b = htonl(bundle[bid].seq_num_t);
			// Set the multilink bits
			*b = mp_bits;
			b += 4;
		}

		bundle[bid].seq_num_t++;

		// Add the message type if this fragment has the begin bit set
		if (mp_bits & MP_BEGIN)
		{
			//*b++ = mtype; // The next two lines are instead of this 
			*(uint16_t *) b = htons(mtype); // Message type
			b += 2;
		}
	}

	if ((b - start) + l > size)
	{
		LOG(2, s, t, "makeppp would overflow buffer (size=%d, header+payload=%d)\n", size, (b - start) + l);
		return NULL;
	}

	// Copy the payload
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

// Send LCP ConfigReq for MRU, authentication type and magic no
void sendlcp(sessionidt s, tunnelidt t)
{
	uint8_t b[500], *q, *l;
	int authtype = sess_local[s].lcp_authtype;

        if (!(q = makeppp(b, sizeof(b), NULL, 0, s, t, PPPLCP, 0, 0, 0)))
		return;

        LOG(3, s, t, "LCP: send ConfigReq%s%s%s including MP options\n",
	    authtype ? " (" : "",
	    authtype ? (authtype == AUTHCHAP ? "CHAP" : "PAP") : "",
	    authtype ? ")" : "");

	l = q;
	*l++ = ConfigReq;
	*l++ = ++sess_local[s].lcp_ident; // ID

	l += 2; //Save space for length

	if (sess_local[s].ppp_mru)
	{
		*l++ = 1; *l++ = 4; // Maximum-Receive-Unit (length 4)
		*(uint16_t *) l = htons(sess_local[s].ppp_mru); l += 2;
	}

	if (authtype)
		l += add_lcp_auth(l, sizeof(b) - (l - b), authtype);

	if (session[s].magic)
	{
		*l++ = 5; *l++ = 6; // Magic-Number (length 6)
		*(uint32_t *) l = htonl(session[s].magic);
		l += 4;
	}

        if (sess_local[s].mp_mrru)
        {
		*l++ = 17; *l++ = 4; // Multilink Max-Receive-Reconstructed-Unit (length 4)
		*(uint16_t *) l = htons(sess_local[s].mp_mrru); l += 2;
	}

        if (sess_local[s].mp_epdis)
        {
		*l++ = 19; *l++ = 7;	// Multilink Endpoint Discriminator (length 7)
		*l++ = IPADDR;	// Endpoint Discriminator class
		*(uint32_t *) l = htonl(sess_local[s].mp_epdis);
		l += 4;
	}

	*(uint16_t *)(q + 2) = htons(l - q); // Length

	LOG_HEX(5, "PPPLCP", q, l - q);
	if (config->debug > 3) dumplcp(q, l - q);

	tunnelsend(b, (l - b), t);
	restart_timer(s, lcp);
}

// Send CCP request for no compression
void sendccp(sessionidt s, tunnelidt t)
{
	uint8_t b[500], *q;

	if (!(q = makeppp(b, sizeof(b), NULL, 0, s, t, PPPCCP, 0, 0, 0)))
		return;

	LOG(3, s, t, "CCP: send ConfigReq (no compression)\n");

	*q = ConfigReq;
	*(q + 1) = ++sess_local[s].lcp_ident; // ID
	*(uint16_t *)(q + 2) = htons(4); // Length

	LOG_HEX(5, "PPPCCP", q, 4);
	tunnelsend(b, (q - b) + 4 , t);
	restart_timer(s, ccp);
}

// Reject unknown/unconfigured protocols
void protoreject(sessionidt s, tunnelidt t, uint8_t *p, uint16_t l, uint16_t proto)
{

	uint8_t buf[MAXETHER];
	uint8_t *q;
	int mru = session[s].mru;
	if (mru < MINMTU) mru = MINMTU;
	if (mru > sizeof(buf)) mru = sizeof(buf);

	l += 6;
	if (l > mru) l = mru;

	q = makeppp(buf, sizeof(buf), 0, 0, s, t, PPPLCP, 0, 0, 0);
	if (!q) return;

	*q = ProtocolRej;
	*(q + 1) = ++sess_local[s].lcp_ident;
	*(uint16_t *)(q + 2) = htons(l);
	*(uint16_t *)(q + 4) = htons(proto);
	memcpy(q + 6, p, l - 6);

	if (proto == PPPIPV6CP)
		LOG(3, s, t, "LCP: send ProtocolRej (IPV6CP: not configured)\n");
	else
		LOG(2, s, t, "LCP: sent ProtocolRej (0x%04X: unsupported)\n", proto);

	tunnelsend(buf, l + (q - buf), t);
}
