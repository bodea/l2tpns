// L2TPNS Radius Stuff
// $Id: radius.c,v 1.4 2004-06-23 03:52:24 fred_nerk Exp $

#include <time.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <malloc.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include "md5.h"
#include "constants.h"
#include "l2tpns.h"
#include "plugin.h"
#include "util.h"

extern radiust *radius;
extern sessiont *session;
extern tunnelt *tunnel;
extern u32 sessionid;
extern struct configt *config;
extern int *radfds;

const char *radius_state(int state)
{
	static char *tmp = NULL;
	int i;
	for (i = 0; radius_states[i]; i++)
		if (i == state) return radius_states[i];

	if (tmp == NULL) tmp = (char *)calloc(64, 1);
	sprintf(tmp, "%d", state);
	return tmp;
}

// Set up socket for radius requests
void initrad(void)
{
	int i;
	log(3, 0, 0, 0, "Creating %d sockets for RADIUS queries\n", config->num_radfds);
	radfds = calloc(sizeof(int), config->num_radfds);
	for (i = 0; i < config->num_radfds; i++)
	{
		int flags;
		if (!radfds[i]) radfds[i] = socket(AF_INET, SOCK_DGRAM, UDP);
		flags = fcntl(radfds[i], F_GETFL, 0);
		fcntl(radfds[i], F_SETFL, flags | O_NONBLOCK);
	}
}

void radiusclear(u16 r, sessionidt s)
{
	if (s) session[s].radius = 0;
	memset(&radius[r], 0, sizeof(radius[r])); // radius[r].state = RADIUSNULL;
}

int next_radius_id = 1;

static u16 new_radius()
{
	u16 i;
	int loops = 0;
	for (i = next_radius_id; ; i = (i + 1) % MAXRADIUS)
	{
		if (radius[i].state == RADIUSNULL)
		{
			next_radius_id = (next_radius_id + 1) % MAXRADIUS;
			return i;
		}
		if (next_radius_id == i)
		{
			if (++loops == 2)
			{
				log(0, 0, 0, 0, "Can't find a free radius session! This is very bad!\n");
				return 0;
			}
		}
	}
}

u16 radiusnew(sessionidt s)
{
	u16 r;
	if (!(r = new_radius()))
	{
		log(1, 0, s, session[s].tunnel, "No free RADIUS sessions\n");
		STAT(radius_overflow);
		return 0;
	};
	memset(&radius[r], 0, sizeof(radius[r]));
	session[s].radius = r;
	radius[r].session = s;
	radius[r].state = RADIUSWAIT;
	radius[r].retry = config->current_time + 1200; // Wait at least 120 seconds to re-claim this.

	log(3,0,s, session[s].tunnel, "Allocated radius %d\n", r);
	return r;
}

// Send a RADIUS request
void radiussend(u16 r, u8 state)
{
	struct sockaddr_in addr;
	u8 b[4096];            // RADIUS packet
	char pass[129];
	int pl;
	u8 *p;
	sessionidt s;
#ifdef STAT_CALLS
	STAT(call_radiussend);
#endif
	s = radius[r].session;
	if (!config->numradiusservers)
	{
		log(0, 0, s, session[s].tunnel, "No RADIUS servers\n");
		return;
	}
	if (!*config->radiussecret)
	{
		log(0, 0, s, session[s].tunnel, "No RADIUS secret\n");
		return;
	}

	if (state != RADIUSAUTH && !config->radius_accounting)
	{
		// Radius accounting is turned off
		radiusclear(r, s);
		return;
	}

	if (radius[r].state != state)
		radius[r].try = 0;
	radius[r].state = state;
	radius[r].retry = backoff(radius[r].try++);
	log(4, 0, s, session[s].tunnel, "Send RADIUS id %d sock %d state %s try %d\n",
			r >> RADIUS_SHIFT, r & RADIUS_MASK,
			radius_state(radius[r].state), radius[r].try);
	if (radius[r].try > config->numradiusservers * 2)
	{
		if (s)
		{
			if (state == RADIUSAUTH)
				sessionshutdown(s, "RADIUS timeout");
			else
			{
				log(1, 0, s, session[s].tunnel, "RADIUS timeout, but in state %s so don't timeout session\n",
					radius_states[state]);
				radiusclear(r, s);
			}
			STAT(radius_timeout);
		}
		else
		{
			STAT(radius_retries);
			radius[r].state = RADIUSWAIT;
			radius[r].retry = 100;
		}
		return ;
	}
	// contruct RADIUS access request
	switch (state)
	{
		case RADIUSAUTH:
			b[0] = 1;               // access request
			break;
		case RADIUSSTART:
		case RADIUSSTOP:
			b[0] = 4;               // accounting request
			break;
		default:
			log(0, 0, 0, 0, "Unknown radius state %d\n", state);
	}
	b[1] = r >> RADIUS_SHIFT;       // identifier
	memcpy(b + 4, radius[r].auth, 16);
	p = b + 20;
	if (s)
	{
		*p = 1;                 // user name
		p[1] = strlen(session[s].user) + 2;
		strcpy(p + 2, session[s].user);
		p += p[1];
	}
	if (state == RADIUSAUTH)
	{
		if (radius[r].chap)
		{
			*p = 3;            // CHAP password
			p[1] = 19;         // length
			p[2] = radius[r].id; // ID
			memcpy(p + 3, radius[r].pass, 16); // response from CHAP request
			p += p[1];
			*p = 60;           // CHAP Challenge
			p[1] = 18;         // length
			memcpy(p + 2, radius[r].auth, 16);
			p += p[1];
		}
		else
		{
			strcpy(pass, radius[r].pass);
			pl = strlen(pass);
			while (pl & 15)
				pass[pl++] = 0; // pad
			if (pl)
			{                // encrypt
				hasht hash;
				int p = 0;
				while (p < pl)
				{
					MD5_CTX ctx;
					MD5Init(&ctx);
					MD5Update(&ctx, config->radiussecret, strlen(config->radiussecret));
					if (p)
						MD5Update(&ctx, pass + p - 16, 16);
					else
						MD5Update(&ctx, radius[r].auth, 16);
					MD5Final(hash, &ctx);
					do
					{
						pass[p] ^= hash[p & 15];
						p++;
					}
					while (p & 15);
				}
			}
			*p = 2;            // password
			p[1] = pl + 2;
			if (pl)
				memcpy(p + 2, pass, pl);
			p += p[1];
		}
	}
	else if (state == RADIUSSTART || state == RADIUSSTOP)
	{                          // accounting
		*p = 40;                // accounting type
		p[1] = 6;
		*(u32 *) (p + 2) = htonl((state == RADIUSSTART) ? 1 : 2);
		p += p[1];
		if (s)
		{
			*p = 44;           // session ID
			p[1] = 18;
			sprintf(p + 2, "%08X%08X", session[s].id, session[s].opened);
			p += p[1];
			if (state == RADIUSSTOP)
			{                // stop
				*p = 42;      // input octets
				p[1] = 6;
				*(u32 *) (p + 2) = htonl(session[s].cin);
				p += p[1];
				*p = 43;      // output octets
				p[1] = 6;
				*(u32 *) (p + 2) = htonl(session[s].cout);
				p += p[1];
				*p = 46;      // session time
				p[1] = 6;
				*(u32 *) (p + 2) = htonl(time(NULL) - session[s].opened);
				p += p[1];
				*p = 47;      // input packets
				p[1] = 6;
				*(u32 *) (p + 2) = htonl(session[s].pin);
				p += p[1];
				*p = 48;      // output spackets
				p[1] = 6;
				*(u32 *) (p + 2) = htonl(session[s].pout);
				p += p[1];
			}
			else
			{                // start
				*p = 41;      // delay
				p[1] = 6;
				*(u32 *) (p + 2) = htonl(time(NULL) - session[s].opened);
				p += p[1];
			}
		}
	}
	if (s)
	{
		*p = 5; // NAS-Port
		p[1] = 6;
		*(u32 *) (p + 2) = htonl(s);
		p += p[1];
	}
	if (s && session[s].ip)
	{
		*p = 8;			// Framed-IP-Address
		p[1] = 6;
		*(u32 *) (p + 2) = htonl(session[s].ip);
		p += p[1];
	}
	if (*session[s].called)
	{
		*p = 30;                // called
		p[1] = strlen(session[s].called) + 2;
		strcpy(p + 2, session[s].called);
		p += p[1];
	}
	if (*radius[r].calling)
	{
		*p = 31;                // calling
		p[1] = strlen(radius[r].calling) + 2;
		strcpy(p + 2, radius[r].calling);
		p += p[1];
	}
	else if (*session[s].calling)
	{
		*p = 31;                // calling
		p[1] = strlen(session[s].calling) + 2;
		strcpy(p + 2, session[s].calling);
		p += p[1];
	}
	// NAS-IP-Address
	*p = 4;
	p[1] = 6;
	*(u32 *)(p + 2) = config->bind_address;
	p += p[1];

	// All AVpairs added
	*(u16 *) (b + 2) = htons(p - b);
	if (state != RADIUSAUTH)
	{
	    // Build auth for accounting packet
	    char z[16] = {0};
	    char hash[16] = {0};
	    MD5_CTX ctx;
	    MD5Init(&ctx);
	    MD5Update(&ctx, b, 4);
	    MD5Update(&ctx, z, 16);
	    MD5Update(&ctx, b + 20, (p - b) - 20);
	    MD5Update(&ctx, config->radiussecret, strlen(config->radiussecret));
	    MD5Final(hash, &ctx);
	    memcpy(b + 4, hash, 16);
	    memcpy(radius[r].auth, hash, 16);
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	*(u32 *) & addr.sin_addr = config->radiusserver[(radius[r].try - 1) % config->numradiusservers];
	addr.sin_port = htons((state == RADIUSAUTH) ? RADPORT : RADAPORT);

	log_hex(5, "RADIUS Send", b, (p - b));
	sendto(radfds[r & RADIUS_MASK], b, p - b, 0, (void *) &addr, sizeof(addr));
}

// process RADIUS response
void processrad(u8 *buf, int len, char socket_index)
{
	u8 b[MAXCONTROL];
	MD5_CTX ctx;
	u16 r;
	sessionidt s;
	tunnelidt t = 0;
	hasht hash;
	u8 routes = 0;

	int r_code, r_id ; // Radius code.

	r_code = buf[0]; // First byte in radius packet.
	r_id = buf[1]; // radius reply indentifier.

#ifdef STAT_CALLS
	STAT(call_processrad);
#endif
	log_hex(5, "RADIUS Response", buf, len);
	if (len < 20 || len < ntohs(*(u16 *) (buf + 2)))
	{
		log(1, 0, 0, 0, "Duff RADIUS response length %d\n", len);
		return ;
	}
	len = ntohs(*(u16 *) (buf + 2));
	r = socket_index | (r_id << RADIUS_SHIFT);
	s = radius[r].session;
	log(3, 0, s, session[s].tunnel, "Received %s, radius %d response for session %u (code %d, id %d)\n",
			radius_states[radius[r].state], r, s, r_code, r_id);
	if (!s && radius[r].state != RADIUSSTOP)
	{
		log(1, 0, s, session[s].tunnel, "   Unexpected RADIUS response\n");
		return;
	}
	if (radius[r].state != RADIUSAUTH && radius[r].state != RADIUSSTART && radius[r].state != RADIUSSTOP)
	{
		log(1, 0, s, session[s].tunnel, "   Unexpected RADIUS response\n");
		return;
	}
	t = session[s].tunnel;
	MD5Init(&ctx);
	MD5Update(&ctx, buf, 4);
	MD5Update(&ctx, radius[r].auth, 16);
	MD5Update(&ctx, buf + 20, len - 20);
	MD5Update(&ctx, config->radiussecret, strlen(config->radiussecret));
	MD5Final(hash, &ctx);
	do {
		if (memcmp(hash, buf + 4, 16))
		{
			log(0, 0, s, session[s].tunnel, "   Incorrect auth on RADIUS response!! (wrong secret in radius config?)\n");
//			radius[r].state = RADIUSWAIT;

			return; // Do nothing. On timeout, it will try the next radius server.
		}
		if ((radius[r].state == RADIUSAUTH && *buf != 2 && *buf != 3) ||
			((radius[r].state == RADIUSSTART || radius[r].state == RADIUSSTOP) && *buf != 5))
		{
			log(1, 0, s, session[s].tunnel, "   Unexpected RADIUS response %d\n", *buf);

			return; // We got something we didn't expect. Let the timeouts take
				// care off finishing the radius session if that's really correct.
// old code. I think incorrect. --mo
//			radius[r].state = RADIUSWAIT;
//			break; // Finish the radius sesssion.
		}
		if (radius[r].state == RADIUSAUTH)
		{
			log(4, 0, s, session[s].tunnel, "   Original response is \"%s\"\n", (*buf == 2) ? "accept" : "reject");
			// process auth response
			if (radius[r].chap)
			{
				// CHAP
				u8 *p = makeppp(b, sizeof(b), 0, 0, t, s, PPPCHAP);
				if (!p) {
					return;	// Abort!
				}
				{
					struct param_post_auth packet = { &tunnel[t], &session[s], session[s].user, (*buf == 2), PPPCHAP };
					run_plugins(PLUGIN_POST_AUTH, &packet);
					*buf = packet.auth_allowed ? 2 : 3;
				}

				log(3, 0, s, session[s].tunnel, "   CHAP User %s authentication %s.\n", session[s].user,
						(*buf == 2) ? "allowed" : "denied");
				*p = (*buf == 2) ? 3 : 4;     // ack/nak
				p[1] = radius[r].id;
				*(u16 *) (p + 2) = ntohs(4); // no message
				tunnelsend(b, (p - b) + 4, t); // send it
			}
			else
			{
				// PAP
				u8 *p = makeppp(b, sizeof(b), 0, 0, t, s, PPPPAP);
				if (!p)
					return;		// Abort!

				{
					struct param_post_auth packet = { &tunnel[t], &session[s], session[s].user, (*buf == 2), PPPPAP };
					run_plugins(PLUGIN_POST_AUTH, &packet);
					*buf = packet.auth_allowed ? 2 : 3;
				}

				log(3, 0, s, session[s].tunnel, "   PAP User %s authentication %s.\n", session[s].user,
						(*buf == 2) ? "allowed" : "denied");
				// ack/nak
				*p = *buf;
				p[1] = radius[r].id;
				*(u16 *) (p + 2) = ntohs(5);
				p[4] = 0; // no message
				tunnelsend(b, (p - b) + 5, t); // send it
			}

			if (*buf == 2)
			{
				// Login successful
				// Extract IP, routes, etc
				u8 *p = buf + 20;
				u8 *e = buf + len;
				for (p = buf + 20; p < e && p[1]; p += p[1])
				{
					if (*p == 8)
					{
						// Statically assigned address
						log(3, 0, s, session[s].tunnel, "   Radius reply contains IP address %s\n", inet_toa(*(u32 *) (p + 2)));
						session[s].ip = ntohl(*(u32 *) (p + 2));
						session[s].ip_pool_index = -1;
					}
					else if (*p == 135)
					{
						// DNS address
						log(3, 0, s, session[s].tunnel, "   Radius reply contains primary DNS address %s\n", inet_toa(*(u32 *) (p + 2)));
						session[s].dns1 = ntohl(*(u32 *) (p + 2));
					}
					else if (*p == 136)
					{
						// DNS address
						log(3, 0, s, session[s].tunnel, "   Radius reply contains secondary DNS address %s\n", inet_toa(*(u32 *) (p + 2)));
						session[s].dns2 = ntohl(*(u32 *) (p + 2));
					}
					else if (*p == 22)
					{
						// framed-route
						ipt ip = 0, mask = 0;
						u8 u = 0;
						u8 bits = 0;
						u8 *n = p + 2;
						u8 *e = p + p[1];
						while (n < e && (isdigit(*n) || *n == '.'))
						{
							if (*n == '.')
							{
								ip = (ip << 8) + u;
								u = 0;
							}
							else
								u = u * 10 + *n - '0';
							n++;
						}
						ip = (ip << 8) + u;
						if (*n == '/')
						{
							n++;
							while (n < e && isdigit(*n))
								bits = bits * 10 + *n++ - '0';
							mask = (( -1) << (32 - bits));
						}
						else if ((ip >> 24) < 128)
							mask = 0xFF0000;
						else if ((ip >> 24) < 192)
							mask = 0xFFFF0000;
						else
							mask = 0xFFFFFF00;
						if (routes == MAXROUTE)
						{
							log(1, 0, s, session[s].tunnel, "   Too many routes\n");
						}
						else if (ip)
						{
							char *ips, *masks;
							ips = strdup(inet_toa(htonl(ip)));
							masks = strdup(inet_toa(htonl(mask)));
							log(3, 0, s, session[s].tunnel, "   Radius reply contains route for %s/%s\n", ips, masks);
							free(ips);
							free(masks);
							session[s].route[routes].ip = ip;
							session[s].route[routes].mask = mask;
							routes++;
						}
					}
					else if (*p == 26)
					{
						// Vendor-Specific Attribute
						int vendor = ntohl(*(int *)(p + 2));
						char attrib = *(p + 6);
						char attrib_length = *(p + 7) - 2;
						log(3, 0, s, session[s].tunnel, "   Radius reply contains Vendor-Specific. Vendor=%d Attrib=%d Length=%d\n", vendor, attrib, attrib_length);
						if (attrib_length == 0) continue;
						if (attrib != 1)
							log(3, 0, s, session[s].tunnel, "      Unknown vendor-specific\n");
						else
						{
							char *avpair, *value, *key, *newp;
							avpair = key = calloc(attrib_length + 1, 1);
							memcpy(avpair, p + 8, attrib_length);
							log(3, 0, s, session[s].tunnel, "      Cisco-Avpair value: %s\n", avpair);
							do {
								value = strchr(key, '=');
								if (!value) break;
								*value++ = 0;

								// Trim quotes off reply string
								if (*value == '\'' || *value == '\"')
								{
									char *x;
									value++;
									x = value + strlen(value) - 1;
									if (*x == '\'' || *x == '\"')
										*x = 0;
								}

								// Run hooks
								newp = strchr(value, ',');
								if (newp) *newp++ = 0;
								{
									struct param_radius_response p = { &tunnel[session[s].tunnel], &session[s], key, value };
									run_plugins(PLUGIN_RADIUS_RESPONSE, &p);
								}
								key = newp;
							} while (newp);
							free(avpair);
						}
					}
				}
			}
			else if (*buf == 3)
			{
				log(2, 0, s, session[s].tunnel, "   Authentication denied for %s\n", session[s].user);
//FIXME: We should tear down the session here!
				break;
			}

			if (!session[s].dns1 && config->default_dns1)
			{
				session[s].dns1 = htonl(config->default_dns1);
				log(3, 0, s, t, "   Sending dns1 = %s\n", inet_toa(config->default_dns1));
			}
			if (!session[s].dns2 && config->default_dns2)
			{
				session[s].dns2 = htonl(config->default_dns2);
				log(3, 0, s, t, "   Sending dns2 = %s\n", inet_toa(config->default_dns2));
			}

			// Valid Session, set it up
			session[s].sid = 0;
			sessionsetup(t, s);
		}
		else
		{
				// An ack for a stop or start record.
			log(3, 0, s, t, "   RADIUS accounting ack recv in state %s\n", radius_states[radius[r].state]);
			break;
		}
	} while (0);

	// finished with RADIUS
	radiusclear(r, s);
}

// Send a retry for RADIUS/CHAP message
void radiusretry(u16 r)
{
	sessionidt s = radius[r].session;
	tunnelidt t = 0;
#ifdef STAT_CALLS
	STAT(call_radiusretry);
#endif
	if (s)
		t = session[s].tunnel;
	radius[r].retry = backoff(radius[r].try + 1);
	switch (radius[r].state)
	{
		case RADIUSCHAP:           // sending CHAP down PPP
			sendchap(t, s);
			break;
		case RADIUSIPCP:
			sendipcp(t, s);         // send IPCP
			break;
		case RADIUSAUTH:           // sending auth to RADIUS server
			radiussend(r, RADIUSAUTH);
			break;
		case RADIUSSTART:          // sending start accounting to RADIUS server
			radiussend(r, RADIUSSTART);
			break;
		case RADIUSSTOP:           // sending stop accounting to RADIUS server
			radiussend(r, RADIUSSTOP);
			break;
		default:
		case RADIUSNULL:           // Not in use
		case RADIUSWAIT:           // waiting timeout before available, in case delayed reply from RADIUS server
			// free up RADIUS task
			radiusclear(r, s);
			log(3, 0, s, session[s].tunnel, "Freeing up radius session %d\n", r);
			break;
	}
}

void radius_clean()
{
	int i;

	log(1, 0, 0, 0, "Cleaning radius session array\n");

	for (i = 1; i < MAXRADIUS; i++)
	{
		if (radius[i].retry == 0
				|| !session[radius[i].session].opened
				|| session[radius[i].session].die
				|| session[radius[i].session].tunnel == 0)
			radiusclear(i, 0);
	}
}
