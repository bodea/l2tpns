// L2TPNS Radius Stuff

char const *cvs_id_radius = "$Id: radius.c,v 1.25 2005-03-10 06:16:05 bodea Exp $";

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
extern configt *config;
extern int *radfds;
extern ip_filtert *ip_filters;

// Set up socket for radius requests
void initrad(void)
{
	int i;
	LOG(3, 0, 0, "Creating %d sockets for RADIUS queries\n", config->num_radfds);
	radfds = calloc(sizeof(int), config->num_radfds);
	for (i = 0; i < config->num_radfds; i++)
	{
		int flags;
		radfds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		flags = fcntl(radfds[i], F_GETFL, 0);
		fcntl(radfds[i], F_SETFL, flags | O_NONBLOCK);
	}
}

void radiusclear(uint16_t r, sessionidt s)
{
	if (s) session[s].radius = 0;
	memset(&radius[r], 0, sizeof(radius[r])); // radius[r].state = RADIUSNULL;
}

static uint16_t get_free_radius()
{
	int count;
	static uint32_t next_radius_id = 0;

	for (count = MAXRADIUS; count > 0 ; --count)
	{
		++next_radius_id;		// Find the next ID to check.
		if (next_radius_id >= MAXRADIUS)
			next_radius_id = 1;

		if (radius[next_radius_id].state == RADIUSNULL)
		{
			return next_radius_id;
		}
	}

	LOG(0, 0, 0, "Can't find a free radius session! This is very bad!\n");
	return 0;
}

uint16_t radiusnew(sessionidt s)
{
	uint16_t r = session[s].radius;

	/* re-use */
	if (r)
	{
		LOG(3, s, session[s].tunnel, "Re-used radius %d\n", r);
		return r;
	}

	if (!(r = get_free_radius()))
	{
		LOG(1, s, session[s].tunnel, "No free RADIUS sessions\n");
		STAT(radius_overflow);
		return 0;
	};

	memset(&radius[r], 0, sizeof(radius[r]));
	session[s].radius = r;
	radius[r].session = s;
	radius[r].state = RADIUSWAIT;
	radius[r].retry = TIME + 1200; // Wait at least 120 seconds to re-claim this.

	LOG(3, s, session[s].tunnel, "Allocated radius %d\n", r);
	return r;
}

// Send a RADIUS request
void radiussend(uint16_t r, uint8_t state)
{
	struct sockaddr_in addr;
	uint8_t b[4096];            // RADIUS packet
	char pass[129];
	int pl;
	uint8_t *p;
	sessionidt s;

	CSTAT(radiussend);

	s = radius[r].session;
	if (!config->numradiusservers)
	{
		LOG(0, s, session[s].tunnel, "No RADIUS servers\n");
		return;
	}
	if (!*config->radiussecret)
	{
		LOG(0, s, session[s].tunnel, "No RADIUS secret\n");
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
	LOG(4, s, session[s].tunnel, "Send RADIUS id %d sock %d state %s try %d\n",
		r >> RADIUS_SHIFT, r & RADIUS_MASK,
		radius_state(radius[r].state), radius[r].try);

	if (radius[r].try > config->numradiusservers * 2)
	{
		if (s)
		{
			if (state == RADIUSAUTH)
				sessionshutdown(s, "RADIUS timeout", 3, 0);
			else
			{
				LOG(1, s, session[s].tunnel, "RADIUS timeout, but in state %s so don't timeout session\n",
					radius_state(state));
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
		return;
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
			LOG(0, 0, 0, "Unknown radius state %d\n", state);
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
		*(uint32_t *) (p + 2) = htonl((state == RADIUSSTART) ? 1 : 2);
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
				*(uint32_t *) (p + 2) = htonl(session[s].cin);
				p += p[1];
				*p = 43;      // output octets
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(session[s].cout);
				p += p[1];
				*p = 46;      // session time
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(time(NULL) - session[s].opened);
				p += p[1];
				*p = 47;      // input packets
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(session[s].pin);
				p += p[1];
				*p = 48;      // output spackets
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(session[s].pout);
				p += p[1];
			}
			else
			{                // start
				*p = 41;      // delay
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(time(NULL) - session[s].opened);
				p += p[1];
			}
		}
	}
	if (s)
	{
		*p = 5; // NAS-Port
		p[1] = 6;
		*(uint32_t *) (p + 2) = htonl(s);
		p += p[1];
	}
	if (s && session[s].ip)
	{
		*p = 8;			// Framed-IP-Address
		p[1] = 6;
		*(uint32_t *) (p + 2) = htonl(session[s].ip);
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
	*(uint32_t *)(p + 2) = config->bind_address;
	p += p[1];

	// All AVpairs added
	*(uint16_t *) (b + 2) = htons(p - b);
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
	*(uint32_t *) & addr.sin_addr = config->radiusserver[(radius[r].try - 1) % config->numradiusservers];
	{
		// get radius port
		uint16_t port = config->radiusport[(radius[r].try - 1) % config->numradiusservers];
		// assume RADIUS accounting port is the authentication port +1
		addr.sin_port = htons((state == RADIUSAUTH) ? port : port+1);
	}

	LOG_HEX(5, "RADIUS Send", b, (p - b));
	sendto(radfds[r & RADIUS_MASK], b, p - b, 0, (void *) &addr, sizeof(addr));
}

// process RADIUS response
void processrad(uint8_t *buf, int len, char socket_index)
{
	uint8_t b[MAXCONTROL];
	MD5_CTX ctx;
	uint16_t r;
	sessionidt s;
	tunnelidt t = 0;
	hasht hash;
	uint8_t routes = 0;
	int r_code;
	int r_id;

	CSTAT(processrad);

	LOG_HEX(5, "RADIUS Response", buf, len);
	if (len < 20 || len < ntohs(*(uint16_t *) (buf + 2)))
	{
		LOG(1, 0, 0, "Duff RADIUS response length %d\n", len);
		return ;
	}

	r_code = buf[0]; // response type
	r_id = buf[1]; // radius reply indentifier.

	len = ntohs(*(uint16_t *) (buf + 2));
	r = socket_index | (r_id << RADIUS_SHIFT);
	s = radius[r].session;
	LOG(3, s, session[s].tunnel, "Received %s, radius %d response for session %u (%s, id %d)\n",
			radius_state(radius[r].state), r, s, radius_code(r_code), r_id);

	if (!s && radius[r].state != RADIUSSTOP)
	{
		LOG(1, s, session[s].tunnel, "   Unexpected RADIUS response\n");
		return;
	}
	if (radius[r].state != RADIUSAUTH && radius[r].state != RADIUSSTART && radius[r].state != RADIUSSTOP)
	{
		LOG(1, s, session[s].tunnel, "   Unexpected RADIUS response\n");
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
			LOG(0, s, session[s].tunnel, "   Incorrect auth on RADIUS response!! (wrong secret in radius config?)\n");
			return; // Do nothing. On timeout, it will try the next radius server.
		}

		if ((radius[r].state == RADIUSAUTH && r_code != AccessAccept && r_code != AccessReject) ||
			((radius[r].state == RADIUSSTART || radius[r].state == RADIUSSTOP) && r_code != AccountingResponse))
		{
			LOG(1, s, session[s].tunnel, "   Unexpected RADIUS response %s\n", radius_code(r_code));
			return; // We got something we didn't expect. Let the timeouts take
				// care off finishing the radius session if that's really correct.
		}

		if (radius[r].state == RADIUSAUTH)
		{
			// run post-auth plugin
			struct param_post_auth packet = {
				&tunnel[t],
				&session[s],
				session[s].user,
				(r_code == AccessAccept),
				radius[r].chap ? PPPCHAP : PPPPAP
			};

			run_plugins(PLUGIN_POST_AUTH, &packet);
			r_code = packet.auth_allowed ? AccessAccept : AccessReject;

			// process auth response
			if (radius[r].chap)
			{
				// CHAP
				uint8_t *p = makeppp(b, sizeof(b), 0, 0, t, s, PPPCHAP);
				if (!p) return;	// Abort!

				*p = (r_code == AccessAccept) ? 3 : 4;     // ack/nak
				p[1] = radius[r].id;
				*(uint16_t *) (p + 2) = ntohs(4); // no message
				tunnelsend(b, (p - b) + 4, t); // send it

				LOG(3, s, session[s].tunnel, "   CHAP User %s authentication %s.\n", session[s].user,
						(r_code == AccessAccept) ? "allowed" : "denied");
			}
			else
			{
				// PAP
				uint8_t *p = makeppp(b, sizeof(b), 0, 0, t, s, PPPPAP);
				if (!p) return;		// Abort!

				// ack/nak
				*p = r_code;
				p[1] = radius[r].id;
				*(uint16_t *) (p + 2) = ntohs(5);
				p[4] = 0; // no message
				tunnelsend(b, (p - b) + 5, t); // send it

				LOG(3, s, session[s].tunnel, "   PAP User %s authentication %s.\n", session[s].user,
						(r_code == AccessAccept) ? "allowed" : "denied");
			}

			if (r_code == AccessAccept)
			{
				// Login successful
				// Extract IP, routes, etc
				uint8_t *p = buf + 20;
				uint8_t *e = buf + len;
				for (; p + 2 <= e && p[1] && p + p[1] <= e; p += p[1])
				{
					if (*p == 8)
					{
						// Framed-IP-Address
					    	if (p[1] < 6) continue;
						session[s].ip = ntohl(*(uint32_t *) (p + 2));
						session[s].ip_pool_index = -1;
						LOG(3, s, session[s].tunnel, "   Radius reply contains IP address %s\n",
							fmtaddr(htonl(session[s].ip), 0));

						if (session[s].ip == 0xFFFFFFFE)
							session[s].ip = 0; // assign from pool
					}
					else if (*p == 135)
					{
						// DNS address
					    	if (p[1] < 6) continue;
						session[s].dns1 = ntohl(*(uint32_t *) (p + 2));
						LOG(3, s, session[s].tunnel, "   Radius reply contains primary DNS address %s\n",
							fmtaddr(htonl(session[s].dns1), 0));
					}
					else if (*p == 136)
					{
						// DNS address
					    	if (p[1] < 6) continue;
						session[s].dns2 = ntohl(*(uint32_t *) (p + 2));
						LOG(3, s, session[s].tunnel, "   Radius reply contains secondary DNS address %s\n",
							fmtaddr(htonl(session[s].dns2), 0));
					}
					else if (*p == 22)
					{
						// Framed-Route
						in_addr_t ip = 0, mask = 0;
						uint8_t u = 0;
						uint8_t bits = 0;
						uint8_t *n = p + 2;
						uint8_t *e = p + p[1];
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
							LOG(1, s, session[s].tunnel, "   Too many routes\n");
						}
						else if (ip)
						{
							LOG(3, s, session[s].tunnel, "   Radius reply contains route for %s/%s\n",
								fmtaddr(htonl(ip), 0), fmtaddr(htonl(mask), 1));
							
							session[s].route[routes].ip = ip;
							session[s].route[routes].mask = mask;
							routes++;
						}
					}
					else if (*p == 11)
					{
					    	// Filter-Id
					    	char *filter = p + 2;
						int l = p[1] - 2;
						char *suffix;
						uint8_t *f = 0;
						int i;

						LOG(3, s, session[s].tunnel, "   Radius reply contains Filter-Id \"%.*s\"\n", l, filter);
						if ((suffix = memchr(filter, '.', l)))
						{
							int b = suffix - filter;
							if (l - b == 3 && !memcmp("in", suffix+1, 2))
								f = &session[s].filter_in;
							else if (l - b == 4 && !memcmp("out", suffix+1, 3))
								f = &session[s].filter_out;

							l = b;
						}

						if (!f)
						{
							LOG(3, s, session[s].tunnel, "    Invalid filter\n");
							continue;
						}

						for (*f = 0, i = 0; !*f && i < MAXFILTER; i++)
							if (strlen(ip_filters[i].name) == l &&
							    !strncmp(ip_filters[i].name, filter, l))
								*f = i + 1;

						if (*f)
							ip_filters[*f - 1].used++;
						else
							LOG(3, s, session[s].tunnel, "    Unknown filter\n");

					}
					else if (*p == 26 && p[1] >= 7)
					{
						// Vendor-Specific Attribute
						int vendor = ntohl(*(int *)(p + 2));
						char attrib = *(p + 6);
						char attrib_length = *(p + 7) - 2;
						char *avpair, *value, *key, *newp;

						LOG(3, s, session[s].tunnel, "   Radius reply contains Vendor-Specific.  Vendor=%d Attrib=%d Length=%d\n", vendor, attrib, attrib_length);
						if (vendor != 9 || attrib != 1)
						{
							LOG(3, s, session[s].tunnel, "      Unknown vendor-specific\n");
							continue;
						}

						if (attrib_length < 0) continue;

						avpair = key = calloc(attrib_length + 1, 1);
						memcpy(avpair, p + 8, attrib_length);
						LOG(3, s, session[s].tunnel, "      Cisco-Avpair value: %s\n", avpair);
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
					else if (*p == 99)
					{
						// Framed-IPv6-Route
						struct in6_addr r6;
						int prefixlen;
						uint8_t *n = p + 2;
						uint8_t *e = p + p[1];
						uint8_t *m = strchr(n, '/');

						*m++ = 0;
						inet_pton(AF_INET6, n, &r6);

						prefixlen = 0;
						while (m < e && isdigit(*m)) {
							prefixlen = prefixlen * 10 + *m++ - '0';
						}

						if (prefixlen)
						{
							LOG(3, s, session[s].tunnel,
								"   Radius reply contains route for %s/%d\n",
								n, prefixlen);
							session[s].ipv6route = r6;
							session[s].ipv6prefixlen = prefixlen;
						}
					}
				}
			}
			else if (r_code == AccessReject)
			{
				LOG(2, s, session[s].tunnel, "   Authentication rejected for %s\n", session[s].user);
				sessionkill(s, "Authentication rejected");
				break;
			}

			if (!session[s].dns1 && config->default_dns1)
			{
				session[s].dns1 = htonl(config->default_dns1);
				LOG(3, s, t, "   Sending dns1 = %s\n", fmtaddr(config->default_dns1, 0));
			}
			if (!session[s].dns2 && config->default_dns2)
			{
				session[s].dns2 = htonl(config->default_dns2);
				LOG(3, s, t, "   Sending dns2 = %s\n", fmtaddr(config->default_dns2, 0));
			}

			// Valid Session, set it up
			session[s].unique_id = 0;
			sessionsetup(t, s);
		}
		else
		{
				// An ack for a stop or start record.
			LOG(3, s, t, "   RADIUS accounting ack recv in state %s\n", radius_state(radius[r].state));
			break;
		}
	} while (0);

	// finished with RADIUS
	radiusclear(r, s);
}

// Send a retry for RADIUS/CHAP message
void radiusretry(uint16_t r)
{
	sessionidt s = radius[r].session;
	tunnelidt t = 0;

	CSTAT(radiusretry);

	if (s) t = session[s].tunnel;

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
			LOG(3, s, session[s].tunnel, "Freeing up radius session %d\n", r);
			break;
	}
}
