// L2TPNS Radius Stuff

char const *cvs_id_radius = "$Id: radius.c,v 1.55 2006-08-02 14:17:30 bodea Exp $";

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
#include <errno.h>
#include "md5.h"
#include "constants.h"
#include "l2tpns.h"
#include "plugin.h"
#include "util.h"
#include "cluster.h"

extern radiust *radius;
extern sessiont *session;
extern tunnelt *tunnel;
extern configt *config;
extern int *radfds;
extern ip_filtert *ip_filters;

static const hasht zero;

static void calc_auth(const void *buf, size_t len, const uint8_t *in, uint8_t *out)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, (void *)buf, 4); // code, id, length
	MD5_Update(&ctx, (void *)in, 16); // auth
	MD5_Update(&ctx, (void *)(buf + 20), len - 20);
	MD5_Update(&ctx, config->radiussecret, strlen(config->radiussecret));
	MD5_Final(out, &ctx);
}

// Set up socket for radius requests
void initrad(void)
{
	int i;
	uint16_t port = 0;
	uint16_t min = config->radius_bind_min;
	uint16_t max = config->radius_bind_max;
	int inc = 1;
	struct sockaddr_in addr;

	if (min)
	{
		port = min;
		if (!max)
			max = ~0 - 1;
	}
	else if (max) /* no minimum specified, bind from max down */
	{
		port = max;
		min = 1;
		inc = -1;
	}

	LOG(3, 0, 0, "Creating %d sockets for RADIUS queries\n", RADIUS_FDS);
	radfds = calloc(sizeof(int), RADIUS_FDS);
	for (i = 0; i < RADIUS_FDS; i++)
	{
		int flags;
		radfds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		flags = fcntl(radfds[i], F_GETFL, 0);
		fcntl(radfds[i], F_SETFL, flags | O_NONBLOCK);

		if (port)
		{
			int b;

			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = INADDR_ANY;

			do {
				addr.sin_port = htons(port);
				if ((b = bind(radfds[i], (struct sockaddr *) &addr, sizeof(addr))) < 0)
				{
					if ((port += inc) < min || port > max)
					{
						LOG(0, 0, 0, "Can't bind RADIUS socket in range %u-%u\n", min, max);
						exit(1);
					}
				}
			} while (b < 0);
		}
	}
}

void radiusclear(uint16_t r, sessionidt s)
{
	if (s) sess_local[s].radius = 0;
	memset(&radius[r], 0, sizeof(radius[r])); // radius[r].state = RADIUSNULL;
}

static uint16_t get_free_radius()
{
	int count;
	static uint32_t next_radius_id = 0;

	for (count = MAXRADIUS; count > 0; --count)
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
	uint16_t r = sess_local[s].radius;

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
	sess_local[s].radius = r;
	radius[r].session = s;
	radius[r].state = RADIUSWAIT;
	radius[r].retry = TIME + 1200; // Wait at least 120 seconds to re-claim this.

	random_data(radius[r].auth, sizeof(radius[r].auth));

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
	radius[r].retry = backoff(radius[r].try++) + 20; // 3s, 4s, 6s, 10s...
	LOG(4, s, session[s].tunnel, "Send RADIUS id %d sock %d state %s try %d\n",
		r >> RADIUS_SHIFT, r & RADIUS_MASK,
		radius_state(radius[r].state), radius[r].try);

	if (radius[r].try > config->numradiusservers * 2)
	{
		if (s)
		{
			if (state == RADIUSAUTH)
				sessionshutdown(s, "RADIUS timeout.", CDN_ADMIN_DISC, TERM_REAUTHENTICATION_FAILURE);
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
			b[0] = AccessRequest;               // access request
			break;
		case RADIUSSTART:
		case RADIUSSTOP:
		case RADIUSINTERIM:
			b[0] = AccountingRequest;               // accounting request
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
		strcpy((char *) p + 2, session[s].user);
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
					MD5_Init(&ctx);
					MD5_Update(&ctx, config->radiussecret, strlen(config->radiussecret));
					if (p)
						MD5_Update(&ctx, pass + p - 16, 16);
					else
						MD5_Update(&ctx, radius[r].auth, 16);
					MD5_Final(hash, &ctx);
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
	else // accounting
	{
		*p = 40;	// accounting type
		p[1] = 6;
		*(uint32_t *) (p + 2) = htonl(state - RADIUSSTART + 1); // start=1, stop=2, interim=3
		p += p[1];
		if (s)
		{
			*p = 44;	// session ID
			p[1] = 18;
			sprintf((char *) p + 2, "%08X%08X", session[s].unique_id, session[s].opened);
			p += p[1];
			if (state == RADIUSSTART)
			{			// start
				*p = 41;	// delay
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(time(NULL) - session[s].opened);
				p += p[1];
				sess_local[s].last_interim = time_now; // Setup "first" Interim
			}
			else
			{			// stop, interim
				*p = 42;	// input octets
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(session[s].cin);
				p += p[1];

				*p = 43;	// output octets
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(session[s].cout);
				p += p[1];

				*p = 46;	// session time
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(time(NULL) - session[s].opened);
				p += p[1];

				*p = 47;	// input packets
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(session[s].pin);
				p += p[1];

				*p = 48;	// output packets
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(session[s].pout);
				p += p[1];

				*p = 52;	// input gigawords
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(session[s].cin_wrap);
				p += p[1];

				*p = 53;	// output gigawords
				p[1] = 6;
				*(uint32_t *) (p + 2) = htonl(session[s].cout_wrap);
				p += p[1];

				if (state == RADIUSSTOP && radius[r].term_cause)
				{
				    	*p = 49; // acct-terminate-cause
					p[1] = 6;
					*(uint32_t *) (p + 2) = htonl(radius[r].term_cause);
					p += p[1];

					if (radius[r].term_msg)
					{
						*p = 26;				// vendor-specific
						*(uint32_t *) (p + 2) = htonl(9);	// Cisco
						p[6] = 1;				// Cisco-AVPair
						p[7] = 2 + sprintf((char *) p + 8, "disc-cause-ext=%s", radius[r].term_msg);
						p[1] = p[7] + 6;
						p += p[1];
					}
				}
			}

			{
				struct param_radius_account acct = { &tunnel[session[s].tunnel], &session[s], &p };
				run_plugins(PLUGIN_RADIUS_ACCOUNT, &acct);
			}
		}
	}

	if (s)
	{
		*p = 5;		// NAS-Port
		p[1] = 6;
		*(uint32_t *) (p + 2) = htonl(s);
		p += p[1];

	        *p = 6;		// Service-Type
		p[1] = 6;
		*(uint32_t *) (p + 2) = htonl(2); // Framed-User
		p += p[1];
		   
	        *p = 7;		// Framed-Protocol
		p[1] = 6;
		*(uint32_t *) (p + 2) = htonl(1); // PPP
		p += p[1];

		if (session[s].ip)
		{
			*p = 8;			// Framed-IP-Address
			p[1] = 6;
			*(uint32_t *) (p + 2) = htonl(session[s].ip);
			p += p[1];
		}

		if (session[s].route[0].ip)
		{
			int r;
			for (r = 0; s && r < MAXROUTE && session[s].route[r].ip; r++)
			{
				int width = 32;
				if (session[s].route[r].mask)
				{
				    int mask = session[s].route[r].mask;
				    while (!(mask & 1))
				    {
					width--;
					mask >>= 1;
				    }
				}

				*p = 22;	// Framed-Route
				p[1] = sprintf((char *) p + 2, "%s/%d %s 1",
					fmtaddr(htonl(session[s].route[r].ip), 0),
					width, fmtaddr(htonl(session[s].ip), 1)) + 2;

				p += p[1];
			}
		}

		if (session[s].session_timeout)
		{
			*p = 27;		// Session-Timeout
			p[1] = 6;
			*(uint32_t *) (p + 2) = htonl(session[s].session_timeout);
			p += p[1];
		}

		if (session[s].idle_timeout)
		{
			*p = 28;		// Idle-Timeout
			p[1] = 6;
			*(uint32_t *) (p + 2) = htonl(session[s].idle_timeout);
			p += p[1];
		}

		if (*session[s].called)
		{
			*p = 30;                // called
			p[1] = strlen(session[s].called) + 2;
			strcpy((char *) p + 2, session[s].called);
			p += p[1];
		}

		if (*session[s].calling)
		{
			*p = 31;                // calling
			p[1] = strlen(session[s].calling) + 2;
			strcpy((char *) p + 2, session[s].calling);
			p += p[1];
		}
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
		calc_auth(b, p - b, zero, b + 4);
		memcpy(radius[r].auth, b + 4, 16);
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

static void handle_avpair(sessionidt s, uint8_t *avp, int len)
{
	uint8_t *key = avp;
	uint8_t *value = memchr(avp, '=', len);
	uint8_t tmp[2048] = "";

	if (value)
	{
		*value++ = 0;
		len -= value - key;
	}
	else
	{
	    	value = tmp;
		len = 0;
	}

	// strip quotes
	if (len > 2 && (*value == '"' || *value == '\'') && value[len - 1] == *value)
	{
		value++;
		len--;
		value[len - 1] = 0;
	}
	// copy and null terminate
	else if (len < sizeof(tmp) - 1)
	{
		memcpy(tmp, value, len);
		tmp[len] = 0;
		value = tmp;
	}
	else
		return;
	
	// Run hooks
	{
		struct param_radius_response p = { &tunnel[session[s].tunnel], &session[s], (char *) key, (char *) value };
		run_plugins(PLUGIN_RADIUS_RESPONSE, &p);
	}
}

// process RADIUS response
void processrad(uint8_t *buf, int len, char socket_index)
{
	uint8_t b[MAXETHER];
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
	if (radius[r].state != RADIUSAUTH && radius[r].state != RADIUSSTART
	    && radius[r].state != RADIUSSTOP && radius[r].state != RADIUSINTERIM)
	{
		LOG(1, s, session[s].tunnel, "   Unexpected RADIUS response\n");
		return;
	}
	t = session[s].tunnel;
	calc_auth(buf, len, radius[r].auth, hash);
	do {
		if (memcmp(hash, buf + 4, 16))
		{
			LOG(0, s, session[s].tunnel, "   Incorrect auth on RADIUS response!! (wrong secret in radius config?)\n");
			return; // Do nothing. On timeout, it will try the next radius server.
		}

		if ((radius[r].state == RADIUSAUTH && r_code != AccessAccept && r_code != AccessReject) ||
			((radius[r].state == RADIUSSTART || radius[r].state == RADIUSSTOP || radius[r].state == RADIUSINTERIM) && r_code != AccountingResponse))
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
				uint8_t *p = makeppp(b, sizeof(b), 0, 0, s, t, PPPCHAP, 0, 0, 0);
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
				uint8_t *p = makeppp(b, sizeof(b), 0, 0, s, t, PPPPAP, 0, 0, 0);
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
					if (*p == 26 && p[1] >= 7)
					{
						// Vendor-Specific Attribute
						uint32_t vendor = ntohl(*(int *)(p + 2));
						uint8_t attrib = *(p + 6);
						int attrib_length = *(p + 7) - 2;

						LOG(4, s, session[s].tunnel, "   Radius reply contains Vendor-Specific.  Vendor=%u Attrib=%u Length=%d\n", vendor, attrib, attrib_length);
						if (vendor == 9 && attrib == 1) // Cisco-AVPair
						{
							if (attrib_length < 0) continue;
							LOG(3, s, session[s].tunnel, "      Cisco-AVPair value: %.*s\n",
								attrib_length, p + 8);

							handle_avpair(s, p + 8, attrib_length);
							continue;
						}
						else if (vendor == 529 && attrib >= 135 && attrib <= 136) // Ascend
						{
							// handle old-format ascend DNS attributes below
						    	p += 6;
						}
						else
						{
							LOG(3, s, session[s].tunnel, "      Unknown vendor-specific\n");
							continue;
						}
					}

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
					    	char *filter = (char *) p + 2;
						int l = p[1] - 2;
						char *suffix;
						int f;
						uint8_t *fp = 0;

						LOG(3, s, session[s].tunnel, "   Radius reply contains Filter-Id \"%.*s\"\n", l, filter);
						if ((suffix = memchr(filter, '.', l)))
						{
							int b = suffix - filter;
							if (l - b == 3 && !memcmp("in", suffix+1, 2))
								fp = &session[s].filter_in;
							else if (l - b == 4 && !memcmp("out", suffix+1, 3))
								fp = &session[s].filter_out;

							l = b;
						}

						if (!fp)
						{
							LOG(3, s, session[s].tunnel, "    Invalid filter\n");
							continue;
						}

						if ((f = find_filter(filter, l)) < 0 || !*ip_filters[f].name)
						{
							LOG(3, s, session[s].tunnel, "    Unknown filter\n");
						}
						else
						{
							*fp = f + 1;
							ip_filters[f].used++;
						}
					}
					else if (*p == 27)
					{
					    	// Session-Timeout
					    	if (p[1] < 6) continue;
						session[s].session_timeout = ntohl(*(uint32_t *)(p + 2));
						LOG(3, s, session[s].tunnel, "   Radius reply contains Session-Timeout = %u\n", session[s].session_timeout);
					}
					else if (*p == 28)
					{
					    	// Idle-Timeout
					    	if (p[1] < 6) continue;
						session[s].idle_timeout = ntohl(*(uint32_t *)(p + 2));
						LOG(3, s, session[s].tunnel, "   Radius reply contains Idle-Timeout = %u\n", session[s].idle_timeout);
					}
					else if (*p == 99)
					{
						// Framed-IPv6-Route
						struct in6_addr r6;
						int prefixlen;
						uint8_t *n = p + 2;
						uint8_t *e = p + p[1];
						uint8_t *m = memchr(n, '/', e - p);

						*m++ = 0;
						inet_pton(AF_INET6, (char *) n, &r6);

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
				session[s].dns1 = ntohl(config->default_dns1);
				LOG(3, s, t, "   Sending dns1 = %s\n", fmtaddr(config->default_dns1, 0));
			}
			if (!session[s].dns2 && config->default_dns2)
			{
				session[s].dns2 = ntohl(config->default_dns2);
				LOG(3, s, t, "   Sending dns2 = %s\n", fmtaddr(config->default_dns2, 0));
			}

			// Valid Session, set it up
			session[s].unique_id = 0;
			sessionsetup(s, t);
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

	switch (radius[r].state)
	{
		case RADIUSCHAP:	// sending CHAP down PPP
			sendchap(s, t);
			break;
		case RADIUSAUTH:	// sending auth to RADIUS server
		case RADIUSSTART:	// sending start accounting to RADIUS server
		case RADIUSSTOP:	// sending stop accounting to RADIUS server
		case RADIUSINTERIM:	// sending interim accounting to RADIUS server
			radiussend(r, radius[r].state);
			break;
		default:
		case RADIUSNULL:	// Not in use
		case RADIUSWAIT:	// waiting timeout before available, in case delayed reply from RADIUS server
			// free up RADIUS task
			radiusclear(r, s);
			LOG(3, s, session[s].tunnel, "Freeing up radius session %d\n", r);
			break;
	}
}

extern int daefd;

void processdae(uint8_t *buf, int len, struct sockaddr_in *addr, int alen, struct in_addr *local)
{
	int i, r_code, r_id, length, attribute_length;
	uint8_t *packet, attribute;
	hasht hash;
	char username[MAXUSER] = "";
	in_addr_t nas = 0;
	in_addr_t ip = 0;
	uint32_t port = 0;
	uint32_t error = 0;
	sessionidt s = 0;
	tunnelidt t;
	int fin = -1;
	int fout = -1;
	uint8_t *avpair[64];
	int avpair_len[sizeof(avpair)/sizeof(*avpair)];
	int avp = 0;
	int auth_only = 0;
	uint8_t *p;

	LOG(3, 0, 0, "DAE request from %s\n", fmtaddr(addr->sin_addr.s_addr, 0));
	LOG_HEX(5, "DAE Request", buf, len);

	if (len < 20 || len < ntohs(*(uint16_t *) (buf + 2)))
	{
		LOG(1, 0, 0, "Duff DAE request length %d\n", len);
		return;
	}

	r_code = buf[0]; // request type
	r_id = buf[1]; // radius indentifier.

	if (r_code != DisconnectRequest && r_code != CoARequest)
	{
		LOG(1, 0, 0, "Unrecognised DAE request %s\n", radius_code(r_code));
		return;
	}

	if (!config->cluster_iam_master)
	{
		master_forward_dae_packet(buf, len, addr->sin_addr.s_addr, addr->sin_port);
		return;
	}

	len = ntohs(*(uint16_t *) (buf + 2));

	LOG(3, 0, 0, "Received DAE %s, id %d\n", radius_code(r_code), r_id);

	// check authenticator
	calc_auth(buf, len, zero, hash);
	if (memcmp(hash, buf + 4, 16) != 0)
	{
		LOG(1, 0, 0, "Incorrect vector in DAE request (wrong secret in radius config?)\n");
		return;
	}

	// unpack attributes
	packet = buf + 20;
	length = len - 20;

	while (length > 0)
	{
		attribute = *packet++;
		attribute_length = *packet++;
		if (attribute_length < 2)
			break;

		length -= attribute_length;
		attribute_length -= 2;
		switch (attribute)
		{
		case 1: /* username */
			len = attribute_length < MAXUSER ? attribute_length : MAXUSER - 1;
			memcpy(username, packet, len);
			username[len] = 0;
			LOG(4, 0, 0, "    Received DAE User-Name: %s\n", username);
			break;

		case 4: /* nas ip address */
			nas = *(uint32_t *) packet; // net order
			if (nas != config->bind_address)
				error = 403; // NAS identification mismatch

			LOG(4, 0, 0, "    Received DAE NAS-IP-Address: %s\n", fmtaddr(nas, 0));
			break;

		case 5: /* nas port */
			port = ntohl(*(uint32_t *) packet);
			if (port < 1 || port > MAXSESSION)
				error = 404;

			LOG(4, 0, 0, "    Received DAE NAS-Port: %u\n", port);
			break;

		case 6: /* service type */
			{
				uint32_t service_type = ntohl(*(uint32_t *) packet);
				auth_only = service_type == 8; // Authenticate only

				LOG(4, 0, 0, "    Received DAE Service-Type: %u\n", service_type);
			}
			break;

		case 8: /* ip address */
			ip = *(uint32_t *) packet; // net order
			LOG(4, 0, 0, "    Received DAE Framed-IP-Address: %s\n", fmtaddr(ip, 0));
			break;

		case 11: /* filter id */
			LOG(4, 0, 0, "    Received DAE Filter-Id: %.*s\n", attribute_length, packet);
			if (!(p = memchr(packet, '.', attribute_length)))
			{
				error = 404; // invalid request
				break;
			}

			len = p - packet;
			i = find_filter((char *) packet, len);
			if (i < 0 || !*ip_filters[i].name)
			{
				error = 404;
				break;
			}

			if (!memcmp(p, ".in", attribute_length - len))
				fin = i + 1;
			else if (!memcmp(p, ".out", attribute_length - len))
				fout = i + 1;
			else
				error = 404;

			break;

		case 26: /* vendor specific */
			if (attribute_length >= 6
			    && ntohl(*(uint32_t *) packet) == 9	// Cisco
			    && *(packet + 4) == 1		// Cisco-AVPair
			    && *(packet + 5) >= 2)		// length
			{
				int len = *(packet + 5) - 2;
				uint8_t *a = packet + 6;

				LOG(4, 0, 0, "    Received DAE Cisco-AVPair: %.*s\n", len, a);
				if (avp < sizeof(avpair)/sizeof(*avpair) - 1)
				{
					avpair[avp] = a;
					avpair_len[avp++] = len;
				}
			}
			break;
		}

		packet += attribute_length;
	}

	if (!error && auth_only)
	{
		if (fin != -1 || fout != -1 || avp)
			error = 401; // unsupported attribute
		else
			error = 405; // unsupported service
	}

	if (!error && !(port || ip || *username))
		error = 402; // missing attribute

	// exact match for SID if given
	if (!error && port)
	{
		s = port;
		if (!session[s].opened)
			error = 503; // not found
	}

	if (!error && ip)
	{
		// find/check session by IP
		i = sessionbyip(ip);
		if (!i || (s && s != i)) // not found or mismatching port
			error = 503;
		else
			s = i;
	}

	if (!error && *username)
	{
		if (s)
		{
			if (strcmp(session[s].user, username))
				error = 503;
		}
		else if (!(s = sessionbyuser(username)))
			error = 503;
	}

	t = session[s].tunnel;

	switch (r_code)
	{
	case DisconnectRequest: // Packet of Disconnect/Death
		if (error)
		{
			r_code = DisconnectNAK;
			break;
		}

		LOG(3, s, t, "    DAE Disconnect %d (%s)\n", s, session[s].user);
		r_code = DisconnectACK;

		sessionshutdown(s, "Requested by PoD", CDN_ADMIN_DISC, TERM_ADMIN_RESET); // disconnect session
		break;

	case CoARequest: // Change of Authorization
		if (error)
		{
		    	r_code = CoANAK;
			break;
		}

		LOG(3, s, t, "    DAE Change %d (%s)\n", s, session[s].user);
		r_code = CoAACK;
	
		// reset
		{
			struct param_radius_reset p = { &tunnel[session[s].tunnel], &session[s] };
			run_plugins(PLUGIN_RADIUS_RESET, &p);
		}

		// apply filters
		if (fin == -1)
			fin = 0;
		else
			LOG(3, s, t, "        Filter in %d (%s)\n", fin, ip_filters[fin - 1].name);

		if (fout == -1)
			fout = 0;
		else
			LOG(3, s, t, "        Filter out %d (%s)\n", fout, ip_filters[fout - 1].name);

		filter_session(s, fin, fout);

		// process cisco av-pair(s)
		for (i = 0; i < avp; i++)
		{
			LOG(3, s, t, "        Cisco-AVPair: %.*s\n", avpair_len[i], avpair[i]);
			handle_avpair(s, avpair[i], avpair_len[i]);
		}

		cluster_send_session(s);
		break;
	}

	// send response
	packet = buf;
	*packet++ = r_code;
	*packet++ = r_id;
	// skip len + auth
	packet += 2 + 16;
	len = packet - buf;

	// add attributes
	if (error)
	{
		// add error cause
		*packet++ = 101;
		*packet++ = 6;
		*(uint32_t *) packet = htonl(error);
		len += 6;
	}

	*((uint16_t *)(buf + 2)) = htons(len);

	// make vector
	calc_auth(buf, len, hash, buf + 4);

	LOG(3, 0, 0, "Sending DAE %s, id=%d\n", radius_code(r_code), r_id);

	// send DAE response
	if (sendtofrom(daefd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *) addr, alen, local) < 0)
		LOG(0, 0, 0, "Error sending DAE response packet: %s\n", strerror(errno));
}
