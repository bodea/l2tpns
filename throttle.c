// L2TPNS Throttle Stuff
// $Id: throttle.c,v 1.1 2003-12-16 07:07:39 fred_nerk Exp $

#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "l2tpns.h"
#include "util.h"

extern char *radiussecret;
extern radiust *radius;
extern sessiont *session;
extern ipt radiusserver[MAXRADSERVER]; // radius servers
extern u32 sessionid;
extern u8 radiusfree;
extern int radfd;
extern u8 numradiusservers;
extern char debug;
extern unsigned long rl_rate;
extern tbft *filter_buckets;

// Throttle or Unthrottle a session
int throttle_session(sessionidt s, int throttle)
{
	if (!rl_rate) return 0;

	if (!*session[s].user)
		return 0; // User not logged in

	if (throttle)
	{
		// Throttle them
		char cmd[2048] = {0};
		log(2, 0, s, session[s].tunnel, "Throttling session %d for user %s\n", s, session[s].user);
		if (!session[s].tbf) session[s].tbf = rl_get_tbf();
		snprintf(cmd, 2048, "iptables -t mangle -A throttle -d %s -j MARK --set-mark %d", inet_toa(ntohl(session[s].ip)),
				session[s].tbf);
		log(4, 0, s, session[s].tunnel, "Running %s\n", cmd);
		system(cmd);
	}
	else
	{
		char cmd[2048] = {0};
		log(2, 0, s, session[s].tunnel, "Unthrottling session %d for user %s\n", s, session[s].user);
		if (session[s].tbf)
		{
			int count = 10;
			snprintf(cmd, 2048, "iptables -t mangle -D throttle -d %s -j MARK --set-mark %d", inet_toa(ntohl(session[s].ip)), session[s].tbf);
			log(4, 0, s, session[s].tunnel, "Running %s\n", cmd);
			while (--count)
			{
				int status = system(cmd);
				if (WEXITSTATUS(status) != 0) break;
			}
			system(cmd);

			rl_done_tbf(session[s].tbf);
			session[s].tbf = 0;
		}
	}
	session[s].throttle = throttle;
	return 0;
}

