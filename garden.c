#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "l2tpns.h"
#include "plugin.h"
#include "control.h"

/* walled garden */

char const *cvs_id = "$Id: garden.c,v 1.21 2005-03-10 03:31:25 bodea Exp $";

int plugin_api_version = PLUGIN_API_VERSION;
static struct pluginfuncs *p = 0;

static int iam_master = 0;	// We're all slaves! Slaves I tell you!

char *up_commands[] = {
	"iptables -t nat -N garden >/dev/null 2>&1",			// Create a chain that all gardened users will go through
	"iptables -t nat -F garden",
	". " PLUGINCONF "/build-garden",				// Populate with site-specific DNAT rules
	"iptables -t nat -N garden_users >/dev/null 2>&1",		// Empty chain, users added/removed by garden_session
	"iptables -t nat -F garden_users",
	"iptables -t nat -A PREROUTING -j garden_users",		// DNAT any users on the garden_users chain
	"sysctl -w net.ipv4.ip_conntrack_max=512000 >/dev/null",	// lots of entries
	NULL,
};

char *down_commands[] = {
	"iptables -t nat -F PREROUTING",
	"iptables -t nat -F garden_users",
	"iptables -t nat -X garden_users",
	"iptables -t nat -F garden",
	"iptables -t nat -X garden",
	"rmmod iptable_nat",	// Should also remove ip_conntrack, but
				// doing so can take hours...  literally.
				// If a master is re-started as a slave,
				// either rmmod manually, or reboot.
	NULL,
};

#define F_UNGARDEN	0
#define F_GARDEN	1
#define F_CLEANUP	2

int garden_session(sessiont *s, int flag, char *newuser);

int plugin_post_auth(struct param_post_auth *data)
{
	// Ignore if user authentication was successful
	if (data->auth_allowed) return PLUGIN_RET_OK;

	p->log(3, p->get_id_by_session(data->s), data->s->tunnel, "Walled Garden allowing login\n");
	data->auth_allowed = 1;
	data->s->walled_garden = 1;
	return PLUGIN_RET_OK;
}

int plugin_new_session(struct param_new_session *data)
{
	if (!iam_master)
		return PLUGIN_RET_OK;	// Slaves don't do walled garden processing.

	if (data->s->walled_garden)
		garden_session(data->s, F_GARDEN, 0);

	return PLUGIN_RET_OK;
}

int plugin_kill_session(struct param_new_session *data)
{
	if (!iam_master)
		return PLUGIN_RET_OK;	// Slaves don't do walled garden processing.

	if (data->s->walled_garden)
		garden_session(data->s, F_CLEANUP, 0);

	return PLUGIN_RET_OK;
}

char *plugin_control_help[] = {
	"  garden USER|SID                             Put user into the walled garden",
	"  ungarden SID [USER]                         Release session from garden",
	0
};

int plugin_control(struct param_control *data)
{
	sessionidt session;
	sessiont *s = 0;
	int flag;
	char *end;

	if (data->argc < 1)
		return PLUGIN_RET_OK;

	if (strcmp(data->argv[0], "garden") && strcmp(data->argv[0], "ungarden"))
		return PLUGIN_RET_OK; // not for us

	if (!iam_master)
		return PLUGIN_RET_NOTMASTER;

	flag = data->argv[0][0] == 'g' ? F_GARDEN : F_UNGARDEN;

	if (data->argc < 2 || data->argc > 3 || (data->argc > 2 && flag == F_GARDEN))
	{
	    	data->response = NSCTL_RES_ERR;
		data->additional = flag == F_GARDEN
		    ? "requires username or session id"
		    : "requires session id and optional username";

		return PLUGIN_RET_STOP;
	}

	if (!(session = strtol(data->argv[1], &end, 10)) || *end)
	{
		if (flag)
			session = p->get_session_by_username(data->argv[1]);
		else
			session = 0; // can't ungarden by username
	}

	if (session)
		s = p->get_session_by_id(session);

	if (!s || !s->ip)
	{
		data->response = NSCTL_RES_ERR;
		data->additional = "session not found";
		return PLUGIN_RET_STOP;
	}

	if (s->walled_garden == flag)
	{
		data->response = NSCTL_RES_ERR;
		data->additional = flag ? "already in walled garden" : "not in walled garden";
		return PLUGIN_RET_STOP;
	}

	garden_session(s, flag, data->argc > 2 ? data->argv[2] : 0);
	p->session_changed(session);

	data->response = NSCTL_RES_OK;
	data->additional = 0;

	return PLUGIN_RET_STOP;
}

int plugin_become_master(void)
{
	int i;
	iam_master = 1;	// We just became the master. Wow!

	for (i = 0; up_commands[i] && *up_commands[i]; i++)
	{
		p->log(3, 0, 0, "Running %s\n", up_commands[i]);
		system(up_commands[i]);
	}

	return PLUGIN_RET_OK;
}

// Called for each active session after becoming master
int plugin_new_session_master(sessiont *s)
{	
	if (s->walled_garden)
		garden_session(s, F_GARDEN, 0);

	return PLUGIN_RET_OK;
}

int garden_session(sessiont *s, int flag, char *newuser)
{
	char cmd[2048];
	sessionidt sess;

	if (!s) return 0;
	if (!s->opened) return 0;

	sess = p->get_id_by_session(s);
	if (flag == F_GARDEN)
	{
		p->log(2, sess, s->tunnel, "Garden user %s (%s)\n", s->user, p->fmtaddr(htonl(s->ip), 0));
		snprintf(cmd, sizeof(cmd), "iptables -t nat -A garden_users -s %s -j garden", p->fmtaddr(htonl(s->ip), 0));
		p->log(3, sess, s->tunnel, "%s\n", cmd);
		system(cmd);
		s->walled_garden = 1;
	}
	else
	{
		sessionidt other;
		int count = 40;

		// Normal User
		p->log(2, sess, s->tunnel, "Un-Garden user %s (%s)\n", s->user, p->fmtaddr(htonl(s->ip), 0));
		if (newuser)
		{
			snprintf(s->user, MAXUSER, "%s", newuser);
			p->log(2, sess, s->tunnel, "  Setting username to %s\n", s->user);
		}

		// Kick off any duplicate usernames
		// but make sure not to kick off ourself
		if (s->ip && !s->die && (other = p->get_session_by_username(s->user)) && s != p->get_session_by_id(other)) {
			p->sessionkill(other, "Duplicate session when user released from walled garden");
		}
		/* Clean up counters */
		s->cin = s->cout = 0;
		s->pin = s->pout = 0;

		snprintf(cmd, sizeof(cmd), "iptables -t nat -D garden_users -s %s -j garden", p->fmtaddr(htonl(s->ip), 0));
		p->log(3, sess, s->tunnel, "%s\n", cmd);
		while (--count)
		{
			int status = system(cmd);
			if (WEXITSTATUS(status) != 0) break;
		}

		s->walled_garden = 0;

		if (flag != F_CLEANUP)
		{
			/* OK, we're up! */
			uint16_t r = p->radiusnew(p->get_id_by_session(s));
			p->radiussend(r, RADIUSSTART);
		}
	}

	return 1;
}

int plugin_init(struct pluginfuncs *funcs)
{
	FILE *tables;
	int found_nat = 0;

	if (!funcs)
		return 0;

	p = funcs;

	if ((tables = fopen("/proc/net/ip_tables_names", "r")))
	{
		char buf[1024];
		while (fgets(buf, sizeof(buf), tables) && !found_nat)
			found_nat = !strcmp(buf, "nat\n");

		fclose(tables);
	}

	/* master killed/crashed? */
	if (found_nat)
	{
		int i;
		for (i = 0; down_commands[i] && *down_commands[i]; i++)
		{
			p->log(3, 0, 0, "Running %s\n", down_commands[i]);
			system(down_commands[i]);
		}
	}

	return 1;
}

void plugin_done()
{
	int i;

	if (!iam_master)	// Never became master. nothing to do.
		return;

	for (i = 0; down_commands[i] && *down_commands[i]; i++)
	{
		p->log(3, 0, 0, "Running %s\n", down_commands[i]);
		system(down_commands[i]);
	}
}

