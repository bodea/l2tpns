#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "l2tpns.h"
#include "plugin.h"
#include "control.h"

/* walled garden */

char const *cvs_id = "$Id: garden.c,v 1.11 2004-11-05 04:55:27 bodea Exp $";

int __plugin_api_version = 1;
static struct pluginfuncs *p = 0;

static int iam_master = 0;	// We're all slaves! Slaves I tell you!

char *up_commands[] = {
	"iptables -t nat -N garden >/dev/null 2>&1",			// Create a chain that all gardened users will go through
	"iptables -t nat -F garden",
	". " PLUGINCONF "/build-garden",				// Populate with site-specific DNAT rules
	"iptables -t nat -N garden_users >/dev/null 2>&1",		// Empty chain, users added/removed by garden_session
	"iptables -t nat -F garden_users",
	"iptables -t nat -A PREROUTING -j garden_users",		// DNAT any users on the garden_users chain
	"sysctl -w net.ipv4.ip_conntrack_max=256000 >/dev/null",	// lots of entries
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

int garden_session(sessiont *s, int flag);

int plugin_post_auth(struct param_post_auth *data)
{
	// Ignore if user authentication was successful
	if (data->auth_allowed) return PLUGIN_RET_OK;

	p->log(3, 0, 0, 0, "Walled Garden allowing login\n");
	data->auth_allowed = 1;
	data->s->walled_garden = 1;
	return PLUGIN_RET_OK;
}

int plugin_new_session(struct param_new_session *data)
{
	if (!iam_master)
		return PLUGIN_RET_OK;	// Slaves don't do walled garden processing.

	if (data->s->walled_garden)
		garden_session(data->s, 1);

	return PLUGIN_RET_OK;
}

int plugin_kill_session(struct param_new_session *data)
{
	if (!iam_master)
		return PLUGIN_RET_OK;	// Slaves don't do walled garden processing.

	if (data->s->walled_garden)
		garden_session(data->s, 0);

	return PLUGIN_RET_OK;
}

int plugin_control(struct param_control *data)
{
	sessiont *s;
	sessionidt session;

	if (!iam_master)	// All garden processing happens on the master.
		return PLUGIN_RET_OK;

	if (data->type != PKT_GARDEN && data->type != PKT_UNGARDEN)
		return PLUGIN_RET_OK;

	if (!data->data && data->data_length)
		return PLUGIN_RET_OK;

	session = atoi((char*)(data->data));
	if (!session)
		return PLUGIN_RET_OK;

	data->send_response = 1;
	s = p->get_session_by_id(session);
	if (!s || !s->ip)
	{
		char *errormsg = "Session not connected";
		*(short *)(data->response + 2) = ntohs(PKT_RESP_ERROR);
		sprintf((data->response + data->response_length), "%s", errormsg);
		data->response_length += strlen(errormsg) + 1;

		p->log(3, 0, 0, 0, "Unknown session %d\n", session);
		return PLUGIN_RET_STOP;
	}
	*(short *)(data->response + 2) = ntohs(PKT_RESP_OK);

	if (!(garden_session(s, (data->type == PKT_GARDEN))))
	{
		char *errormsg = "User not connected";
		*(short *)(data->response + 2) = ntohs(PKT_RESP_ERROR);
		sprintf((data->response + data->response_length), "%s", errormsg);
		data->response_length += strlen(errormsg) + 1;
	}

	return PLUGIN_RET_STOP;
}

int plugin_become_master(void)
{
	int i;
	iam_master = 1;	// We just became the master. Wow!

	for (i = 0; up_commands[i] && *up_commands[i]; i++)
	{
		p->log(3, 0, 0, 0, "Running %s\n", up_commands[i]);
		system(up_commands[i]);
	}

	return PLUGIN_RET_OK;
}

// Called for each active session after becoming master
int plugin_new_session_master(sessiont * s)
{	
	if (s->walled_garden)
		garden_session(s, 1);

	return PLUGIN_RET_OK;
}

int garden_session(sessiont *s, int flag)
{
	char cmd[2048];

	if (!s) return 0;
	if (!s->opened) return 0;

	if (flag == 1)
	{
		p->log(2, 0, 0, s->tunnel, "Garden user %s (%s)\n", s->user, p->inet_toa(htonl(s->ip)));
		snprintf(cmd, sizeof(cmd), "iptables -t nat -A garden_users -s %s -j garden", p->inet_toa(htonl(s->ip)));
		p->log(3, 0, 0, s->tunnel, "%s\n", cmd);
		system(cmd);
		s->walled_garden = 1;
	}
	else
	{
		sessionidt other;
		int count = 40;

		// Normal User
		p->log(2, 0, 0, s->tunnel, "Un-Garden user %s (%s)\n", s->user, p->inet_toa(htonl(s->ip)));
		// Kick off any duplicate usernames
		// but make sure not to kick off ourself
		if (s->ip && !s->die && (other = p->get_session_by_username(s->user)) && s != p->get_session_by_id(other)) {
			p->sessionkill(other, "Duplicate session when user released from walled garden");
		}
		/* Clean up counters */
		s->cin = s->cout = 0;
		s->pin = s->pout = 0;

		snprintf(cmd, sizeof(cmd), "iptables -t nat -D garden_users -s %s -j garden", p->inet_toa(htonl(s->ip)));
		p->log(3, 0, 0, s->tunnel, "%s\n", cmd);
		while (--count)
		{
			int status = system(cmd);
			if (WEXITSTATUS(status) != 0) break;
		}

		s->walled_garden = 0;

		if (!s->die) {
			/* OK, we're up! */
			u16 r = p->radiusnew(p->get_id_by_session(s));
			p->radiussend(r, RADIUSSTART);
		}
	}
	s->walled_garden = flag;
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
			p->log(3, 0, 0, 0, "Running %s\n", down_commands[i]);
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
		p->log(3, 0, 0, 0, "Running %s\n", down_commands[i]);
		system(down_commands[i]);
	}
}

