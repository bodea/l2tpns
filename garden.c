#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "l2tpns.h"
#include "plugin.h"
#include "control.h"

int __plugin_api_version = 1;
struct pluginfuncs p;

int garden_session(sessiont *s, int flag);

char *init_commands[] = {
	// This is for incoming connections to a gardened user
	"iptables -t nat -N garden_users 2>&1 >/dev/null",
	"iptables -t nat -F garden_users 2>&1 >/dev/null",
	"iptables -t nat -N garden 2>&1 >/dev/null",
	"iptables -t nat -A l2tpns -j garden_users",
	NULL
};

char *done_commands[] = {
	"iptables -t nat -F garden_users 2>&1 >/dev/null",
	"iptables -t nat -D l2tpns -j garden_users 2>&1 >/dev/null",
	NULL
};

int plugin_post_auth(struct param_post_auth *data)
{
	// Ignore if user authentication was successful
	if (data->auth_allowed) return PLUGIN_RET_OK;

	p.log(3, 0, 0, 0, "User allowed into walled garden\n");
	data->auth_allowed = 1;
	data->s->walled_garden = 1;
	return PLUGIN_RET_OK;
}

int plugin_new_session(struct param_new_session *data)
{
	if (data->s->walled_garden) garden_session(data->s, 1);
	return PLUGIN_RET_OK;
}

int plugin_kill_session(struct param_new_session *data)
{
	if (data->s->walled_garden) garden_session(data->s, 0);
	return PLUGIN_RET_OK;
}

int plugin_control(struct param_control *data)
{
	sessiont *s;
	sessionidt session;

	if (data->type != PKT_GARDEN && data->type != PKT_UNGARDEN) return PLUGIN_RET_OK;
	if (!data->data && data->data_length) return PLUGIN_RET_OK;
	session = atoi((char*)(data->data));

	if (!session)
		return PLUGIN_RET_OK;

	data->send_response = 1;
	s = p.get_session_by_id(session);
	if (!s || !s->ip)
	{
		char *errormsg = "Session not connected";
		*(short *)(data->response + 2) = ntohs(PKT_RESP_ERROR);
		sprintf((data->response + data->response_length), "%s", errormsg);
		data->response_length += strlen(errormsg) + 1;

		p.log(3, 0, 0, 0, "Unknown session %s\n", session);
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

int plugin_config(struct param_config *data)
{
	return PLUGIN_RET_OK;
}

int garden_session(sessiont *s, int flag)
{
	char cmd[2048];

	if (!s) return 0;
	if (!s->opened) return 0;

	if (flag == 1)
	{
		p.log(2, 0, 0, s->tunnel, "Trap user %s (%s) in walled garden\n", s->user, p.inet_toa(ntohl(s->ip)));
		snprintf(cmd, 2048, "iptables -t nat -A garden_users -s %s -j garden", p.inet_toa(ntohl(s->ip)));
		p.log(3, 0, 0, s->tunnel, "%s\n", cmd);
		system(cmd);
		s->walled_garden = 1;
	}
	else
	{
		sessionidt other;
		int count = 10;

		// Normal User
		p.log(2, 0, 0, s->tunnel, "Release user %s (%s) from walled garden\n", s->user, p.inet_toa(ntohl(s->ip)));
		// Kick off any duplicate usernames
		// but make sure not to kick off ourself
		if (s->ip && !s->die && (other = p.get_session_by_username(s->user)) && s != p.get_session_by_id(other)) {
			p.sessionkill(other, "Duplicate session when user ungardened");
		}
		/* Clean up counters */
		s->cin = s->cout = 0;
		s->pin = s->pout = 0;

		snprintf(cmd, 2048, "iptables -t nat -D garden_users -s %s -j garden", p.inet_toa(ntohl(s->ip)));
		p.log(3, 0, 0, s->tunnel, "%s\n", cmd);
		while (--count)
		{
			int status = system(cmd);
			if (WEXITSTATUS(status) != 0) break;
		}

		s->walled_garden = 0;

		if (!s->die) {
			/* OK, we're up! */
			u8 r = p.radiusnew(p.get_id_by_session(s));
			p.radiussend(r, RADIUSSTART);
		}
	}
	s->walled_garden = flag;
	return 1;
}

int plugin_init(struct pluginfuncs *funcs)
{
	int i;

	if (!funcs) return 0;
	memcpy(&p, funcs, sizeof(p));

	p.log(1, 0, 0, 0, "Enabling walled garden service\n");

	for (i = 0; init_commands[i] && *init_commands[i]; i++)
	{
		p.log(4, 0, 0, 0, "Running %s\n", init_commands[i]);
		system(init_commands[i]);
	}

	return 1;
}

void plugin_done()
{
	int i;
	for (i = 0; done_commands[i] && *done_commands[i]; i++)
	{
		p.log(4, 0, 0, 0, "Running %s\n", done_commands[i]);
		system(done_commands[i]);
	}
}

