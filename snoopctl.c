#include <string.h>
#include "l2tpns.h"
#include "plugin.h"
#include "control.h"

/* snoop control */

char const *cvs_id = "$Id: snoopctl.c,v 1.7 2005-10-11 09:04:53 bodea Exp $";

int plugin_api_version = PLUGIN_API_VERSION;
static struct pluginfuncs *f = 0;

char *plugin_control_help[] = {
    "  snoop USER|SID IP PORT                      Intercept user traffic",
    "  unsnoop USER|SID                            Stop intercepting user",
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

    if (strcmp(data->argv[0], "snoop") && strcmp(data->argv[0], "unsnoop"))
	return PLUGIN_RET_OK; // not for us

    if (!data->iam_master)
	return PLUGIN_RET_NOTMASTER;

    flag = data->argv[0][0] != 'u';

    if (flag)
    {
	if (data->argc != 4)
	{
	    data->response = NSCTL_RES_ERR;
	    data->additional = "requires username or session id and host, port";
	    return PLUGIN_RET_STOP;
	}
    }
    else
    {
	if (data->argc != 2)
	{
	    data->response = NSCTL_RES_ERR;
	    data->additional = "requires username or session id";
	    return PLUGIN_RET_STOP;
	}
    }

    if (!(session = strtol(data->argv[1], &end, 10)) || *end)
	session = f->get_session_by_username(data->argv[1]);

    if (session)
	s = f->get_session_by_id(session);

    if (!s || !s->ip)
    {
	data->response = NSCTL_RES_ERR;
	data->additional = "session not found";
	return PLUGIN_RET_STOP;
    }

    if (flag)
    {
	in_addr_t ip = inet_addr(data->argv[2]);
	uint16_t port = atoi(data->argv[3]);

	if (!ip || ip == INADDR_NONE)
	{
	    data->response = NSCTL_RES_ERR;
	    data->additional = "invalid ip address";
	    return PLUGIN_RET_STOP;
	}

	if (!port)
	{
	    data->response = NSCTL_RES_ERR;
	    data->additional = "invalid port";
	    return PLUGIN_RET_STOP;
	}

	if (ip == s->snoop_ip && port == s->snoop_port)
	{
	    data->response = NSCTL_RES_ERR;
	    data->additional = "already intercepted";
	    return PLUGIN_RET_STOP;
	}

	s->snoop_ip = ip;
	s->snoop_port = port;
    }
    else
    {
	if (!s->snoop_ip)
	{
	    data->response = NSCTL_RES_ERR;
	    data->additional = "not intercepted";
	    return PLUGIN_RET_STOP;
	}

	s->snoop_ip = 0;
	s->snoop_port = 0;
    }

    f->session_changed(session);

    data->response = NSCTL_RES_OK;
    data->additional = 0;

    return PLUGIN_RET_STOP;
}

int plugin_init(struct pluginfuncs *funcs)
{
    return ((f = funcs)) ? 1 : 0;
}
