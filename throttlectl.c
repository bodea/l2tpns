#include <string.h>
#include "l2tpns.h"
#include "plugin.h"
#include "control.h"

/* throttle control */

char const *cvs_id = "$Id: throttlectl.c,v 1.1 2004-11-17 15:08:19 bodea Exp $";

int plugin_api_version = PLUGIN_API_VERSION;
static struct pluginfuncs *p = 0;

char *plugin_control_help[] = {
	"  throttle USER|SID [RATE|[in|out] RATE ...]  Throttle user traffic",
	"  unthrottle USER|SID                         Stop throttling user",
	0
};

static int iam_master = 0;

int plugin_init(struct pluginfuncs *funcs)
{
	if (!funcs)
		return 0;

	p = funcs;
	return 1;
}

int plugin_become_master(void)
{
	iam_master = 1;
	return PLUGIN_RET_OK;
}

int plugin_control(struct param_control *data)
{
	sessionidt session;
	sessiont *s = 0;
	int flag;
	char *end;
	int rate_in = 0;
	int rate_out = 0;

	if (data->argc < 1)
		return PLUGIN_RET_OK;

	if (strcmp(data->argv[0], "throttle")
	    && strcmp(data->argv[0], "unthrottle"))
		return PLUGIN_RET_OK; // not for us

	flag = data->argv[0][0] != 'g';

	if (!iam_master)
	{
	    	data->response = NSCTL_RES_ERR;
		data->additional = "must be run on the cluster master";
		return PLUGIN_RET_STOP;
	}

	if (flag)
	{
		if (data->argc < 2 || data->argc > 4)
		{
			data->response = NSCTL_RES_ERR;
			data->additional = "requires username or session id and optional rate(s)";
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
		session = p->get_session_by_username(data->argv[1]);

	if (session)
		s = p->get_session_by_id(session);

	if (!s || !s->ip)
	{
		data->response = NSCTL_RES_ERR;
		data->additional = "session not found";
		return PLUGIN_RET_STOP;
	}

	if (flag)
	{
		rate_in = rate_out = -1;
		if (data->argc == 2)
		{
		    	unsigned long *rate = p->getconfig("throttle_speed", UNSIGNED_LONG);
			rate_in = rate_out = *rate;
		}
		else if (data->argc == 3)
		{
			rate_in = rate_out = atoi(data->argv[2]);
		}
		else
		{
		    	int i;
			for (i = 2; i < data->argc - 1; i += 2)
			{
				int len = strlen(data->argv[i]);
				if (!strncmp(data->argv[i], "in", len))
				{
					rate_in = atoi(argv[i+1]);
				}
				else if (!strncmp(data->argv[i], "out", len))
				{
					rate_out = atoi(argv[i+1]);
				}
				else
				{
					data->response = NSCTL_RES_ERR;
					data->additional = "invalid rate";
					return PLUGIN_RET_STOP;
				}
			}
		}

		if (!rate_in || !rate_out)
		{
			data->response = NSCTL_RES_ERR;
			data->additional = "invalid rate";
			return PLUGIN_RET_STOP;
		}
	}

	if (rate_in != -1 && rate_in == s->throttle_in &&
	    rate_out != -1 && rate_out == s->throttle_out)
	{
		data->response = NSCTL_RES_ERR;
		data->additional = flag ? "already throttled" : "not throttled";
		return PLUGIN_RET_STOP;
	}

	p->throttle(session, rate_in, rate_out);
	p->sesssion_changed(session);

	data->response = NSCTL_RES_OK;
	data->additional = 0;

	return PLUGIN_RET_STOP;
}
