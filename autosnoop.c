#include <string.h>
#include "l2tpns.h"
#include "plugin.h"

/* set up intercept based on RADIUS reply */

char const *cvs_id = "$Id: autosnoop.c,v 1.9 2004-11-29 02:17:17 bodea Exp $";

int plugin_api_version = PLUGIN_API_VERSION;
struct pluginfuncs *p;

int plugin_radius_response(struct param_radius_response *data)
{
	if (strcmp(data->key, "intercept") == 0)
	{
		char *x;
		data->s->snoop_ip = 0;
		data->s->snoop_port = 0;
		if ((x = strchr(data->value, ':')))
		{
			*x++ = 0;
			if (*data->value) data->s->snoop_ip = inet_addr(data->value);
			if (data->s->snoop_ip == INADDR_NONE) data->s->snoop_ip = 0;
			if (*x) data->s->snoop_port = atoi(x);
			p->log(3, p->get_id_by_session(data->s), data->s->tunnel,
				"         Intercepting user to %s:%d\n",
				p->fmtaddr(data->s->snoop_ip, 0), data->s->snoop_port);
		}
		else
		{
			p->log(3, p->get_id_by_session(data->s), data->s->tunnel,
				"         Not Intercepting user (reply string should be intercept=ip:port)\n");
		}
	}
	return PLUGIN_RET_OK;
}

int plugin_init(struct pluginfuncs *funcs)
{
	return ((p = funcs)) ? 1 : 0;
}
