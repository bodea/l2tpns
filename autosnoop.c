#include <string.h>
#include "l2tpns.h"
#include "plugin.h"

/* set up intercept based on RADIUS reply */

char const *cvs_id = "$Id: autosnoop.c,v 1.6 2004-11-09 06:02:37 bodea Exp $";

int __plugin_api_version = 1;
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
			p->log(3, 0, 0, 0, "         Intercepting user to %s:%d\n",
				p->inet_toa(data->s->snoop_ip), data->s->snoop_port);
		}
		else
		{
			p->log(3, 0, 0, 0, "         Not Intercepting user (reply string should be intercept=ip:port)\n");
		}
	}
	return PLUGIN_RET_OK;
}

int plugin_init(struct pluginfuncs *funcs)
{
	return ((p = funcs)) ? 1 : 0;
}
