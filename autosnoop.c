#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "l2tpns.h"
#include "plugin.h"
#include "control.h"

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
			p->_log(3, 0, 0, 0, "         Intercepting user to %s:%d\n",
				p->inet_toa(data->s->snoop_ip), data->s->snoop_port);
		}
		else
		{
			p->_log(3, 0, 0, 0, "         Not Intercepting user (reply string should be snoop=ip:port)\n");
		}
	}
	return PLUGIN_RET_OK;
}

int plugin_init(struct pluginfuncs *funcs)
{
	return ((p = funcs)) ? 1 : 0;
}

void plugin_done()
{
}

