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
	if (strcmp(data->key, "throttle") == 0)
	{
		if (strcmp(data->value, "yes") == 0)
		{
			p->log(3, 0, 0, 0, "         Throttling user\n");
			data->s->throttle = 1;
		}
		else if (strcmp(data->value, "no") == 0)
		{
			p->log(3, 0, 0, 0, "         Not throttling user\n");
			data->s->throttle = 0;
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

