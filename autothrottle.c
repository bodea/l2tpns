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

#define THROTTLE_KEY "lcp:interface-config"

int plugin_radius_response(struct param_radius_response *data)
{
	char *t;
	int i = 0;
	int rate;

	if (strncmp(data->key, THROTTLE_KEY, strlen(THROTTLE_KEY)) == 0)
	{
		char *pt = strdup(data->value);
		while ((t = strsep(&pt, " ")) != NULL)
		{
			if (strcmp(t, "serv") == 0)
				i = 1;
			else if (strcmp(t, "o") && i == 1)
				i = 2;
			else if (strcmp(t, "i") && i == 1)
				i = 3;
			else if (i > 1 && (rate = atoi(t)) > 0)
			{
				switch (i)
				{
					case 2: // output
						data->s->throttle |= (rate & 0xFFFF);
						free(pt);
						p->log(3, 0, p->get_id_by_session(data->s), data->s->tunnel, "      Set output throttle rate %dkb/s\n", rate);
						return PLUGIN_RET_OK;

					case 3: //input
						data->s->throttle |= (rate << 16);
						free(pt);
						p->log(3, 0, p->get_id_by_session(data->s), data->s->tunnel, "      Set input throttle rate %dkb/s\n", rate);
						return PLUGIN_RET_OK;

					default:
						p->log(1, 0, p->get_id_by_session(data->s), data->s->tunnel, "Syntax error in rate limit AV pair: %s=%s\n", data->key, data->value);
						free(pt);
						return PLUGIN_RET_OK;
				}
			}
			else
			{
				free(pt);
				p->log(1, 0, p->get_id_by_session(data->s), data->s->tunnel, "Syntax error in rate limit AV pair: %s=%s\n",
					data->key, data->value);
				return PLUGIN_RET_OK;
			}
		}
		free(pt);
	}
	else if (strcmp(data->key, "throttle") == 0)
	{
		if (strcmp(data->value, "yes") == 0)
		{
			p->log(3, 0, p->get_id_by_session(data->s), data->s->tunnel, "         Throttling user\n");
			data->s->throttle = 1;
		}
		else if (strcmp(data->value, "no") == 0)
		{
			p->log(3, 0, p->get_id_by_session(data->s), data->s->tunnel, "         Not throttling user\n");
			data->s->throttle = 0;
		}
	}

	p->log(4, 0, p->get_id_by_session(data->s), data->s->tunnel, "autothrottle module ignoring AV pair %s=%s\n",
		data->key, data->value);

	return PLUGIN_RET_OK;
}

int plugin_init(struct pluginfuncs *funcs)
{
	return ((p = funcs)) ? 1 : 0;
}

void plugin_done()
{
}

