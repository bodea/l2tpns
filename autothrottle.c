#include <string.h>
#include "l2tpns.h"
#include "plugin.h"

/* set up throttling based on RADIUS reply */

char const *cvs_id = "$Id: autothrottle.c,v 1.13 2004-11-30 07:14:45 bodea Exp $";

int plugin_api_version = PLUGIN_API_VERSION;
struct pluginfuncs *p;

#define THROTTLE_KEY "lcp:interface-config"

int plugin_radius_response(struct param_radius_response *data)
{
	if (!strncmp(data->key, THROTTLE_KEY, sizeof(THROTTLE_KEY) - 1))
	{
		char *sp = strchr(data->value, ' ');
		char type;
		int rate;

		if (!sp || sp - data->value < 4 ||
		    strncmp("service-policy", data->value, sp - data->value))
			return PLUGIN_RET_OK;

		while (*sp == ' ') sp++;
		data->value = sp;

		if (!(sp = strchr(data->value, ' ')) ||
		    (strncmp("input", data->value, sp - data->value) &&
		    strncmp("output", data->value, sp - data->value)))
		{
			p->log(3, p->get_id_by_session(data->s), data->s->tunnel,
				"         Not throttling user (invalid type %.*s)\n",
				sp - data->value, data->value);

			return PLUGIN_RET_OK;
		}

		type = *data->value;

		while (*sp == ' ') sp++;
		data->value = sp;

		if ((rate = strtol(data->value, &sp, 10)) < 0 || *sp)
		{
			p->log(3, p->get_id_by_session(data->s), data->s->tunnel,
				"         Not throttling user (invalid rate %s)\n",
				data->value);

			return PLUGIN_RET_OK;
		}

		if (type == 'i')
		{
			data->s->throttle_in = rate;
			p->log(3, p->get_id_by_session(data->s), data->s->tunnel,
				"         Throttling user input to %dkb/s\n",
				rate);
		}
		else
		{
			data->s->throttle_out = rate;
			p->log(3, p->get_id_by_session(data->s), data->s->tunnel,
				"         Throttling user output to %dkb/s\n",
				rate);
		}
	}

	if (!strcmp(data->key, "throttle"))
	{
		if (!strcmp(data->value, "yes"))
		{
		    	unsigned long *rate = p->getconfig("throttle_speed", UNSIGNED_LONG);
			if (rate)
			{
				if (*rate)
					p->log(3, p->get_id_by_session(data->s), data->s->tunnel,
						"         Throttling user to %dkb/s\n", *rate);
				else
					p->log(3, p->get_id_by_session(data->s), data->s->tunnel,
						"         Not throttling user (throttle_speed=0)\n");

				data->s->throttle_in = data->s->throttle_out = *rate;
			}
			else
				p->log(1, p->get_id_by_session(data->s), data->s->tunnel,
					"         Not throttling user (can't get throttle_speed)\n");
		}
		else if (!strcmp(data->value, "no"))
		{
			p->log(3, p->get_id_by_session(data->s), data->s->tunnel,
				"         Not throttling user\n");

			data->s->throttle_in = data->s->throttle_out = 0;
		}
	}

	return PLUGIN_RET_OK;
}

int plugin_init(struct pluginfuncs *funcs)
{
	return ((p = funcs)) ? 1 : 0;
}
