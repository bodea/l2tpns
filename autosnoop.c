#include <string.h>
#include "l2tpns.h"
#include "plugin.h"

/* set up intercept based on RADIUS reply */

char const *cvs_id = "$Id: autosnoop.c,v 1.12 2005-10-11 09:04:53 bodea Exp $";

int plugin_api_version = PLUGIN_API_VERSION;
static struct pluginfuncs *f = 0;

int plugin_radius_response(struct param_radius_response *data)
{
    if (!strcmp(data->key, "intercept"))
    {
	char *p;
	data->s->snoop_ip = 0;
	data->s->snoop_port = 0;
	if ((p = strchr(data->value, ':')))
	{
	    *p++ = 0;
	    if (*data->value)
		data->s->snoop_ip = inet_addr(data->value);

	    if (data->s->snoop_ip == INADDR_NONE)
		data->s->snoop_ip = 0;

	    if (*p)
		data->s->snoop_port = atoi(p);

	    f->log(3, f->get_id_by_session(data->s), data->s->tunnel,
		"         Intercepting user to %s:%d\n",
		f->fmtaddr(data->s->snoop_ip, 0), data->s->snoop_port);
	}
	else
	{
	    f->log(3, f->get_id_by_session(data->s), data->s->tunnel,
		    "         Not Intercepting user (reply string should"
		    " be intercept=ip:port)\n");
	}
    }

	return PLUGIN_RET_OK;
}

int plugin_radius_reset(struct param_radius_reset *data)
{
    data->s->snoop_ip = 0;
    data->s->snoop_port = 0;
    return PLUGIN_RET_OK;
}

int plugin_radius_account(struct param_radius_account *data)
{
    if (data->s->snoop_ip && data->s->snoop_port)
    {
	uint8_t *p = *data->packet;

	*p = 26;				// vendor-specific
	*(uint32_t *) (p + 2) = htonl(9);	// Cisco
	p[6] = 1;				// Cisco-AVPair
	p[7] = 2 + sprintf((char *) p + 8, "intercept=%s:%d",
	    f->fmtaddr(data->s->snoop_ip, 0), data->s->snoop_port);

	p[1] = p[7] + 6;
	*data->packet += p[1];
    }

    return PLUGIN_RET_OK;
}

int plugin_init(struct pluginfuncs *funcs)
{
    return ((f = funcs)) ? 1 : 0;
}
