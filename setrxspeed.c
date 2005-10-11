#include <string.h>
#include "l2tpns.h"
#include "plugin.h"

/* fudge up session rx speed if not set */

char const *cvs_id = "$Id: setrxspeed.c,v 1.4 2005-10-11 09:04:53 bodea Exp $";

int plugin_api_version = PLUGIN_API_VERSION;
static struct pluginfuncs *f = 0;

int plugin_post_auth(struct param_post_auth *data)
{
    if (!data->auth_allowed)
    	return PLUGIN_RET_OK;

    if (data->s->rx_connect_speed)
    	return PLUGIN_RET_OK;

    switch (data->s->tx_connect_speed)
    {
    case 256:
	data->s->rx_connect_speed = 64;
	break;

    case 512:
	data->s->rx_connect_speed = 128;
	break;

    case 1500:
	data->s->rx_connect_speed = 256;
	break;
    }

    return PLUGIN_RET_OK;
}

int plugin_init(struct pluginfuncs *funcs)
{
    return ((f = funcs)) ? 1 : 0;
}
