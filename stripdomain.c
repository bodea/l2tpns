#include <string.h>
#include "l2tpns.h"
#include "plugin.h"

/* strip domain part of username before sending RADIUS requests */

char const *cvs_id = "$Id: stripdomain.c,v 1.8 2005-10-11 09:04:53 bodea Exp $";

int plugin_api_version = PLUGIN_API_VERSION;
static struct pluginfuncs *f = 0;

int plugin_pre_auth(struct param_pre_auth *data)
{
    char *p;

    if (!data->continue_auth) return PLUGIN_RET_STOP;

    // Strip off @domain
    if ((p = strchr(data->username, '@')))
    {
	f->log(3, 0, 0, "Stripping off trailing domain name \"%s\"\n", p);
	*p = 0;
    }

    return PLUGIN_RET_OK;
}

int plugin_init(struct pluginfuncs *funcs)
{
    return ((f = funcs)) ? 1 : 0;
}
