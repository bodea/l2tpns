#include <string.h>
#include "l2tpns.h"
#include "plugin.h"

char const *cvs_id = "$Id: stripdomain.c,v 1.2 2004-11-03 13:29:31 bodea Exp $";

int __plugin_api_version = 1;
static struct pluginfuncs *p = 0;

int plugin_pre_auth(struct param_pre_auth *data)
{
	char *x;

	if (!data->continue_auth) return PLUGIN_RET_STOP;

	// Strip off @domain
	if ((x = strchr(data->username, '@')))
	{
		p->_log(3, 0, 0, 0, "Stripping off trailing domain name \"%s\"\n", x);
		*x = 0;
	}

	return PLUGIN_RET_OK;
}

int plugin_init(struct pluginfuncs *funcs)
{
	return ((p = funcs)) ? 1 : 0;
}
