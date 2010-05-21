#include <string.h>
#include "l2tpns.h"
#include "plugin.h"

/* change the username into a copy of the calling station id */

char const *cvs_id = "Id: clitousername.c,v 1.0 2007/05/31 010:50:53 matw Exp $";

int plugin_api_version = PLUGIN_API_VERSION;
static struct pluginfuncs *f = 0;

int plugin_pre_auth(struct param_pre_auth *data)
{
	f->log(3, 0, 0, "Setting username as CLI..\n");
        free(data->username);
        data->username = strdup(data->s->calling);
        f->log(3, 0, 0, "Username is now %s\n",data->username);

        return PLUGIN_RET_OK;
}

int plugin_init(struct pluginfuncs *funcs)
{
    return ((f = funcs)) ? 1 : 0;
}
