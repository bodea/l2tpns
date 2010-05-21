#include <string.h>
#include "l2tpns.h"
#include "plugin.h"

/* Append a realm to the username */

char const *cvs_id = "Id: appendrealm.c,v 1.0 2007/06/12 010:50:53 rmcleay Exp $";

int plugin_api_version = PLUGIN_API_VERSION;
static struct pluginfuncs *f = 0;

int plugin_pre_auth(struct param_pre_auth *data)
{
	char tmp[MAXUSER];

//	char *tmp = malloc(MAXUSER);
	char *realm = f->getconfig("append_realm", STRING);
	char *p;

   	if (!data->continue_auth) return PLUGIN_RET_STOP;
	if (!realm) return PLUGIN_RET_OK;

	f->log(3, 0, 0, "Seeking to append realm: \"%s\"\n", realm);
	
	//Remove existing realm
	if ((p = strchr(data->username, '@')))
		*p = 0;
		
	//Add realm
	snprintf(tmp, sizeof(tmp), "%s@%s", data->username, realm);
	free(data->username);
	data->username = strdup(tmp);

	f->log(3, 0, 0, "Appended or replaced realm. Username: \"%s\"\n", data->s->user);

	return PLUGIN_RET_OK;
}

int plugin_init(struct pluginfuncs *funcs)
{
    return ((f = funcs)) ? 1 : 0;
}
