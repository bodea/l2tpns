#include <string.h>
#include "l2tpns.h"
#include "plugin.h"
#include "control.h"

/* session control */

char const *cvs_id = "$Id: sessionctl.c,v 1.5 2006-04-13 11:14:35 bodea Exp $";

int plugin_api_version = PLUGIN_API_VERSION;
static struct pluginfuncs *f = 0;

char *plugin_control_help[] = {
    "  drop USER|SID [REASON]                      Shutdown user session",
    "  kill USER|SID [REASON]                      Kill user session",
    0
};

int plugin_control(struct param_control *data)
{
    sessionidt session;
    sessiont *s = 0;
    char *end;
    char *reason;

    if (data->argc < 1)
	return PLUGIN_RET_OK;

    if (strcmp(data->argv[0], "drop") && strcmp(data->argv[0], "kill"))
	return PLUGIN_RET_OK; // not for us

    if (!data->iam_master)
	return PLUGIN_RET_NOTMASTER;

    if (data->argc < 2 || data->argc > 3)
    {
	data->response = NSCTL_RES_ERR;
	data->additional = "requires username or session id and optional reason";
	return PLUGIN_RET_STOP;
    }

    if (!(session = strtol(data->argv[1], &end, 10)) || *end)
	session = f->get_session_by_username(data->argv[1]);

    if (session)
	s = f->get_session_by_id(session);

    if (!s || !s->ip)
    {
	data->response = NSCTL_RES_ERR;
	data->additional = "session not found";
	return PLUGIN_RET_STOP;
    }

    if (data->argc > 2)
	reason = data->argv[2];
    else
	reason = "Requested by administrator.";

    if (data->argv[0][0] == 'd')
	f->sessionshutdown(session, reason, CDN_ADMIN_DISC, TERM_ADMIN_RESET);
    else
	f->sessionkill(session, reason);

    data->response = NSCTL_RES_OK;
    data->additional = 0;

    return PLUGIN_RET_STOP;
}

int plugin_init(struct pluginfuncs *funcs)
{
    return ((f = funcs)) ? 1 : 0;
}
