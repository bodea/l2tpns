#ifndef __PLUGIN_H__
#define __PLUGIN_H__

#define PLUGIN_API_VERSION	4
#define MAX_PLUGIN_TYPES	30

enum
{
	PLUGIN_PRE_AUTH = 1,
	PLUGIN_POST_AUTH,
	PLUGIN_PACKET_RX,
	PLUGIN_PACKET_TX,
	PLUGIN_TIMER,
	PLUGIN_NEW_SESSION,
	PLUGIN_KILL_SESSION,
	PLUGIN_CONTROL,
	PLUGIN_RADIUS_RESPONSE,
	PLUGIN_BECOME_MASTER,
	PLUGIN_NEW_SESSION_MASTER,
};

#define PLUGIN_RET_ERROR	0
#define PLUGIN_RET_OK		1
#define PLUGIN_RET_STOP		2 
#define PLUGIN_RET_NOTMASTER	3

struct pluginfuncs
{
	void (*log)(int level, sessionidt s, tunnelidt t, const char *format, ...);
	void (*log_hex)(int level, const char *title, const char *data, int maxsize);
	char *(*fmtaddr)(ipt addr, int n);
	sessionidt (*get_session_by_username)(char *username);
	sessiont *(*get_session_by_id)(sessionidt s);
	sessionidt (*get_id_by_session)(sessiont *s);
	u16 (*radiusnew)(sessionidt s);
	void (*radiussend)(u16 r, u8 state);
	void *(*getconfig)(char *key, enum config_typet type);
	void (*sessionkill)(sessionidt s, char *reason);
	void (*throttle)(sessionidt s, int rate_in, int rate_out);
	int (*session_changed)(int sid);
};

struct param_pre_auth
{
	tunnelt *t;
	sessiont *s;
	char *username;
	char *password;
	int protocol;
	int continue_auth;
};

struct param_post_auth
{
	tunnelt *t;
	sessiont *s;
	char *username;
	short auth_allowed;
	int protocol;
};

struct param_packet_rx
{
	tunnelt *t;
	sessiont *s;
	char *buf;
	int len;
};

struct param_packet_tx
{
	tunnelt *t;
	sessiont *s;
	char *buf;
	int len;
};

struct param_timer
{
	time_t time_now;
};

struct param_control
{
	int iam_master;
    	int argc;
	char **argv;
	// output
	int response;
	char *additional;
};

struct param_new_session
{
	tunnelt *t;
	sessiont *s;
};

struct param_kill_session
{
	tunnelt *t;
	sessiont *s;
};

struct param_radius_response
{
	tunnelt *t;
	sessiont *s;
	char *key;
	char *value;
};

#endif /* __PLUGIN_H__ */
