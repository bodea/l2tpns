#ifndef __PLUGIN_H__
#define __PLUGIN_H__

#define PLUGIN_API_VERSION	1
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
	PLUGIN_RADIUS_RESPONSE
};

#define PLUGIN_RET_ERROR	0
#define PLUGIN_RET_OK		1
#define PLUGIN_RET_STOP		2

struct pluginfuncs
{
	void (*_log)(int level, ipt address, sessionidt s, tunnelidt t, const char *format, ...);
	void (*_log_hex)(int level, ipt address, sessionidt s, tunnelidt t, const char *title, const char *data, int maxsize);
	char *(*inet_toa)(unsigned long addr);
	sessionidt (*get_session_by_username)(char *username);
	sessiont *(*get_session_by_id)(sessionidt s);
	sessionidt (*get_id_by_session)(sessiont *s);
	void (*sessionkill)(sessionidt s, char *reason);
	u8 (*radiusnew)(sessionidt s);
	void (*radiussend)(u8 r, u8 state);
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

struct param_config
{
	char *key;
	char *value;
};

struct param_control
{
	char *buf;
	int l;
	unsigned int source_ip;
	unsigned short source_port;
	char *response;
	int response_length;
	int send_response;
	short type;
	int id;
	char *data;
	int data_length;
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

#endif
