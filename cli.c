// L2TPNS Command Line Interface
// $Id: cli.c,v 1.2 2004-03-05 00:09:03 fred_nerk Exp $
// vim: sw=4 ts=8

#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <syslog.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include "l2tpns.h"
#include "libcli.h"
#include "util.h"

extern tunnelt *tunnel;
extern sessiont *session;
extern radiust *radius;
extern ippoolt *ip_address_pool;
extern struct Tstats *_statistics;
extern int cli_pid;
struct cli_def *cli = NULL;
int cli_quit = 0;
extern int clifd, udpfd, tapfd, snoopfd, radfd, ifrfd, cluster_sockfd;
extern sessionidt *cli_session_kill;
extern tunnelidt *cli_tunnel_kill;
extern tbft *filter_buckets;
extern struct configt *config;
extern struct config_descriptt config_values[];
extern char hostname[];
#ifdef RINGBUFFER
extern struct Tringbuffer *ringbuffer;
#endif

char *rcs_id = "$Id: cli.c,v 1.2 2004-03-05 00:09:03 fred_nerk Exp $";

char *debug_levels[] = {
    "CRIT",
    "ERROR",
    "WARN",
    "INFO",
    "CALL",
    "DATA",
};

struct
{
    char critical;
    char error;
    char warning;
    char info;
    char calls;
    char data;
} debug_flags;

int debug_session;
int debug_tunnel;
int debug_rb_tail;
FILE *save_config_fh;

int cmd_show_session(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_tunnels(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_users(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_radius(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_counters(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_version(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_pool(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_run(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_banana(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_plugins(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_write_memory(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_clear_counters(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_drop_user(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_drop_tunnel(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_drop_session(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_snoop(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_no_snoop(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_throttle(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_no_throttle(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_debug(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_no_debug(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_watch_session(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_watch_tunnel(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_set(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_load_plugin(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_remove_plugin(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_uptime(struct cli_def *cli, char *command, char **argv, int argc);
int regular_stuff(struct cli_def *cli);

void init_cli()
{
    FILE *f;
    char buf[4096];
    struct cli_command *c;
    int on = 1;
    struct sockaddr_in addr;

    cli = cli_init();

    c = cli_register_command(cli, NULL, "show", NULL, NULL);
    cli_register_command(cli, c, "session", cmd_show_session, "Show a list of sessions or details for a single session");
    cli_register_command(cli, c, "tunnels", cmd_show_tunnels, "Show a list of tunnels or details for a single tunnel");
    cli_register_command(cli, c, "users", cmd_show_users, "Show a list of all connected users");
    cli_register_command(cli, c, "version", cmd_show_version, "Show currently running software version");
    cli_register_command(cli, c, "banana", cmd_show_banana, "Show a banana");
    cli_register_command(cli, c, "pool", cmd_show_pool, "Show the IP address allocation pool");
    cli_register_command(cli, c, "running-config", cmd_show_run, "Show the currently running configuration");
    cli_register_command(cli, c, "radius", cmd_show_radius, "Show active radius queries");
    cli_register_command(cli, c, "plugins", cmd_show_plugins, "List all installed plugins");

#ifdef STATISTICS
    cli_register_command(cli, c, "counters", cmd_show_counters, "Display all the internal counters and running totals");

    c = cli_register_command(cli, NULL, "clear", NULL, NULL);
    cli_register_command(cli, c, "counters", cmd_clear_counters, "Clear internal counters");
#endif

    cli_register_command(cli, NULL, "uptime", cmd_uptime, "Show uptime and bandwidth utilisation");

    c = cli_register_command(cli, NULL, "write", NULL, NULL);
    cli_register_command(cli, c, "memory", cmd_write_memory, "Save the running config to flash");
    cli_register_command(cli, c, "terminal", cmd_show_run, "Show the running config");

    cli_register_command(cli, NULL, "snoop", cmd_snoop, "Temporarily enable interception for a user");
    cli_register_command(cli, NULL, "throttle", cmd_throttle, "Temporarily enable throttling for a user");

    c = cli_register_command(cli, NULL, "no", NULL, NULL);
    cli_register_command(cli, c, "snoop", cmd_no_snoop, "Temporarily disable interception for a user");
    cli_register_command(cli, c, "throttle", cmd_no_throttle, "Temporarily disable throttling for a user");
    cli_register_command(cli, c, "debug", cmd_no_debug, "Turn off logging of a certain level of debugging");

    c = cli_register_command(cli, NULL, "drop", NULL, NULL);
    cli_register_command(cli, c, "user", cmd_drop_user, "Disconnect a user");
    cli_register_command(cli, c, "tunnel", cmd_drop_tunnel, "Disconnect a tunnel and all sessions on that tunnel");
    cli_register_command(cli, c, "session", cmd_drop_session, "Disconnect a session");

    cli_register_command(cli, NULL, "debug", cmd_debug, "Set the level of logging that is shown on the console");

    /*
    c = cli_register_command(cli, NULL, "watch", NULL, NULL);
    cli_register_command(cli, c, "session", cmd_watch_session, "Dump logs for a session");
    cli_register_command(cli, c, "tunnel", cmd_watch_tunnel, "Dump logs for a tunnel");
    */

    c = cli_register_command(cli, NULL, "load", NULL, NULL);
    cli_register_command(cli, c, "plugin", cmd_load_plugin, "Load a plugin");

    c = cli_register_command(cli, NULL, "remove", NULL, NULL);
    cli_register_command(cli, c, "plugin", cmd_remove_plugin, "Remove a plugin");

    cli_register_command(cli, NULL, "set", cmd_set, "Set a configuration variable");

    // Enable regular processing
    cli_regular(cli, regular_stuff);

    if (!(f = fopen(CLIUSERS, "r")))
    {
	log(0, 0, 0, 0, "WARNING! No users specified. Command-line access is open to all\n");
    }
    else
    {
	while (fgets(buf, 4096, f))
	{
	    char *p;
	    if (*buf == '#') continue;
	    if ((p = strchr(buf, '\r'))) *p = 0;
	    if ((p = strchr(buf, '\n'))) *p = 0;
	    if (!*buf) continue;
	    if (!(p = strchr((char *)buf, ':'))) continue;
	    *p++ = 0;
	    cli_allow_user(cli, buf, p);
	    log(3, 0, 0, 0, "Allowing user %s to connect to the CLI\n", buf);
	}
	fclose(f);
    }

    memset(&addr, 0, sizeof(addr));
    clifd = socket(PF_INET, SOCK_STREAM, 6);
    setsockopt(clifd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    {
	int flags;
	// Set cli fd as non-blocking
	flags = fcntl(clifd, F_GETFL, 0);
	fcntl(clifd, F_SETFL, flags | O_NONBLOCK);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(23);
    if (bind(clifd, (void *) &addr, sizeof(addr)) < 0)
    {
	    log(0, 0, 0, 0, "Error listening on cli port 23: %s\n", strerror(errno));
	    return;
    }
    listen(clifd, 10);
}

void cli_do(int sockfd)
{
    if (fork()) return;

    // Close sockets
    if (udpfd) close(udpfd); udpfd = 0;
    if (tapfd) close(tapfd); tapfd = 0;
    if (snoopfd) close(snoopfd); snoopfd = 0;
    if (radfd) close(radfd); radfd = 0;
    if (ifrfd) close(ifrfd); ifrfd = 0;
    if (cluster_sockfd) close(cluster_sockfd); cluster_sockfd = 0;
    if (clifd) close(clifd); clifd = 0;

    signal(SIGPIPE, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    signal(SIGUSR1, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGKILL, SIG_DFL);
    signal(SIGALRM, SIG_DFL);

    log(3, 0, 0, 0, "Accepted connection to CLI\n");

    debug_session = 0;
    debug_tunnel = 0;
#ifdef RINGBUFFER
    debug_rb_tail = ringbuffer->tail;
#endif
    memset(&debug_flags, 0, sizeof(debug_flags));
    debug_flags.critical = 1;

    {
	char prompt[1005];
	snprintf(prompt, 1005, "%s> ", hostname);
	cli_loop(cli, sockfd, prompt);
    }

    close(sockfd);
    log(3, 0, 0, 0, "Closed CLI connection\n");
    exit(0);
}

void cli_print_log(struct cli_def *cli, char *string)
{
    log(3, 0, 0, 0, "%s\n", string);
}

void cli_do_file(FILE *fh)
{
    log(3, 0, 0, 0, "Reading configuration file\n");
    cli_print_callback(cli, cli_print_log);
    cli_file(cli, fh);
    cli_print_callback(cli, NULL);
}

int cmd_show_session(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;
    time_t time_now;

    time(&time_now);
    if (argc > 0)
    {
	// Show individual session
	for (i = 0; i < argc; i++)
	{
	    unsigned int s;
	    s = atoi(argv[i]);
	    if (!s || s > MAXSESSION)
	    {
		cli_print(cli, "Invalid session id \"%s\"", argv[i]);
		continue;
	    }
	    cli_print(cli, "\r\nSession %d:", s);
	    cli_print(cli, "	User:		%s", session[s].user[0] ? session[s].user : "none");
	    cli_print(cli, "	Calling Num:	%s", session[s].calling);
	    cli_print(cli, "	Called Num:	%s", session[s].called);
	    cli_print(cli, "	Tunnel ID:	%d", session[s].tunnel);
	    cli_print(cli, "	IP address:	%s", inet_toa(htonl(session[s].ip)));
	    cli_print(cli, "	HSD sid:	%lu", session[s].sid);
	    cli_print(cli, "	Idle time:	%u seconds", abs(time_now - session[s].last_packet));
	    cli_print(cli, "	Next Recv:	%u", session[s].nr);
	    cli_print(cli, "	Next Send:	%u", session[s].ns);
	    cli_print(cli, "	Bytes In/Out:	%lu/%lu", (unsigned long)session[s].cin, (unsigned long)session[s].total_cout);
	    cli_print(cli, "	Pkts In/Out:	%lu/%lu", (unsigned long)session[s].pin, (unsigned long)session[s].pout);
	    cli_print(cli, "	Radius Session:	%u", session[s].radius);
	    cli_print(cli, "	Rx Speed:	%lu", session[s].rx_connect_speed);
	    cli_print(cli, "	Tx Speed:	%lu", session[s].tx_connect_speed);
	    cli_print(cli, "	Intercepted:	%s", session[s].snoop ? "YES" : "no");
	    cli_print(cli, "	Throttled:	%s", session[s].throttle ? "YES" : "no");
	    cli_print(cli, "	Servicenet:	%s", session[s].servicenet ? "YES" : "no");
	    cli_print(cli, "	Filter Bucket:	%s", session[s].tbf ? filter_buckets[session[s].tbf].handle : "none");
	}
	return CLI_OK;
    }

    // Show Summary
    cli_print(cli, "  %s %4s %-32s %-15s %s %s %s %10s %10s %10s %4s %-15s %s",
	    "SID",
	    "TID",
	    "Username",
	    "IP",
	    "I",
	    "T",
	    "S",
	    "opened",
	    "downloaded",
	    "uploaded",
	    "idle",
	    "LAC",
	    "CLI");
    for (i = 1; i < MAXSESSION; i++)
    {
	char *userip, *tunnelip;
	if (!session[i].opened) continue;
	userip = strdup(inet_toa(htonl(session[i].ip)));
	tunnelip = strdup(inet_toa(htonl(tunnel[ session[i].tunnel ].ip)));
	cli_print(cli, "%5d %4d %-32s %-15s %s %s %s %10u %10lu %10lu %4u %-15s %s",
		i,
		session[i].tunnel,
		session[i].user[0] ? session[i].user : "*",
		userip,
		(session[i].snoop) ? "Y" : "N",
		(session[i].throttle) ? "Y" : "N",
		(session[i].servicenet) ? "Y" : "N",
		abs(time_now - (unsigned long)session[i].opened),
		(unsigned long)session[i].total_cout,
		(unsigned long)session[i].total_cin,
		abs(time_now - (session[i].last_packet ? session[i].last_packet : time_now)),
                tunnelip,
		session[i].calling[0] ? session[i].calling : "*");
	if (userip) free(userip);
	if (tunnelip) free(tunnelip);
    }
    return CLI_OK;
}

int cmd_show_tunnels(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i, x, show_all = 0;
    time_t time_now;
    char *states[] = {
	"Free",
	"Open",
	"Closing",
	"Opening",
    };

    time(&time_now);
    if (argc > 0)
    {
	if (strcmp(argv[0], "all") == 0)
	{
	    show_all = 1;
	}
	else
	{
	    // Show individual tunnel
	    for (i = 0; i < argc; i++)
	    {
		char s[65535] = {0};
		unsigned int t;
		t = atoi(argv[i]);
		if (!t || t > MAXTUNNEL)
		{
		    cli_print(cli, "Invalid tunnel id \"%s\"", argv[i]);
		    continue;
		}
		cli_print(cli, "\r\nTunnel %d:", t);
		cli_print(cli, "	State:		%s", states[tunnel[t].state]);
		cli_print(cli, "	Hostname:	%s", tunnel[t].hostname[0] ? tunnel[t].hostname : "(none)");
		cli_print(cli, "	Remote IP:	%s", inet_toa(htonl(tunnel[t].ip)));
		cli_print(cli, "	Remote Port:	%d", tunnel[t].port);
		cli_print(cli, "	Rx Window:	%u", tunnel[t].window);
		cli_print(cli, "	Next Recv:	%u", tunnel[t].nr);
		cli_print(cli, "	Next Send:	%u", tunnel[t].ns);
		cli_print(cli, "	Queue Len:	%u", tunnel[t].controlc);
		cli_print(cli, "	Last Packet Age:%u", (unsigned)(time_now - tunnel[t].last));

		for (x = 0; x < MAXSESSION; x++)
			if (session[x].tunnel == t && session[x].opened && !session[x].die)
				sprintf(s, "%s%u ", s, x);
		cli_print(cli, "	Sessions:	%s", s);
	    }
	    return CLI_OK;
	}
    }

    // Show tunnel summary
    cli_print(cli, "%s %s %s %s %s",
	    "TID",
	    "Hostname",
	    "IP",
	    "State",
	    "Sessions");
    for (i = 1; i < MAXTUNNEL; i++)
    {
	int sessions = 0;
	if (!show_all && (!tunnel[i].ip || tunnel[i].die || !tunnel[i].hostname[0])) continue;

	for (x = 0; x < MAXSESSION; x++) if (session[x].tunnel == i && session[x].opened && !session[x].die) sessions++;
	cli_print(cli, "%d %s %s %s %d",
		i,
		*tunnel[i].hostname ? tunnel[i].hostname : "(null)",
		inet_toa(htonl(tunnel[i].ip)),
		states[tunnel[i].state],
		sessions);
    }
    return CLI_OK;
}

int cmd_show_users(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;
    for (i = 0; i < MAXSESSION; i++)
    {
	if (!session[i].opened) continue;
	if (!session[i].user[0]) continue;
	cli_print(cli, "%s",
		session[i].user);
    }
    return CLI_OK;
}

int cmd_show_counters(struct cli_def *cli, char *command, char **argv, int argc)
{
    cli_print(cli, "%-10s %-8s %-10s %-8s", "Ethernet", "Bytes", "Packets", "Errors");
    cli_print(cli, "%-10s %8lu %8lu %8lu", "RX",
	    GET_STAT(tap_rx_bytes),
	    GET_STAT(tap_rx_packets),
	    GET_STAT(tap_rx_errors));
    cli_print(cli, "%-10s %8lu %8lu %8lu", "TX",
	    GET_STAT(tap_tx_bytes),
	    GET_STAT(tap_tx_packets),
	    GET_STAT(tap_tx_errors));
    cli_print(cli, "");

    cli_print(cli, "%-10s %-8s %-10s %-8s %-8s", "Tunnel", "Bytes", "Packets", "Errors", "Retries");
    cli_print(cli, "%-10s %8lu %8lu %8lu %8lu", "RX",
	    GET_STAT(tunnel_rx_bytes),
	    GET_STAT(tunnel_rx_packets),
	    GET_STAT(tunnel_rx_errors),
	    0L);
    cli_print(cli, "%-10s %8lu %8lu %8lu %8lu", "TX",
	    GET_STAT(tunnel_tx_bytes),
	    GET_STAT(tunnel_tx_packets),
	    GET_STAT(tunnel_rx_errors),
	    GET_STAT(tunnel_retries));
    cli_print(cli, "");

    cli_print(cli, "%-30s%-10s", "Counter", "Value");
    cli_print(cli, "-----------------------------------------");
    cli_print(cli, "%-30s%lu", "radius_retries",	GET_STAT(radius_retries));
    cli_print(cli, "%-30s%lu", "arp_errors",		GET_STAT(arp_errors));
    cli_print(cli, "%-30s%lu", "arp_replies",		GET_STAT(arp_replies));
    cli_print(cli, "%-30s%lu", "arp_discarded",		GET_STAT(arp_discarded));
    cli_print(cli, "%-30s%lu", "arp_sent",		GET_STAT(arp_sent));
    cli_print(cli, "%-30s%lu", "arp_recv",		GET_STAT(arp_recv));
    cli_print(cli, "%-30s%lu", "packets_snooped",	GET_STAT(packets_snooped));
    cli_print(cli, "%-30s%lu", "tunnel_created",	GET_STAT(tunnel_created));
    cli_print(cli, "%-30s%lu", "session_created",	GET_STAT(session_created));
    cli_print(cli, "%-30s%lu", "tunnel_timeout",	GET_STAT(tunnel_timeout));
    cli_print(cli, "%-30s%lu", "session_timeout",	GET_STAT(session_timeout));
    cli_print(cli, "%-30s%lu", "radius_timeout",	GET_STAT(radius_timeout));
    cli_print(cli, "%-30s%lu", "radius_overflow",	GET_STAT(radius_overflow));
    cli_print(cli, "%-30s%lu", "tunnel_overflow",	GET_STAT(tunnel_overflow));
    cli_print(cli, "%-30s%lu", "session_overflow",	GET_STAT(session_overflow));
    cli_print(cli, "%-30s%lu", "ip_allocated",		GET_STAT(ip_allocated));
    cli_print(cli, "%-30s%lu", "ip_freed",		GET_STAT(ip_freed));

#ifdef STAT_CALLS
    cli_print(cli, "\n%-30s%-10s", "Counter", "Value");
    cli_print(cli, "-----------------------------------------");
    cli_print(cli, "%-30s%lu", "call_processtap",	GET_STAT(call_processtap));
    cli_print(cli, "%-30s%lu", "call_processarp",	GET_STAT(call_processarp));
    cli_print(cli, "%-30s%lu", "call_processipout",	GET_STAT(call_processipout));
    cli_print(cli, "%-30s%lu", "call_processudp",	GET_STAT(call_processudp));
    cli_print(cli, "%-30s%lu", "call_processpap",	GET_STAT(call_processpap));
    cli_print(cli, "%-30s%lu", "call_processchap",	GET_STAT(call_processchap));
    cli_print(cli, "%-30s%lu", "call_processlcp",	GET_STAT(call_processlcp));
    cli_print(cli, "%-30s%lu", "call_processipcp",	GET_STAT(call_processipcp));
    cli_print(cli, "%-30s%lu", "call_processipin",	GET_STAT(call_processipin));
    cli_print(cli, "%-30s%lu", "call_processccp",	GET_STAT(call_processccp));
    cli_print(cli, "%-30s%lu", "call_processrad",	GET_STAT(call_processrad));
    cli_print(cli, "%-30s%lu", "call_sendarp",		GET_STAT(call_sendarp));
    cli_print(cli, "%-30s%lu", "call_sendipcp",		GET_STAT(call_sendipcp));
    cli_print(cli, "%-30s%lu", "call_sendchap",		GET_STAT(call_sendchap));
    cli_print(cli, "%-30s%lu", "call_sessionbyip",	GET_STAT(call_sessionbyip));
    cli_print(cli, "%-30s%lu", "call_sessionbyuser",	GET_STAT(call_sessionbyuser));
    cli_print(cli, "%-30s%lu", "call_tunnelsend",	GET_STAT(call_tunnelsend));
    cli_print(cli, "%-30s%lu", "call_tunnelkill",	GET_STAT(call_tunnelkill));
    cli_print(cli, "%-30s%lu", "call_tunnelshutdown",	GET_STAT(call_tunnelshutdown));
    cli_print(cli, "%-30s%lu", "call_sessionkill",	GET_STAT(call_sessionkill));
    cli_print(cli, "%-30s%lu", "call_sessionshutdown",	GET_STAT(call_sessionshutdown));
    cli_print(cli, "%-30s%lu", "call_sessionsetup",	GET_STAT(call_sessionsetup));
    cli_print(cli, "%-30s%lu", "call_assign_ip_address",GET_STAT(call_assign_ip_address));
    cli_print(cli, "%-30s%lu", "call_free_ip_address",	GET_STAT(call_free_ip_address));
    cli_print(cli, "%-30s%lu", "call_dump_acct_info",	GET_STAT(call_dump_acct_info));
    cli_print(cli, "%-30s%lu", "call_radiussend",	GET_STAT(call_radiussend));
    cli_print(cli, "%-30s%lu", "call_radiusretry",	GET_STAT(call_radiusretry));
#endif
    return CLI_OK;
}

int cmd_show_version(struct cli_def *cli, char *command, char **argv, int argc)
{
    cli_print(cli, "L2TPNS %s", VERSION);
    cli_print(cli, "ID: %s", rcs_id);
    return CLI_OK;
}

int cmd_show_pool(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;
    int used = 0, free = 0, show_all = 0;
    time_t time_now;

    if (argc > 0 && strcmp(argv[0], "all") == 0)
	show_all = 1;

    time(&time_now);
    cli_print(cli, "%-15s %4s %8s %s", "IP Address", "Used", "Session", "User");
    for (i = 0; i < MAXIPPOOL; i++)
    {
	if (!ip_address_pool[i].address) continue;
	if (ip_address_pool[i].assigned)
	{
	    sessionidt s = sessionbyip(ip_address_pool[i].address);
	    cli_print(cli, "%-15s    Y %8d %s",
		inet_toa(ip_address_pool[i].address), s, session[s].user);

	    used++;
	}
	else
	{
	    if (ip_address_pool[i].last)
		cli_print(cli, "%-15s    N %8s [%s] %ds",
		    inet_toa(ip_address_pool[i].address), "",
		    ip_address_pool[i].user, time_now - ip_address_pool[i].last);
	    else if (show_all)
		cli_print(cli, "%-15s    N", inet_toa(ip_address_pool[i].address));

	    free++;
	}
    }

    if (!show_all)
	cli_print(cli, "(Not displaying unused addresses)");

    cli_print(cli, "\r\nFree: %d\r\nUsed: %d", free, used);
    return CLI_OK;
}

void print_save_config(struct cli_def *cli, char *string)
{
    if (save_config_fh)
	fprintf(save_config_fh, "%s\n", string);
}

int cmd_write_memory(struct cli_def *cli, char *command, char **argv, int argc)
{
    if ((save_config_fh = fopen(config->config_file, "w")))
    {
	cli_print(cli, "Writing configuration");
	cli_print_callback(cli, print_save_config);
	cmd_show_run(cli, command, argv, argc);
	cli_print_callback(cli, NULL);
	fclose(save_config_fh);
	sleep(1);
    }
    else
    {
	cli_print(cli, "Error writing configuration: %s", strerror(errno));
    }
    return CLI_OK;
}

int cmd_show_run(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;

    cli_print(cli, "# Current configuration:");

    for (i = 0; config_values[i].key; i++)
    {
	void *value = ((void *)config) + config_values[i].offset;
	if (config_values[i].type == STRING)
	    cli_print(cli, "set %s \"%.*s\"", config_values[i].key, config_values[i].size, (char *)value);
	else if (config_values[i].type == IP)
	    cli_print(cli, "set %s %s", config_values[i].key, inet_toa(*(unsigned *)value));
	else if (config_values[i].type == SHORT)
	    cli_print(cli, "set %s %hu", config_values[i].key, *(short *)value);
	else if (config_values[i].type == BOOL)
	    cli_print(cli, "set %s %s", config_values[i].key, (*(int *)value) ? "yes" : "no");
	else if (config_values[i].type == INT)
	    cli_print(cli, "set %s %d", config_values[i].key, *(int *)value);
	else if (config_values[i].type == UNSIGNED_LONG)
	    cli_print(cli, "set %s %lu", config_values[i].key, *(unsigned long *)value);
    }

    cli_print(cli, "# Plugins");
    for (i = 0; i < MAXPLUGINS; i++)
    {
	if (*config->plugins[i])
	{
	    cli_print(cli, "load plugin \"%s\"", config->plugins[i]);
	}
    }

    cli_print(cli, "# end");
    return CLI_OK;
}

int cmd_show_radius(struct cli_def *cli, char *command, char **argv, int argc)
{
    char *states[] = {
	"NULL",
	"CHAP",
	"AUTH",
	"IPCP",
	"START",
	"STOP",
	"WAIT",
    };
    int i, free = 0, used = 0, show_all = 0;
    time_t time_now;

    cli_print(cli, "%6s%6s%9s%9s%4s", "Radius", "State", "Session", "Retry", "Try");

    time(&time_now);

    if (argc > 0 && strcmp(argv[0], "all") == 0)
	show_all = 1;

    for (i = 1; i < MAXRADIUS; i++)
    {
	if (radius[i].state == RADIUSNULL)
	    free++;
	else
	    used++;

	if (!show_all && radius[i].state == RADIUSNULL) continue;

	cli_print(cli, "%6d%6s%9d%9u%4d",
		i,
		states[radius[i].state],
		radius[i].session,
		radius[i].retry,
		radius[i].try);
    }

    cli_print(cli, "\r\nFree: %d\r\nUsed: %d", free, used);

    return CLI_OK;
}

int cmd_show_plugins(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;
    cli_print(cli, "Plugins currently loaded:");
    for (i = 0; i < MAXPLUGINS; i++)
    {
	if (*config->plugins[i])
	{
	    cli_print(cli, "  %s", config->plugins[i]);
	}
    }
    return CLI_OK;
}

int cmd_show_banana(struct cli_def *cli, char *command, char **argv, int argc)
{
    cli_print(cli, " _\n"
		      "//\\\n"
		      "V  \\\n"
		      " \\  \\_\n"
		      "  \\,'.`-.\n"
		      "   |\\ `. `.\n"
		      "   ( \\  `. `-.                        _,.-:\\\n"
		      "    \\ \\   `.  `-._             __..--' ,-';/\n"
		      "     \\ `.   `-.   `-..___..---'   _.--' ,'/\n"
		      "      `. `.    `-._        __..--'    ,' /\n"
		      "        `. `-_     ``--..''       _.-' ,'\n"
		      "          `-_ `-.___        __,--'   ,'\n"
		      "             `-.__  `----\"\"\"    __.-'\n"
		      "hh                `--..____..--'");

    return CLI_OK;
}

int cmd_clear_counters(struct cli_def *cli, char *command, char **argv, int argc)
{
    cli_print(cli, "Counters cleared");
    SET_STAT(last_reset, time(NULL));
    return CLI_OK;
}

int cmd_drop_user(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;
    sessionidt s;

    if (!argc)
    {
	cli_print(cli, "Specify a user to drop");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    cli_print(cli, "username ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	if (!(s = sessionbyuser(argv[i])))
	{
	    cli_print(cli, "User %s is not connected", argv[i]);
	    continue;
	}

	if (session[s].ip && session[s].opened && !session[s].die)
	{
	    int x;

	    cli_print(cli, "Dropping user %s", session[s].user);
	    for (x = 0; x < MAXSESSION; x++)
	    {
		if (!cli_session_kill[x])
		{
		    cli_session_kill[x] = s;
		    break;
		}
	    }
	}
    }

    return CLI_OK;
}

int cmd_drop_tunnel(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;
    tunnelidt tid;

    if (!argc)
    {
	cli_print(cli, "Specify a tunnel to drop");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    cli_print(cli, "tunnel_id ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	int x;

	if ((tid = atol(argv[i])) <= 0 || (tid > MAXTUNNEL))
	{
	    cli_print(cli, "Invalid tunnel ID (%d - %d)", 0, MAXTUNNEL);
	    continue;
	}

	if (!tunnel[tid].ip)
	{
	    cli_print(cli, "Tunnel %d is not connected", tid);
	    continue;
	}

	if (tunnel[tid].die)
	{
	    cli_print(cli, "Tunnel %d is already being shut down", tid);
	    continue;
	}

	for (x = 0; x < MAXTUNNEL; x++)
	{
	    if (!cli_tunnel_kill[x])
	    {
		cli_tunnel_kill[x] = tid;
		cli_print(cli, "Tunnel %d shut down (%s)", tid, tunnel[tid].hostname);
		break;
	    }
	}
    }

    return CLI_OK;
}

int cmd_drop_session(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;
    sessionidt s;

    if (!argc)
    {
	cli_print(cli, "Specify a session id to drop");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    cli_print(cli, "session_id ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	if ((s = atol(argv[i])) <= 0 || (s > MAXSESSION))
	{
	    cli_print(cli, "Invalid session ID (%d - %d)", 0, MAXSESSION);
	    continue;
	}

	if (session[s].opened && !session[s].die)
	{
	    int x;
	    for (x = 0; x < MAXSESSION; x++)
	    {
		if (!cli_session_kill[x])
		{
		    cli_session_kill[x] = s;
		    break;
		}
	    }
	    cli_print(cli, "Dropping session %d", s);
	}
	else
	{
	    cli_print(cli, "Session %d is not active.", s);
	}
    }

    return CLI_OK;
}

int cmd_snoop(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;
    sessionidt s;

    if (!argc)
    {
	cli_print(cli, "Specify a user");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    cli_print(cli, "username ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	if (!(s = sessionbyuser(argv[i])))
	{
	    cli_print(cli, "User %s is not connected", argv[i]);
	    continue;
	}
	session[s].snoop = 1;

	cli_print(cli, "Snooping user %s", argv[i]);
    }
    return CLI_OK;
}

int cmd_no_snoop(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;
    sessionidt s;

    if (!argc)
    {
	cli_print(cli, "Specify a user");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    cli_print(cli, "username ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	if (!(s = sessionbyuser(argv[i])))
	{
	    cli_print(cli, "User %s is not connected", argv[i]);
	    continue;
	}
	session[s].snoop = 0;

	cli_print(cli, "Not snooping user %s", argv[i]);
    }
    return CLI_OK;
}

int cmd_throttle(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;
    sessionidt s;

    if (!argc)
    {
	cli_print(cli, "Specify a user");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    cli_print(cli, "username ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	if (!(s = sessionbyuser(argv[i])))
	{
	    cli_print(cli, "User %s is not connected", argv[i]);
	    continue;
	}
	throttle_session(s, 1);

	cli_print(cli, "throttling user %s", argv[i]);
    }
    return CLI_OK;
}

int cmd_no_throttle(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;
    sessionidt s;

    if (!argc)
    {
	cli_print(cli, "Specify a user");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    cli_print(cli, "username ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
	{
	if (!(s = sessionbyuser(argv[i])))
	{
	    cli_print(cli, "User %s is not connected", argv[i]);
	    continue;
	}
	throttle_session(s, 0);

	cli_print(cli, "unthrottling user %s", argv[i]);
    }
    return CLI_OK;
}

int cmd_debug(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;

    if (!argc)
    {
	cli_print(cli, "Currently debugging: ");
	if (debug_flags.critical) cli_print(cli, "critical ");
	if (debug_flags.error) cli_print(cli, "error ");
	if (debug_flags.warning) cli_print(cli, "warning ");
	if (debug_flags.info) cli_print(cli, "info ");
	if (debug_flags.calls) cli_print(cli, "calls ");
	if (debug_flags.data) cli_print(cli, "data ");
	cli_print(cli, "");
	return CLI_OK;
    }

    for (i = 0; i < argc; i++)
    {
	if (*argv[i] == '?')
	{
	    cli_print(cli, "Possible debugging states are:");
	    cli_print(cli, "	critical");
	    cli_print(cli, "	error");
	    cli_print(cli, "	warning");
	    cli_print(cli, "	info");
	    cli_print(cli, "	calls");
	    cli_print(cli, "	data");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	if (strcasecmp(argv[i], "critical") == 0) debug_flags.critical = 1;
	if (strcasecmp(argv[i], "error") == 0) debug_flags.error = 1;
	if (strcasecmp(argv[i], "warning") == 0) debug_flags.warning = 1;
	if (strcasecmp(argv[i], "info") == 0) debug_flags.info = 1;
	if (strcasecmp(argv[i], "calls") == 0) debug_flags.calls = 1;
	if (strcasecmp(argv[i], "data") == 0) debug_flags.data = 1;
	if (strcasecmp(argv[i], "all") == 0)
	{
	    memset(&debug_flags, 1, sizeof(debug_flags));
	    debug_flags.data = 0;
	}
    }

    return CLI_OK;
}

int cmd_no_debug(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;

    for (i = 0; i < argc; i++)
    {
	if (strcasecmp(argv[i], "critical") == 0) debug_flags.critical = 0;
	if (strcasecmp(argv[i], "error") == 0) debug_flags.error = 0;
	if (strcasecmp(argv[i], "warning") == 0) debug_flags.warning = 0;
	if (strcasecmp(argv[i], "info") == 0) debug_flags.info = 0;
	if (strcasecmp(argv[i], "calls") == 0) debug_flags.calls = 0;
	if (strcasecmp(argv[i], "data") == 0) debug_flags.data = 0;
	if (strcasecmp(argv[i], "all") == 0) memset(&debug_flags, 0, sizeof(debug_flags));
    }

    return CLI_OK;
}

int cmd_watch_session(struct cli_def *cli, char *command, char **argv, int argc)
{
    sessionidt s;

    if (argc != 1)
    {
	cli_print(cli, "Specify a single session to debug (0 to disable)");
	return CLI_OK;
    }
    s = atoi(argv[0]);

    if (debug_session)
	cli_print(cli, "No longer debugging session %d", debug_session);

    if (s) cli_print(cli, "Debugging session %d.", s);
    debug_session = s;

    return CLI_OK;
}

int cmd_watch_tunnel(struct cli_def *cli, char *command, char **argv, int argc)
{
    tunnelidt s;

    if (argc != 1)
    {
	cli_print(cli, "Specify a single tunnel to debug (0 to disable)");
	return CLI_OK;
    }
    s = atoi(argv[0]);

    if (debug_tunnel)
	cli_print(cli, "No longer debugging tunnel %d", debug_tunnel);

    if (s) cli_print(cli, "Debugging tunnel %d.", s);
    debug_tunnel = s;

    return CLI_OK;
}

int cmd_load_plugin(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i, firstfree = 0;
    if (argc != 1)
    {
	cli_print(cli, "Specify a plugin to load");
	return CLI_OK;
    }

    for (i = 0; i < MAXPLUGINS; i++)
    {
	if (!*config->plugins[i] && !firstfree)
	    firstfree = i;
	if (strcmp(config->plugins[i], argv[0]) == 0)
	{
	    cli_print(cli, "Plugin is already loaded");
	    return CLI_OK;
	}
    }

    if (firstfree)
    {
	strncpy(config->plugins[firstfree], argv[0], sizeof(config->plugins[firstfree]) - 1);
	config->reload_config = 1;
	cli_print(cli, "Loading plugin %s", argv[0]);
    }

    return CLI_OK;
}

int cmd_remove_plugin(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;

    if (argc != 1)
    {
	cli_print(cli, "Specify a plugin to remove");
	return CLI_OK;
    }

    for (i = 0; i < MAXPLUGINS; i++)
    {
	if (strcmp(config->plugins[i], argv[0]) == 0)
	{
	    config->reload_config = 1;
	    memset(config->plugins[i], 0, sizeof(config->plugins[i]));
	    return CLI_OK;
	}
    }

    cli_print(cli, "Plugin is not loaded");
    return CLI_OK;
}

char *duration(time_t seconds)
{
    static char *buf = NULL;
    if (!buf) buf = calloc(64, 1);

    if (seconds > 86400)
	sprintf(buf, "%d days", (int)(seconds / 86400.0));
    else if (seconds > 60)
	sprintf(buf, "%02d:%02lu", (int)(seconds / 3600.0), seconds % 60);
    else
	sprintf(buf, "%lu sec", seconds);
    return buf;
}

int cmd_uptime(struct cli_def *cli, char *command, char **argv, int argc)
{
    FILE *fh;
    char buf[100], *p = buf, *loads[3];
    int i, num_sessions = 0;
    time_t time_now;

    fh = fopen("/proc/loadavg", "r");
    fgets(buf, 100, fh);
    fclose(fh);

    for (i = 0; i < 3; i++)
	loads[i] = strdup(strsep(&p, " "));

    time(&time_now);
    strftime(buf, 99, "%H:%M:%S", localtime(&time_now));

    for (i = 1; i < MAXSESSION; i++)
	if (session[i].opened) num_sessions++;

    cli_print(cli, "%s up %s, %d users, load average: %s, %s, %s",
	    buf,
	    duration(abs(time_now - config->start_time)),
	    num_sessions,
	    loads[0], loads[1], loads[2]
    );
    for (i = 0; i < 3; i++)
	if (loads[i]) free(loads[i]);

    cli_print(cli, "Bandwidth: %s", config->bandwidth);

    return CLI_OK;
}

int cmd_set(struct cli_def *cli, char *command, char **argv, int argc)
{
    int i;

    if (argc != 2)
    {
	cli_print(cli, "Usage: set <variable> <value>");
	return CLI_OK;
    }

    for (i = 0; config_values[i].key; i++)
    {
	void *value = ((void *)config) + config_values[i].offset;
	if (strcmp(config_values[i].key, argv[0]) == 0)
	{
	    // Found a value to set
	    cli_print(cli, "Setting \"%s\" to \"%s\"", argv[0], argv[1]);
	    switch (config_values[i].type)
	    {
		case STRING:
		    strncpy((char *)value, argv[1], config_values[i].size - 1);
		    break;
		case INT:
		    *(int *)value = atoi(argv[1]);
		    break;
		case UNSIGNED_LONG:
		    *(unsigned long *)value = atol(argv[1]);
		    break;
		case SHORT:
		    *(short *)value = atoi(argv[1]);
		    break;
		case IP:
		    *(unsigned *)value = inet_addr(argv[1]);
		    break;
		case BOOL:
		    if (strcasecmp(argv[1], "yes") == 0 || strcasecmp(argv[1], "true") == 0 || strcasecmp(argv[1], "1") == 0)
			*(int *)value = 1;
		    else
			*(int *)value = 0;
		    break;
		default:
		    cli_print(cli, "Unknown variable type");
		    break;
	    }
	    config->reload_config = 1;
	    return CLI_OK;
	}
    }

    cli_print(cli, "Unknown variable \"%s\"", argv[0]);
    return CLI_OK;
}

int regular_stuff(struct cli_def *cli)
{
    int i = debug_rb_tail;
    int reprompt = 0;

#ifdef RINGBUFFER
    while (i != ringbuffer->tail)
    {
	int show_message = 0;

	if (*ringbuffer->buffer[i].message)
	{
	    // Always show messages if we are doing general debug
	    if (ringbuffer->buffer[i].level == 0 && debug_flags.critical) show_message = 1;
	    if (ringbuffer->buffer[i].level == 1 && debug_flags.error) show_message = 1;
	    if (ringbuffer->buffer[i].level == 2 && debug_flags.warning) show_message = 1;
	    if (ringbuffer->buffer[i].level == 3 && debug_flags.info) show_message = 1;
	    if (ringbuffer->buffer[i].level == 4 && debug_flags.calls) show_message = 1;
	    if (ringbuffer->buffer[i].level == 5 && debug_flags.data) show_message = 1;
	}

	if (show_message)
	{
	    ipt address = ntohl(ringbuffer->buffer[i].address);
	    char *ipaddr;
	    struct in_addr addr;

	    memcpy(&addr, &address, sizeof(ringbuffer->buffer[i].address));
	    ipaddr = inet_ntoa(addr);

	    cli_print(cli, "\r%s-%s-%u-%u %s",
		    debug_levels[(int)ringbuffer->buffer[i].level],
		    ipaddr,
		    ringbuffer->buffer[i].tunnel,
		    ringbuffer->buffer[i].session,
		    ringbuffer->buffer[i].message);

	    reprompt = 1;
	}

	if (++i == ringbuffer->tail) break;
	if (i == RINGBUFFER_SIZE) i = 0;
    }

    debug_rb_tail = ringbuffer->tail;
    if (reprompt)
	cli_reprompt(cli);
#endif
    return CLI_OK;
}
