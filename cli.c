// L2TPNS Command Line Interface
// vim: sw=4 ts=8

char const *cvs_name = "$Name:  $";
char const *cvs_id_cli = "$Id: cli.c,v 1.11 2004-08-13 00:02:50 fred_nerk Exp $";

#include <stdio.h>
#include <stdarg.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <syslog.h>
#include <malloc.h>
#include <sched.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>
#include <libcli.h>
#include "l2tpns.h"
#include "util.h"
#include "cluster.h"
#include "tbf.h"
#include "ll.h"
#ifdef BGP
#include "bgp.h"
#endif

extern tunnelt *tunnel;
extern sessiont *session;
extern radiust *radius;
extern ippoolt *ip_address_pool;
extern struct Tstats *_statistics;
struct cli_def *cli = NULL;
int cli_quit = 0;
extern int clifd, udpfd, tunfd, snoopfd, ifrfd, cluster_sockfd;
extern int *radfds;
extern struct configt *config;
extern struct config_descriptt config_values[];
#ifdef RINGBUFFER
extern struct Tringbuffer *ringbuffer;
#endif
extern struct cli_session_actions *cli_session_actions;
extern struct cli_tunnel_actions *cli_tunnel_actions;

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
int cmd_show_throttle(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_show_cluster(struct cli_def *cli, char *command, char **argv, int argc);
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
int cmd_set(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_load_plugin(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_remove_plugin(struct cli_def *cli, char *command, char **argv, int argc);
int cmd_uptime(struct cli_def *cli, char *command, char **argv, int argc);
int regular_stuff(struct cli_def *cli);

void init_cli(char *hostname)
{
	FILE *f;
	char buf[4096];
	struct cli_command *c;
	struct cli_command *c2;
	int on = 1;
	struct sockaddr_in addr;

	cli = cli_init();
	if (hostname && *hostname)
			cli_set_hostname(cli, hostname);
	else
			cli_set_hostname(cli, "l2tpns");

	c = cli_register_command(cli, NULL, "show", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "banana", cmd_show_banana, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show a banana");
#ifdef BGP
	cli_register_command(cli, c, "bgp", cmd_show_bgp, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show BGP status");
#endif /* BGP */
	cli_register_command(cli, c, "cluster", cmd_show_cluster, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show cluster information");
	cli_register_command(cli, c, "ipcache", cmd_show_ipcache, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show contents of the IP cache");
	cli_register_command(cli, c, "plugins", cmd_show_plugins, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "List all installed plugins");
	cli_register_command(cli, c, "pool", cmd_show_pool, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show the IP address allocation pool");
	cli_register_command(cli, c, "radius", cmd_show_radius, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show active radius queries");
	cli_register_command(cli, c, "running-config", cmd_show_run, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show the currently running configuration");
	cli_register_command(cli, c, "session", cmd_show_session, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show a list of sessions or details for a single session");
	cli_register_command(cli, c, "tbf", cmd_show_tbf, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "List all token bucket filters in use");
	cli_register_command(cli, c, "throttle", cmd_show_throttle, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "List all throttled sessions and associated TBFs");
	cli_register_command(cli, c, "tunnels", cmd_show_tunnels, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show a list of tunnels or details for a single tunnel");
	cli_register_command(cli, c, "users", cmd_show_users, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show a list of all connected users or details of selected user");
	cli_register_command(cli, c, "version", cmd_show_version, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show currently running software version");

	c2 = cli_register_command(cli, c, "histogram", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c2, "idle", cmd_show_hist_idle, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show histogram of session idle times");
	cli_register_command(cli, c2, "open", cmd_show_hist_open, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show histogram of session durations");

#ifdef STATISTICS
	cli_register_command(cli, c, "counters", cmd_show_counters, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Display all the internal counters and running totals");

	c = cli_register_command(cli, NULL, "clear", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "counters", cmd_clear_counters, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Clear internal counters");
#endif

	cli_register_command(cli, NULL, "uptime", cmd_uptime, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show uptime and bandwidth utilisation");

	c = cli_register_command(cli, NULL, "write", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "memory", cmd_write_memory, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Save the running config to flash");
	cli_register_command(cli, c, "terminal", cmd_show_run, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show the running config");

	cli_register_command(cli, NULL, "snoop", cmd_snoop, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Temporarily enable interception for a user");
	cli_register_command(cli, NULL, "throttle", cmd_throttle, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Temporarily enable throttling for a user");
	cli_register_command(cli, NULL, "debug", cmd_debug, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Set the level of logging that is shown on the console");

	c = cli_register_command(cli, NULL, "suspend", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "bgp", cmd_suspend_bgp, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Withdraw routes from BGP peer");

	c = cli_register_command(cli, NULL, "no", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "snoop", cmd_no_snoop, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Temporarily disable interception for a user");
	cli_register_command(cli, c, "throttle", cmd_no_throttle, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Temporarily disable throttling for a user");
	cli_register_command(cli, c, "debug", cmd_no_debug, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Turn off logging of a certain level of debugging");
	c2 = cli_register_command(cli, c, "suspend", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c2, "bgp", cmd_no_suspend_bgp, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Advertise routes to BGP peer");

	c = cli_register_command(cli, NULL, "drop", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "user", cmd_drop_user, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Disconnect a user");
	cli_register_command(cli, c, "tunnel", cmd_drop_tunnel, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Disconnect a tunnel and all sessions on that tunnel");
	cli_register_command(cli, c, "session", cmd_drop_session, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Disconnect a session");

	c = cli_register_command(cli, NULL, "restart", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "bgp", cmd_restart_bgp, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Restart BGP");

	c = cli_register_command(cli, NULL, "load", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, NULL);
	cli_register_command(cli, c, "plugin", cmd_load_plugin, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Load a plugin");

	c = cli_register_command(cli, NULL, "remove", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, NULL);
	cli_register_command(cli, c, "plugin", cmd_remove_plugin, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Remove a plugin");

	cli_register_command(cli, NULL, "set", cmd_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Set a configuration variable");

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
			if (!strcmp(buf, "enable"))
			{
				cli_allow_enable(cli, p);
				log(3, 0, 0, 0, "Setting enable password\n");
			}
			else
			{
				cli_allow_user(cli, buf, p);
				log(3, 0, 0, 0, "Allowing user %s to connect to the CLI\n", buf);
			}
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
	int i;

	if (fork()) return;
	if (config->scheduler_fifo)
	{
		int ret;
		struct sched_param params = {0};
		params.sched_priority = 0;
		if ((ret = sched_setscheduler(0, SCHED_OTHER, &params)) == 0)
		{
			log(3, 0, 0, 0, "Dropped FIFO scheduler\n");
		}
		else
		{
			log(0, 0, 0, 0, "Error setting scheduler to OTHER: %s\n", strerror(errno));
			log(0, 0, 0, 0, "This is probably really really bad.\n");
		}
	}

	signal(SIGPIPE, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
	signal(SIGUSR1, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	signal(SIGKILL, SIG_DFL);
	signal(SIGALRM, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	// Close sockets
	if (udpfd) close(udpfd); udpfd = 0;
	if (tunfd) close(tunfd); tunfd = 0;
	if (snoopfd) close(snoopfd); snoopfd = 0;
	for (i = 0; i < config->num_radfds; i++)
		if (radfds[i]) close(radfds[i]);
	if (ifrfd) close(ifrfd); ifrfd = 0;
	if (cluster_sockfd) close(cluster_sockfd); cluster_sockfd = 0;
	if (clifd) close(clifd); clifd = 0;
#ifdef BGP
	for (i = 0; i < BGP_NUM_PEERS; i++)
		if (bgp_peers[i].sock != -1)
			close(bgp_peers[i].sock);
#endif /* BGP */

	{
		int require_auth = 1;
		struct sockaddr_in addr;
		int l = sizeof(addr);
		if (getpeername(sockfd, (struct sockaddr *)&addr, &l) == 0)
		{
			log(3, 0, 0, 0, "Accepted connection to CLI from %s\n", inet_toa(addr.sin_addr.s_addr));
			require_auth = addr.sin_addr.s_addr != inet_addr("127.0.0.1");
		}
		else
			log(0, 0, 0, 0, "getpeername() failed on cli socket. Requiring authentication: %s\n", strerror(errno));

		if (require_auth)
		{
			log(3, 0, 0, 0, "CLI is remote, requiring authentication\n");
			if (!cli->users) /* paranoia */
			{
				log(0, 0, 0, 0, "No users for remote authentication!  Exiting CLI\n");
				exit(0);
			}
		}
		else
		{
			/* no username/pass required */
			cli->users = 0;
		}
	}

	debug_session = 0;
	debug_tunnel = 0;
#ifdef RINGBUFFER
	debug_rb_tail = ringbuffer->tail;
#endif
	memset(&debug_flags, 0, sizeof(debug_flags));
	debug_flags.critical = 1;

	cli_loop(cli, sockfd);

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
	cli_file(cli, fh, PRIVILEGE_PRIVILEGED, MODE_CONFIG);
	cli_print_callback(cli, NULL);
}

int cli_arg_help(struct cli_def *cli, int cr_ok, char *entry, ...)
{
	va_list ap;
	char *desc;
	char buf[16];
	char *p;

	va_start(ap, entry);
	while (entry)
	{
		/* allow one %d */
		if ((p = strchr(entry, '%')) && !strchr(p+1, '%') && p[1] == 'd')
		{
			int v = va_arg(ap, int);
			snprintf(buf, sizeof(buf), entry, v);
			p = buf;
		}
		else
			p = entry;

		desc = va_arg(ap, char *);
		if (desc && *desc)
			cli_print(cli, "  %-20s %s", p, desc);
		else
			cli_print(cli, "  %s", p);

		entry = desc ? va_arg(ap, char *) : 0;
	}

	va_end(ap);
	if (cr_ok)
			cli_print(cli, "  <cr>");

	return CLI_OK;
}

int cmd_show_session(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, 1,
			"<1-%d>", MAXSESSION-1, "Show specific session by id",
			NULL);

	time(&time_now);
	if (argc > 0)
	{
		// Show individual session
		for (i = 0; i < argc; i++)
		{
			unsigned int s;
			s = atoi(argv[i]);
			if (s <= 0 || s >= MAXSESSION)
			{
				cli_print(cli, "Invalid session id \"%s\"", argv[i]);
				continue;
			}
			cli_print(cli, "\r\nSession %d:", s);
			cli_print(cli, "		User:				%s", session[s].user[0] ? session[s].user : "none");
			cli_print(cli, "		Calling Num:		%s", session[s].calling);
			cli_print(cli, "		Called Num:		%s", session[s].called);
			cli_print(cli, "		Tunnel ID:		%d", session[s].tunnel);
			cli_print(cli, "		IP address:		%s", inet_toa(htonl(session[s].ip)));
			cli_print(cli, "		HSD sid:		%lu", session[s].sid);
			cli_print(cli, "		Idle time:		%u seconds", abs(time_now - session[s].last_packet));
			cli_print(cli, "		Next Recv:		%u", session[s].nr);
			cli_print(cli, "		Next Send:		%u", session[s].ns);
			cli_print(cli, "		Bytes In/Out:		%lu/%lu", (unsigned long)session[s].total_cout, (unsigned long)session[s].total_cin);
			cli_print(cli, "		Pkts In/Out:		%lu/%lu", (unsigned long)session[s].pout, (unsigned long)session[s].pin);
			cli_print(cli, "		MRU:				%d", session[s].mru);
			cli_print(cli, "		Radius Session:		%u", session[s].radius);
			cli_print(cli, "		Rx Speed:		%lu", session[s].rx_connect_speed);
			cli_print(cli, "		Tx Speed:		%lu", session[s].tx_connect_speed);
			if (session[s].snoop_ip && session[s].snoop_port)
				cli_print(cli, "		Intercepted:	%s:%d", inet_toa(session[s].snoop_ip), session[s] .snoop_port);
			else
				cli_print(cli, "		Intercepted:	no");
			cli_print(cli, "		Throttled:		%s", session[s].throttle ? "YES" : "no");
			cli_print(cli, "		Walled Garden:		%s", session[s].walled_garden ? "YES" : "no");
			cli_print(cli, "		Filter BucketI:		%d", session[s].tbf_in);
			cli_print(cli, "		Filter BucketO:		%d", session[s].tbf_out);
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
			"G",
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
				(session[i].snoop_ip && session[i].snoop_port) ? "Y" : "N",
				(session[i].throttle) ? "Y" : "N",
				(session[i].walled_garden) ? "Y" : "N",
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
	char *states[] = {
		"Free",
		"Open",
		"Closing",
		"Opening",
	};

	if (CLI_HELP_REQUESTED)
	{
		if (argc > 1)
			return cli_arg_help(cli, 1,
				"<1-%d>", MAXTUNNEL-1, "Show specific tunnel by id",
				NULL);

		return cli_arg_help(cli, 1,
			"all", "Show all tunnels, including unused",
			"<1-%d>", MAXTUNNEL-1, "Show specific tunnel by id",
			NULL);
	}

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
				if (t <= 0 || t >= MAXTUNNEL)
				{
					cli_print(cli, "Invalid tunnel id \"%s\"", argv[i]);
					continue;
				}
				cli_print(cli, "\r\nTunnel %d:", t);
				cli_print(cli, "		State:				%s", states[tunnel[t].state]);
				cli_print(cli, "		Hostname:		%s", tunnel[t].hostname[0] ? tunnel[t].hostname : "(none)");
				cli_print(cli, "		Remote IP:		%s", inet_toa(htonl(tunnel[t].ip)));
				cli_print(cli, "		Remote Port:		%d", tunnel[t].port);
				cli_print(cli, "		Rx Window:		%u", tunnel[t].window);
				cli_print(cli, "		Next Recv:		%u", tunnel[t].nr);
				cli_print(cli, "		Next Send:		%u", tunnel[t].ns);
				cli_print(cli, "		Queue Len:		%u", tunnel[t].controlc);
				cli_print(cli, "		Last Packet Age:%u", (unsigned)(time_now - tunnel[t].last));

				for (x = 0; x < MAXSESSION; x++)
						if (session[x].tunnel == t && session[x].opened && !session[x].die)
								sprintf(s, "%s%u ", s, x);
				cli_print(cli, "		Sessions:		%s", s);
			}
			return CLI_OK;
		}
	}

	// Show tunnel summary
	cli_print(cli, "%4s %20s %20s %6s %s",
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
		cli_print(cli, "%4d %20s %20s %6s %6d",
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
	char sid[32][8];
	char *sargv[32];
	int sargc = 0;
	int i;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, 1,
			"USER", "Show details for specific username",
			NULL);

	for (i = 0; i < MAXSESSION; i++)
	{
		if (!session[i].opened) continue;
		if (!session[i].user[0]) continue;
		if (argc > 0)
		{
			int j;
			for (j = 0; j < argc && sargc < 32; j++)
			{
				if (strcmp(argv[j], session[i].user) == 0)
				{
					snprintf(sid[sargc], sizeof(sid[0]), "%d", i);
					sargv[sargc] = sid[sargc];
					sargc++;
				}
			}

			continue;
		}

		cli_print(cli, "%s", session[i].user);
	}

	if (sargc > 0)
			return cmd_show_session(cli, "users", sargv, sargc);

	return CLI_OK;
}

int cmd_show_counters(struct cli_def *cli, char *command, char **argv, int argc)
{
	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_print(cli, "%-10s %-8s %-10s %-8s", "Ethernet", "Bytes", "Packets", "Errors");
	cli_print(cli, "%-10s %8lu %8lu %8lu", "RX",
			GET_STAT(tun_rx_bytes),
			GET_STAT(tun_rx_packets),
			GET_STAT(tun_rx_errors));
	cli_print(cli, "%-10s %8lu %8lu %8lu", "TX",
			GET_STAT(tun_tx_bytes),
			GET_STAT(tun_tx_packets),
			GET_STAT(tun_tx_errors));
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
			GET_STAT(tunnel_tx_errors),
			GET_STAT(tunnel_retries));
	cli_print(cli, "");

	cli_print(cli, "%-30s%-10s", "Counter", "Value");
	cli_print(cli, "-----------------------------------------");
	cli_print(cli, "%-30s%lu", "radius_retries",		GET_STAT(radius_retries));
	cli_print(cli, "%-30s%lu", "arp_sent",				GET_STAT(arp_sent));
	cli_print(cli, "%-30s%lu", "packets_snooped",		GET_STAT(packets_snooped));
	cli_print(cli, "%-30s%lu", "tunnel_created",		GET_STAT(tunnel_created));
	cli_print(cli, "%-30s%lu", "session_created",		GET_STAT(session_created));
	cli_print(cli, "%-30s%lu", "tunnel_timeout",		GET_STAT(tunnel_timeout));
	cli_print(cli, "%-30s%lu", "session_timeout",		GET_STAT(session_timeout));
	cli_print(cli, "%-30s%lu", "radius_timeout",		GET_STAT(radius_timeout));
	cli_print(cli, "%-30s%lu", "radius_overflow",		GET_STAT(radius_overflow));
	cli_print(cli, "%-30s%lu", "tunnel_overflow",		GET_STAT(tunnel_overflow));
	cli_print(cli, "%-30s%lu", "session_overflow",		GET_STAT(session_overflow));
	cli_print(cli, "%-30s%lu", "ip_allocated",				GET_STAT(ip_allocated));
	cli_print(cli, "%-30s%lu", "ip_freed",				GET_STAT(ip_freed));
	cli_print(cli, "%-30s%lu", "cluster_forwarded",		GET_STAT(c_forwarded));
	cli_print(cli, "%-30s%lu", "recv_forward",				GET_STAT(recv_forward));


#ifdef STATISTICS
	cli_print(cli, "\n%-30s%-10s", "Counter", "Value");
	cli_print(cli, "-----------------------------------------");
	cli_print(cli, "%-30s%lu", "call_processtun",		GET_STAT(call_processtun));
	cli_print(cli, "%-30s%lu", "call_processipout",		GET_STAT(call_processipout));
	cli_print(cli, "%-30s%lu", "call_processudp",		GET_STAT(call_processudp));
	cli_print(cli, "%-30s%lu", "call_processpap",		GET_STAT(call_processpap));
	cli_print(cli, "%-30s%lu", "call_processchap",		GET_STAT(call_processchap));
	cli_print(cli, "%-30s%lu", "call_processlcp",		GET_STAT(call_processlcp));
	cli_print(cli, "%-30s%lu", "call_processipcp",		GET_STAT(call_processipcp));
	cli_print(cli, "%-30s%lu", "call_processipin",		GET_STAT(call_processipin));
	cli_print(cli, "%-30s%lu", "call_processccp",		GET_STAT(call_processccp));
	cli_print(cli, "%-30s%lu", "call_processrad",		GET_STAT(call_processrad));
	cli_print(cli, "%-30s%lu", "call_sendarp",				GET_STAT(call_sendarp));
	cli_print(cli, "%-30s%lu", "call_sendipcp",				GET_STAT(call_sendipcp));
	cli_print(cli, "%-30s%lu", "call_sendchap",				GET_STAT(call_sendchap));
	cli_print(cli, "%-30s%lu", "call_sessionbyip",		GET_STAT(call_sessionbyip));
	cli_print(cli, "%-30s%lu", "call_sessionbyuser",		GET_STAT(call_sessionbyuser));
	cli_print(cli, "%-30s%lu", "call_tunnelsend",		GET_STAT(call_tunnelsend));
	cli_print(cli, "%-30s%lu", "call_tunnelkill",		GET_STAT(call_tunnelkill));
	cli_print(cli, "%-30s%lu", "call_tunnelshutdown",		GET_STAT(call_tunnelshutdown));
	cli_print(cli, "%-30s%lu", "call_sessionkill",		GET_STAT(call_sessionkill));
	cli_print(cli, "%-30s%lu", "call_sessionshutdown",		GET_STAT(call_sessionshutdown));
	cli_print(cli, "%-30s%lu", "call_sessionsetup",		GET_STAT(call_sessionsetup));
	cli_print(cli, "%-30s%lu", "call_assign_ip_address",GET_STAT(call_assign_ip_address));
	cli_print(cli, "%-30s%lu", "call_free_ip_address",		GET_STAT(call_free_ip_address));
	cli_print(cli, "%-30s%lu", "call_dump_acct_info",		GET_STAT(call_dump_acct_info));
	cli_print(cli, "%-30s%lu", "call_radiussend",		GET_STAT(call_radiussend));
	cli_print(cli, "%-30s%lu", "call_radiusretry",		GET_STAT(call_radiusretry));
#endif
	return CLI_OK;
}

int cmd_show_version(struct cli_def *cli, char *command, char **argv, int argc)
{
	int tag = 0;
	int file = 0;
	int i = 0;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, 1,
			"tag", "Include CVS release tag",
			"file", "Include file versions",
			NULL);

	for (i = 0; i < argc; i++)
		if (!strcmp(argv[i], "tag"))
			tag++;
		else if (!strcmp(argv[i], "file"))
			file++;

	cli_print(cli, "L2TPNS %s", VERSION);
	if (tag)
	{
		char const *p = strchr(cvs_name, ':');
		char const *e;
		if (p)
		{
			p++;
			while (isspace(*p))
				p++;
		}

		if (!p || *p == '$')
			p = "HEAD";

		e = strpbrk(p, " \t$");
		cli_print(cli, "Tag: %.*s", e ? e - p + 1 : strlen(p), p);
	}
	
	if (file)
	{
		extern linked_list *loaded_plugins;
		void *p;

		cli_print(cli, "Files:");
		cli_print(cli, "  %s", cvs_id_arp);
#ifdef BGP
		cli_print(cli, "  %s", cvs_id_bgp);
#endif /* BGP */
		cli_print(cli, "  %s", cvs_id_cli);
		cli_print(cli, "  %s", cvs_id_cluster);
		cli_print(cli, "  %s", cvs_id_constants);
		cli_print(cli, "  %s", cvs_id_control);
		cli_print(cli, "  %s", cvs_id_icmp);
		cli_print(cli, "  %s", cvs_id_l2tpns);
		cli_print(cli, "  %s", cvs_id_ll);
		cli_print(cli, "  %s", cvs_id_md5);
		cli_print(cli, "  %s", cvs_id_ppp);
		cli_print(cli, "  %s", cvs_id_radius);
		cli_print(cli, "  %s", cvs_id_tbf);
		cli_print(cli, "  %s", cvs_id_util);

		ll_reset(loaded_plugins);
		while ((p = ll_next(loaded_plugins)))
		{
			char const **id = dlsym(p, "cvs_id");
			if (id)
				cli_print(cli, "  %s", *id);
		}
	}

	return CLI_OK;
}

int cmd_show_pool(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	int used = 0, free = 0, show_all = 0;

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s", inet_toa(config->cluster_master_address));
		return CLI_OK;
	}

	if (CLI_HELP_REQUESTED)
	{
		if (argc > 1)
			return cli_arg_help(cli, 1, NULL);

		return cli_arg_help(cli, 1,
			"all", "Show all pool addresses, including unused",
			NULL);
	}

	if (argc > 0 && strcmp(argv[0], "all") == 0)
		show_all = 1;

	time(&time_now);
	cli_print(cli, "%-15s %4s %8s %s", "IP Address", "Used", "Session", "User");
	for (i = 0; i < MAXIPPOOL; i++)
	{
		if (!ip_address_pool[i].address) continue;
		if (ip_address_pool[i].assigned)
		{
			cli_print(cli, "%-15s	Y %8d %s",
				inet_toa(htonl(ip_address_pool[i].address)), ip_address_pool[i].session, session[ip_address_pool[i].session].user);

			used++;
		}
		else
		{
			if (ip_address_pool[i].last)
				cli_print(cli, "%-15s	N %8s [%s] %ds",
					inet_toa(htonl(ip_address_pool[i].address)), "",
					ip_address_pool[i].user, time_now - ip_address_pool[i].last);
			else if (show_all)
				cli_print(cli, "%-15s	N", inet_toa(htonl(ip_address_pool[i].address)));

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
	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	if ((save_config_fh = fopen(config->config_file, "w")))
	{
		cli_print(cli, "Writing configuration");
		cli_print_callback(cli, print_save_config);
		cmd_show_run(cli, command, argv, argc);
		cli_print_callback(cli, NULL);
		fclose(save_config_fh);
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

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

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
	int i, free = 0, used = 0, show_all = 0;
	char *states[] = {
		"NULL",
		"CHAP",
		"AUTH",
		"IPCP",
		"START",
		"STOP",
		"WAIT",
	};

	if (CLI_HELP_REQUESTED)
	{
		if (argc > 1)
			return cli_arg_help(cli, 1, NULL);

		return cli_arg_help(cli, 1,
			"all", "Show all RADIUS sessions, including unused",
			NULL);
	}

	cli_print(cli, "%6s%5s%6s%9s%9s%4s", "Radius", "Sock", "State", "Session", "Retry", "Try");

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

		cli_print(cli, "%6d%5d%6s%9d%9u%4d",
				i >> RADIUS_SHIFT,
				i & RADIUS_MASK,
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

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

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

int cmd_show_throttle(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_print(cli, "Token bucket filters:");
	cli_print(cli, "%-6s %8s %-4s", "ID", "Handle", "Used");
	for (i = 0; i < MAXSESSION; i++)
	{
		if (!session[i].throttle)
			continue;

		cli_print(cli, "%-6d %8d %8d",
			i,
			session[i].tbf_in,
			session[i].tbf_out);
	}
	return CLI_OK;
}

int cmd_show_banana(struct cli_def *cli, char *command, char **argv, int argc)
{
	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_print(cli, " _\n"
					  "//\\\n"
					  "V  \\\n"
					  " \\  \\_\n"
					  "  \\,'.`-.\n"
					  "   |\\ `. `.\n"
					  "   ( \\  `. `-.						_,.-:\\\n"
					  "	\\ \\   `.  `-._			 __..--' ,-';/\n"
					  "	 \\ `.   `-.   `-..___..---'   _.--' ,'/\n"
					  "	  `. `.	`-._		__..--'	,' /\n"
					  "		`. `-_	 ``--..''	   _.-' ,'\n"
					  "		  `-_ `-.___		__,--'   ,'\n"
					  "			 `-.__  `----\"\"\"	__.-'\n"
					  "hh				`--..____..--'");

	return CLI_OK;
}

int cmd_clear_counters(struct cli_def *cli, char *command, char **argv, int argc)
{
	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_print(cli, "Counters cleared");
	SET_STAT(last_reset, time(NULL));
	return CLI_OK;
}

int cmd_drop_user(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	sessionidt s;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1,
			"USER", "Username of session to drop", NULL);

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s", inet_toa(config->cluster_master_address));
		return CLI_OK;
	}

	if (!argc)
	{
		cli_print(cli, "Specify a user to drop");
		return CLI_OK;
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
			cli_print(cli, "Dropping user %s", session[s].user);
			cli_session_actions[s].action |= CLI_SESS_KILL;
		}
	}

	return CLI_OK;
}

int cmd_drop_tunnel(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	tunnelidt t;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1,
			"<1-%d>", MAXTUNNEL-1, "Tunnel id to drop", NULL);

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s", inet_toa(config->cluster_master_address));
		return CLI_OK;
	}

	if (!argc)
	{
		cli_print(cli, "Specify a tunnel to drop");
		return CLI_OK;
	}

	for (i = 0; i < argc; i++)
	{
		if ((t = atol(argv[i])) <= 0 || (t >= MAXTUNNEL))
		{
			cli_print(cli, "Invalid tunnel ID (1-%d)", MAXTUNNEL-1);
			continue;
		}

		if (!tunnel[t].ip)
		{
			cli_print(cli, "Tunnel %d is not connected", t);
			continue;
		}

		if (tunnel[t].die)
		{
			cli_print(cli, "Tunnel %d is already being shut down", t);
			continue;
		}

		cli_print(cli, "Tunnel %d shut down (%s)", t, tunnel[t].hostname);
		cli_tunnel_actions[t].action |= CLI_TUN_KILL;
	}

	return CLI_OK;
}

int cmd_drop_session(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	sessionidt s;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1,
			"<1-%d>", MAXSESSION-1, "Session id to drop", NULL);

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s", inet_toa(config->cluster_master_address));
		return CLI_OK;
	}

	if (!argc)
	{
		cli_print(cli, "Specify a session id to drop");
		return CLI_OK;
	}

	for (i = 0; i < argc; i++)
	{
		if ((s = atol(argv[i])) <= 0 || (s > MAXSESSION))
		{
			cli_print(cli, "Invalid session ID (1-%d)", MAXSESSION-1);
			continue;
		}

		if (session[s].ip && session[s].opened && !session[s].die)
		{
			cli_print(cli, "Dropping session %d", s);
			cli_session_actions[s].action |= CLI_SESS_KILL;
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
	ipt ip;
	u16 port;
	sessionidt s;

	if (CLI_HELP_REQUESTED)
	{
		switch (argc)
		{
		case 1:
			return cli_arg_help(cli, 0,
				"USER", "Username of session to snoop", NULL);

		case 2:
			return cli_arg_help(cli, 0,
				"A.B.C.D", "IP address of snoop destination", NULL);

		case 3:
			return cli_arg_help(cli, 0,
				"N", "Port of snoop destination", NULL);

		case 4:
			if (!argv[3][1])
				return cli_arg_help(cli, 1, NULL);

		default:
			return CLI_OK;
		}
	}

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s", inet_toa(config->cluster_master_address));
		return CLI_OK;
	}

	if (argc < 3)
	{
		cli_print(cli, "Specify username ip port");
		return CLI_OK;
	}

	if (!(s = sessionbyuser(argv[0])))
	{
		cli_print(cli, "User %s is not connected", argv[0]);
		return CLI_OK;
	}

	ip = inet_addr(argv[1]);
	if (!ip || ip == INADDR_NONE)
	{
		cli_print(cli, "Cannot parse IP \"%s\"", argv[1]);
		return CLI_OK;
	}

	port = atoi(argv[2]);
	if (!port)
	{
		cli_print(cli, "Invalid port %s", argv[2]);
		return CLI_OK;
	}

	cli_print(cli, "Snooping user %s to %s:%d", argv[0], inet_toa(session[s].snoop_ip), session[s].snoop_port);
	cli_session_actions[s].snoop_ip = ip;
	cli_session_actions[s].snoop_port = port;
	cli_session_actions[s].action |= CLI_SESS_SNOOP;

	return CLI_OK;
}

int cmd_no_snoop(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	sessionidt s;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1,
			"USER", "Username of session to un-snoop", NULL);

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s", inet_toa(config->cluster_master_address));
		return CLI_OK;
	}

	if (!argc)
	{
		cli_print(cli, "Specify a user");
		return CLI_OK;
	}

	for (i = 0; i < argc; i++)
	{
		if (!(s = sessionbyuser(argv[i])))
		{
			cli_print(cli, "User %s is not connected", argv[i]);
			continue;
		}

		cli_print(cli, "Not snooping user %s", argv[i]);
		cli_session_actions[s].action |= CLI_SESS_NOSNOOP;
	}
	return CLI_OK;
}

int cmd_throttle(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	sessionidt s;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1,
			"USER", "Username of session to throttle", NULL);

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s", inet_toa(config->cluster_master_address));
		return CLI_OK;
	}

	if (!argc)
	{
		cli_print(cli, "Specify a user");
		return CLI_OK;
	}

	for (i = 0; i < argc; i++)
	{
		if (!(s = sessionbyuser(argv[i])))
		{
			cli_print(cli, "User %s is not connected", argv[i]);
			continue;
		}

		if (session[s].throttle)
		{
			cli_print(cli, "User %s already throttled", argv[i]);
			continue;
		}

		cli_print(cli, "Throttling user %s", argv[i]);
		cli_session_actions[s].throttle = config->rl_rate; // could be configurable at some stage
		cli_session_actions[s].action |= CLI_SESS_THROTTLE;
	}

	return CLI_OK;
}

int cmd_no_throttle(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	sessionidt s;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1,
			"USER", "Username of session to un-throttle", NULL);

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s", inet_toa(config->cluster_master_address));
		return CLI_OK;
	}

	if (!argc)
	{
		cli_print(cli, "Specify a user");
		return CLI_OK;
	}

	for (i = 0; i < argc; i++)
	{
		if (!(s = sessionbyuser(argv[i])))
		{
			cli_print(cli, "User %s is not connected", argv[i]);
			continue;
		}

		if (!session[s].throttle)
		{
			cli_print(cli, "User %s not throttled", argv[i]);
			continue;
		}

		cli_print(cli, "Unthrottling user %s", argv[i]);
		cli_session_actions[s].action |= CLI_SESS_NOTHROTTLE;
	}

	return CLI_OK;
}

int cmd_debug(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, 1,
			"all",	  "Enable debugging for all except \"data\"",
			"critical", "", // FIXME: add descriptions
			"error",	"",
			"warning",  "",
			"info",	 "",
			"calls",	"",
			"data",	 "",
			NULL);

	if (!argc)
	{
		char *p = (char *) &debug_flags;
		for (i = 0; i < sizeof(debug_flags); i++)
		{
			if (p[i])
			{
				cli_print(cli, "Currently debugging:%s%s%s%s%s%s",
					(debug_flags.critical) ? " critical" : "",
					(debug_flags.error)	? " error"	: "",
					(debug_flags.warning)  ? " warning"  : "",
					(debug_flags.info)	 ? " info"	 : "",
					(debug_flags.calls)	? " calls"	: "",
					(debug_flags.data)	 ? " data"	 : "");

				return CLI_OK;
			}
		}

		cli_print(cli, "Debugging off");
		return CLI_OK;
	}

	for (i = 0; i < argc; i++)
	{
		int len = strlen(argv[i]);

		if (argv[i][0] == 'c' && len < 2)
			len = 2; /* distinguish [cr]itical from [ca]lls */

		if (!strncasecmp(argv[i], "critical", len)) { debug_flags.critical = 1; continue; }
		if (!strncasecmp(argv[i], "error",	len)) { debug_flags.error = 1;	continue; }
		if (!strncasecmp(argv[i], "warning",  len)) { debug_flags.warning = 1;  continue; }
		if (!strncasecmp(argv[i], "info",	 len)) { debug_flags.info = 1;	 continue; }
		if (!strncasecmp(argv[i], "calls",	len)) { debug_flags.calls = 1;	continue; }
		if (!strncasecmp(argv[i], "data",	 len)) { debug_flags.data = 1;	 continue; }
		if (!strncasecmp(argv[i], "all",	  len))
		{
			memset(&debug_flags, 1, sizeof(debug_flags));
			debug_flags.data = 0;
			continue;
		}

		cli_print(cli, "Invalid debugging flag \"%s\"", argv[i]);
	}

	return CLI_OK;
}

int cmd_no_debug(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, 1,
			"all",	  "Disable all debugging",
			"critical", "", // FIXME: add descriptions
			"error",	"",
			"warning",  "",
			"info",	 "",
			"calls",	"",
			"data",	 "",
			NULL);

	if (!argc)
	{
			memset(&debug_flags, 0, sizeof(debug_flags));
		return CLI_OK;
	}

	for (i = 0; i < argc; i++)
	{
		int len = strlen(argv[i]);

		if (argv[i][0] == 'c' && len < 2)
			len = 2; /* distinguish [cr]itical from [ca]lls */

		if (!strncasecmp(argv[i], "critical", len)) { debug_flags.critical = 0; continue; }
		if (!strncasecmp(argv[i], "error",	len)) { debug_flags.error = 0;	continue; }
		if (!strncasecmp(argv[i], "warning",  len)) { debug_flags.warning = 0;  continue; }
		if (!strncasecmp(argv[i], "info",	 len)) { debug_flags.info = 0;	 continue; }
		if (!strncasecmp(argv[i], "calls",	len)) { debug_flags.calls = 0;	continue; }
		if (!strncasecmp(argv[i], "data",	 len)) { debug_flags.data = 0;	 continue; }
		if (!strncasecmp(argv[i], "all",	  len))
		{
			memset(&debug_flags, 0, sizeof(debug_flags));
			continue;
		}

		cli_print(cli, "Invalid debugging flag \"%s\"", argv[i]);
	}

	return CLI_OK;
}

int cmd_load_plugin(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i, firstfree = 0;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1,
			"PLUGIN", "Name of plugin to load", NULL);

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

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1,
			"PLUGIN", "Name of plugin to unload", NULL);

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

char *duration(time_t secs)
{
	static char *buf = NULL;
	int p = 0;

	if (!buf) buf = calloc(64, 1);

	if (secs >= 86400)
	{
		int days = secs / 86400;
		p = sprintf(buf, "%d day%s, ", days, days > 1 ? "s" : "");
		secs %= 86400;
	}

	if (secs >= 3600)
	{
		int mins = secs / 60;
		int hrs = mins / 60;

		mins %= 60;
		sprintf(buf + p, "%d:%02d", hrs, mins);
	}
	else if (secs >= 60)
	{
		int mins = secs / 60;
		sprintf(buf + p, "%d min%s", mins, mins > 1 ? "s" : "");
	}
	else
		sprintf(buf, "%ld sec%s", secs, secs > 1 ? "s" : "");

	return buf;
}

int cmd_uptime(struct cli_def *cli, char *command, char **argv, int argc)
{
	FILE *fh;
	char buf[100], *p = buf, *loads[3];
	int i, num_sessions = 0;

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

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
			duration(time_now - config->start_time),
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

	if (CLI_HELP_REQUESTED)
	{
		switch (argc)
		{
		case 1:
			{
				int len = strlen(argv[0])-1;
				for (i = 0; config_values[i].key; i++)
					if (!len || !strncmp(argv[0], config_values[i].key, len))
						cli_print(cli, "  %s", config_values[i].key);
			}

			return CLI_OK;

		case 2:
			return cli_arg_help(cli, 0,
				"VALUE", "Value for variable", NULL);

		case 3:
			if (!argv[2][1])
					return cli_arg_help(cli, 1, NULL);

		default:
			return CLI_OK;
		}
	}

	if (argc != 2)
	{
		cli_print(cli, "Specify variable and value");
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
			ipt address = htonl(ringbuffer->buffer[i].address);
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
