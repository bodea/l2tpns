// L2TPNS Command Line Interface
// vim: sw=8 ts=8

char const *cvs_name = "$Name:  $";
char const *cvs_id_cli = "$Id: cli.c,v 1.26 2004-11-11 05:38:01 bodea Exp $";

#include <stdio.h>
#include <stdarg.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <syslog.h>
#include <malloc.h>
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
#include <netdb.h>
#endif

extern tunnelt *tunnel;
extern sessiont *session;
extern radiust *radius;
extern ippoolt *ip_address_pool;
extern struct Tstats *_statistics;
struct cli_def *cli = NULL;
int cli_quit = 0;
extern struct configt *config;
extern struct config_descriptt config_values[];
#ifdef RINGBUFFER
extern struct Tringbuffer *ringbuffer;
#endif
extern struct cli_session_actions *cli_session_actions;
extern struct cli_tunnel_actions *cli_tunnel_actions;
extern tbft *filter_list;

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

static int cmd_show_session(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_show_tunnels(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_show_users(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_show_radius(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_show_counters(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_show_version(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_show_pool(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_show_run(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_show_banana(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_show_plugins(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_show_throttle(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_write_memory(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_clear_counters(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_drop_user(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_drop_tunnel(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_drop_session(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_snoop(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_no_snoop(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_throttle(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_no_throttle(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_debug(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_no_debug(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_set(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_load_plugin(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_remove_plugin(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_uptime(struct cli_def *cli, char *command, char **argv, int argc);
static int regular_stuff(struct cli_def *cli);
static void parsemac(char *string, char mac[6]);

#ifdef BGP
#define MODE_CONFIG_BGP 8
static int cmd_router_bgp(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_router_bgp_neighbour(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_router_bgp_no_neighbour(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_show_bgp(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_suspend_bgp(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_no_suspend_bgp(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_restart_bgp(struct cli_def *cli, char *command, char **argv, int argc);
#endif /* BGP */

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

#ifdef BGP
	c = cli_register_command(cli, NULL, "suspend", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "bgp", cmd_suspend_bgp, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Withdraw routes from BGP neighbour");
#endif /* BGP */

	c = cli_register_command(cli, NULL, "no", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "snoop", cmd_no_snoop, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Temporarily disable interception for a user");
	cli_register_command(cli, c, "throttle", cmd_no_throttle, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Temporarily disable throttling for a user");
	cli_register_command(cli, c, "debug", cmd_no_debug, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Turn off logging of a certain level of debugging");

#ifdef BGP
	c2 = cli_register_command(cli, c, "suspend", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c2, "bgp", cmd_no_suspend_bgp, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Advertise routes to BGP neighbour");

	c = cli_register_command(cli, NULL, "restart", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "bgp", cmd_restart_bgp, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Restart BGP");

	c = cli_register_command(cli, NULL, "router", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, NULL);
	cli_register_command(cli, c, "bgp", cmd_router_bgp, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure BGP");

	cli_register_command(cli, NULL, "neighbour", cmd_router_bgp_neighbour, PRIVILEGE_PRIVILEGED, MODE_CONFIG_BGP, "Configure BGP neighbour");

	c = cli_register_command(cli, NULL, "no", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG_BGP, NULL);
	cli_register_command(cli, c, "neighbour", cmd_router_bgp_no_neighbour, PRIVILEGE_PRIVILEGED, MODE_CONFIG_BGP, "Remove BGP neighbour");
#endif /* BGP */

	c = cli_register_command(cli, NULL, "drop", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "user", cmd_drop_user, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Disconnect a user");
	cli_register_command(cli, c, "tunnel", cmd_drop_tunnel, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Disconnect a tunnel and all sessions on that tunnel");
	cli_register_command(cli, c, "session", cmd_drop_session, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Disconnect a session");

	c = cli_register_command(cli, NULL, "load", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, NULL);
	cli_register_command(cli, c, "plugin", cmd_load_plugin, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Load a plugin");

	c = cli_register_command(cli, NULL, "remove", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, NULL);
	cli_register_command(cli, c, "plugin", cmd_remove_plugin, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Remove a plugin");

	cli_register_command(cli, NULL, "set", cmd_set, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Set a configuration variable");

	// Enable regular processing
	cli_regular(cli, regular_stuff);

	if (!(f = fopen(CLIUSERS, "r")))
	{
		LOG(0, 0, 0, 0, "WARNING! No users specified. Command-line access is open to all\n");
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
				LOG(3, 0, 0, 0, "Setting enable password\n");
			}
			else
			{
				cli_allow_user(cli, buf, p);
				LOG(3, 0, 0, 0, "Allowing user %s to connect to the CLI\n", buf);
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
		LOG(0, 0, 0, 0, "Error listening on cli port 23: %s\n", strerror(errno));
		return;
	}
	listen(clifd, 10);
}

void cli_do(int sockfd)
{
	int require_auth = 1;
	struct sockaddr_in addr;
	int l = sizeof(addr);

	if (fork_and_close()) return;
	if (getpeername(sockfd, (struct sockaddr *)&addr, &l) == 0)
	{
		LOG(3, 0, 0, 0, "Accepted connection to CLI from %s\n", inet_toa(addr.sin_addr.s_addr));
		require_auth = addr.sin_addr.s_addr != inet_addr("127.0.0.1");
	}
	else
		LOG(0, 0, 0, 0, "getpeername() failed on cli socket. Requiring authentication: %s\n", strerror(errno));

	if (require_auth)
	{
		LOG(3, 0, 0, 0, "CLI is remote, requiring authentication\n");
		if (!cli->users) /* paranoia */
		{
			LOG(0, 0, 0, 0, "No users for remote authentication!  Exiting CLI\n");
			exit(0);
		}
	}
	else
	{
		/* no username/pass required */
		cli->users = 0;
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
	LOG(3, 0, 0, 0, "Closed CLI connection from %s\n", inet_toa(addr.sin_addr.s_addr));
	exit(0);
}

void cli_print_log(struct cli_def *cli, char *string)
{
	LOG(3, 0, 0, 0, "%s\n", string);
}

void cli_do_file(FILE *fh)
{
	LOG(3, 0, 0, 0, "Reading configuration file\n");
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

static int cmd_show_session(struct cli_def *cli, char *command, char **argv, int argc)
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
			unsigned int s, b_in, b_out;
			s = atoi(argv[i]);
			if (s <= 0 || s >= MAXSESSION)
			{
				cli_print(cli, "Invalid session id \"%s\"", argv[i]);
				continue;
			}
			cli_print(cli, "\r\nSession %d:", s);
			cli_print(cli, "\tUser:\t\t%s", session[s].user[0] ? session[s].user : "none");
			cli_print(cli, "\tCalling Num:\t%s", session[s].calling);
			cli_print(cli, "\tCalled Num:\t%s", session[s].called);
			cli_print(cli, "\tTunnel ID:\t%d", session[s].tunnel);
			cli_print(cli, "\tIP address:\t%s", inet_toa(htonl(session[s].ip)));
			cli_print(cli, "\tUnique SID:\t%lu", session[s].unique_id);
			cli_print(cli, "\tIdle time:\t%u seconds", abs(time_now - session[s].last_packet));
			cli_print(cli, "\tNext Recv:\t%u", session[s].nr);
			cli_print(cli, "\tNext Send:\t%u", session[s].ns);
			cli_print(cli, "\tBytes In/Out:\t%lu/%lu", (unsigned long)session[s].total_cout, (unsigned long)session[s].total_cin);
			cli_print(cli, "\tPkts In/Out:\t%lu/%lu", (unsigned long)session[s].pout, (unsigned long)session[s].pin);
			cli_print(cli, "\tMRU:\t\t%d", session[s].mru);
			cli_print(cli, "\tRadius Session:\t%u", session[s].radius);
			cli_print(cli, "\tRx Speed:\t%lu", session[s].rx_connect_speed);
			cli_print(cli, "\tTx Speed:\t%lu", session[s].tx_connect_speed);
			if (session[s].snoop_ip && session[s].snoop_port)
				cli_print(cli, "\tIntercepted:\t%s:%d", inet_toa(session[s].snoop_ip), session[s] .snoop_port);
			else
				cli_print(cli, "\tIntercepted:\tno");

			cli_print(cli, "\tWalled Garden:\t%s", session[s].walled_garden ? "YES" : "no");
			{
				int t = (session[s].throttle_in || session[s].throttle_out);
				cli_print(cli, "\tThrottled:\t%s%s%.0d%s%s%.0d%s%s",
					t ? "YES" : "no", t ? " (" : "",
					session[s].throttle_in, session[s].throttle_in ? "kbps" : t ? "-" : "",
					t ? "/" : "",
					session[s].throttle_out, session[s].throttle_out ? "kbps" : t ? "-" : "",
					t ? ")" : "");
			}

			b_in = session[s].tbf_in;
			b_out = session[s].tbf_out;
			if (b_in || b_out)
				cli_print(cli, "\t\t\t%5s %6s %6s | %7s %7s %8s %8s %8s %8s",
					"Rate", "Credit", "Queued", "ByteIn", "PackIn",
					"ByteSent", "PackSent", "PackDrop", "PackDelay");

			if (b_in)
				cli_print(cli, "\tTBFI#%d%1s%s\t%5d %6d %6d | %7d %7d %8d %8d %8d %8d",
					b_in,
					(filter_list[b_in].next ? "*" : " "),
					(b_in < 100 ? "\t" : ""),
					filter_list[b_in].rate * 8,
					filter_list[b_in].credit,
					filter_list[b_in].queued,
					filter_list[b_in].b_queued,
					filter_list[b_in].p_queued,
					filter_list[b_in].b_sent,
					filter_list[b_in].p_sent,
					filter_list[b_in].p_dropped,
					filter_list[b_in].p_delayed);

			if (b_out)
				cli_print(cli, "\tTBFO#%d%1s%s\t%5d %6d %6d | %7d %7d %8d %8d %8d %8d",
					b_out,
					(filter_list[b_out].next ? "*" : " "),
					(b_out < 100 ? "\t" : ""),
					filter_list[b_out].rate * 8,
					filter_list[b_out].credit,
					filter_list[b_out].queued,
					filter_list[b_out].b_queued,
					filter_list[b_out].p_queued,
					filter_list[b_out].b_sent,
					filter_list[b_out].p_sent,
					filter_list[b_out].p_dropped,
					filter_list[b_out].p_delayed);

		}
		return CLI_OK;
	}

	// Show Summary
	cli_print(cli, "%5s %4s %-32s %-15s %s %s %s %10s %10s %10s %4s %-15s %s",
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
				(session[i].throttle_in || session[i].throttle_out) ? "Y" : "N",
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

static int cmd_show_tunnels(struct cli_def *cli, char *command, char **argv, int argc)
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
				cli_print(cli, "\tState:\t\t%s", states[tunnel[t].state]);
				cli_print(cli, "\tHostname:\t%s", tunnel[t].hostname[0] ? tunnel[t].hostname : "(none)");
				cli_print(cli, "\tRemote IP:\t%s", inet_toa(htonl(tunnel[t].ip)));
				cli_print(cli, "\tRemote Port:\t%d", tunnel[t].port);
				cli_print(cli, "\tRx Window:\t%u", tunnel[t].window);
				cli_print(cli, "\tNext Recv:\t%u", tunnel[t].nr);
				cli_print(cli, "\tNext Send:\t%u", tunnel[t].ns);
				cli_print(cli, "\tQueue Len:\t%u", tunnel[t].controlc);
				cli_print(cli, "\tLast Packet Age:%u", (unsigned)(time_now - tunnel[t].last));

				for (x = 0; x < MAXSESSION; x++)
					if (session[x].tunnel == t && session[x].opened && !session[x].die)
						sprintf(s, "%s%u ", s, x);

				cli_print(cli, "\tSessions:\t%s", s);
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
		if (!show_all && (!tunnel[i].ip || tunnel[i].die)) continue;

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

static int cmd_show_users(struct cli_def *cli, char *command, char **argv, int argc)
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

static int cmd_show_counters(struct cli_def *cli, char *command, char **argv, int argc)
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
	cli_print(cli, "%-30s%lu", "arp_sent",			GET_STAT(arp_sent));
	cli_print(cli, "%-30s%lu", "packets_snooped",		GET_STAT(packets_snooped));
	cli_print(cli, "%-30s%lu", "tunnel_created",		GET_STAT(tunnel_created));
	cli_print(cli, "%-30s%lu", "session_created",		GET_STAT(session_created));
	cli_print(cli, "%-30s%lu", "tunnel_timeout",		GET_STAT(tunnel_timeout));
	cli_print(cli, "%-30s%lu", "session_timeout",		GET_STAT(session_timeout));
	cli_print(cli, "%-30s%lu", "radius_timeout",		GET_STAT(radius_timeout));
	cli_print(cli, "%-30s%lu", "radius_overflow",		GET_STAT(radius_overflow));
	cli_print(cli, "%-30s%lu", "tunnel_overflow",		GET_STAT(tunnel_overflow));
	cli_print(cli, "%-30s%lu", "session_overflow",		GET_STAT(session_overflow));
	cli_print(cli, "%-30s%lu", "ip_allocated",		GET_STAT(ip_allocated));
	cli_print(cli, "%-30s%lu", "ip_freed",			GET_STAT(ip_freed));
	cli_print(cli, "%-30s%lu", "cluster_forwarded",		GET_STAT(c_forwarded));
	cli_print(cli, "%-30s%lu", "recv_forward",		GET_STAT(recv_forward));


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
	cli_print(cli, "%-30s%lu", "call_sendarp",		GET_STAT(call_sendarp));
	cli_print(cli, "%-30s%lu", "call_sendipcp",		GET_STAT(call_sendipcp));
	cli_print(cli, "%-30s%lu", "call_sendchap",		GET_STAT(call_sendchap));
	cli_print(cli, "%-30s%lu", "call_sessionbyip",		GET_STAT(call_sessionbyip));
	cli_print(cli, "%-30s%lu", "call_sessionbyuser",	GET_STAT(call_sessionbyuser));
	cli_print(cli, "%-30s%lu", "call_tunnelsend",		GET_STAT(call_tunnelsend));
	cli_print(cli, "%-30s%lu", "call_tunnelkill",		GET_STAT(call_tunnelkill));
	cli_print(cli, "%-30s%lu", "call_tunnelshutdown",	GET_STAT(call_tunnelshutdown));
	cli_print(cli, "%-30s%lu", "call_sessionkill",		GET_STAT(call_sessionkill));
	cli_print(cli, "%-30s%lu", "call_sessionshutdown",	GET_STAT(call_sessionshutdown));
	cli_print(cli, "%-30s%lu", "call_sessionsetup",		GET_STAT(call_sessionsetup));
	cli_print(cli, "%-30s%lu", "call_assign_ip_address",	GET_STAT(call_assign_ip_address));
	cli_print(cli, "%-30s%lu", "call_free_ip_address",	GET_STAT(call_free_ip_address));
	cli_print(cli, "%-30s%lu", "call_dump_acct_info",	GET_STAT(call_dump_acct_info));
	cli_print(cli, "%-30s%lu", "call_radiussend",		GET_STAT(call_radiussend));
	cli_print(cli, "%-30s%lu", "call_radiusretry",		GET_STAT(call_radiusretry));
#endif
	return CLI_OK;
}

static int cmd_show_version(struct cli_def *cli, char *command, char **argv, int argc)
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

static int cmd_show_pool(struct cli_def *cli, char *command, char **argv, int argc)
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
			cli_print(cli, "%-15s\tY %8d %s",
				inet_toa(htonl(ip_address_pool[i].address)), ip_address_pool[i].session, session[ip_address_pool[i].session].user);

			used++;
		}
		else
		{
			if (ip_address_pool[i].last)
				cli_print(cli, "%-15s\tN %8s [%s] %ds",
					inet_toa(htonl(ip_address_pool[i].address)), "",
					ip_address_pool[i].user, time_now - ip_address_pool[i].last);
			else if (show_all)
				cli_print(cli, "%-15s\tN", inet_toa(htonl(ip_address_pool[i].address)));

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

static int cmd_write_memory(struct cli_def *cli, char *command, char **argv, int argc)
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

static int cmd_show_run(struct cli_def *cli, char *command, char **argv, int argc)
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
		else if (config_values[i].type == MAC)
			cli_print(cli, "set %s %02x%02x.%02x%02x.%02x%02x", config_values[i].key,
					*(unsigned short *)(value + 0),
					*(unsigned short *)(value + 1),
					*(unsigned short *)(value + 2),
					*(unsigned short *)(value + 3),
					*(unsigned short *)(value + 4),
					*(unsigned short *)(value + 5));
	}

	cli_print(cli, "# Plugins");
	for (i = 0; i < MAXPLUGINS; i++)
	{
		if (*config->plugins[i])
		{
			cli_print(cli, "load plugin \"%s\"", config->plugins[i]);
		}
	}

#ifdef BGP
	if (config->as_number)
	{
	    	int k;
		int h;

	    	cli_print(cli, "# BGP");
		cli_print(cli, "router bgp %u", config->as_number);
		for (i = 0; i < BGP_NUM_PEERS; i++)
		{
			if (!config->neighbour[i].name[0])
				continue;

		    	cli_print(cli, " neighbour %s remote-as %u", config->neighbour[i].name, config->neighbour[i].as);

			k = config->neighbour[i].keepalive;
			h = config->neighbour[i].hold;

			if (k == -1)
			{
				if (h == -1)
					continue;

				k = BGP_KEEPALIVE_TIME;
			}

			if (h == -1)
				h = BGP_HOLD_TIME;

			cli_print(cli, " neighbour %s timers %d %d", config->neighbour[i].name, k, h);
		}
	}
#endif

	cli_print(cli, "# end");
	return CLI_OK;
}

static int cmd_show_radius(struct cli_def *cli, char *command, char **argv, int argc)
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

	cli_print(cli, "%6s%6s%5s%6s%9s%9s%4s", "ID", "Radius", "Sock", "State", "Session", "Retry", "Try");

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

		cli_print(cli, "%6d%6d%5d%6s%9d%9u%4d",
				i,
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

static int cmd_show_plugins(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_print(cli, "Plugins currently loaded:");
	for (i = 0; i < MAXPLUGINS; i++)
		if (*config->plugins[i])
			cli_print(cli, "  %s", config->plugins[i]);

	return CLI_OK;
}

static int cmd_show_throttle(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_print(cli, "%5s %4s %-32s %7s %6s %6s %6s",
			"SID",
			"TID",
			"Username",
			"Rate In",
			"Out",
			"TBFI",
			"TBFO");

	for (i = 0; i < MAXSESSION; i++)
	{
		if (session[i].throttle_in || session[i].throttle_out)
			cli_print(cli, "%5d %4d %-32s  %6d %6d %6d %6d",
				i,
				session[i].tunnel,
				session[i].user,
				session[i].throttle_in,
				session[i].throttle_out,
				session[i].tbf_in,
				session[i].tbf_out);
	}

	return CLI_OK;
}

static int cmd_show_banana(struct cli_def *cli, char *command, char **argv, int argc)
{
	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_print(cli,	" _\n"
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

static int cmd_clear_counters(struct cli_def *cli, char *command, char **argv, int argc)
{
	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_print(cli, "Counters cleared");
	SET_STAT(last_reset, time(NULL));
	return CLI_OK;
}

static int cmd_drop_user(struct cli_def *cli, char *command, char **argv, int argc)
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

static int cmd_drop_tunnel(struct cli_def *cli, char *command, char **argv, int argc)
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

static int cmd_drop_session(struct cli_def *cli, char *command, char **argv, int argc)
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

static int cmd_snoop(struct cli_def *cli, char *command, char **argv, int argc)
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
		cli_print(cli, "Specify username, ip and port");
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

	cli_print(cli, "Snooping user %s to %s:%d", argv[0], inet_toa(ip), port);
	cli_session_actions[s].snoop_ip = ip;
	cli_session_actions[s].snoop_port = port;
	cli_session_actions[s].action |= CLI_SESS_SNOOP;

	return CLI_OK;
}

static int cmd_no_snoop(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	sessionidt s;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1,
			"USER", "Username of session to unsnoop", NULL);

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s", inet_toa(config->cluster_master_address));
		return CLI_OK;
	}

	if (!argc)
	{
		cli_print(cli, "Specify a user to unsnoop");
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

static int cmd_throttle(struct cli_def *cli, char *command, char **argv, int argc)
{
	int rate_in = 0;
	int rate_out = 0;
	sessionidt s;

	/*
	   throttle USER                   - throttle in/out to default rate
	   throttle USER RATE              - throttle in/out to default rate
	   throttle USER in RATE           - throttle input only
	   throttle USER out RATE          - throttle output only
	   throttle USER in RATE out RATE  - throttle both
	 */

	if (CLI_HELP_REQUESTED)
	{
		switch (argc)
		{
		case 1:
			return cli_arg_help(cli, 0,
				"USER", "Username of session to throttle", NULL);

		case 2:
			return cli_arg_help(cli, 1,
				"RATE", "Rate in kbps (in and out)",
				"in",   "Select incoming rate",
				"out",  "Select outgoing rate", NULL);

		case 4:
			return cli_arg_help(cli, 1,
				"in",   "Select incoming rate",
				"out",  "Select outgoing rate", NULL);

		case 3:
			if (isdigit(argv[1][0]))
				return cli_arg_help(cli, 1, NULL);

		case 5:
			return cli_arg_help(cli, 0, "RATE", "Rate in kbps", NULL);

		default:
			return cli_arg_help(cli, argc > 1, NULL);
		}
	}

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s", inet_toa(config->cluster_master_address));
		return CLI_OK;
	}

	if (argc == 0)
	{
		cli_print(cli, "Specify a user to throttle");
		return CLI_OK;
	}

	if (!(s = sessionbyuser(argv[0])))
	{
		cli_print(cli, "User %s is not connected", argv[0]);
		return CLI_OK;
	}

	if (argc == 1)
	{
		rate_in = rate_out = config->rl_rate;
	}
	else if (argc == 2)
	{
		rate_in = rate_out = atoi(argv[1]);
		if (rate_in < 1)
		{
			cli_print(cli, "Invalid rate \"%s\"", argv[1]);
			return CLI_OK;
		}
	}
	else if (argc == 3 || argc == 5)
	{
		int i;
		for (i = 1; i < argc - 1; i += 2)
		{
			int len = strlen(argv[i]);
			int r = 0;
			if (!strncasecmp(argv[i], "in", len))
				r = rate_in = atoi(argv[i+1]);
			else if (!strncasecmp(argv[i], "out", len))
				r = rate_out = atoi(argv[i+1]);

			if (r < 1)
			{
				cli_print(cli, "Invalid rate specification \"%s %s\"", argv[i], argv[i+1]);
				return CLI_OK;
			}
		}
	}
	else
	{
		cli_print(cli, "Invalid arguments");
		return CLI_OK;
	}

	if ((rate_in && session[s].throttle_in) || (rate_out && session[s].throttle_out))
	{
		cli_print(cli, "User %s already throttled, unthrottle first", argv[0]);
		return CLI_OK;
	}

	cli_session_actions[s].throttle_in = cli_session_actions[s].throttle_out = -1;
	if (rate_in && session[s].throttle_in != rate_in)
		cli_session_actions[s].throttle_in = rate_in;

	if (rate_out && session[s].throttle_out != rate_out)
		cli_session_actions[s].throttle_out = rate_out;

	if (cli_session_actions[s].throttle_in == -1 &&
	    cli_session_actions[s].throttle_out == -1)
	{
		cli_print(cli, "User %s already throttled at this rate", argv[0]);
		return CLI_OK;
	}

	cli_print(cli, "Throttling user %s", argv[0]);
	cli_session_actions[s].action |= CLI_SESS_THROTTLE;

	return CLI_OK;
}

static int cmd_no_throttle(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	sessionidt s;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1,
			"USER", "Username of session to unthrottle", NULL);

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s", inet_toa(config->cluster_master_address));
		return CLI_OK;
	}

	if (!argc)
	{
		cli_print(cli, "Specify a user to unthrottle");
		return CLI_OK;
	}

	for (i = 0; i < argc; i++)
	{
		if (!(s = sessionbyuser(argv[i])))
		{
			cli_print(cli, "User %s is not connected", argv[i]);
			continue;
		}

		if (session[s].throttle_in || session[s].throttle_out)
		{
			cli_print(cli, "Unthrottling user %s", argv[i]);
			cli_session_actions[s].action |= CLI_SESS_NOTHROTTLE;
		}
		else
		{
			cli_print(cli, "User %s not throttled", argv[i]);
		}
	}

	return CLI_OK;
}

static int cmd_debug(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, 1,
			"all",		"Enable debugging for all except \"data\"",
			"critical",	"", // FIXME: add descriptions
			"error",	"",
			"warning",	"",
			"info",		"",
			"calls",	"",
			"data",		"",
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
					(debug_flags.error)    ? " error"    : "",
					(debug_flags.warning)  ? " warning"  : "",
					(debug_flags.info)     ? " info"     : "",
					(debug_flags.calls)    ? " calls"    : "",
					(debug_flags.data)     ? " data"     : "");

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
		if (!strncasecmp(argv[i], "error",    len)) { debug_flags.error = 1;    continue; }
		if (!strncasecmp(argv[i], "warning",  len)) { debug_flags.warning = 1;  continue; }
		if (!strncasecmp(argv[i], "info",     len)) { debug_flags.info = 1;     continue; }
		if (!strncasecmp(argv[i], "calls",    len)) { debug_flags.calls = 1;    continue; }
		if (!strncasecmp(argv[i], "data",     len)) { debug_flags.data = 1;     continue; }
		if (!strncasecmp(argv[i], "all",      len))
		{
			memset(&debug_flags, 1, sizeof(debug_flags));
			debug_flags.data = 0;
			continue;
		}

		cli_print(cli, "Invalid debugging flag \"%s\"", argv[i]);
	}

	return CLI_OK;
}

static int cmd_no_debug(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, 1,
			"all",		"Disable all debugging",
			"critical",	"", // FIXME: add descriptions
			"error",	"",
			"warning",	"",
			"info",		"",
			"calls",	"",
			"data",		"",
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
		if (!strncasecmp(argv[i], "error",    len)) { debug_flags.error = 0;    continue; }
		if (!strncasecmp(argv[i], "warning",  len)) { debug_flags.warning = 0;  continue; }
		if (!strncasecmp(argv[i], "info",     len)) { debug_flags.info = 0;     continue; }
		if (!strncasecmp(argv[i], "calls",    len)) { debug_flags.calls = 0;    continue; }
		if (!strncasecmp(argv[i], "data",     len)) { debug_flags.data = 0;     continue; }
		if (!strncasecmp(argv[i], "all",      len))
		{
			memset(&debug_flags, 0, sizeof(debug_flags));
			continue;
		}

		cli_print(cli, "Invalid debugging flag \"%s\"", argv[i]);
	}

	return CLI_OK;
}

static int cmd_load_plugin(struct cli_def *cli, char *command, char **argv, int argc)
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

static int cmd_remove_plugin(struct cli_def *cli, char *command, char **argv, int argc)
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

static int cmd_uptime(struct cli_def *cli, char *command, char **argv, int argc)
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

static int cmd_set(struct cli_def *cli, char *command, char **argv, int argc)
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
			case MAC:
				parsemac(argv[1], (char *)value);
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
			if (ringbuffer->buffer[i].level == 1 && debug_flags.error)    show_message = 1;
			if (ringbuffer->buffer[i].level == 2 && debug_flags.warning)  show_message = 1;
			if (ringbuffer->buffer[i].level == 3 && debug_flags.info)     show_message = 1;
			if (ringbuffer->buffer[i].level == 4 && debug_flags.calls)    show_message = 1;
			if (ringbuffer->buffer[i].level == 5 && debug_flags.data)     show_message = 1;
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

#ifdef BGP
static int cmd_router_bgp(struct cli_def *cli, char *command, char **argv, int argc)
{
	int as;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1,
			"<1-65535>", "Autonomous system number", NULL);

	if (argc != 1 || (as = atoi(argv[0])) < 1 || as > 65535)
	{
		cli_print(cli, "Invalid autonomous system number");
		return CLI_OK;
	}

	if (bgp_configured && as != config->as_number)
	{
		cli_print(cli, "Can't change local AS on a running system");
		return CLI_OK;
	}

	config->as_number = as;
	cli_set_configmode(cli, MODE_CONFIG_BGP, "router");

	return CLI_OK;
}

static int cmd_router_bgp_exit(struct cli_def *cli, char *command, char **argv, int argc)
{
	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_set_configmode(cli, MODE_CONFIG, NULL);
    	return CLI_OK;
}

static int find_bgp_neighbour(char *name)
{
	int i;
	int new = -1;
	struct hostent *h;
	in_addr_t addrs[4] = { 0 };
	char **a;

	if (!(h = gethostbyname(name)) || h->h_addrtype != AF_INET)
		return -2;

	for (i = 0; i < sizeof(addrs) / sizeof(*addrs) && h->h_addr_list[i]; i++)
		memcpy(&addrs[i], h->h_addr_list[i], sizeof(*addrs));

	for (i = 0; i < BGP_NUM_PEERS; i++)
	{
	    	if (!config->neighbour[i].name[0])
		{
			if (new == -1) new = i;
			continue;
		}

		if (!strcmp(name, config->neighbour[i].name))
			return i;

		if (!(h = gethostbyname(config->neighbour[i].name)) || h->h_addrtype != AF_INET)
			continue;

		for (a = h->h_addr_list; *a; a++)
		{
			int j;
			for (j = 0; j < sizeof(addrs) / sizeof(*addrs) && addrs[j]; j++)
				if (!memcmp(&addrs[j], *a, sizeof(*addrs)))
					return i;
		}
	}

	return new;
}

static int cmd_router_bgp_neighbour(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	int keepalive;
	int hold;

    	if (CLI_HELP_REQUESTED)
	{
		switch (argc)
		{
		case 1:
			return cli_arg_help(cli, 0,
				"A.B.C.D", "BGP neighbour address",
				"NAME",    "BGP neighbour name",
				NULL);

		case 2:
			return cli_arg_help(cli, 0,
				"remote-as", "Set remote autonomous system number",
				"timers",    "Set timers",
				NULL);

		default:
		    	if (!strncmp("remote-as", argv[1], strlen(argv[1])))
			    	return cli_arg_help(cli, argv[2][1], "<1-65535>", "Autonomous system number", NULL);

			if (!strncmp("timers", argv[1], strlen(argv[1])))
			{
			    	if (argc == 3)
					return cli_arg_help(cli, 0, "<1-65535>", "Keepalive time", NULL);

				if (argc == 4)
					return cli_arg_help(cli, argv[3][1], "<3-65535>", "Hold time", NULL);

				if (argc == 5 && !argv[4][1])
					return cli_arg_help(cli, 1, NULL);
			}

			return CLI_OK;
		}
	}

	if (argc < 3)
	{
		cli_print(cli, "Invalid arguments");
		return CLI_OK;
	}

	if ((i = find_bgp_neighbour(argv[0])) == -2)
	{
		cli_print(cli, "Invalid neighbour");
		return CLI_OK;
	}

	if (i == -1)
	{
		cli_print(cli, "Too many neighbours (max %d)", BGP_NUM_PEERS);
		return CLI_OK;
	}

	if (!strncmp("remote-as", argv[1], strlen(argv[1])))
	{
	    	int as = atoi(argv[2]);
		if (as < 0 || as > 65535)
		{
			cli_print(cli, "Invalid autonomous system number");
			return CLI_OK;
		}

		if (!config->neighbour[i].name[0])
		{
			snprintf(config->neighbour[i].name, sizeof(config->neighbour[i].name), argv[0]);
			config->neighbour[i].keepalive = -1;
			config->neighbour[i].hold = -1;
		}

		config->neighbour[i].as = as;
		return CLI_OK;
	}

	if (argc != 4 || strncmp("timers", argv[1], strlen(argv[1])))
	{
		cli_print(cli, "Invalid arguments");
		return CLI_OK;
	}

	if (!config->neighbour[i].name[0])
	{
		cli_print(cli, "Specify remote-as first");
		return CLI_OK;
	}

	keepalive = atoi(argv[2]);
	hold = atoi(argv[3]);

	if (keepalive < 1 || keepalive > 65535)
	{
		cli_print(cli, "Invalid keepalive time");
		return CLI_OK;
	}

	if (hold < 3 || hold > 65535)
	{
		cli_print(cli, "Invalid hold time");
		return CLI_OK;
	}

	if (keepalive == BGP_KEEPALIVE_TIME)
		keepalive = -1; // using default value

	if (hold == BGP_HOLD_TIME)
		hold = -1;

	config->neighbour[i].keepalive = keepalive;
	config->neighbour[i].hold = hold;

    	return CLI_OK;
}

static int cmd_router_bgp_no_neighbour(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;

    	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 0,
			"A.B.C.D", "BGP neighbour address",
			"NAME",    "BGP neighbour name",
			NULL);

	if (argc != 1)
	{
		cli_print(cli, "Specify a BGP neighbour");
		return CLI_OK;
	}

	if ((i = find_bgp_neighbour(argv[0])) == -2)
	{
		cli_print(cli, "Invalid neighbour");
		return CLI_OK;
	}

	if (i < 0 || !config->neighbour[i].name[0])
	{
		cli_print(cli, "Neighbour %s not configured", argv[0]);
		return CLI_OK;
	}

	memset(&config->neighbour[i], 0, sizeof(config->neighbour[i]));
    	return CLI_OK;
}

static int cmd_show_bgp(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	int hdr = 0;
	char *addr;

	if (!bgp_configured)
		return CLI_OK;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, 1,
			"A.B.C.D", "BGP neighbour address",
			"NAME",    "BGP neighbour name",
			NULL);

	cli_print(cli, "BGPv%d router identifier %s, local AS number %d",
		BGP_VERSION, inet_toa(my_address), (int) config->as_number);

	time(&time_now);

	for (i = 0; i < BGP_NUM_PEERS; i++)
	{
		if (!*bgp_peers[i].name)
			continue;

		addr = inet_toa(bgp_peers[i].addr);
		if (argc && strcmp(addr, argv[0]) &&
		    strncmp(bgp_peers[i].name, argv[0], strlen(argv[0])))
			continue;

		if (!hdr++)
		{
			cli_print(cli, "");
			cli_print(cli, "Peer                  AS         Address "
			    "State       Retries Retry in Route Pend Timers");
			cli_print(cli, "------------------ ----- --------------- "
			    "----------- ------- -------- ----- ---- ---------");
		}

		cli_print(cli, "%-18.18s %5d %15s %-11s %7d %7ds %5s %4s %4d %4d",
			bgp_peers[i].name,
			bgp_peers[i].as,
			addr,
			bgp_state_str(bgp_peers[i].state),
			bgp_peers[i].retry_count,
			bgp_peers[i].retry_time ? bgp_peers[i].retry_time - time_now : 0,
			bgp_peers[i].routing ? "yes" : "no",
			bgp_peers[i].update_routes ? "yes" : "no",
			bgp_peers[i].keepalive,
			bgp_peers[i].hold);
	}

	return CLI_OK;
}

static int cmd_suspend_bgp(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	char *addr;

	if (!bgp_configured)
		return CLI_OK;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, 1,
			"A.B.C.D", "BGP neighbour address",
			"NAME",    "BGP neighbour name",
			NULL);

	for (i = 0; i < BGP_NUM_PEERS; i++)
	{
		if (bgp_peers[i].state != Established)
			continue;

		if (!bgp_peers[i].routing)
			continue;

		addr = inet_toa(bgp_peers[i].addr);
		if (argc && strcmp(addr, argv[0]) && strcmp(bgp_peers[i].name, argv[0]))
			continue;

		bgp_peers[i].cli_flag = BGP_CLI_SUSPEND;
		cli_print(cli, "Suspending peer %s", bgp_peers[i].name);
	}

	return CLI_OK;
}

static int cmd_no_suspend_bgp(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	char *addr;

	if (!bgp_configured)
		return CLI_OK;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, 1,
			"A.B.C.D", "BGP neighbour address",
			"NAME",    "BGP neighbour name",
			NULL);

	for (i = 0; i < BGP_NUM_PEERS; i++)
	{
		if (bgp_peers[i].state != Established)
			continue;

		if (bgp_peers[i].routing)
			continue;

		addr = inet_toa(bgp_peers[i].addr);
		if (argc && strcmp(addr, argv[0]) &&
		    strncmp(bgp_peers[i].name, argv[0], strlen(argv[0])))
			continue;

		bgp_peers[i].cli_flag = BGP_CLI_ENABLE;
		cli_print(cli, "Un-suspending peer %s", bgp_peers[i].name);
	}

	return CLI_OK;
}

static int cmd_restart_bgp(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	char *addr;

	if (!bgp_configured)
		return CLI_OK;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, 1,
			"A.B.C.D", "BGP neighbour address",
			"NAME",    "BGP neighbour name",
			NULL);

	for (i = 0; i < BGP_NUM_PEERS; i++)
	{
		if (!*bgp_peers[i].name)
			continue;

		addr = inet_toa(bgp_peers[i].addr);
		if (argc && strcmp(addr, argv[0]) &&
		    strncmp(bgp_peers[i].name, argv[0], strlen(argv[0])))
			continue;

		bgp_peers[i].cli_flag = BGP_CLI_RESTART;
		cli_print(cli, "Restarting peer %s", bgp_peers[i].name);
	}

	return CLI_OK;
}
#endif /* BGP*/

// Convert a string in the form of abcd.ef12.3456 into char[6]
void parsemac(char *string, char mac[6])
{
	if (sscanf(string, "%02x%02x.%02x%02x.%02x%02x", (unsigned int *)&mac[0], (unsigned int *)&mac[1], (unsigned int *)&mac[2], (unsigned int *)&mac[3], (unsigned int *)&mac[4], (unsigned int *)&mac[5]) == 6)
		return;
	if (sscanf(string, "%02x%02x:%02x%02x:%02x%02x", (unsigned int *)&mac[0], (unsigned int *)&mac[1], (unsigned int *)&mac[2], (unsigned int *)&mac[3], (unsigned int *)&mac[4], (unsigned int *)&mac[5]) == 6)
		return;
	memset(mac, 0, 6);
}
