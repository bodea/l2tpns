// L2TPNS Command Line Interface
// vim: sw=8 ts=8

char const *cvs_name = "$Name:  $";
char const *cvs_id_cli = "$Id: cli.c,v 1.51 2005-01-13 08:26:25 bodea Exp $";

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
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
#include <dlfcn.h>
#include <netdb.h>
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
static struct cli_def *cli = NULL;
extern configt *config;
extern config_descriptt config_values[];
#ifdef RINGBUFFER
extern struct Tringbuffer *ringbuffer;
#endif
extern struct cli_session_actions *cli_session_actions;
extern struct cli_tunnel_actions *cli_tunnel_actions;
extern tbft *filter_list;
extern ip_filtert *ip_filters;

static char *debug_levels[] = {
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

static int debug_session;
static int debug_tunnel;
static int debug_rb_tail;

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

#define MODE_CONFIG_NACL 9
static int cmd_ip_access_list(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_no_ip_access_list(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_ip_access_list_rule(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_filter(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_no_filter(struct cli_def *cli, char *command, char **argv, int argc);
static int cmd_show_access_list(struct cli_def *cli, char *command, char **argv, int argc);

/* match if b is a substr of a */
#define MATCH(a,b) (!strncmp((a), (b), strlen(b)))

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
	cli_register_command(cli, c, "access-list", cmd_show_access_list, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show named access-list");

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

	cli_register_command(cli, NULL, "snoop", cmd_snoop, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Enable interception of a session");
	cli_register_command(cli, NULL, "throttle", cmd_throttle, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Enable throttling of a session");
	cli_register_command(cli, NULL, "filter", cmd_filter, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Add filtering to a session");
	cli_register_command(cli, NULL, "debug", cmd_debug, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Set the level of logging that is shown on the console");

#ifdef BGP
	c = cli_register_command(cli, NULL, "suspend", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "bgp", cmd_suspend_bgp, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Withdraw routes from BGP neighbour");
#endif /* BGP */

	c = cli_register_command(cli, NULL, "no", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, NULL);
	cli_register_command(cli, c, "snoop", cmd_no_snoop, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Disable interception of a session");
	cli_register_command(cli, c, "throttle", cmd_no_throttle, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Disable throttling of a session");
	cli_register_command(cli, c, "filter", cmd_no_filter, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Remove filtering from a session");
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

	c = cli_register_command(cli, NULL, "ip", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, NULL);
	cli_register_command(cli, c, "access-list", cmd_ip_access_list, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Add named access-list");

	cli_register_command(cli, NULL, "permit", cmd_ip_access_list_rule, PRIVILEGE_PRIVILEGED, MODE_CONFIG_NACL, "Permit rule");
	cli_register_command(cli, NULL, "deny", cmd_ip_access_list_rule, PRIVILEGE_PRIVILEGED, MODE_CONFIG_NACL, "Deny rule");

	c = cli_register_command(cli, NULL, "no", NULL, PRIVILEGE_UNPRIVILEGED, MODE_CONFIG, NULL);
	c2 = cli_register_command(cli, c, "ip", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, NULL);
	cli_register_command(cli, c2, "access-list", cmd_no_ip_access_list, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Remove named access-list");

	// Enable regular processing
	cli_regular(cli, regular_stuff);

	if (!(f = fopen(CLIUSERS, "r")))
	{
		LOG(0, 0, 0, "WARNING! No users specified. Command-line access is open to all\n");
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
				LOG(3, 0, 0, "Setting enable password\n");
			}
			else
			{
				cli_allow_user(cli, buf, p);
				LOG(3, 0, 0, "Allowing user %s to connect to the CLI\n", buf);
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
		LOG(0, 0, 0, "Error listening on cli port 23: %s\n", strerror(errno));
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
		require_auth = addr.sin_addr.s_addr != inet_addr("127.0.0.1");
		LOG(require_auth ? 3 : 4, 0, 0, "Accepted connection to CLI from %s\n",
			fmtaddr(addr.sin_addr.s_addr, 0));
	}
	else
		LOG(0, 0, 0, "getpeername() failed on cli socket.  Requiring authentication: %s\n", strerror(errno));

	if (require_auth)
	{
		LOG(3, 0, 0, "CLI is remote, requiring authentication\n");
		if (!cli->users) /* paranoia */
		{
			LOG(0, 0, 0, "No users for remote authentication!  Exiting CLI\n");
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
	LOG(require_auth ? 3 : 4, 0, 0, "Closed CLI connection from %s\n",
		fmtaddr(addr.sin_addr.s_addr, 0));

	exit(0);
}

static void cli_print_log(struct cli_def *cli, char *string)
{
	LOG(3, 0, 0, "%s\n", string);
}

void cli_do_file(FILE *fh)
{
	LOG(3, 0, 0, "Reading configuration file\n");
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
			cli_print(cli, "\tIP address:\t%s", fmtaddr(htonl(session[s].ip), 0));
			cli_print(cli, "\tUnique SID:\t%lu", session[s].unique_id);
			cli_print(cli, "\tIdle time:\t%u seconds", abs(time_now - session[s].last_packet));
			cli_print(cli, "\tNext Recv:\t%u", session[s].nr);
			cli_print(cli, "\tNext Send:\t%u", session[s].ns);
			cli_print(cli, "\tBytes In/Out:\t%u/%u", session[s].total_cout, session[s].total_cin);
			cli_print(cli, "\tPkts In/Out:\t%u/%u", session[s].pout, session[s].pin);
			cli_print(cli, "\tMRU:\t\t%d", session[s].mru);
			cli_print(cli, "\tRadius Session:\t%u", session[s].radius);
			cli_print(cli, "\tRx Speed:\t%u", session[s].rx_connect_speed);
			cli_print(cli, "\tTx Speed:\t%u", session[s].tx_connect_speed);
			if (session[s].filter_in && session[s].filter_in <= MAXFILTER)
				cli_print(cli, "\tFilter in:\t%u (%s)", session[s].filter_in, ip_filters[session[s].filter_in - 1].name);
			if (session[s].filter_out && session[s].filter_out <= MAXFILTER)
				cli_print(cli, "\tFilter out:\t%u (%s)", session[s].filter_out, ip_filters[session[s].filter_out - 1].name);
			if (session[s].snoop_ip && session[s].snoop_port)
				cli_print(cli, "\tIntercepted:\t%s:%d", fmtaddr(session[s].snoop_ip, 0), session[s] .snoop_port);
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
		if (!session[i].opened) continue;
		cli_print(cli, "%5d %4d %-32s %-15s %s %s %s %10u %10lu %10lu %4u %-15s %s",
				i,
				session[i].tunnel,
				session[i].user[0] ? session[i].user : "*",
				fmtaddr(htonl(session[i].ip), 0),
				(session[i].snoop_ip && session[i].snoop_port) ? "Y" : "N",
				(session[i].throttle_in || session[i].throttle_out) ? "Y" : "N",
				(session[i].walled_garden) ? "Y" : "N",
				abs(time_now - (unsigned long)session[i].opened),
				(unsigned long)session[i].total_cout,
				(unsigned long)session[i].total_cin,
				abs(time_now - (session[i].last_packet ? session[i].last_packet : time_now)),
				fmtaddr(htonl(tunnel[ session[i].tunnel ].ip), 1),
				session[i].calling[0] ? session[i].calling : "*");
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
				cli_print(cli, "\tRemote IP:\t%s", fmtaddr(htonl(tunnel[t].ip), 0));
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
				fmtaddr(htonl(tunnel[i].ip), 0),
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

	cli_print(cli, "%-10s %10s %10s %10s %10s", "Ethernet", "Bytes", "Packets", "Errors", "Dropped");
	cli_print(cli, "%-10s %10u %10u %10u %10u", "RX",
			GET_STAT(tun_rx_bytes),
			GET_STAT(tun_rx_packets),
			GET_STAT(tun_rx_errors),
			GET_STAT(tun_rx_dropped));
	cli_print(cli, "%-10s %10u %10u %10u", "TX",
			GET_STAT(tun_tx_bytes),
			GET_STAT(tun_tx_packets),
			GET_STAT(tun_tx_errors));
	cli_print(cli, "");

	cli_print(cli, "%-10s %10s %10s %10s %10s", "Tunnel", "Bytes", "Packets", "Errors", "Retries");
	cli_print(cli, "%-10s %10u %10u %10u", "RX",
			GET_STAT(tunnel_rx_bytes),
			GET_STAT(tunnel_rx_packets),
			GET_STAT(tunnel_rx_errors));
	cli_print(cli, "%-10s %10u %10u %10u %10u", "TX",
			GET_STAT(tunnel_tx_bytes),
			GET_STAT(tunnel_tx_packets),
			GET_STAT(tunnel_tx_errors),
			GET_STAT(tunnel_retries));
	cli_print(cli, "");

	cli_print(cli, "%-30s%-10s", "Counter", "Value");
	cli_print(cli, "-----------------------------------------");
	cli_print(cli, "%-30s%u", "radius_retries",		GET_STAT(radius_retries));
	cli_print(cli, "%-30s%u", "arp_sent",			GET_STAT(arp_sent));
	cli_print(cli, "%-30s%u", "packets_snooped",		GET_STAT(packets_snooped));
	cli_print(cli, "%-30s%u", "tunnel_created",		GET_STAT(tunnel_created));
	cli_print(cli, "%-30s%u", "session_created",		GET_STAT(session_created));
	cli_print(cli, "%-30s%u", "tunnel_timeout",		GET_STAT(tunnel_timeout));
	cli_print(cli, "%-30s%u", "session_timeout",		GET_STAT(session_timeout));
	cli_print(cli, "%-30s%u", "radius_timeout",		GET_STAT(radius_timeout));
	cli_print(cli, "%-30s%u", "radius_overflow",		GET_STAT(radius_overflow));
	cli_print(cli, "%-30s%u", "tunnel_overflow",		GET_STAT(tunnel_overflow));
	cli_print(cli, "%-30s%u", "session_overflow",		GET_STAT(session_overflow));
	cli_print(cli, "%-30s%u", "ip_allocated",		GET_STAT(ip_allocated));
	cli_print(cli, "%-30s%u", "ip_freed",			GET_STAT(ip_freed));
	cli_print(cli, "%-30s%u", "cluster_forwarded",		GET_STAT(c_forwarded));
	cli_print(cli, "%-30s%u", "recv_forward",		GET_STAT(recv_forward));
	cli_print(cli, "%-30s%u", "select_called",		GET_STAT(select_called));
	cli_print(cli, "%-30s%u", "multi_read_used",		GET_STAT(multi_read_used));
	cli_print(cli, "%-30s%u", "multi_read_exceeded",	GET_STAT(multi_read_exceeded));


#ifdef STATISTICS
	cli_print(cli, "\n%-30s%-10s", "Counter", "Value");
	cli_print(cli, "-----------------------------------------");
	cli_print(cli, "%-30s%u", "call_processtun",		GET_STAT(call_processtun));
	cli_print(cli, "%-30s%u", "call_processipout",		GET_STAT(call_processipout));
	cli_print(cli, "%-30s%u", "call_processudp",		GET_STAT(call_processudp));
	cli_print(cli, "%-30s%u", "call_processpap",		GET_STAT(call_processpap));
	cli_print(cli, "%-30s%u", "call_processchap",		GET_STAT(call_processchap));
	cli_print(cli, "%-30s%u", "call_processlcp",		GET_STAT(call_processlcp));
	cli_print(cli, "%-30s%u", "call_processipcp",		GET_STAT(call_processipcp));
	cli_print(cli, "%-30s%u", "call_processipin",		GET_STAT(call_processipin));
	cli_print(cli, "%-30s%u", "call_processccp",		GET_STAT(call_processccp));
	cli_print(cli, "%-30s%u", "call_processrad",		GET_STAT(call_processrad));
	cli_print(cli, "%-30s%u", "call_sendarp",		GET_STAT(call_sendarp));
	cli_print(cli, "%-30s%u", "call_sendipcp",		GET_STAT(call_sendipcp));
	cli_print(cli, "%-30s%u", "call_sendchap",		GET_STAT(call_sendchap));
	cli_print(cli, "%-30s%u", "call_sessionbyip",		GET_STAT(call_sessionbyip));
	cli_print(cli, "%-30s%u", "call_sessionbyuser",		GET_STAT(call_sessionbyuser));
	cli_print(cli, "%-30s%u", "call_tunnelsend",		GET_STAT(call_tunnelsend));
	cli_print(cli, "%-30s%u", "call_tunnelkill",		GET_STAT(call_tunnelkill));
	cli_print(cli, "%-30s%u", "call_tunnelshutdown",	GET_STAT(call_tunnelshutdown));
	cli_print(cli, "%-30s%u", "call_sessionkill",		GET_STAT(call_sessionkill));
	cli_print(cli, "%-30s%u", "call_sessionshutdown",	GET_STAT(call_sessionshutdown));
	cli_print(cli, "%-30s%u", "call_sessionsetup",		GET_STAT(call_sessionsetup));
	cli_print(cli, "%-30s%u", "call_assign_ip_address",	GET_STAT(call_assign_ip_address));
	cli_print(cli, "%-30s%u", "call_free_ip_address",	GET_STAT(call_free_ip_address));
	cli_print(cli, "%-30s%u", "call_dump_acct_info",	GET_STAT(call_dump_acct_info));
	cli_print(cli, "%-30s%u", "call_radiussend",		GET_STAT(call_radiussend));
	cli_print(cli, "%-30s%u", "call_radiusretry",		GET_STAT(call_radiusretry));
	cli_print(cli, "%-30s%u", "call_random_data",		GET_STAT(call_random_data));
#endif

	{
		time_t l = GET_STAT(last_reset);
		char *t = ctime(&l);
		char *p = strchr(t, '\n');
		if (p) *p = 0;

		cli_print(cli, "");
		cli_print(cli, "Last counter reset %s", t);
	}

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
		cli_print(cli, "Tag: %.*s", (int) (e ? e - p + 1 : strlen(p)), p);
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
		cli_print(cli, "Can't do this on a slave.  Do it on %s",
			fmtaddr(config->cluster_master_address, 0));

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
				fmtaddr(htonl(ip_address_pool[i].address), 0),
				ip_address_pool[i].session,
				session[ip_address_pool[i].session].user);

			used++;
		}
		else
		{
			if (ip_address_pool[i].last)
				cli_print(cli, "%-15s\tN %8s [%s] %ds",
					fmtaddr(htonl(ip_address_pool[i].address), 0), "",
					ip_address_pool[i].user, (int) time_now - ip_address_pool[i].last);

			else if (show_all)
				cli_print(cli, "%-15s\tN", fmtaddr(htonl(ip_address_pool[i].address), 0));

			free++;
		}
	}

	if (!show_all)
		cli_print(cli, "(Not displaying unused addresses)");

	cli_print(cli, "\r\nFree: %d\r\nUsed: %d", free, used);
	return CLI_OK;
}

static FILE *save_config_fh = 0;
static void print_save_config(struct cli_def *cli, char *string)
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
		save_config_fh = 0;
	}
	else
	{
		cli_print(cli, "Error writing configuration: %s", strerror(errno));
	}
	return CLI_OK;
}

static char const *show_access_list_rule(int extended, ip_filter_rulet *rule);

static int cmd_show_run(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	char ipv6addr[INET6_ADDRSTRLEN];

	if (CLI_HELP_REQUESTED)
		return CLI_HELP_NO_ARGS;

	cli_print(cli, "# Current configuration:");

	for (i = 0; config_values[i].key; i++)
	{
		void *value = ((void *)config) + config_values[i].offset;
		if (config_values[i].type == STRING)
			cli_print(cli, "set %s \"%.*s\"", config_values[i].key, config_values[i].size, (char *) value);
		else if (config_values[i].type == IPv4)
			cli_print(cli, "set %s %s", config_values[i].key, fmtaddr(*(in_addr_t *) value, 0));
		else if (config_values[i].type == IPv6)
			cli_print(cli, "set %s %s", config_values[i].key, inet_ntop(AF_INET6, value, ipv6addr, INET6_ADDRSTRLEN));
		else if (config_values[i].type == SHORT)
			cli_print(cli, "set %s %hu", config_values[i].key, *(short *) value);
		else if (config_values[i].type == BOOL)
			cli_print(cli, "set %s %s", config_values[i].key, (*(int *) value) ? "yes" : "no");
		else if (config_values[i].type == INT)
			cli_print(cli, "set %s %d", config_values[i].key, *(int *) value);
		else if (config_values[i].type == UNSIGNED_LONG)
			cli_print(cli, "set %s %lu", config_values[i].key, *(unsigned long *) value);
		else if (config_values[i].type == MAC)
			cli_print(cli, "set %s %02x%02x.%02x%02x.%02x%02x", config_values[i].key,
					*(unsigned short *) (value + 0),
					*(unsigned short *) (value + 1),
					*(unsigned short *) (value + 2),
					*(unsigned short *) (value + 3),
					*(unsigned short *) (value + 4),
					*(unsigned short *) (value + 5));
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

	cli_print(cli, "# Filters");
	for (i = 0; i < MAXFILTER; i++)
	{
		ip_filter_rulet *rules;
	    	if (!*ip_filters[i].name)
			continue;

		cli_print(cli, "ip access-list %s %s",
			ip_filters[i].extended ? "extended" : "standard",
			ip_filters[i].name);

		rules = ip_filters[i].rules;
		while (rules->action)
			cli_print(cli, "%s", show_access_list_rule(ip_filters[i].extended, rules++));
	}

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

	cli_print(cli, "%6s%7s%5s%6s%9s%9s%4s", "ID", "Radius", "Sock", "State", "Session", "Retry", "Try");

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

		cli_print(cli, "%6d%7d%5d%6s%9d%9u%4d",
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

	memset(_statistics, 0, sizeof(struct Tstats));
	SET_STAT(last_reset, time(NULL));

	cli_print(cli, "Counters cleared");
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
		cli_print(cli, "Can't do this on a slave.  Do it on %s",
			fmtaddr(config->cluster_master_address, 0));

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
		cli_print(cli, "Can't do this on a slave.  Do it on %s",
			fmtaddr(config->cluster_master_address, 0));

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
		cli_print(cli, "Can't do this on a slave.  Do it on %s",
			fmtaddr(config->cluster_master_address, 0));

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
	in_addr_t ip;
	uint16_t port;
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
		cli_print(cli, "Can't do this on a slave.  Do it on %s",
			fmtaddr(config->cluster_master_address, 0));

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

	cli_print(cli, "Snooping user %s to %s:%d", argv[0], fmtaddr(ip, 0), port);
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
		cli_print(cli, "Can't do this on a slave.  Do it on %s",
			fmtaddr(config->cluster_master_address, 0));

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
		cli_print(cli, "Can't do this on a slave.  Do it on %s",
			fmtaddr(config->cluster_master_address, 0));

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
			int r = 0;
			if (MATCH("in", argv[i]))
				r = rate_in = atoi(argv[i+1]);
			else if (MATCH("out", argv[i]))
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
		cli_print(cli, "Can't do this on a slave.  Do it on %s",
			fmtaddr(config->cluster_master_address, 0));

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

		if (!strncmp("critical", argv[i], len)) { debug_flags.critical = 1; continue; }
		if (!strncmp("error",    argv[i], len)) { debug_flags.error = 1;    continue; }
		if (!strncmp("warning",  argv[i], len)) { debug_flags.warning = 1;  continue; }
		if (!strncmp("info",     argv[i], len)) { debug_flags.info = 1;     continue; }
		if (!strncmp("calls",    argv[i], len)) { debug_flags.calls = 1;    continue; }
		if (!strncmp("data",     argv[i], len)) { debug_flags.data = 1;     continue; }
		if (!strncmp("all",      argv[i], len))
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

		if (!strncmp("critical", argv[i], len)) { debug_flags.critical = 0; continue; }
		if (!strncmp("error",    argv[i], len)) { debug_flags.error = 0;    continue; }
		if (!strncmp("warning",  argv[i], len)) { debug_flags.warning = 0;  continue; }
		if (!strncmp("info",     argv[i], len)) { debug_flags.info = 0;     continue; }
		if (!strncmp("calls",    argv[i], len)) { debug_flags.calls = 0;    continue; }
		if (!strncmp("data",     argv[i], len)) { debug_flags.data = 0;     continue; }
		if (!strncmp("all",      argv[i], len))
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

static char *duration(time_t secs)
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
					if (!len || !strncmp(config_values[i].key, argv[0], len))
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
		void *value = ((void *) config) + config_values[i].offset;
		if (strcmp(config_values[i].key, argv[0]) == 0)
		{
			// Found a value to set
			cli_print(cli, "Setting \"%s\" to \"%s\"", argv[0], argv[1]);
			switch (config_values[i].type)
			{
			case STRING:
				snprintf((char *) value, config_values[i].size, "%s", argv[1]);
				break;
			case INT:
				*(int *) value = atoi(argv[1]);
				break;
			case UNSIGNED_LONG:
				*(unsigned long *) value = atol(argv[1]);
				break;
			case SHORT:
				*(short *) value = atoi(argv[1]);
				break;
			case IPv4:
				*(in_addr_t *) value = inet_addr(argv[1]);
				break;
			case IPv6:
				inet_pton(AF_INET6, argv[1], value);
				break;
			case MAC:
				parsemac(argv[1], (char *)value);
				break;
			case BOOL:
				if (strcasecmp(argv[1], "yes") == 0 || strcasecmp(argv[1], "true") == 0 || strcasecmp(argv[1], "1") == 0)
					*(int *) value = 1;
				else
					*(int *) value = 0;
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
	int out = 0;
	int i;

#ifdef RINGBUFFER
	for (i = debug_rb_tail; i != ringbuffer->tail; i = (i + 1) % RINGBUFFER_SIZE)
	{
		char *m = ringbuffer->buffer[i].message;
		char *p;
		int show = 0;

		if (!*m) continue;

		switch (ringbuffer->buffer[i].level)
		{
		case 0: show = debug_flags.critical;	break;
		case 1: show = debug_flags.error;	break;
		case 2: show = debug_flags.warning;	break;
		case 3: show = debug_flags.info;	break;
		case 4: show = debug_flags.calls;	break;
		case 5: show = debug_flags.data;	break;
		}

		if (!show) continue;

		if (!(p = strchr(m, '\n')))
			p = m + strlen(p);

		cli_print(cli, "\r%s-%u-%u %.*s",
			debug_levels[(int)ringbuffer->buffer[i].level],
			ringbuffer->buffer[i].tunnel,
			ringbuffer->buffer[i].session,
			(int) (p - m), m);

		out++;
	}

	debug_rb_tail = ringbuffer->tail;
	if (out)
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

static int find_bgp_neighbour(char const *name)
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
			if (MATCH("remote-as", argv[1]))
				return cli_arg_help(cli, argv[2][1], "<1-65535>", "Autonomous system number", NULL);

			if (MATCH("timers", argv[1]))
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

	if (MATCH("remote-as", argv[1]))
	{
		int as = atoi(argv[2]);
		if (as < 0 || as > 65535)
		{
			cli_print(cli, "Invalid autonomous system number");
			return CLI_OK;
		}

		if (!config->neighbour[i].name[0])
		{
			snprintf(config->neighbour[i].name, sizeof(config->neighbour[i].name), "%s", argv[0]);
			config->neighbour[i].keepalive = -1;
			config->neighbour[i].hold = -1;
		}

		config->neighbour[i].as = as;
		return CLI_OK;
	}

	if (argc != 4 || !MATCH("timers", argv[1]))
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
		BGP_VERSION, fmtaddr(my_address, 0), (int) config->as_number);

	time(&time_now);

	for (i = 0; i < BGP_NUM_PEERS; i++)
	{
		if (!*bgp_peers[i].name)
			continue;

		addr = fmtaddr(bgp_peers[i].addr, 0);
		if (argc && strcmp(addr, argv[0]) &&
		    strncmp(bgp_peers[i].name, argv[0], strlen(argv[0])))
			continue;

		if (!hdr++)
		{
			cli_print(cli, "");
			cli_print(cli, "Peer                  AS         Address "
			    "State       Retries Retry in Route Pend    Timers");
			cli_print(cli, "------------------ ----- --------------- "
			    "----------- ------- -------- ----- ---- ---------");
		}

		cli_print(cli, "%-18.18s %5d %15s %-11s %7d %7lds %5s %4s %4d %4d",
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

		addr = fmtaddr(bgp_peers[i].addr, 0);
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

		addr = fmtaddr(bgp_peers[i].addr, 0);
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

		addr = fmtaddr(bgp_peers[i].addr, 0);
		if (argc && strcmp(addr, argv[0]) &&
		    strncmp(bgp_peers[i].name, argv[0], strlen(argv[0])))
			continue;

		bgp_peers[i].cli_flag = BGP_CLI_RESTART;
		cli_print(cli, "Restarting peer %s", bgp_peers[i].name);
	}

	return CLI_OK;
}
#endif /* BGP*/

static int filt;
static int find_access_list(char const *name)
{
	int i;

	for (i = 0; i < MAXFILTER; i++)
		if (!(*ip_filters[i].name && strcmp(ip_filters[i].name, name)))
			return i;

	return -1;
}

static int access_list(struct cli_def *cli, char **argv, int argc, int add)
{
	int extended;

	if (CLI_HELP_REQUESTED)
	{
		switch (argc)
		{
		case 1:
			return cli_arg_help(cli, 0,
				"standard", "Standard syntax",
				"extended", "Extended syntax",
				NULL);

		case 2:
			return cli_arg_help(cli, argv[1][1],
				"NAME", "Access-list name",
				NULL);

		default:
			if (argc == 3 && !argv[2][1])
				return cli_arg_help(cli, 1, NULL);

			return CLI_OK;
		}
	}

	if (argc != 2)
	{
		cli_print(cli, "Specify access-list type and name");
		return CLI_OK;
	}

	if (MATCH("standard", argv[0]))
		extended = 0;
	else if (MATCH("extended", argv[0]))
		extended = 1;
	else
	{
		cli_print(cli, "Invalid access-list type");
		return CLI_OK;
	}

	if (strlen(argv[1]) > sizeof(ip_filters[0].name) - 1 ||
	    strspn(argv[1], "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") != strlen(argv[1]))
	{
		cli_print(cli, "Invalid access-list name");
		return CLI_OK;
	}

	filt = find_access_list(argv[1]);
	if (add)
	{
		if (filt < 0)
		{
			cli_print(cli, "Too many access-lists");
			return CLI_OK;
		}

		// racy
		if (!*ip_filters[filt].name)
		{
			memset(&ip_filters[filt], 0, sizeof(ip_filters[filt]));
			strcpy(ip_filters[filt].name, argv[1]);
			ip_filters[filt].extended = extended;
		}
		else if (ip_filters[filt].extended != extended)
		{
			cli_print(cli, "Access-list is %s",
				ip_filters[filt].extended ? "extended" : "standard");

			return CLI_OK;
		}

		cli_set_configmode(cli, MODE_CONFIG_NACL, extended ? "ext-nacl" : "std-nacl");
		return CLI_OK;
	}

	if (filt < 0 || !*ip_filters[filt].name)
	{
		cli_print(cli, "Access-list not defined");
		return CLI_OK;
	}

	// racy
	if (ip_filters[filt].used)
	{
		cli_print(cli, "Access-list in use");
		return CLI_OK;
	}

	memset(&ip_filters[filt], 0, sizeof(ip_filters[filt]));
	return CLI_OK;
}

static int cmd_ip_access_list(struct cli_def *cli, char *command, char **argv, int argc)
{
	return access_list(cli, argv, argc, 1);
}

static int cmd_no_ip_access_list(struct cli_def *cli, char *command, char **argv, int argc)
{
	return access_list(cli, argv, argc, 0);
}

static int show_ip_wild(char *buf, in_addr_t ip, in_addr_t wild)
{
	if (ip == INADDR_ANY && wild == INADDR_BROADCAST)
		return sprintf(buf, " any");

	if (wild == INADDR_ANY)
		return sprintf(buf, " host %s", fmtaddr(ip, 0));

	return sprintf(buf, " %s %s", fmtaddr(ip, 0), fmtaddr(wild, 1));
}

static int show_ports(char *buf, ip_filter_portt *ports)
{
	switch (ports->op)
	{
	case FILTER_PORT_OP_EQ:    return sprintf(buf, " eq %u", ports->port);
	case FILTER_PORT_OP_NEQ:   return sprintf(buf, " neq %u", ports->port);
	case FILTER_PORT_OP_GT:    return sprintf(buf, " gt %u", ports->port);
	case FILTER_PORT_OP_LT:    return sprintf(buf, " lt %u", ports->port);
	case FILTER_PORT_OP_RANGE: return sprintf(buf, " range %u %u", ports->port, ports->port2);
	}

	return 0;
}

static char const *show_access_list_rule(int extended, ip_filter_rulet *rule)
{
	static char buf[256];
	char *p = buf;

	p += sprintf(p, " %s", rule->action == FILTER_ACTION_PERMIT ? "permit" : "deny");
	if (extended)
	{
		struct protoent *proto = getprotobynumber(rule->proto);
		p += sprintf(p, " %s", proto ? proto->p_name : "ERR");
	}

	p += show_ip_wild(p, rule->src_ip, rule->src_wild);
	if (!extended)
		return buf;

	if (rule->proto == IPPROTO_TCP || rule->proto == IPPROTO_UDP)
		p += show_ports(p, &rule->src_ports);

	p += show_ip_wild(p, rule->dst_ip, rule->dst_wild);
	if (rule->proto == IPPROTO_TCP || rule->proto == IPPROTO_UDP)
		p += show_ports(p, &rule->dst_ports);

	if (rule->proto == IPPROTO_TCP && rule->tcp_flag_op)
	{
		switch (rule->tcp_flag_op)
		{
		case FILTER_FLAG_OP_EST:
			p += sprintf(p, " established");
			break;

		case FILTER_FLAG_OP_ANY:
		case FILTER_FLAG_OP_ALL:
		    	p += sprintf(p, " match-%s", rule->tcp_flag_op == FILTER_FLAG_OP_ALL ? "all" : "any");
			if (rule->tcp_sflags & TCP_FLAG_FIN) p += sprintf(p, " +fin");
			if (rule->tcp_cflags & TCP_FLAG_FIN) p += sprintf(p, " -fin");
			if (rule->tcp_sflags & TCP_FLAG_SYN) p += sprintf(p, " +syn");
			if (rule->tcp_cflags & TCP_FLAG_SYN) p += sprintf(p, " -syn");
			if (rule->tcp_sflags & TCP_FLAG_RST) p += sprintf(p, " +rst");
			if (rule->tcp_cflags & TCP_FLAG_RST) p += sprintf(p, " -rst");
			if (rule->tcp_sflags & TCP_FLAG_PSH) p += sprintf(p, " +psh");
			if (rule->tcp_cflags & TCP_FLAG_PSH) p += sprintf(p, " -psh");
			if (rule->tcp_sflags & TCP_FLAG_ACK) p += sprintf(p, " +ack");
			if (rule->tcp_cflags & TCP_FLAG_ACK) p += sprintf(p, " -ack");
			if (rule->tcp_sflags & TCP_FLAG_URG) p += sprintf(p, " +urg");
			if (rule->tcp_cflags & TCP_FLAG_URG) p += sprintf(p, " -urg");
			break;
		}
	}

	if (rule->frag)
		p += sprintf(p, " fragments");

	return buf;
}

ip_filter_rulet *access_list_rule_ext(struct cli_def *cli, char *command, char **argv, int argc)
{
	static ip_filter_rulet rule;
	struct in_addr addr;
	int i;
	int a;

	if (CLI_HELP_REQUESTED)
	{
		if (argc == 1)
		{
			cli_arg_help(cli, 0,
				"ip",  "Match IP packets",
				"tcp", "Match TCP packets",
				"udp", "Match UDP packets",
				NULL);

			return NULL;
		}

		// *sigh*, too darned complex
		cli_arg_help(cli, 0, "RULE", "SOURCE [PORTS] DEST [PORTS] FLAGS", NULL);
		return NULL;
	}

	if (argc < 3)
	{
		cli_print(cli, "Specify rule details");
		return NULL;
	}

	memset(&rule, 0, sizeof(rule));
	rule.action = (command[0] == 'p')
		? FILTER_ACTION_PERMIT
		: FILTER_ACTION_DENY;

	if (MATCH("ip", argv[0]))
		rule.proto = IPPROTO_IP;
	else if (MATCH("udp", argv[0]))
		rule.proto = IPPROTO_UDP;
	else if (MATCH("tcp", argv[0]))
		rule.proto = IPPROTO_TCP;
	else
	{
		cli_print(cli, "Invalid protocol \"%s\"", argv[0]);
		return NULL;
	}

	for (a = 1, i = 0; i < 2; i++)
	{
	    	in_addr_t *ip;
		in_addr_t *wild;
		ip_filter_portt *port;

		if (i == 0)
		{
			ip = &rule.src_ip;
			wild = &rule.src_wild;
			port = &rule.src_ports;
		}
		else
		{
			ip = &rule.dst_ip;
			wild = &rule.dst_wild;
			port = &rule.dst_ports;
			if (a >= argc)
			{
				cli_print(cli, "Specify destination");
				return NULL;
			}
		}

		if (MATCH("any", argv[a]))
		{
			*ip = INADDR_ANY;
			*wild = INADDR_BROADCAST;
			a++;
		}
		else if (MATCH("host", argv[a]))
		{
			if (++a >= argc)
			{
				cli_print(cli, "Specify host ip address");
				return NULL;
			}

			if (!inet_aton(argv[a], &addr))
			{
				cli_print(cli, "Cannot parse IP \"%s\"", argv[a]);
				return NULL;
			}

			*ip = addr.s_addr;
			*wild = INADDR_ANY;
			a++;
		}
		else
		{
			if (a >= argc - 1)
			{
				cli_print(cli, "Specify %s ip address and wildcard", i ? "destination" : "source");
				return NULL;
			}

			if (!inet_aton(argv[a], &addr))
			{
				cli_print(cli, "Cannot parse IP \"%s\"", argv[a]);
				return NULL;
			}

			*ip = addr.s_addr;

			if (!inet_aton(argv[++a], &addr))
			{
				cli_print(cli, "Cannot parse IP \"%s\"", argv[a]);
				return NULL;
			}

			*wild = addr.s_addr;
			a++;
		}

		if (rule.proto == IPPROTO_IP || a >= argc)
			continue;

		port->op = 0;
		if (MATCH("eq", argv[a]))
			port->op = FILTER_PORT_OP_EQ;
		else if (MATCH("neq", argv[a]))
			port->op = FILTER_PORT_OP_NEQ;
		else if (MATCH("gt", argv[a]))
			port->op = FILTER_PORT_OP_GT;
		else if (MATCH("lt", argv[a]))
			port->op = FILTER_PORT_OP_LT;
		else if (MATCH("range", argv[a]))
			port->op = FILTER_PORT_OP_RANGE;

		if (!port->op)
			continue;

		if (++a >= argc)
		{
			cli_print(cli, "Specify port");
			return NULL;
		}

		if (!(port->port = atoi(argv[a])))
		{
			cli_print(cli, "Invalid port \"%s\"", argv[a]);
			return NULL;
		}
			
		a++;
		if (port->op != FILTER_PORT_OP_RANGE)
			continue;

		if (a >= argc)
		{
			cli_print(cli, "Specify port");
			return NULL;
		}

		if (!(port->port2 = atoi(argv[a])) || port->port2 < port->port)
		{
			cli_print(cli, "Invalid port \"%s\"", argv[a]);
			return NULL;
		}
			
		a++;
	}

	if (rule.proto == IPPROTO_TCP && a < argc)
	{
		if (MATCH("established", argv[a]))
		{
			rule.tcp_flag_op = FILTER_FLAG_OP_EST;
		    	a++;
		}
		else if (!strcmp(argv[a], "match-any") || !strcmp(argv[a], "match-an") ||
			 !strcmp(argv[a], "match-all") || !strcmp(argv[a], "match-al"))
		{
			rule.tcp_flag_op = argv[a][7] == 'n'
				? FILTER_FLAG_OP_ANY
				: FILTER_FLAG_OP_ALL;

			if (++a >= argc)
			{
				cli_print(cli, "Specify tcp flags");
				return NULL;
			}

			while (a < argc && (argv[a][0] == '+' || argv[a][0] == '-'))
			{
			    	uint8_t *f;

				f = (argv[a][0] == '+') ? &rule.tcp_sflags : &rule.tcp_cflags;

				if (MATCH("fin", &argv[a][1]))      *f |= TCP_FLAG_FIN;
				else if (MATCH("syn", &argv[a][1])) *f |= TCP_FLAG_SYN;
				else if (MATCH("rst", &argv[a][1])) *f |= TCP_FLAG_RST;
				else if (MATCH("psh", &argv[a][1])) *f |= TCP_FLAG_PSH;
				else if (MATCH("ack", &argv[a][1])) *f |= TCP_FLAG_ACK;
				else if (MATCH("urg", &argv[a][1])) *f |= TCP_FLAG_URG;
				else
				{
					cli_print(cli, "Invalid tcp flag \"%s\"", argv[a]);
					return NULL;
				}

				a++;
			}
		}
	}

	if (a < argc && MATCH("fragments", argv[a]))
	{
		if (rule.src_ports.op || rule.dst_ports.op || rule.tcp_flag_op)
		{
			cli_print(cli, "Can't specify \"fragments\" on rules with layer 4 matches");
			return NULL;
		}

	    	rule.frag = 1;
		a++;
	}

	if (a < argc)
	{
		cli_print(cli, "Invalid flag \"%s\"", argv[a]);
		return NULL;
	}

	return &rule;
}

ip_filter_rulet *access_list_rule_std(struct cli_def *cli, char *command, char **argv, int argc)
{
	static ip_filter_rulet rule;
	struct in_addr addr;

	if (CLI_HELP_REQUESTED)
	{
		if (argc == 1)
		{
			cli_arg_help(cli, argv[0][1],
				"A.B.C.D", "Source address",
				"any",     "Any source address",
				"host",    "Source host",
				NULL);

			return NULL;
		}

		if (MATCH("any", argv[0]))
		{
			if (argc == 2 && !argv[1][1])
				cli_arg_help(cli, 1, NULL);
		}
		else if (MATCH("host", argv[0]))
		{
			if (argc == 2)
			{
				cli_arg_help(cli, argv[1][1],
					"A.B.C.D", "Host address",
					NULL);
			}
			else if (argc == 3 && !argv[2][1])
				cli_arg_help(cli, 1, NULL);
		}
		else
		{
			if (argc == 2)
			{
				cli_arg_help(cli, 1,
					"A.B.C.D", "Wildcard bits",
					NULL);
			}
			else if (argc == 3 && !argv[2][1])
				cli_arg_help(cli, 1, NULL);
		}

		return NULL;
	}

	if (argc < 1)
	{
		cli_print(cli, "Specify rule details");
		return NULL;
	}

	memset(&rule, 0, sizeof(rule));
	rule.action = (command[0] == 'p')
		? FILTER_ACTION_PERMIT
		: FILTER_ACTION_DENY;

	rule.proto = IPPROTO_IP;
	if (MATCH("any", argv[0]))
	{
		rule.src_ip = INADDR_ANY;
		rule.src_wild = INADDR_BROADCAST;
	}
	else if (MATCH("host", argv[0]))
	{
		if (argc != 2)
		{
			cli_print(cli, "Specify host ip address");
			return NULL;
		}

		if (!inet_aton(argv[1], &addr))
		{
			cli_print(cli, "Cannot parse IP \"%s\"", argv[1]);
			return NULL;
		}

		rule.src_ip = addr.s_addr;
		rule.src_wild = INADDR_ANY;
	}
	else
	{
		if (argc > 2)
		{
			cli_print(cli, "Specify source ip address and wildcard");
			return NULL;
		}

		if (!inet_aton(argv[0], &addr))
		{
			cli_print(cli, "Cannot parse IP \"%s\"", argv[0]);
			return NULL;
		}

		rule.src_ip = addr.s_addr;

		if (argc > 1)
		{
			if (!inet_aton(argv[1], &addr))
			{
				cli_print(cli, "Cannot parse IP \"%s\"", argv[1]);
				return NULL;
			}

			rule.src_wild = addr.s_addr;
		}
		else
			rule.src_wild = INADDR_ANY;
	}

	return &rule;
}

static int cmd_ip_access_list_rule(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	ip_filter_rulet *rule = ip_filters[filt].extended
		? access_list_rule_ext(cli, command, argv, argc)
		: access_list_rule_std(cli, command, argv, argc);

	if (!rule)
		return CLI_OK;

	for (i = 0; i < MAXFILTER_RULES - 1; i++) // -1: list always terminated by empty rule
	{
		if (!ip_filters[filt].rules[i].action)
		{
			memcpy(&ip_filters[filt].rules[i], rule, sizeof(*rule));
			return CLI_OK;
		}

		if (!memcmp(&ip_filters[filt].rules[i], rule, sizeof(*rule)))
			return CLI_OK;
	}

	cli_print(cli, "Too many rules");
	return CLI_OK;
}

static int cmd_filter(struct cli_def *cli, char *command, char **argv, int argc)
{
	sessionidt s;
	int i;

	/* filter USER {in|out} FILTER ... */
	if (CLI_HELP_REQUESTED)
	{
		switch (argc)
		{
		case 1:
			return cli_arg_help(cli, 0,
				"USER", "Username of session to filter", NULL);

		case 2:
		case 4:
			return cli_arg_help(cli, 0,
				"in",   "Set incoming filter",
				"out",  "Set outgoing filter", NULL);

		case 3:
		case 5:
			return cli_arg_help(cli, argc == 5 && argv[4][1],
				"NAME", "Filter name", NULL);

		default:
			return cli_arg_help(cli, argc > 1, NULL);
		}
	}

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s",
			fmtaddr(config->cluster_master_address, 0));

		return CLI_OK;
	}

	if (argc != 3 && argc != 5)
	{
		cli_print(cli, "Specify a user and filters");
		return CLI_OK;
	}

	if (!(s = sessionbyuser(argv[0])))
	{
		cli_print(cli, "User %s is not connected", argv[0]);
		return CLI_OK;
	}

	cli_session_actions[s].filter_in = cli_session_actions[s].filter_out = -1;
	for (i = 1; i < argc; i += 2)
	{
		int *f = 0;
		int v;

		if (MATCH("in", argv[i]))
		{
			if (session[s].filter_in)
			{
				cli_print(cli, "Input already filtered");
				return CLI_OK;
			}
			f = &cli_session_actions[s].filter_in;
		}
		else if (MATCH("out", argv[i]))
		{
			if (session[s].filter_out)
			{
				cli_print(cli, "Output already filtered");
				return CLI_OK;
			}
			f = &cli_session_actions[s].filter_out;
		}
		else
		{
			cli_print(cli, "Invalid filter specification");
			return CLI_OK;
		}

		v = find_access_list(argv[i+1]);
		if (v < 0 || !*ip_filters[v].name)
		{
			cli_print(cli, "Access-list %s not defined", argv[i+1]);
			return CLI_OK;
		}

		*f = v + 1;
	}

	cli_print(cli, "Filtering user %s", argv[0]);
	cli_session_actions[s].action |= CLI_SESS_FILTER;

	return CLI_OK;
}

static int cmd_no_filter(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;
	sessionidt s;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1,
			"USER", "Username of session to remove filters from", NULL);

	if (!config->cluster_iam_master)
	{
		cli_print(cli, "Can't do this on a slave.  Do it on %s",
			fmtaddr(config->cluster_master_address, 0));

		return CLI_OK;
	}

	if (!argc)
	{
		cli_print(cli, "Specify a user to remove filters from");
		return CLI_OK;
	}

	for (i = 0; i < argc; i++)
	{
		if (!(s = sessionbyuser(argv[i])))
		{
			cli_print(cli, "User %s is not connected", argv[i]);
			continue;
		}

		if (session[s].filter_in || session[s].filter_out)
		{
			cli_print(cli, "Removing filters from user %s", argv[i]);
			cli_session_actions[s].action |= CLI_SESS_NOFILTER;
		}
		else
		{
			cli_print(cli, "User %s not filtered", argv[i]);
		}
	}

	return CLI_OK;
}

static int cmd_show_access_list(struct cli_def *cli, char *command, char **argv, int argc)
{
	int i;

	if (CLI_HELP_REQUESTED)
		return cli_arg_help(cli, argc > 1, "NAME", "Filter name", NULL);

	if (argc < 1)
	{
		cli_print(cli, "Specify a filter name");
		return CLI_OK;
	}

	for (i = 0; i < argc; i++)
	{
		int f = find_access_list(argv[i]);
		ip_filter_rulet *rules;

		if (f < 0 || !*ip_filters[f].name)
		{
			cli_print(cli, "Access-list %s not defined", argv[i]);
			return CLI_OK;
		}

		if (i)
			cli_print(cli, "");

		cli_print(cli, "%s IP access list %s",
			ip_filters[f].extended ? "Extended" : "Standard",
			ip_filters[f].name);

		for (rules = ip_filters[f].rules; rules->action; rules++)
		{
			char const *r = show_access_list_rule(ip_filters[f].extended, rules);
		    	if (rules->counter)
				cli_print(cli, "%s (%d match%s)", r,
					rules->counter, rules->counter > 1 ? "es" : "");
			else
				cli_print(cli, "%s", r);
		}
	}

	return CLI_OK;
}

// Convert a string in the form of abcd.ef12.3456 into char[6]
void parsemac(char *string, char mac[6])
{
	if (sscanf(string, "%02x%02x.%02x%02x.%02x%02x", (unsigned int *)&mac[0], (unsigned int *)&mac[1], (unsigned int *)&mac[2], (unsigned int *)&mac[3], (unsigned int *)&mac[4], (unsigned int *)&mac[5]) == 6)
		return;
	if (sscanf(string, "%02x%02x:%02x%02x:%02x%02x", (unsigned int *)&mac[0], (unsigned int *)&mac[1], (unsigned int *)&mac[2], (unsigned int *)&mac[3], (unsigned int *)&mac[4], (unsigned int *)&mac[5]) == 6)
		return;
	memset(mac, 0, 6);
}
