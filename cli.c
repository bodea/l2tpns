// L2TPNS Command Line Interface
// $Id: cli.c,v 1.1.1.1 2003-12-16 07:07:39 fred_nerk Exp $
// vim: sw=4 ts=8

#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
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
#include <libcli.h>
#include "l2tpns.h"
#include "util.h"
#include "config.h"

#ifdef HAVE_LIBCLI

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
#ifdef RINGBUFFER
extern struct Tringbuffer *ringbuffer;
#endif

char *rcs_id = "$Id: cli.c,v 1.1.1.1 2003-12-16 07:07:39 fred_nerk Exp $";

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

int cmd_show_session(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_show_tunnels(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_show_users(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_show_counters(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_show_version(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_show_pool(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_show_banana(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_clear_counters(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_drop_user(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_drop_tunnel(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_drop_session(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_snoop(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_no_snoop(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_throttle(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_no_throttle(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_debug(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_no_debug(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_watch_session(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int cmd_watch_tunnel(struct cli_def *cli, FILE *w, char *command, char **argv, int argc);
int regular_stuff(struct cli_def *cli, FILE *w);

void init_cli()
{
    FILE *f;
    char buf[4096];
    struct cli_command *c;
    int on = 1;
    struct sockaddr_in addr;

    cli = cli_init();

    c = cli_register_command(cli, NULL, "show", NULL, NULL);
    cli_register_command(cli, c, "session", cmd_show_session, "Show a list of sessions");
    cli_register_command(cli, c, "tunnels", cmd_show_tunnels, NULL);
    cli_register_command(cli, c, "users", cmd_show_users, NULL);
    cli_register_command(cli, c, "version", cmd_show_version, NULL);
    cli_register_command(cli, c, "banana", cmd_show_banana, "Show a banana");
    cli_register_command(cli, c, "pool", cmd_show_pool, NULL);

#ifdef STATISTICS
    cli_register_command(cli, c, "counters", cmd_show_counters, NULL);

    c = cli_register_command(cli, NULL, "clear", NULL, NULL);
    cli_register_command(cli, c, "counters", cmd_clear_counters, NULL);
#endif

    cli_register_command(cli, NULL, "snoop", cmd_snoop, NULL);
    cli_register_command(cli, NULL, "throttle", cmd_throttle, NULL);

    c = cli_register_command(cli, NULL, "no", NULL, NULL);
    cli_register_command(cli, c, "snoop", cmd_no_snoop, NULL);
    cli_register_command(cli, c, "throttle", cmd_no_throttle, NULL);
    cli_register_command(cli, c, "debug", cmd_no_debug, NULL);

    c = cli_register_command(cli, NULL, "drop", NULL, NULL);
    cli_register_command(cli, c, "user", cmd_drop_user, NULL);
    cli_register_command(cli, c, "tunnel", cmd_drop_tunnel, NULL);
    cli_register_command(cli, c, "session", cmd_drop_session, NULL);

    cli_register_command(cli, NULL, "debug", cmd_debug, "Specify a debugging level");

    c = cli_register_command(cli, NULL, "watch", NULL, NULL);
    cli_register_command(cli, c, "session", cmd_watch_session, "Dump logs for a tunnel");
    cli_register_command(cli, c, "tunnel", cmd_watch_tunnel, "Dump logs for a tunnel");

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
    if ((cli_pid = fork())) return;

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

    cli_loop(cli, sockfd, "l2tpns> ");

    close(sockfd);
    log(3, 0, 0, 0, "Closed CLI connection\n");
    exit(0);
}

int cmd_show_session(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
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
		fprintf(w, "Invalid session id \"%s\"\r\n", argv[i]);
		continue;
	    }
	    fprintf(w, "\r\nSession %d:\r\n", s);
	    fprintf(w, "	User:		%s\r\n", session[s].user[0] ? session[s].user : "none");
	    fprintf(w, "	Calling Num:	%s\r\n", session[s].calling);
	    fprintf(w, "	Called Num:	%s\r\n", session[s].called);
	    fprintf(w, "	Tunnel ID:	%d\r\n", session[s].tunnel);
	    fprintf(w, "	IP address:	%s\r\n", inet_toa(htonl(session[s].ip)));
	    fprintf(w, "	HSD sid:	%lu\r\n", session[s].sid);
	    fprintf(w, "	Idle time:	%u seconds\r\n", abs(time_now - session[s].last_packet));
	    fprintf(w, "	Next Recv:	%u\r\n", session[s].nr);
	    fprintf(w, "	Next Send:	%u\r\n", session[s].ns);
	    fprintf(w, "	Bytes In/Out:	%lu/%lu\r\n", (unsigned long)session[s].cin, (unsigned long)session[s].cout);
	    fprintf(w, "	Pkts In/Out:	%lu/%lu\r\n", (unsigned long)session[s].pin, (unsigned long)session[s].pout);
	    fprintf(w, "	Radius Session:	%u\r\n", session[s].radius);
	    fprintf(w, "	Rx Speed:	%lu\r\n", session[s].rx_connect_speed);
	    fprintf(w, "	Tx Speed:	%lu\r\n", session[s].tx_connect_speed);
	    fprintf(w, "	Intercepted:	%s\r\n", session[s].snoop ? "YES" : "no");
	    fprintf(w, "	Throttled:	%s\r\n", session[s].throttle ? "YES" : "no");
	    fprintf(w, "	Walled Garden:	%s\r\n", session[s].walled_garden ? "YES" : "no");
	    fprintf(w, "	Filter Bucket:	%s\r\n", session[s].tbf ? filter_buckets[session[s].tbf].handle : "none");
	}
	return CLI_OK;
    }

    // Show Summary
    fprintf(w, "  %s %4s %-32s %-15s %s %s %s %10s %10s %10s %4s %-15s %s\r\n",
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
    for (i = 0; i < MAXSESSION; i++)
    {
	char *userip, *tunnelip;
	if (!session[i].opened) continue;
	userip = strdup(inet_toa(htonl(session[i].ip)));
	tunnelip = strdup(inet_toa(htonl(tunnel[ session[i].tunnel ].ip)));
	fprintf(w, "%5d %4d %-32s %-15s %s %s %s %10lu %10lu %10lu %4u %-15s %s\r\n",
		i,
		session[i].tunnel,
		session[i].user[0] ? session[i].user : "*",
		userip,
		(session[i].snoop) ? "Y" : "N",
		(session[i].throttle) ? "Y" : "N",
		(session[i].walled_garden) ? "Y" : "N",
		(unsigned long)session[i].opened,
		(unsigned long)session[i].cout,
		(unsigned long)session[i].cin,
		abs(time_now - (session[i].last_packet ? session[i].last_packet : time_now)),
                tunnelip,
		session[i].calling[0] ? session[i].calling : "*");
	if (userip) free(userip);
	if (tunnelip) free(tunnelip);
    }
    return CLI_OK;
}

int cmd_show_tunnels(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    int i, x;
    time_t time_now;

    time(&time_now);
    if (argc > 0)
    {
	// Show individual tunnel
	for (i = 0; i < argc; i++)
	{
	    char s[65535] = {0};
	    unsigned int t;
	    t = atoi(argv[i]);
	    if (!t || t > MAXTUNNEL)
	    {
		fprintf(w, "Invalid tunnel id \"%s\"\r\n", argv[i]);
		continue;
	    }
	    fprintf(w, "\r\nTunnel %d:\r\n", t);
	    fprintf(w, "	Hostname:	%s\r\n", tunnel[t].hostname[0] ? tunnel[t].hostname : "(none)");
	    fprintf(w, "	Remote IP:	%s\r\n", inet_toa(htonl(tunnel[t].ip)));
	    fprintf(w, "	Remote Port:	%d\r\n", tunnel[t].port);
	    fprintf(w, "	Rx Window:	%u\r\n", tunnel[t].window);
	    fprintf(w, "	Next Recv:	%u\r\n", tunnel[t].nr);
	    fprintf(w, "	Next Send:	%u\r\n", tunnel[t].ns);
	    fprintf(w, "	Queue Len:	%u\r\n", tunnel[t].controlc);
	    fprintf(w, "	Last Packet Age:%u\r\n", (unsigned)(time_now - tunnel[t].last));

	    for (x = 0; x < MAXSESSION; x++)
		    if (session[x].tunnel == t && session[x].opened && !session[x].die)
			    sprintf(s, "%s%u ", s, x);
	    fprintf(w, "	Sessions:	%s\r\n", s);
	}
	return CLI_OK;
    }

    // Show tunnel summary
    fprintf(w, "%s %s %s %s\r\n",
	    "TID",
	    "Hostname",
	    "IP",
	    "Sessions");
    for (i = 0; i < MAXTUNNEL; i++)
    {
	int sessions = 0;
	if (!tunnel[i].ip || tunnel[i].die || !tunnel[i].hostname[0]) continue;

	for (x = 0; x < MAXSESSION; x++) if (session[x].tunnel == i && session[x].opened && !session[x].die) sessions++;
	fprintf(w, "%d %s %s %d\r\n",
		i,
		tunnel[i].hostname,
		inet_toa(htonl(tunnel[i].ip)),
		sessions);
    }
    return CLI_OK;
}

int cmd_show_users(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    int i;
    for (i = 0; i < MAXSESSION; i++)
    {
	if (!session[i].opened) continue;
	if (!session[i].user[0]) continue;
	fprintf(w, "%s\r\n",
		session[i].user);
    }
    return CLI_OK;
}

int cmd_show_counters(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    fprintf(w, "%-10s %-8s %-10s %-8s\r\n", "Ethernet", "Bytes", "Packets", "Errors");
    fprintf(w, "%-10s %8lu %8lu %8lu\r\n", "RX",
	    GET_STAT(tap_rx_bytes),
	    GET_STAT(tap_rx_packets),
	    GET_STAT(tap_rx_errors));
    fprintf(w, "%-10s %8lu %8lu %8lu\r\n", "TX",
	    GET_STAT(tap_tx_bytes),
	    GET_STAT(tap_tx_packets),
	    GET_STAT(tap_tx_errors));
    fprintf(w, "\r\n");

    fprintf(w, "%-10s %-8s %-10s %-8s %-8s\r\n", "Tunnel", "Bytes", "Packets", "Errors", "Retries");
    fprintf(w, "%-10s %8lu %8lu %8lu %8lu\r\n", "RX",
	    GET_STAT(tunnel_rx_bytes),
	    GET_STAT(tunnel_rx_packets),
	    GET_STAT(tunnel_rx_errors),
	    0L);
    fprintf(w, "%-10s %8lu %8lu %8lu %8lu\r\n", "TX",
	    GET_STAT(tunnel_tx_bytes),
	    GET_STAT(tunnel_tx_packets),
	    GET_STAT(tunnel_rx_errors),
	    GET_STAT(tunnel_retries));
    fprintf(w, "\r\n");

    fprintf(w, "%-30s%-10s\r\n", "Counter", "Value");
    fprintf(w, "-----------------------------------------\r\n");
    fprintf(w, "%-30s%lu\r\n", "radius_retries",	GET_STAT(radius_retries));
    fprintf(w, "%-30s%lu\r\n", "arp_errors",		GET_STAT(arp_errors));
    fprintf(w, "%-30s%lu\r\n", "arp_replies",		GET_STAT(arp_replies));
    fprintf(w, "%-30s%lu\r\n", "arp_discarded",		GET_STAT(arp_discarded));
    fprintf(w, "%-30s%lu\r\n", "arp_sent",		GET_STAT(arp_sent));
    fprintf(w, "%-30s%lu\r\n", "arp_recv",		GET_STAT(arp_recv));
    fprintf(w, "%-30s%lu\r\n", "packets_snooped",	GET_STAT(packets_snooped));
    fprintf(w, "%-30s%lu\r\n", "tunnel_created",	GET_STAT(tunnel_created));
    fprintf(w, "%-30s%lu\r\n", "session_created",	GET_STAT(session_created));
    fprintf(w, "%-30s%lu\r\n", "tunnel_timeout",	GET_STAT(tunnel_timeout));
    fprintf(w, "%-30s%lu\r\n", "session_timeout",	GET_STAT(session_timeout));
    fprintf(w, "%-30s%lu\r\n", "radius_timeout",	GET_STAT(radius_timeout));
    fprintf(w, "%-30s%lu\r\n", "radius_overflow",	GET_STAT(radius_overflow));
    fprintf(w, "%-30s%lu\r\n", "tunnel_overflow",	GET_STAT(tunnel_overflow));
    fprintf(w, "%-30s%lu\r\n", "session_overflow",	GET_STAT(session_overflow));
    fprintf(w, "%-30s%lu\r\n", "ip_allocated",		GET_STAT(ip_allocated));
    fprintf(w, "%-30s%lu\r\n", "ip_freed",		GET_STAT(ip_freed));

#ifdef STAT_CALLS
    fprintf(w, "\n%-30s%-10s\r\n", "Counter", "Value");
    fprintf(w, "-----------------------------------------\r\n");
    fprintf(w, "%-30s%lu\r\n", "call_processtap",	GET_STAT(call_processtap));
    fprintf(w, "%-30s%lu\r\n", "call_processarp",	GET_STAT(call_processarp));
    fprintf(w, "%-30s%lu\r\n", "call_processipout",	GET_STAT(call_processipout));
    fprintf(w, "%-30s%lu\r\n", "call_processudp",	GET_STAT(call_processudp));
    fprintf(w, "%-30s%lu\r\n", "call_processpap",	GET_STAT(call_processpap));
    fprintf(w, "%-30s%lu\r\n", "call_processchap",	GET_STAT(call_processchap));
    fprintf(w, "%-30s%lu\r\n", "call_processlcp",	GET_STAT(call_processlcp));
    fprintf(w, "%-30s%lu\r\n", "call_processipcp",	GET_STAT(call_processipcp));
    fprintf(w, "%-30s%lu\r\n", "call_processipin",	GET_STAT(call_processipin));
    fprintf(w, "%-30s%lu\r\n", "call_processccp",	GET_STAT(call_processccp));
    fprintf(w, "%-30s%lu\r\n", "call_processrad",	GET_STAT(call_processrad));
    fprintf(w, "%-30s%lu\r\n", "call_sendarp",		GET_STAT(call_sendarp));
    fprintf(w, "%-30s%lu\r\n", "call_sendipcp",		GET_STAT(call_sendipcp));
    fprintf(w, "%-30s%lu\r\n", "call_sendchap",		GET_STAT(call_sendchap));
    fprintf(w, "%-30s%lu\r\n", "call_sessionbyip",	GET_STAT(call_sessionbyip));
    fprintf(w, "%-30s%lu\r\n", "call_sessionbyuser",	GET_STAT(call_sessionbyuser));
    fprintf(w, "%-30s%lu\r\n", "call_tunnelsend",	GET_STAT(call_tunnelsend));
    fprintf(w, "%-30s%lu\r\n", "call_tunnelkill",	GET_STAT(call_tunnelkill));
    fprintf(w, "%-30s%lu\r\n", "call_tunnelshutdown",	GET_STAT(call_tunnelshutdown));
    fprintf(w, "%-30s%lu\r\n", "call_sessionkill",	GET_STAT(call_sessionkill));
    fprintf(w, "%-30s%lu\r\n", "call_sessionshutdown",	GET_STAT(call_sessionshutdown));
    fprintf(w, "%-30s%lu\r\n", "call_sessionsetup",	GET_STAT(call_sessionsetup));
    fprintf(w, "%-30s%lu\r\n", "call_assign_ip_address",GET_STAT(call_assign_ip_address));
    fprintf(w, "%-30s%lu\r\n", "call_free_ip_address",	GET_STAT(call_free_ip_address));
    fprintf(w, "%-30s%lu\r\n", "call_dump_acct_info",	GET_STAT(call_dump_acct_info));
    fprintf(w, "%-30s%lu\r\n", "call_radiussend",	GET_STAT(call_radiussend));
    fprintf(w, "%-30s%lu\r\n", "call_radiusretry",	GET_STAT(call_radiusretry));
#endif
    return CLI_OK;
}

int cmd_show_version(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    fprintf(w, "L2TPNS %s\r\n", VERSION);
    fprintf(w, "ID: %s\r\n", rcs_id);
    return CLI_OK;
}
int cmd_show_pool(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    int i;
    int used = 0, free = 0;

    fprintf(w, "%-15s  %4s   %8s %s\r\n", "IP Address", "Used", "Session", "User");
    for (i = 0; i < MAXIPPOOL; i++)
    {
	sessionidt s = 0;

	if (!ip_address_pool[i].address) continue;
	if (ip_address_pool[i].assigned)
	{
	    used++;
	    s = sessionbyip(ip_address_pool[i].address);
	}
	else
	{
	    free++;
	}

	fprintf(w, "%-15s %4s %8d %s\r\n",
		inet_toa(ip_address_pool[i].address),
		(s) ? "Y" : "N",
		s,
		session[s].user);
    }
    fprintf(w, "\r\nFree: %d\r\nUsed: %d\r\n", free, used);
    return CLI_OK;
}
int cmd_show_banana(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    fputs(" _\r\n"
          "//\\\r\n"
          "V  \\\r\n"
          " \\  \\_\r\n"
          "  \\,'.`-.\r\n"
          "   |\\ `. `.\r\n"
          "   ( \\  `. `-.                        _,.-:\\\r\n"
          "    \\ \\   `.  `-._             __..--' ,-';/\r\n"
          "     \\ `.   `-.   `-..___..---'   _.--' ,'/\r\n"
          "      `. `.    `-._        __..--'    ,' /\r\n"
          "        `. `-_     ``--..''       _.-' ,'\r\n"
          "          `-_ `-.___        __,--'   ,'\r\n"
          "             `-.__  `----\"\"\"    __.-'\r\n"
          "hh                `--..____..--'\r\n", w);

    return CLI_OK;
}

int cmd_clear_counters(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    fprintf(w, "Counters cleared\r\n");
    SET_STAT(last_reset, time(NULL));
    return CLI_OK;
}

int cmd_drop_user(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    int i;
    sessionidt s;

    if (!argc)
    {
	fprintf(w, "Specify a user to drop\r\n");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    fprintf(w, "username ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	if (!(s = sessionbyuser(argv[i])))
	{
	    fprintf(w, "User %s is not connected\r\n", argv[i]);
	    continue;
	}

	if (session[s].ip && session[s].opened && !session[s].die)
	{
	    int x;

	    fprintf(w, "Dropping user %s\r\n", session[s].user);
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

int cmd_drop_tunnel(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    int i;
    tunnelidt tid;

    if (!argc)
    {
	fprintf(w, "Specify a tunnel to drop\r\n");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    fprintf(w, "tunnel_id ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	int x;

	if ((tid = atol(argv[i])) <= 0 || (tid > MAXTUNNEL))
	{
	    fprintf(w, "Invalid tunnel ID (%d - %d)\r\n", 0, MAXTUNNEL);
	    continue;
	}

	if (!tunnel[tid].ip)
	{
	    fprintf(w, "Tunnel %d is not connected\r\n", tid);
	    continue;
	}

	if (tunnel[tid].die)
	{
	    fprintf(w, "Tunnel %d is already being shut down\r\n", tid);
	    continue;
	}

	for (x = 0; x < MAXTUNNEL; x++)
	{
	    if (!cli_tunnel_kill[x])
	    {
		cli_tunnel_kill[x] = tid;
		fprintf(w, "Tunnel %d shut down (%s)\r\n", tid, tunnel[tid].hostname);
		break;
	    }
	}
    }

    return CLI_OK;
}

int cmd_drop_session(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    int i;
    sessionidt s;

    if (!argc)
    {
	fprintf(w, "Specify a session id to drop\r\n");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    fprintf(w, "session_id ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	if ((s = atol(argv[i])) <= 0 || (s > MAXSESSION))
	{
	    fprintf(w, "Invalid session ID (%d - %d)\r\n", 0, MAXSESSION);
	    continue;
	}

	if (session[s].ip && session[s].opened && !session[s].die)
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
	    fprintf(w, "Dropping session %d\r\n", s);
	}
	else
	{
	    fprintf(w, "Session %d is not active.\r\n", s);
	}
    }

    return CLI_OK;
}

int cmd_snoop(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    int i;
    sessionidt s;

    if (!argc)
    {
	fprintf(w, "Specify a user\r\n");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    fprintf(w, "username ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	if (!(s = sessionbyuser(argv[i])))
	{
	    fprintf(w, "User %s is not connected\r\n", argv[i]);
	    continue;
	}
	session[s].snoop = 1;

	fprintf(w, "Snooping user %s\r\n", argv[i]);
    }
    return CLI_OK;
}

int cmd_no_snoop(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    int i;
    sessionidt s;

    if (!argc)
    {
	fprintf(w, "Specify a user\r\n");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    fprintf(w, "username ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	if (!(s = sessionbyuser(argv[i])))
	{
	    fprintf(w, "User %s is not connected\r\n", argv[i]);
	    continue;
	}
	session[s].snoop = 0;

	fprintf(w, "Not snooping user %s\r\n", argv[i]);
    }
    return CLI_OK;
}

int cmd_throttle(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    int i;
    sessionidt s;

    if (!argc)
    {
	fprintf(w, "Specify a user\r\n");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    fprintf(w, "username ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
    {
	if (!(s = sessionbyuser(argv[i])))
	{
	    fprintf(w, "User %s is not connected\r\n", argv[i]);
	    continue;
	}
	throttle_session(s, 1);

	fprintf(w, "throttling user %s\r\n", argv[i]);
    }
    return CLI_OK;
}

int cmd_no_throttle(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    int i;
    sessionidt s;

    if (!argc)
    {
	fprintf(w, "Specify a user\r\n");
	return CLI_OK;
    }
    for (i = 0; i < argc; i++)
    {
	if (strchr(argv[i], '?'))
	{
	    fprintf(w, "username ...");
	    return CLI_OK;
	}
    }

    for (i = 0; i < argc; i++)
	{
	if (!(s = sessionbyuser(argv[i])))
	{
	    fprintf(w, "User %s is not connected\r\n", argv[i]);
	    continue;
	}
	throttle_session(s, 0);

	fprintf(w, "unthrottling user %s\r\n", argv[i]);
    }
    return CLI_OK;
}

int cmd_debug(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    int i;

    if (!argc)
    {
	fprintf(w, "Currently debugging: ");
	if (debug_flags.critical) fprintf(w, "critical ");
	if (debug_flags.error) fprintf(w, "error ");
	if (debug_flags.warning) fprintf(w, "warning ");
	if (debug_flags.info) fprintf(w, "info ");
	if (debug_flags.calls) fprintf(w, "calls ");
	if (debug_flags.data) fprintf(w, "data ");
	fprintf(w, "\r\n");
	return CLI_OK;
    }

    for (i = 0; i < argc; i++)
    {
	if (*argv[i] == '?')
	{
	    fprintf(w, "Possible debugging states are:\r\n");
	    fprintf(w, "	critical\r\n");
	    fprintf(w, "	error\r\n");
	    fprintf(w, "	warning\r\n");
	    fprintf(w, "	info\r\n");
	    fprintf(w, "	calls\r\n");
	    fprintf(w, "	data\r\n");
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

int cmd_no_debug(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
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

int cmd_watch_session(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    sessionidt s;

    if (argc != 1)
    {
	fprintf(w, "Specify a single session to debug (0 to disable)\r\n");
	return CLI_OK;
    }
    s = atoi(argv[0]);

    if (debug_session)
	fprintf(w, "No longer debugging session %d\r\n", debug_session);

    if (s) fprintf(w, "Debugging session %d.\r\n", s);
    debug_session = s;

    return CLI_OK;
}

int cmd_watch_tunnel(struct cli_def *cli, FILE *w, char *command, char **argv, int argc)
{
    tunnelidt s;

    if (argc != 1)
    {
	fprintf(w, "Specify a single tunnel to debug (0 to disable)\r\n");
	return CLI_OK;
    }
    s = atoi(argv[0]);

    if (debug_tunnel)
	fprintf(w, "No longer debugging tunnel %d\r\n", debug_tunnel);

    if (s) fprintf(w, "Debugging tunnel %d.\r\n", s);
    debug_tunnel = s;

    return CLI_OK;
}

int regular_stuff(struct cli_def *cli, FILE *w)
{
    int i = debug_rb_tail;

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

	    fprintf(w, "%s-%s-%u-%u %s\r",
		    debug_levels[(int)ringbuffer->buffer[i].level],
		    ipaddr,
		    ringbuffer->buffer[i].tunnel,
		    ringbuffer->buffer[i].session,
		    ringbuffer->buffer[i].message);
	}

	if (++i == ringbuffer->tail) break;
	if (i == RINGBUFFER_SIZE) i = 0;
    }

    debug_rb_tail = ringbuffer->tail;
#endif
    return CLI_OK;
}

#endif
