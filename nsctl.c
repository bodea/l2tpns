/* l2tpns plugin control */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <signal.h>

#include "l2tpns.h"
#include "control.h"

struct {
    char *command;
    char *usage;
    int action;
} builtins[] = {
    { "load_plugin", " PLUGIN                          Load named plugin",		NSCTL_REQ_LOAD },
    { "unload_plugin", " PLUGIN                        Unload named plugin",		NSCTL_REQ_UNLOAD },
    { "help", "                                        List available commands",	NSCTL_REQ_HELP },
    { 0 }
};

static int debug = 0;
static int timeout = 2; // 2 seconds
static char *me;

#define USAGE() fprintf(stderr, "Usage: %s [-d] [-h HOST[:PORT]] [-t TIMEOUT] COMMAND [ARG ...]\n", me)

static struct nsctl *request(char *host, int port, int type, int argc, char *argv[]);

int main(int argc, char *argv[])
{
    int req_type = 0;
    char *host = 0;
    int port;
    int i;
    char *p;
    struct nsctl *res;

    if ((p = strrchr((me = argv[0]), '/')))
    	me = p + 1;

    opterr = 0;
    while ((i = getopt(argc, argv, "dh:t:")) != -1)
	switch (i)
	{
	case 'd':
	    debug++;
	    break;

	case 'h':
	    host = optarg;
	    break;

	case 't':
	    timeout = atoi(optarg);
	    break;

	default:
	    USAGE();
	    return EXIT_FAILURE;
	}

    argc -= optind;
    argv += optind;

    if (argc < 1 || !argv[0][0])
    {
    	USAGE();
	return EXIT_FAILURE;
    }

    if (!host)
    	host = "127.0.0.1";

    if ((p = strchr(host, ':')))
    {
	port = atoi(p + 1);
	if (!port)
	{
	    fprintf(stderr, "%s: invalid port `%s'\n", me, p + 1);
	    return EXIT_FAILURE;
	}

	*p = 0;
    }
    else
    {
	port = NSCTL_PORT;
    }

    for (i = 0; !req_type && builtins[i].command; i++)
	if (!strcmp(argv[0], builtins[i].command))
	    req_type = builtins[i].action;

    if (req_type == NSCTL_REQ_HELP)
    {
	printf("Available commands:\n");
	for (i = 0; builtins[i].command; i++)
	    printf("  %s%s\n", builtins[i].command, builtins[i].usage);
    }

    if (req_type)
    {
	argc--;
	argv++;
    }
    else
    {
	req_type = NSCTL_REQ_CONTROL;
    }

    if ((res = request(host, port, req_type, argc, argv)))
    {
	FILE *stream = stderr;
	int status = EXIT_FAILURE;

	if (res->type == NSCTL_RES_OK)
	{
	    stream = stdout;
	    status = EXIT_SUCCESS;
	}

	for (i = 0; i < res->argc; i++)
	    fprintf(stream, "%s\n", res->argv[i]);

	return status;
    }

    return EXIT_FAILURE;
}

static void sigalrm_handler(int sig) { }

static struct nsctl *request(char *host, int port, int type, int argc, char *argv[])
{
    static struct nsctl res;
    struct sockaddr_in peer;
    socklen_t len = sizeof(peer);
    struct hostent *h = gethostbyname(host);
    int fd;
    uint8_t buf[NSCTL_MAX_PKT_SZ];
    int sz;
    char *err;

    if (!h || h->h_addrtype != AF_INET)
    {
	fprintf(stderr, "%s: invalid host `%s'\n", me, host);
	return 0;
    }

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
	fprintf(stderr, "%s: can't create udp socket (%s)\n", me, strerror(errno));
	return 0;
    }

    memset(&peer, 0, len);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(port);
    memcpy(&peer.sin_addr.s_addr, h->h_addr, sizeof(peer.sin_addr.s_addr));

    if (connect(fd, (struct sockaddr *) &peer, sizeof(peer)) < 0)
    {
	fprintf(stderr, "%s: udp connect failed (%s)\n", me, strerror(errno));
	return 0;
    }

    if ((sz = pack_control(buf, sizeof(buf), type, argc, argv)) < 0)
    {
	fprintf(stderr, "%s: error packing request\n", me);
	return 0;
    }

    if (debug)
    {
	struct nsctl req;
	if (unpack_control(&req, buf, sz) == type)
	{
	    fprintf(stderr, "Sending ");
	    dump_control(&req, stderr);
	}
    }

    if (send(fd, buf, sz, 0) < 0)
    {
	fprintf(stderr, "%s: error sending request (%s)\n", me, strerror(errno));
	return 0;
    }

    /* set timer */
    if (timeout)
    {
	struct sigaction alrm;
	alrm.sa_handler = sigalrm_handler;
	sigemptyset(&alrm.sa_mask);
	alrm.sa_flags = 0;

	sigaction(SIGALRM, &alrm, 0);
	alarm(timeout);
    }

    sz = recv(fd, buf, sizeof(buf), 0);
    alarm(0);

    if (sz < 0)
    {
	fprintf(stderr, "%s: error receiving response (%s)\n", me,
	    errno == EINTR ? "timed out" : strerror(errno));

	return 0;
    }

    if ((type = unpack_control(&res, buf, sz)) > 0 && type & NSCTL_RESPONSE)
    {
	if (debug)
	{
	    fprintf(stderr, "Received ");
	    dump_control(&res, stderr);
	}

	return &res;
    }

    err = "unknown error";
    switch (type)
    {
    case NSCTL_ERR_SHORT:  err = "short packet"; break;
    case NSCTL_ERR_LONG:   err = "extra data";   break;
    case NSCTL_ERR_MAGIC:  err = "bad magic";    break;
    case NSCTL_ERR_TYPE:   err = "invalid type"; break;
    }

    fprintf(stderr, "%s: %s\n", me, err);
    return 0;
}
