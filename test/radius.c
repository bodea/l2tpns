/* RADIUS authentication load test */

#define _SVID_SOURCE
#define _POSIX_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <sys/select.h>
#include <signal.h>
#include "../md5.h"

extern char *optarg;
extern int optind;

struct user {
    char *user;
    char *pass;
    int flags;
#define F_FAKE	1
#define F_BAD	2
#define F_USED	4
    char *request;
    int request_len;
    struct user *next;
};

typedef uint32_t u32;

struct user_list {
    struct user *entry;
    int attempts;
    int response;
    u32 begin;
    u32 retry;
    u32 end;
};

struct stats {
    int total;
    int out;
    int in;
    int err;
    int ready;
};

enum {
    AccessRequest = 1,
    AccessAccept,
    AccessReject,
    AccessFail = 99
};

#define USAGE "Usage: %s [-i input] [-n instances] [-f fake] [-b bad] " \
    "[-l limit] server port secret\n"

#define MAX_ATTEMPTS 5

void *xmalloc(size_t size)
{
    void *p = malloc(size);
    if (!p)
    {
	fprintf(stderr, "out of memory allocating %d bytes\n", size);
	exit(1);
    }

    return p;
}

char *xstrdup(char *s)
{
    int l = strlen(s);
    char *p = xmalloc(l + 1);
    return strcpy(p, s);
}

void *xmmap(size_t size)
{
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, 0, 0);

    if (p == MAP_FAILED)
    {
	fprintf(stderr, "out of memory allocating %d shared bytes\n", size);
	exit(1);
    }

    return p;
}

void logmsg(char *fmt, ...)
{
    static int new = 1;

    if (new)
    {
	static char time_s[] = "YYYY-MM-DD HH:MM:SS ";
	time_t now = time(NULL);

	strftime(time_s, sizeof(time_s), "%Y-%m-%d %T ", localtime(&now));
	fputs(time_s, stdout);
    }

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    fflush(stdout);

    new = strchr(fmt, '\n') != NULL;
}

void catch(int sig __attribute__ ((unused)) ) {}

void child(struct user_list *users, int count, int rshift,
    struct stats *stats, in_addr_t addr, int port, int limit)
    __attribute__ ((noreturn));

time_t basetime;

int main(int argc, char *argv[])
{
    char *input = 0;
    int instances = 1;
    int fake = 0;
    int bad = 0;
    int limit = 100000;
    int o;

    while ((o = getopt(argc, argv, "i:n:f:b:l:")) != -1)
    {
	switch (o)
	{
	case 'i': /* input file */
	    input = optarg;
	    break;

	case 'n': /* parallel instances */
	    instances = atoi(optarg);
	    if (instances < 1 || instances > 32)
	    {
		fprintf(stderr, "invalid instances value: `%s' (1-32)\n", optarg);
		return 2;
	    }
	    break;

	case 'f': /* percentage of additional fake users to add */
	    fake = atoi(optarg);
	    if (fake < 1 || fake > 100)
	    {
		fprintf(stderr, "invalid fake value: `%s' (1-100)\n", optarg);
		return 2;
	    }
	    break;

	case 'b': /* percentage of users to use incorrect passwords for */
	    bad = atoi(optarg);
	    if (bad < 1 || bad > 100)
	    {
		fprintf(stderr, "invalid bad value: `%s' (1-100)\n", optarg);
		return 2;
	    }
	    break;

	case 'l': /* limit number of messages per 1/10 sec */
	    limit = atoi(optarg);
	    if (limit < 1)
	    {
		fprintf(stderr, "invalid limit value: `%s'\n", optarg);
		return 2;
	    }
	    break;

	default:
	    fprintf(stderr, USAGE, argv[0]);
	    return 2;
	}
    }

    if (argc - optind != 3)
    {
	fprintf(stderr, USAGE, argv[0]);
	return 2;
    }

    char *server = argv[optind++];
    char *port_s = argv[optind++];
    char *secret = argv[optind];

    int port = atoi(port_s);
    if (port < 1)
    {
	fprintf(stderr, "invalid port: `%s'\n", port_s);
	return 2;
    }

    in_addr_t server_addr;
    {
	struct hostent *h;
	if (!(h = gethostbyname(server)) || h->h_addrtype != AF_INET)
	{
	    fprintf(stderr, "invalid server `%s' (%s)\n", server,
		h ? "no address" : hstrerror(h_errno));

	    return 1;
	}

	memcpy(&server_addr, h->h_addr, sizeof(server_addr));
    }

    time(&basetime); /* start clock */

    FILE *in = stdin;
    if (input && !(in = fopen(input, "r")))
    {
	fprintf(stderr, "can't open input file `%s' (%s)\n", input,
	    strerror(errno));

	return 1;
    }

    logmsg("Loading users from %s: ", input ? input : "stdin");

    struct user *users = 0;
    struct user *u = 0;

    int count = 0;
    char buf[1024];

    while (fgets(buf, sizeof(buf), in))
    {
	count++;

	/* format: username \t password \n */
	char *p = strchr(buf, '\t');
	if (!p)
	{
	    fprintf(stderr, "invalid input line %d (no TAB)\n", count);
	    return 1;
	}

	*p++ = 0;
	if (!u)
	{
	    users = xmalloc(sizeof(struct user));
	    u = users;
	}
	else
	{
	    u->next = xmalloc(sizeof(struct user));
	    u = u->next;
	}

	u->user = xstrdup(buf);
	while (*p == '\t')
	    p++;

	char *q = strchr(p, '\n');
	if (q)
	    *q = 0;

	if (!*p)
	{
	    fprintf(stderr, "invalid input line %d (no password)\n", count);
	    return 1;
	}

	u->pass = xstrdup(p);
	u->flags = 0;
	u->next = 0;
    }

    if (input)
    	fclose(in);

    logmsg("%d\n", count);

    if (!count)
    	return 1;

    char *fake_pw = "__fake__";
    if (fake)
    {
	/* add f fake users to make a total of which fake% are bogus */
	int f = ((count * fake) / (100.0 - fake) + 0.5);
	char fake_user[] = "__fake_99999999";

	logmsg("Generating %d%% extra fake users: ", fake);
	for (int i = 0; i < f; i++, count++)
	{
	    snprintf(fake_user, sizeof(fake_user), "__fake_%d", i);
	    u->next = xmalloc(sizeof(struct user));
	    u = u->next;
	    u->user = xstrdup(fake_user);
	    u->pass = fake_pw;
	    u->flags = F_FAKE;
	    u->next = 0;
	}

	logmsg("%d\n", f);
    }

    if (bad)
    {
	int b = (count * bad) / 100.0 + 0.5;

	logmsg("Setting %d%% bad passwords: ", bad);

	u = users;
	for (int i = 0; i < b; i++, u = u->next)
	{
	    if (u->pass != fake_pw)
		free(u->pass);

	    u->pass = "__bad__";
	    u->flags |= F_BAD;
	}

	logmsg("%d\n", b);
    }

    struct user **unsorted = xmalloc(sizeof(struct user) * count);

    u = users;
    for (int i = 0; i < count; i++, u = u->next)
	unsorted[i] = u;

    struct user_list *random = xmmap(sizeof(struct user_list) * count);
    memset(random, 0, sizeof(struct user_list) * count);

    logmsg("Randomising users: ");

    srand(time(NULL) ^ getpid());

    for (int i = 0; i < count; )
    {
	int j = 1.0 * count * rand() / RAND_MAX;
	if (unsorted[j]->flags & F_USED)
	    continue;

	random[i++].entry = unsorted[j];
	unsorted[j]->flags |= F_USED;
    }

    logmsg("done\n");
    logmsg("Building RADIUS queries: ");

    {
	char pass[128];

	for (u = users; u; u = u->next)
	{
	    int pw_len = strlen(u->pass);
	    int len = 4				/* code, identifier, length */
		+ 16				/* authenticator */
		+ 2 + strlen(u->user)		/* user */
		+ 2 + ((pw_len / 16) + ((pw_len % 16) ? 1 : 0)) * 16;
						/* encoded password */

	    char *p = xmalloc(len);
	    u->request = p;
	    u->request_len = len;

	    *p++ = AccessRequest;
	    *p++ = 0; /* identifier set in child */
	    *(uint16_t *) p = htons(len);
	    p += 2;

	    /* authenticator */
	    for (int j = 0; j < 16; j++)
	    	*p++ = rand();

	    *p = 1; /* user name */
	    p[1] = strlen(u->user) + 2;
	    strcpy(p + 2, u->user);
	    p += p[1];

	    strcpy(pass, u->pass);
	    while (pw_len % 16)
	    	pass[pw_len++] = 0; /* pad */

	    for (int j = 0; j < pw_len; j += 16)
	    {
		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx, secret, strlen(secret));
		if (j)
		    MD5_Update(&ctx, pass + j - 16, 16);
		else
		    /* authenticator */
		    MD5_Update(&ctx, u->request + 4, 16);

		uint8_t digest[16];
		MD5_Final(digest, &ctx);

		for (int k = 0; k < 16; k++)
		    pass[j + k] ^= digest[k];
	    }

	    *p = 2; /* password */
	    p[1] = pw_len + 2;
	    memcpy(p + 2, pass, pw_len);
	    p += p[1];
	}
    }

    logmsg("done\n");

    signal(SIGUSR1, catch);

    struct stats *stats = xmmap(sizeof(struct stats) * instances);
    memset(stats, 0, sizeof(struct stats) * instances);

    logmsg("Spawning %d processes: ", instances);

    int per_child = count / instances;
    int rshift = 0;
    for (u32 tmp = per_child; tmp & 0xff00; tmp >>= 1)
	rshift++;

    for (int i = 0, offset = 0; i < instances; i++)
    {
	int slack = i ? 0 : count % instances;

	stats[i].total = per_child + slack;
	if (!fork())
	    child(random + offset, per_child + slack, rshift, stats + i,
		server_addr, port, limit / instances);

	offset += per_child + slack;
    }

    logmsg("done\n");

    /* wait for children to setup */
    int ready = 0;
    do {
	ready = 0;
	for (int i = 0; i < instances; i++)
	    ready += stats[i].ready;

	sleep(1);
    } while (ready < instances);

    /* go! */
    kill(0, SIGUSR1);

    logmsg("Processing...\n");
    logmsg(" total:      ");

    for (int i = 0; i < instances; i++)
    	logmsg("[%5d %5s %5s]", stats[i].total, "", "");

    logmsg("\n");
    logmsg(" out/in/err: ");

    int done = 0;
    do {
	for (int i = 0; i < instances; i++)
	    logmsg("[%5d %5d %5d]", stats[i].out, stats[i].in,
		stats[i].err);

	logmsg("\n");

	if (waitpid(-1, NULL, WNOHANG) > 0)
	    done++;

	if (done < instances)
	{
	    sleep(1);
	    logmsg("             ");
	}
    } while (done < instances);

    int a_hist[MAX_ATTEMPTS + 1];
    memset(&a_hist, 0, sizeof(a_hist));

    u32 min = 0;
    u32 max = 0;
    u32 r_hist[64];
    memset(&r_hist, 0, sizeof(r_hist));
    int hsz = sizeof(r_hist) / sizeof(*r_hist);

    for (int i = 0; i < count; i++)
    {
	if ((random[i].response != AccessAccept &&
	     random[i].response != AccessReject) ||
	    (random[i].attempts < 1 ||
	     random[i].attempts > MAX_ATTEMPTS))
	{
	    a_hist[MAX_ATTEMPTS]++;
	    continue;
	}

	a_hist[random[i].attempts - 1]++;

	u32 interval = random[i].end - random[i].begin;

	if (!i || interval < min)
	    min = interval;

	if (interval > max)
	    max = interval;

	/* histogram in 1/10s intervals */
	int t = interval / 10 + 0.5;
	if (t > hsz - 1)
	    t = hsz - 1;

	r_hist[t]++;
    }

    logmsg("Send attempts:\n");
    for (int i = 0; i < MAX_ATTEMPTS; i++)
	logmsg(" %6d: %d\n", i + 1, a_hist[i]);

    logmsg(" failed: %d\n", a_hist[MAX_ATTEMPTS]);

    logmsg("Response time in seconds (min %.2f, max %.2f)\n",
	min / 100.0, max / 100.0);

    for (int i = 0; i < hsz; i++)
    {
	if (i < hsz - 1)
	    logmsg("    %3.1f:", i / 10.0);
	else
	    logmsg("   more:");

	logmsg(" %6d\n", r_hist[i]);
    }

    return 0;
}

/* time in sec/100 since program commenced */
u32 now(void)
{
    struct timeval t;
    gettimeofday(&t, 0);
    return (t.tv_sec - basetime) * 100 + t.tv_usec / 10000 + 1;
}

void child(struct user_list *users, int count, int rshift,
    struct stats *stats, in_addr_t addr, int port, int limit)
{
    int sockets = 1 << rshift;
    unsigned rmask = sockets - 1;

    int *sock = xmalloc(sizeof(int) * sockets);

    fd_set r_in;
    int nfd = 0;

    FD_ZERO(&r_in);

    for (int s = 0; s < sockets; s++)
    {
	if ((sock[s] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
	    fprintf(stderr, "can't create a UDP socket (%s)\n",
		strerror(errno));

	    exit(1);
	}

	int flags = fcntl(sock[s], F_GETFL, 0);
	fcntl(sock[s], F_SETFL, flags | O_NONBLOCK);

	struct sockaddr_in svr;
	memset(&svr, 0, sizeof(svr));
	svr.sin_family = AF_INET;
	svr.sin_port = htons(port);
	svr.sin_addr.s_addr = addr;

	connect(sock[s], (struct sockaddr *) &svr, sizeof(svr));

	FD_SET(sock[s], &r_in);
	if (sock[s] + 1 > nfd)
	    nfd = sock[s] + 1;
    }

    for (int i = 0; i < count; i++)
	/* set identifier */
	*((unsigned char *) users[i].entry->request + 1) = i >> rshift;

    stats->ready = 1;
    pause();

    u32 out_timer = now();
    int out_count = 0;

    while ((stats->in + stats->err) < count)
    {
	u32 time_now = now();

	while (out_timer + 10 < time_now)
	{
	    out_timer += 10;
	    if (out_count > 0)
	    	out_count -= limit;
	}

	for (int pass = 1; pass <= 2; pass++)
	{
	    for (int i = 0; i < count && out_count < limit; i++)
	    {
		if (users[i].response)
		    continue;

		if (users[i].attempts)
		{
		    if (users[i].retry > time_now)
			continue;
		}
		else if (pass == 1)
		{
		    /* retries only on the first pass */
		    continue;
		}

		struct user *e = users[i].entry;
		if (write(sock[i & rmask], e->request, e->request_len)
			!= e->request_len)
		    break;

		time_now = now();
		out_count++;

		if (!users[i].attempts)
		{
		    users[i].begin = time_now;
		    stats->out++;
		}

		if (++users[i].attempts > MAX_ATTEMPTS)
		{
			users[i].response = AccessFail;
			stats->err++;
			continue;
		}

		users[i].retry = time_now + 200 + 100 * (1 << users[i].attempts);
	    }
	}

	struct timeval tv = { 0, 100000 };

	fd_set r;
	memcpy(&r, &r_in, sizeof(r));

	if (select(nfd, &r, NULL, NULL, &tv) < 1)
	    continue;

	char buf[4096];

	for (int s = 0; s < sockets; s++)
	{
	    if (!FD_ISSET(sock[s], &r))
	    	continue;

	    int sz;

	    while ((sz = read(sock[s], buf, sizeof(buf))) > 0)
	    {
		if (sz < 2)
		{
		    fprintf(stderr, "short packet returned\n");
		    continue;
		}

		if (buf[0] != AccessAccept && buf[0] != AccessReject)
		{
		    fprintf(stderr, "unrecognised response type %d\n",
			(int) buf[0]);

		    continue;
		}

		int i = s | (((unsigned char) buf[1]) << rshift);
		if (i < 0 || i > count)
		{
		    fprintf(stderr, "bogus identifier returned %d\n", i);
		    continue;
		}

		if (!users[i].attempts)
		{
		    fprintf(stderr, "unexpected identifier returned %d\n", i);
		    continue;
		}

		if (users[i].response)
		    continue;

		int expect = (users[i].entry->flags & (F_FAKE|F_BAD))
		    ? AccessReject : AccessAccept;

		if (buf[0] != expect)
		    fprintf(stderr, "unexpected response %d for user %s "
			"(expected %d)\n", (int) buf[0], users[i].entry->user,
			expect);

		users[i].response = buf[0];
		users[i].end = now();
		stats->in++;
	    }
	}
    }

    exit(0);
}
