/* Misc util functions */

char const *cvs_id_util = "$Id: util.c,v 1.4 2004-11-02 04:35:04 bodea Exp $";

#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/mman.h>

#include "l2tpns.h"
#ifdef BGP
#include "bgp.h"
#endif

char *inet_toa(unsigned long addr)
{
	struct in_addr in;
	memcpy(&in, &addr, sizeof(unsigned long));
	return inet_ntoa(in);
}

void *shared_malloc(unsigned int size)
{
	void * p;
	p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);

	if (p == MAP_FAILED)
		p = NULL;

	return p;
}

extern int udpfd, tunfd, snoopfd, ifrfd, cluster_sockfd;
extern int *radfds;

pid_t fork_and_close()
{
	pid_t pid = fork();
	int i;

	if (pid)
		return pid;

	if (config->scheduler_fifo)
	{
		struct sched_param params = {0};
		params.sched_priority = 0;
		if (sched_setscheduler(0, SCHED_OTHER, &params))
		{
			log(0, 0, 0, 0, "Error setting scheduler to OTHER after fork: %s\n", strerror(errno));
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

	return pid;
}
