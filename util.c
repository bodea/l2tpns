/* Misc util functions */

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

// format ipv4 addr as a dotted-quad; n chooses one of 4 static buffers
// to use
char *fmtaddr(in_addr_t addr, int n)
{
    static char addrs[4][16];
    struct in_addr in;

    if (n < 0 || n >= 4)
	return "";

    in.s_addr = addr;
    return strcpy(addrs[n], inet_ntoa(in));
}

void *shared_malloc(unsigned int size)
{
    void * p;
    p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);

    if (p == MAP_FAILED)
	p = NULL;

    return p;
}

extern int forked;
extern int cluster_sockfd, tunfd, udpfd, controlfd, daefd, snoopfd, ifrfd, ifr6fd, rand_fd;
extern int *radfds;

pid_t fork_and_close()
{
    pid_t pid = fork();
    int i;

    if (pid)
	return pid;

    forked++;
    if (config->scheduler_fifo)
    {
	struct sched_param params = {0};
	params.sched_priority = 0;
	if (sched_setscheduler(0, SCHED_OTHER, &params))
	{
	    LOG(0, 0, 0, "Error setting scheduler to OTHER after fork: %s\n", strerror(errno));
	    LOG(0, 0, 0, "This is probably really really bad.\n");
	}
    }

    signal(SIGPIPE, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);
    signal(SIGHUP,  SIG_DFL);
    signal(SIGUSR1, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
    signal(SIGKILL, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    // Close sockets
    if (clifd != -1)          close(clifd);
    if (cluster_sockfd != -1) close(cluster_sockfd);
    if (tunfd != -1)          close(tunfd);
    if (udpfd != -1)          close(udpfd);
    if (controlfd != -1)      close(controlfd);
    if (daefd != -1)          close(daefd);
    if (snoopfd != -1)        close(snoopfd);
    if (ifrfd != -1)          close(ifrfd);
    if (ifr6fd != -1)         close(ifr6fd);
    if (rand_fd != -1)        close(rand_fd);
    if (epollfd != -1)        close(epollfd);

    for (i = 0; radfds && i < RADIUS_FDS; i++)
	close(radfds[i]);

#ifdef BGP
    for (i = 0; i < BGP_NUM_PEERS; i++)
	if (bgp_peers[i].sock != -1)
	    close(bgp_peers[i].sock);
#endif /* BGP */

    return pid;
}

ssize_t recvfromto(int s, void *buf, size_t len, int flags,
    struct sockaddr *from, socklen_t *fromlen, struct in_addr *toaddr)
{
    ssize_t r;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct iovec vec;
    char cbuf[128];

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = from;
    msg.msg_namelen = *fromlen;

    vec.iov_base = buf;
    vec.iov_len = len;
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;

    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    if ((r = recvmsg(s, &msg, flags)) < 0)
    	return r;

    if (fromlen)
	*fromlen = msg.msg_namelen;

    memset(toaddr, 0, sizeof(*toaddr));
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
    {
	if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO)
	{
	    struct in_pktinfo *i = (struct in_pktinfo *) CMSG_DATA(cmsg);
	    memcpy(toaddr, &i->ipi_addr, sizeof(*toaddr));
	    break;
	}
    }

    return r;
}

ssize_t sendtofrom(int s, void const *buf, size_t len, int flags,
    struct sockaddr const *to, socklen_t tolen, struct in_addr const *from)
{
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct iovec vec;
    struct in_pktinfo pktinfo;
    char cbuf[CMSG_SPACE(sizeof(pktinfo))];

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr *) to;
    msg.msg_namelen = tolen;

    vec.iov_base = (void *) buf;
    vec.iov_len = len;
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;

    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(pktinfo));

    memset(&pktinfo, 0, sizeof(pktinfo));
    memcpy(&pktinfo.ipi_spec_dst, from, sizeof(*from));
    memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));

    return sendmsg(s, &msg, flags);
}
