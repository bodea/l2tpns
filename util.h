#ifndef __UTIL_H__
#define __UTIL_H__

char *fmtaddr(in_addr_t addr, int n);
void *shared_malloc(unsigned int size);
pid_t fork_and_close(void);
ssize_t sendtofrom(int s, void const *buf, size_t len, int flags,
    struct sockaddr const *to, socklen_t tolen, struct in_addr const *from);

ssize_t recvfromto(int s, void *buf, size_t len, int flags,
    struct sockaddr *from, socklen_t *fromlen, struct in_addr *toaddr);

#endif /* __UTIL_H__ */
