#ifndef __UTIL_H__
#define __UTIL_H__

char *fmtaddr(ipt addr, int n);
void *shared_malloc(unsigned int size);
pid_t fork_and_close(void);

#endif /* __UTIL_H__ */
