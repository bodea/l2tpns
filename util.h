#ifndef __UTIL_H__
#define __UTIL_H__

char *fmtaddr(in_addr_t addr, int n);
void *shared_malloc(unsigned int size);
pid_t fork_and_close(void);

#endif /* __UTIL_H__ */
