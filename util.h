#ifndef __UTIL_H__
#define __UTIL_H__

char *inet_toa(unsigned long addr);
void *shared_malloc(unsigned int size);
pid_t fork_and_close(void);

#endif /* __UTIL_H__ */
