/* Misc util functions */

char const *cvs_id_util = "$Id: util.c,v 1.3.2.1 2004-09-23 06:15:38 fred_nerk Exp $";

#include "l2tpns.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

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
