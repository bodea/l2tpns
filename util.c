/* Misc util functions */

#include "l2tpns.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

char *inet_toa(unsigned long addr)
{
	struct in_addr in;
	memcpy(&in, &addr, sizeof(unsigned long));
	return inet_ntoa(in);
}

