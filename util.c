/* Misc util functions */

char const *cvs_id_util = "$Id: util.c,v 1.2 2004-06-28 02:43:13 fred_nerk Exp $";

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

