// L2TPNS Clustering Stuff
// $Id: cluster.h,v 1.2 2004-03-05 00:09:03 fred_nerk Exp $

#define C_HELLO			1
#define C_HELLO_RESPONSE	2
#define C_PING			3
#define C_TUNNEL		4
#define C_SESSION		5
#define C_GOODBYE		6

#define CLUSTERPORT		32792
#define CLUSTERCLIENTPORT	32793
#define UDP			17
#define TIMEOUT			20
#define IL			sizeof(int)

int cluster_init(uint32_t bind_address, int server);
int cluster_send_message(unsigned long ip_address, uint32_t vip, char type, void *data, int datalen);
int processcluster(char *buf, int l);
