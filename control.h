#ifndef __CONTROL_H__
#define __CONTROL_H__

#define PKT_RESP_OK		1
#define PKT_RESP_ERROR		2

#define PKT_LOAD_PLUGIN		5
#define PKT_UNLOAD_PLUGIN	6

#define PKT_GARDEN		1000
#define PKT_UNGARDEN		1001

int new_packet(short type, char *packet);
int send_packet(int sockfd, int dest_ip, int dest_port, char *packet, int len);
void dump_packet(char *packet, FILE *stream);
int read_packet(int sockfd, char *packet);

#endif
