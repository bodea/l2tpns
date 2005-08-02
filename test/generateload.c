#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <sys/mman.h>

#define PPPLCP	0xc021
#define PPPPAP	0xc023
#define PPPCHAP	0xc223
#define PPPIPCP	0x8021
#define PPPIP	0x0021
#define PPPCCP	0x80fd

#define CONFREQ	1
#define CONFACK	2
#define CONFNAK	3
#define CONFREJ	4
#define TERMREQ	5
#define TERMACK	6
#define CODEREJ	7
#define PROTREJ	8
#define ECHOREQ	9
#define ECHOREP	10
#define DISCREQ	11

#define PACKET_LENGTH	1000
#define TARGET_PPS	5000
#define TARGET		"211.29.131.33"
#define GWADDR		"211.29.131.30"
#define NUM_SESSIONS	1
#define MAX_PACKETS	0
#define AVG_SIZE	5

typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned char u8;

char *lcp_codes[] = {
	"reserved",
	"CONFREQ",
	"CONFACK",
	"CONFNAK",
	"CONFREJ",
	"TERMREQ",
	"TERMACK",
	"CODEREJ",
	"PROTREJ",
	"ECHOREQ",
	"ECHOREP",
	"DISCREQ",
};

char *mtypes[] = {
	"reserved",
	"SCCRQ",
	"SCCRP",
	"SCCCN",
	"StopCCN", // 4
	"reserved",
	"HELLO",
	"OCRQ",
	"OCRP",
	"OCCN",
	"ICRQ", // 10
	"ICRP",
	"ICCN",
	"reserved",
	"CDN",
	"WEN", // 15
	"SLI",
};

char *attributes[] = {
	"Message Type", // 0
	"Result Code", // 1
	"Protocol Version", // 2
	"Framing Capabilities", // 3
	"Bearer Capabilities", // 4
	"Tie Breaker", // 5
	"Firmware Revision", // 6
	"Host Name", // 7
	"Vendor Name", // 8
	"Assigned Tunnel ID", // 9
	"Receive Window Size", // 10
	"Challenge", // 11
	"Q.931 Cause Code", // 12
	"Challenge Response", // 13
	"Assigned Session ID", // 14
	"Call Serial Number", // 15
	"Minimum BPS", // 16
	"Maximum BPS", // 17
	"Bearer Type", // 18 (2 = Analog, 1 = Digital)
	"Framing Type", // 19 (2 = Async, 1 = Sync)
	"Reserved 20", // 20
	"Called Number", // 21
	"Calling Number", // 22
	"Sub Address", // 23
	"Tx Connect Speed", // 24
	"Physical Channel ID", // 25
	"Initial Received LCP CONFREQ", // 26
	"Last Sent LCP CONFREQ", // 27
	"Last Received LCP CONFREQ", // 28
	"Proxy Authen Type", // 29
	"Proxy Authen Name", // 30
	"Proxy Authen Challenge", // 31
	"Proxy Authen ID", // 32
	"Proxy Authen Response", // 33
	"Call Errors", // 34
	"ACCM", // 35
	"Random Vector", // 36
	"Private Group ID", // 37
	"Rx Connect Speed", // 38
	"Sequencing Required", // 39
};

char *result_codes[] = {
	"Reserved",
	"General request to clear control connection",
	"General error--Error Code indicates the problem",
	"Control channel already exists",
	"Requester is not authorized to establish a control channel",
	"The protocol version of the requester is not supported",
	"Requester is being shut down",
	"Finite State Machine error",
};

char *error_codes[] = {
	"No general error",
	"No control connection exists yet for this LAC-LNS pair",
	"Length is wrong",
	"One of the field values was out of range or reserved field was non-zero",
	"Insufficient resources to handle this operation now",
	"The Session ID is invalid in this context",
	"A generic vendor-specific error occurred in the LAC",
	"Try another LNS",
	"Session or tunnel was shutdown due to receipt of an unknown AVP with the M-bit set",
};


typedef struct
{
	char buf[4096];
	int length;
} controlt;

typedef struct avp_s
{
	int length;
	int type;
	struct avp_s *next;
	char value[1024];
} avp;

typedef struct
{
	int length;
	u16 session;
	u16 tunnel;
	u16 ns;
	u16 nr;
	u16 mtype;
	char *buf;
	avp *first;
	avp *last;
} control_message;

typedef struct {
unsigned long long send_count , recv_count ;
unsigned long long spkt , rpkt ;
unsigned int dropped;
unsigned long sbytes , rbytes ;
int quitit;
struct sessiont
{
	short remote_session;
	char open;
	int ppp_state;
	unsigned char ppp_identifier;
	int addr;
} sessions[65536];

int active_sessions ;
} sharedt;

sharedt * ss;

void controlsend(controlt * c, short t, short s);
void controlnull(short t);
controlt *controlnew(u16 mtype);
void controls(controlt * c, u16 avp, char *val, u8 m);
void control16(controlt * c, u16 avp, u16 val, u8 m);
void control32(controlt * c, u16 avp, u32 val, u8 m);
void controlfree(controlt *c);
control_message *parsecontrol(char *buf, int length);
void dump_control_message(control_message *c);
u32 avp_get_32(control_message *c, int id);
u16 avp_get_16(control_message *c, int id);
char *avp_get_s(control_message *c, int id);
void reader_thread(int udpfd);
void skip_zlb();
void cm_free(control_message *m);
controlt *ppp_new(u16 session, int protocol);
void ppp_free(controlt *packet);
controlt *ppp_lcp(u16 s, unsigned char type, char identifier);
controlt *ppp_ipcp(u16 s, unsigned char type, char identifier);
void ppp_send(controlt *c);
void ppp_add_16(controlt * c, u16 val);
void ppp_add_32(controlt * c, u32 val);
void ppp_add_s(controlt * c, char *val);
void ppp_lcp_add_option(controlt *c, unsigned char option, unsigned char length, int data);
void dump_ppp_packet(char *packet, int l);
controlt *ppp_pap(u16 s, unsigned char type, char identifier, char *username, char *password);
char *inet_toa(unsigned long addr);
__u16 checksum(unsigned char *addr, int count);
void sigalarm(int junk);
void sigint(int signal);
void clean_shutdown();
void print_report();

int ns = 0, nr = 0;
int udpfd;
int t = 0;
struct sockaddr_in gatewayaddr = {0};
int numsessions = NUM_SESSIONS;
int packet_length = PACKET_LENGTH;
int target_pps = TARGET_PPS;
char *target = TARGET;
char *gwaddr = GWADDR;
int max_packets = MAX_PACKETS;
int ppsend;
int do_init = 1;
char **session_usernames;
char *base_username = "dslloadtest";
char *base_password = "testing";
char *suffix = "@optusnet.com.au";

int main(int argc, char *argv[])
{
	int s;
	char *packet;

	ss = (sharedt*) mmap(NULL, sizeof(*ss), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);

	// Process Arguments {{{
	while ((s = getopt(argc, argv, "?hs:g:l:p:m:t:nU:P:")) > 0)
	{
		switch (s)
		{
			case 's' :
				numsessions = atoi(optarg);
				if (numsessions <= 0)
				{
					printf("You must have at least 1 session\n");
					return -1;
				}
				break;
			case 'l' :
				packet_length = atoi(optarg);
				if (packet_length < 64)
				{
					printf("You must have at least 64 byte packets\n");
					return -1;
				}
				break;
			case 'n' :
				do_init = 0;
				break;
			case 'p' :
				target_pps = atoi(optarg);
				break;
			case 'm' :
				max_packets = atoi(optarg);
				if (max_packets < 50)
				{
					printf("You must send at least 50 packets.\n");
					return -1;
				}
				break;
			case 't' :
				target = strdup(optarg);
				break;
			case 'g' :
				gwaddr = strdup(optarg);
				break;
			case 'U' :
				base_username = strdup(optarg);
				break;
			case 'P' :
				base_password = strdup(optarg);
				break;
			case 'h' :
			case '?' :
				printf("Options:\n");
				printf("\t-s number of ss->sessions\n");
				printf("\t-l packet length\n");
				printf("\t-p target pps\n");
				printf("\t-m maximum number of packets\n");
				printf("\t-t target IP address\n");
				printf("\t-g gateway IP address\n");
				printf("\t-U username (or base if multiple)\n");
				printf("\t-P password\n");
				return(0);
				break;
		}
	}
	if (target_pps)
		ppsend = target_pps / 50;
	else
		ppsend = 0;

	packet = calloc(4096, 1);

	memset(ss->sessions, 0, sizeof(ss->sessions));

	if (do_init)
		printf("Creating %d ss->sessions to %s\n", numsessions, gwaddr);
	printf("Targeting %d packets per second\n", target_pps);
	if (max_packets) printf("Sending a maximum of %d packets\n", max_packets);
	printf("Sending packets to %s\n", target);
	printf("Sending %d byte packets\n", packet_length);

	session_usernames = (char **)calloc(sizeof(char *), numsessions);
	if (numsessions > 1)
	{
		int sul = strlen(base_username) + 10;
		int i;

		for (i = 0; i < numsessions; i++)
		{
			session_usernames[i] = (char *)calloc(sul, 1);
			snprintf(session_usernames[i], sul, "%s%d", base_username, i+1);
		}
	}
	else
	{
		session_usernames[0] = strdup(base_username);
	}
	// }}}

	// Create socket/*{{{*/
	{
		int on = 1;
		struct sockaddr_in addr;

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(38001);

		udpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (udpfd <= 0)
		{
			perror("socket");
			return -1;
		}

		setsockopt(udpfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		if (bind(udpfd, (void *) &addr, sizeof(addr)) < 0)
		{
			perror("bind");
			return -1;
		}

		printf("Bound to port %d\n", htons(addr.sin_port));
	}/*}}}*/

	gatewayaddr.sin_family = AF_INET;
	gatewayaddr.sin_port = htons(1701);
	inet_aton(gwaddr, &gatewayaddr.sin_addr);

	// Create tunnel/*{{{*/
	if (do_init) {
		controlt *c;
		control_message *r;

		c = controlnew(1); // SCCRQ
		controls(c, 7, "loadtest", 0); // Tunnel Hostname
		controls(c, 8, "OIE", 0); // Vendor Name
		control16(c, 9, 1, 0); // Assigned Tunnel ID
		control16(c, 2, 256, 0); // Version 1.0
		control16(c, 3, 1, 0); // Framing (Async)
		control16(c, 4, 1, 0); // Bearer (Digital)
		control16(c, 10, 20, 0); // Receive Window Size
		controlsend(c, 0, 0);
		controlfree(c);

		// Receive reply/*{{{*/
		{
			struct sockaddr_in addr;
			int alen = sizeof(addr), l;

			l = recvfrom(udpfd, packet, 4096, 0, (void *) &addr, &alen);
			if (l < 0)
			{
				printf("Error creating tunnel: %s\n", strerror(errno));
				return -1;
			}
			printf("Received ");
			r = parsecontrol(packet, l);
			if (!r->first)
			{
				printf("Invalid packet.. no first avp\n");
				return -1;
			}

			printf("Assigned tunnel: %d\n", t = avp_get_16(r, 9));
			cm_free(r);

			c = controlnew(3); // SCCCN
			controlsend(c, t, 0);
			controlfree(c);
			skip_zlb();
		}/*}}}*/
	}/*}}}*/


	// Create ss->sessions/*{{{*/
	if (do_init)
	{
		for (s = 1; s <= numsessions; s++)
		{
			controlt *c;

			c = controlnew(10); // ICRQ
			controls(c, 21, "12356", 0); // Called Number
			controls(c, 22, "000", 0); // Calling Number
			control16(c, 14, s, 0); // Assigned Session ID
			controlsend(c, t, 0);
			controlfree(c);
			usleep(15000); // 15 ms
		}
	}
	printf("All session create requests sent...\n");/*}}}*/

	if ( fork() == 0) {
		reader_thread(udpfd);
		exit(0);
	}

	{
		char tmp[512];
		fprintf(stderr, "Press enter to begin sending traffic\n");
		fgets(tmp, 512, stdin);
	}

	fprintf(stderr, "Beginning sending traffic through %d ss->sessions\n", ss->active_sessions);
	printf("	TS: Total Packets Sent\n");
	printf("	TL: Total Packets Lost\n");
	printf("	PL: Packet Loss\n");
	printf("	SS: Send Speed\n");
	printf("	RS: Receive Speed\n");
	printf("	SP: Packets/Second Sent\n");
	printf("	RP: Packets/Second Received\n");
	printf("	NS: Number of active ss->sessions\n");

	signal(SIGALRM, sigalarm);
	signal(SIGINT, sigint);
	alarm(1);

	// Traffic generation loop {{{
	{
		struct sockaddr_in to;
		struct iphdr *iph;
		struct udphdr *udph;
		char *data;
		int len = 0;
		unsigned int seq = 0;
		controlt *c;

		// Get address
		memset(&to, 0, sizeof(struct sockaddr_in));
		to.sin_family = AF_INET;
		inet_aton(target, &to.sin_addr);

		c = ppp_new(1, PPPIP);

		iph = (struct iphdr *)(c->buf + c->length);
		udph = (struct udphdr *)(c->buf + c->length + sizeof(struct iphdr));
		data = (char *)(c->buf + c->length + sizeof(struct iphdr) + sizeof(struct udphdr));
		len = sizeof(struct iphdr) + sizeof(struct udphdr);
		c->length += len;

		//IP
		c->length += sizeof(struct iphdr);
		iph->tos = 0;
		iph->id = ntohs(1);
		iph->frag_off = ntohs(1 << 14);
		iph->ttl = 30;
		iph->check = 0;
		iph->version = 4;
		iph->ihl = 5;
		iph->protocol = 17;
		memcpy(&iph->daddr, &to.sin_addr, sizeof(iph->daddr));

		// UDP
		udph->source = ntohs(39999);
		udph->dest = ntohs(39000);
		udph->check = 0;

		// Data
		memset(data, 64, 1500);

		udph->len = ntohs(sizeof(struct udphdr) + packet_length);
		iph->tot_len = ntohs(len + packet_length);
		c->length += packet_length;

		while (!ss->quitit && ss->active_sessions)
		{
			int i;
			for (i = 1; i <= numsessions && !ss->quitit; i++)
			{
				// Skip ss->sessions that aren't active yet
				if (!ss->sessions[i].open || ss->sessions[i].ppp_state != 2)
					continue;

				*(u16 *)(c->buf + 4) = htons(ss->sessions[i].remote_session); // Session ID
				iph->saddr = ss->sessions[i].addr;
				iph->check = 0;
				iph->check = ntohs(checksum((char *)iph, sizeof(struct iphdr)));

				*((unsigned int *) data) = seq++;
				ppp_send(c);

				ss->send_count++;
				ss->spkt++;
				ss->sbytes += c->length;

				if (ppsend && ss->send_count % ppsend == 0)
				{
					struct timespec req;
					req.tv_sec = 0;
					req.tv_nsec = 5 * 1000 * 1000;
					nanosleep(&req, NULL);
				}

				if (max_packets && ss->send_count >= max_packets) ss->quitit++;
			}
		}

		c->length -= packet_length;

	}/*}}}*/

	clean_shutdown();
	print_report();

	close(udpfd);
	return 0;
}

void print_report()
{
	float loss;

	loss = 100 - (((ss->recv_count * 1.0) / (ss->send_count * 1.0)) * 100.0);

	printf("\n");
	printf("Total Packets Sent:	%llu\n", ss->send_count);
	printf("Total Packets Received:	%llu\n", ss->recv_count);
	printf("Overall Packet Loss:	%0.2f%%", loss);
	printf("\n");
}

void clean_shutdown()/*{{{*/
{
	int i;
	for (i = 0; i < numsessions; i++)
	{
		// Close Session
		controlt *c;

		if (!ss->sessions[i].open) continue;
		c = controlnew(14); // CDN
		control16(c, 14, i, 0); // Assigned Session ID
		control16(c, 1, 1, 0); // Result Code
		controlsend(c, t, ss->sessions[i].remote_session);
		controlfree(c);
	}

	// Close Tunnel
	{
		controlt *c;

		c = controlnew(4); // StopCCN
		control16(c, 9, 1, 0); // Assigned Tunnel ID
		control16(c, 1, 1, 0); // Result Code
		controlsend(c, t, 0);
		controlfree(c);
	}
}/*}}}*/

void sigint(int signal)
{
	ss->quitit++;
}

void sigalarm(int junk)
{
	static unsigned long long last_rpkts[AVG_SIZE], last_spkts[AVG_SIZE];
	static int last = 0, avg_count = 0;
	register unsigned int avg_s = 0, avg_r = 0, i;
	float loss;

	last_rpkts[last] = ss->rpkt;
	last_spkts[last] = ss->spkt;
	last = (last + 1) % AVG_SIZE;
	if (avg_count < AVG_SIZE) avg_count++;

	for (i = 0; i < avg_count; i++)
	{
		avg_s += last_spkts[i];
		avg_r += last_rpkts[i];
	}
	avg_s /= avg_count;
	avg_r /= avg_count;

	loss = 100 - (((avg_r * 1.0) / (avg_s * 1.0)) * 100.0);
	fprintf(stderr, "TS:%llu TL:%lld DR:%4d PL:%-3.2f%% SS:%0.1fMbits/s RS:%0.1fMbits/s NS:%u SP:%u RP:%u\n",
			ss->send_count, ss->send_count-ss->recv_count, ss->dropped, loss,
			(ss->sbytes/1024.0/1024.0*8), (ss->rbytes/1024.0/1024.0*8),
			ss->active_sessions,
			avg_s, avg_r);

	ss->spkt = ss->rpkt = 0;
	ss->sbytes = ss->rbytes = 0;
	alarm(1);
}

__u16 checksum(unsigned char *addr, int count)
{
	register long sum = 0;

	for (; count > 1; count -= 2)
	{
		sum += ntohs(*(u16 *)addr);
		addr += 2;
	}

	if (count > 0) sum += *(unsigned char *)addr;

	// take only 16 bits out of the 32 bit sum and add up the carries
	if (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// one's complement the result
	sum = ~sum;

	return ((u16) sum);
}

// Control Stuff {{{
void control16(controlt * c, u16 avp, u16 val, u8 m)
{
	u16 l = (m ? 0x8008 : 0x0008);
	*(u16 *) (c->buf + c->length + 0) = htons(l);
	*(u16 *) (c->buf + c->length + 2) = htons(0);
	*(u16 *) (c->buf + c->length + 4) = htons(avp);
	*(u16 *) (c->buf + c->length + 6) = htons(val);
	c->length += 8;
}

// add an AVP (32 bit)
void control32(controlt * c, u16 avp, u32 val, u8 m)
{
	u16 l = (m ? 0x800A : 0x000A);
	*(u16 *) (c->buf + c->length + 0) = htons(l);
	*(u16 *) (c->buf + c->length + 2) = htons(0);
	*(u16 *) (c->buf + c->length + 4) = htons(avp);
	*(u32 *) (c->buf + c->length + 6) = htonl(val);
	c->length += 10;
}

// add an AVP (32 bit)
void controls(controlt * c, u16 avp, char *val, u8 m)
{
	u16 l = ((m ? 0x8000 : 0) + strlen(val) + 6);
	*(u16 *) (c->buf + c->length + 0) = htons(l);
	*(u16 *) (c->buf + c->length + 2) = htons(0);
	*(u16 *) (c->buf + c->length + 4) = htons(avp);
	memcpy(c->buf + c->length + 6, val, strlen(val));
	c->length += 6 + strlen(val);
}

// new control connection
controlt *controlnew(u16 mtype)
{
	controlt *c;
	c = calloc(sizeof(controlt), 1);
	c->length = 12;
	control16(c, 0, mtype, 1);
	return c;
}

void controlnull(short t)
{
	controlt *c;
	c = calloc(sizeof(controlt), 1);
	c->length = 12;
	controlsend(c, t, 0);
	controlfree(c);
	ns--;
}

// add a control message to a tunnel, and send if within window
void controlsend(controlt * c, short t, short s)
{
	*(u16 *) (c->buf + 0) = htons(0xC802); // flags/ver
	*(u16 *) (c->buf + 2) = htons(c->length); // length
	*(u16 *) (c->buf + 4) = htons(t); // tunnel
	*(u16 *) (c->buf + 6) = htons(s); // session
	*(u16 *) (c->buf + 8) = htons(ns++); // sequence
	*(u16 *) (c->buf + 10) = htons(nr); // sequence
//	printf("Sending ");
//	cm_free(parsecontrol(c->buf, c->length));
	sendto(udpfd, c->buf, c->length, 0, (struct sockaddr *)&gatewayaddr, sizeof(gatewayaddr));
}

void controlfree(controlt *c)
{
	if (!c) return;
	free(c);
}

control_message *parsecontrol(char *buf, int length)
{
	char *p = buf;
	control_message *c;

	c = calloc(sizeof(control_message), 1);
	c->buf = buf;
	c->length = length;

	c->tunnel = ntohs(*(u16 *)(buf + 4));
	c->session = ntohs(*(u16 *)(buf + 6));
	c->ns = ntohs(*(u16 *)(buf + 8));
	c->nr = nr = ntohs(*(u16 *)(buf + 10));
	p += 12;
	while ((p - buf) < length)
	{
		avp *a = calloc(sizeof(avp), 1);
		a->length = ntohs(*(short *)(p)) & 0x3FF;
		a->type = ntohs(*(short *)(p + 4));
		memcpy(a->value, p + 6, a->length - 6);
		if (a->type == 0) c->mtype = ntohs(*(short *)a->value);
		p += a->length;
		if (c->last)
			c->last->next = a;
		else
			c->first = a;
		c->last = a;
	}
	if (c->first)
		dump_control_message(c);
	return c;
}

void dump_control_message(control_message *c)
{
	avp *a;
	printf("Control Message (type=%u s=%u t=%d ns=%d nr=%d)\n", c->mtype, c->session, c->tunnel, c->ns, c->nr);
	for (a = c->first; a; a = a->next)
	{
		printf("	avp: %s, len: %d", attributes[a->type], a->length - 6);
		switch (a->type)
		{
			// Short
			case 6 :
			case 9 :
			case 10 :
			case 39 :
			case 14 : printf(", value: %u\n", ntohs(*(short *)a->value));
				 break;

			// Integer
			case 16 :
			case 17 :
			case 24 :
			case 25 :
			case 38 :
			case 15 : printf(", value: %u\n", ntohl(*(u32 *)a->value));
				  break;

			// String
			case 7 :
			case 21 :
			case 22 :
			case 23 :
			case 37 :
			case 8 : printf(", value: \"%s\"\n", a->value);
				 break;

			case 2 : printf(", value: %d.%d\n", *(char *)a->value, *(char *)a->value + 1);
				 break;
			case 0 : printf(", value: %s\n", mtypes[ntohs(*(short *)a->value)]);
				 break;
			case 19 :
			case 3 : printf(", value: (%d) %s %s\n", ntohl(*(u32 *)a->value),
						 (ntohl(*(u32 *)a->value) & 0x01) ? "synchronous" : "",
						 (ntohl(*(u32 *)a->value) & 0x02) ? "asynchronous" : "");
				 break;
			case 18 :
			case 4 : printf(", value: (%d) %s %s\n", ntohl(*(u32 *)a->value),
						 (ntohl(*(u32 *)a->value) & 0x01) ? "digital" : "",
						 (ntohl(*(u32 *)a->value) & 0x02) ? "analog" : "");
				 break;

			default : printf("\n");
				  break;
		}
	}
	printf("\n");
}

u16 avp_get_16(control_message *c, int id)
{
	avp *a;

	for (a = c->first; a; a = a->next)
		if (a->type == id) return ntohs(*(short *)a->value);
	return 0;
}

u32 avp_get_32(control_message *c, int id)
{
	avp *a;

	for (a = c->first; a; a = a->next)
		if (a->type == id) return ntohl(*(u32 *)a->value);
	return 0;
}

char *avp_get_s(control_message *c, int id)
{
	avp *a;

	for (a = c->first; a; a = a->next)
		if (a->type == id) return (char *)a->value;
	return 0;
}

void cm_free(control_message *m)
{
	avp *a, *n;

	for (a = m->first; a; )
	{
		n = a->next;
		free(a);
		a = n;
	}

	free(m);
}

// }}}

void reader_thread(int updfd)/*{{{*/
{
	unsigned char *packet;
	unsigned int seq = 0;

	printf("Starting reader thread\n");
	packet = malloc(4096);
	while (!ss->quitit)
	{
		struct sockaddr_in addr;
		int alen = sizeof(addr);
		control_message *m;
		int l;
		int s;
		int pfc = 0;

//		memset(packet, 0, 4096);
		if ((l = recvfrom(udpfd, packet, 4096, 0, (void *) &addr, &alen)) < 0) break;
		ss->rbytes += l;
		if (!do_init)
		{
			ss->recv_count++;
			ss->rpkt++;
			continue;
		}
		if (l < 12)
		{
			printf("Short packet received: %d bytes\n", l);
		}
		s = ntohs(*(u16 *)(packet + 4));
		if (!s)
		{
			printf("Invalid session ID\n");
			continue;
		}
		if (packet[0] == 0xc8)
		{
			// Control Packet
			printf("Reader Received ");
			m = parsecontrol(packet, l);
			printf("\n");
			s = m->session;

			switch (m->mtype)
			{
				case 4  : printf("StopCCN\n");
					  printf("Killing tunnel %d\n", avp_get_16(m, 9));
					  ss->quitit++;
					  break;
				case 6  : printf("HELLO, sending ZLB ACK\n");
					  controlnull(t);
					  break;
				case 11 :
					{
						controlt *c;

						printf("Received ICRP. Responding with CONFREQ\n");

						ss->sessions[s].remote_session = avp_get_16(m, 14);
						ss->sessions[s].open = 1;
						ss->sessions[s].ppp_state = 1;

						c = controlnew(12); // ICCN
						controlsend(c, t, ss->sessions[s].remote_session);
						controlfree(c);

						c = ppp_lcp(s, CONFREQ, 0);
						ppp_lcp_add_option(c, 1, 2, htons(1500)); // MRU = 1400
						ppp_lcp_add_option(c, 3, 2, htons(0xC023)); // Authentication Protocol - PAP
						ppp_send(c);
						controlfree(c);
						break;
					}
				case 14 : {
						int s;
						printf("CDN\n");
						s = avp_get_16(m, 14);
						printf("Killing session %d\n", s);
						ss->sessions[s].open = 0;
						ss->sessions[s].ppp_state = 0;
						ss->active_sessions--;
					        controlnull(t);
					        break;
					  }

			}
			if (m->mtype == 4)
			{
				printf("StopCCN Received.. Dieing\n");
				ss->quitit++;
				break;
			}
			cm_free(m);
		}
		else
		{
			// Data Packet
			unsigned short protocol = ntohs(*(u16 *)(packet + 6));

			if (protocol == 0xff03)
			{
				pfc = 2;
				packet += 2;
				protocol = ntohs(*(u16 *)(packet + 6));
			}
			if (protocol != PPPIP)
			{
				printf("Received ");
				dump_ppp_packet(packet + 6, l - 6);
			}

			if (protocol == PPPLCP)
			{
				controlt *r;
				unsigned char ppp_id = *(char *)(packet + 9);

				switch (*(char *)(packet + 8))
				{
					case CONFREQ :
						r = ppp_lcp(s, CONFACK, ppp_id);
						ppp_send(r);
						break;
					case CONFACK :
						r = ppp_pap(s, CONFREQ, 0, session_usernames[s-1], base_password);
						ppp_send(r);
						break;
					case TERMREQ :
						r = ppp_lcp(s, TERMACK, ppp_id);
						ppp_send(r);
						break;
					case ECHOREQ :
						r = ppp_lcp(s, ECHOREP, ppp_id);
						ppp_add_32(r, 0);
						ppp_send(r);
						break;
				}
			}
			else if (protocol == PPPIPCP)
			{
				controlt *r;
				int taddr = 0;
				u32 address = *(u32 *)(packet + 14);

				switch (*(char *)(packet + 8))
				{
					case CONFREQ :
						r = ppp_ipcp(s, CONFREQ, time(NULL) % 255);
						ppp_lcp_add_option(r, 3, 4, htonl(taddr)); // Request 0.0.0.0
						ppp_send(r);
						controlfree(r);
						r = ppp_ipcp(s, CONFACK, time(NULL) % 255);
						ppp_lcp_add_option(r, 3, 4, address); // ACK gateway IP
						ppp_send(r);
						controlfree(r);
						break;
					case CONFNAK :
						// Request whatever address we are given - it's ours
						r = ppp_ipcp(s, CONFREQ, time(NULL) % 255);
						ppp_lcp_add_option(r, 3, 4, address);
						ppp_send(r);
						controlfree(r);
						printf("Session %d: %s\n", s, inet_toa(address));
						ss->sessions[s].ppp_state = 2;
						ss->sessions[s].addr = address;
						ss->active_sessions++;
						break;
					case CONFACK :
						printf("Conf-Ack Received\n");
						break;
					case TERMREQ :
						printf("Term-Req Received\n");
						break;
					case ECHOREQ :
						printf("Echo-Req Received\n");
						break;
					case ECHOREP :
						printf("Echo-Rep Received\n");
						break;
				}
			}
			else if (protocol == PPPPAP)
			{
				if (*(u16 *)(packet + 8) == 3)
				{
					controlt *c;
					printf("Closing Connection\n");

					c = controlnew(14); // CDN
					control16(c, 14, ss->sessions[s].remote_session, 0); // Assigned Session ID
					controlsend(c, t, 0);
					controlfree(c);
					ss->sessions[s].open = 0;
				}
			}
			else if (protocol == PPPIP)
			{
				struct iphdr *iph = (struct iphdr *)(packet + 8);
				char * data = (char*) (packet + 8 + sizeof(struct iphdr) + sizeof(struct udphdr));
				if (!ss->sessions[s].open)
				{
					printf("Packet for closed session %d\n", s);
					continue;
				}

				if (iph->protocol == 17)
				{
					int iseq;
					ss->recv_count++;
					ss->rpkt++;
					iseq = *((unsigned int *) data);
					if (seq != iseq) {
						ss->dropped += (iseq - seq) ;
					}
					seq = iseq + 1; // Next sequence number to expect.
				}
			}
		}
		packet -= pfc;
	}
	free(packet);

	printf("Closing reader thread\n");

}/*}}}*/

void skip_zlb() /*{{{*/
{
	struct sockaddr_in addr;
	int alen = sizeof(addr);
	char buf[1024];
	int l;
	l = recvfrom(udpfd, buf, 1024, MSG_PEEK, (void *) &addr, &alen);
	if (l < 0)
	{
		printf("recvfrom: %s\n", strerror(errno));
		return;
	}
	if (l <= 12)
	{
		printf("Skipping ZLB (l=%d)\n", l);
		recvfrom(udpfd, buf, 1024, 0, (void *) &addr, &alen);
	}
}
/*}}}*/

// PPP Stuff {{{
controlt *ppp_new(u16 session, int protocol)
{
	controlt *c = calloc(sizeof(controlt), 1);
	*(u16 *)(c->buf + 4) = htons(ss->sessions[session].remote_session); // Tunnel
	*(u16 *)(c->buf + 6) = htons(protocol);
	c->length += 8;

	return c;
}

void ppp_free(controlt *c)
{
	free(c);
}

controlt *ppp_lcp(u16 s, unsigned char type, char identifier)
{
	controlt *c;

	if (!identifier) identifier = ss->sessions[s].ppp_identifier++;
	c = ppp_new(s, PPPLCP);
	*(char *)(c->buf + c->length + 0) = type;
	*(char *)(c->buf + c->length + 1) = identifier;
	*(u16 *)(c->buf + c->length + 2) = ntohs(4);
	c->length += 4;

	return c;
}

controlt *ppp_ipcp(u16 s, unsigned char type, char identifier)
{
	controlt *c;

	if (!identifier) identifier = ss->sessions[s].ppp_identifier++;
	c = ppp_new(s, PPPIPCP);
	*(char *)(c->buf + c->length + 0) = type;
	*(char *)(c->buf + c->length + 1) = identifier;
	*(u16 *)(c->buf + c->length + 2) = ntohs(4);
	c->length += 4;

	return c;
}

controlt *ppp_pap(u16 s, unsigned char type, char identifier, char *username, char *password)
{
	controlt *c;

	if (!identifier) identifier = ss->sessions[s].ppp_identifier++;
	c = ppp_new(s, PPPPAP);
	*(char *)(c->buf + c->length + 0) = type;
	*(char *)(c->buf + c->length + 1) = identifier;
	*(u16 *)(c->buf + c->length + 2) = ntohs(4);
	c->length += 4;

	*(char *)(c->buf + c->length) = strlen(username) + strlen(suffix);
	memcpy((c->buf + c->length + 1), username, strlen(username));
	memcpy((c->buf + c->length + 1 + strlen(username)), suffix, strlen(suffix));
	c->length += strlen(username) + 1 + strlen(suffix);

	*(char *)(c->buf + c->length) = strlen(password);
	memcpy((c->buf + c->length + 1), password, strlen(password));
	c->length += strlen(password) + 1;

	return c;
}

void ppp_send(controlt *c)
{
	*(u16 *)(c->buf + 0) = htons(0x0002); // flags/ver
	*(u16 *)(c->buf + 2) = htons(t); // tunnel
	*(u16 *)(c->buf + 10) = ntohs(c->length - 8);
	if (sendto(udpfd, c->buf, c->length, 0, (struct sockaddr *)&gatewayaddr, sizeof(gatewayaddr)) < 0)
		perror("sendto");
	if (htons(*(u16 *)(c->buf + 6)) != PPPIP)
	{
		printf("PPP Sending ");
		dump_ppp_packet(c->buf + 6, c->length - 6);
	}
}

void ppp_add_16(controlt *c, u16 val)
{
	*(u16 *) (c->buf + c->length) = htons(val);
	c->length += 2;
}

void ppp_add_32(controlt *c, u32 val)
{
	*(u32 *) (c->buf + c->length) = htons(val);
	c->length += 4;
}

void ppp_add_s(controlt *c, char *val)
{
	memcpy(c->buf + c->length, val, strlen(val));
	c->length += strlen(val);
}

void ppp_lcp_add_option(controlt *c, unsigned char option, unsigned char length, int data)
{
	*(char *)(c->buf + c->length + 0) = option;
	*(char *)(c->buf + c->length + 1) = length + 2;
	memcpy(c->buf + c->length + 2, &data, length);
	c->length += 2 + length;
}

void dump_ppp_packet(char *packet, int l)
{
	char *p = packet;
	int protocol ;
	if (*(unsigned char *)p == 0xff) p += 2;
	protocol = ntohs(*(u16 *)(p));
	printf("PPP Packet\n");
	switch (protocol)
	{
		case PPPCCP : printf("	Protocol: PPPCCP\n"); break;
	}
	if (protocol == PPPLCP)
	{
		printf("	Protocol: PPPLCP\n");
		printf("	LCP Code: %s\n", lcp_codes[*(u8 *)(p + 2)]);
	}
	else if (protocol == PPPPAP)
	{
		printf("	Protocol: PPPPAP\n");
		if (*(char *)(p + 2) == 2)
		{
				printf("	Authentication accepted\n");
		}
		else if (*(char *)(p + 2) == 3)
		{
				printf("	Authentication denied\n");
		}
	}
	else if (protocol == PPPIPCP)
	{
		printf("	Protocol: PPPIPCP\n");
		printf("	IPCP Code: %s\n", lcp_codes[*(u8 *)(p + 2)]);
		printf("	Address: %s\n", inet_toa(*(u32 *)(p + 8)));
	}
	else if (protocol == PPPIP)
	{
		struct iphdr *iph;
		struct protoent *pr;

		iph = (struct iphdr *)(p + 2);

		printf("	Protocol: PPPIP\n");
		printf("	Length: %d\n", l);
		printf("	IP Version: %d\n", iph->version);
		if (iph->version != 4) return;
		pr = getprotobynumber(iph->protocol);
		printf("	IP Header Length: %d\n", iph->ihl);
		printf("	IP TTL: %d\n", iph->ttl);
		printf("	IP Protocol: %s (%d)\n", (pr ? pr->p_name : "unknown"), iph->protocol);
		printf("	IP Checksum: %x\n", ntohs(iph->check));
	}
	else
	{
		printf("	Protocol: unknown 0x%x\n", protocol);
	}
	printf("\n");
}

char *inet_toa(unsigned long addr)
{
	struct in_addr in;
	memcpy(&in, &addr, sizeof(unsigned long));
	return inet_ntoa(in);
}

// }}}

