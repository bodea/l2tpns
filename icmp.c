// L2TPNS: icmp

char const *cvs_id_icmp = "$Id: icmp.c,v 1.6 2004-12-16 08:49:53 bodea Exp $";

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <asm/types.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <memory.h>

#include "l2tpns.h"

static uint16_t _checksum(unsigned char *addr, int count);

void host_unreachable(in_addr_t destination, uint16_t id, in_addr_t source, char *packet, int packet_len)
{
	char buf[128] = {0};
	struct iphdr *iph;
	struct icmphdr *icmp;
	char *data;
	int len = 0, on = 1, icmp_socket;
	struct sockaddr_in whereto = {0};

	if ((icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return;

	setsockopt(icmp_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));

	whereto.sin_addr.s_addr = destination;
	whereto.sin_family = AF_INET;

	iph = (struct iphdr *)(buf);
	len = sizeof(struct iphdr);
	icmp = (struct icmphdr *)(buf + len);
	len += sizeof(struct icmphdr);
	data = (char *)(buf + len);
	len += (packet_len < 64) ? packet_len : 64;
	memcpy(data, packet, (packet_len < 64) ? packet_len : 64);

	iph->tos = 0;
	iph->id = id;
	iph->frag_off = 0;
	iph->ttl = 30;
	iph->check = 0;
	iph->version = 4;
	iph->ihl = 5;
	iph->protocol = 1;
	iph->check = 0;
	iph->daddr = destination;
	iph->saddr = source;

	iph->tot_len = ntohs(len);

	icmp->type = ICMP_DEST_UNREACH;
	icmp->code = ICMP_HOST_UNREACH;
	icmp->checksum = _checksum((char *) icmp, sizeof(struct icmphdr) + ((packet_len < 64) ? packet_len : 64));

	iph->check = _checksum((char *) iph, sizeof(struct iphdr));

	sendto(icmp_socket, (char *)buf, len, 0, (struct sockaddr *)&whereto, sizeof(struct sockaddr));
	close(icmp_socket);
}

static uint16_t _checksum(unsigned char *addr, int count)
{
	register long sum = 0;

	for (; count > 1; count -= 2)
	{
		sum += ntohs(*(uint32_t *) addr);
		addr += 2;
	}

	if (count > 1) sum += *(unsigned char *)addr;

	// take only 16 bits out of the 32 bit sum and add up the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// one's complement the result
	sum = ~sum;

	return htons((uint16_t) sum);
}
