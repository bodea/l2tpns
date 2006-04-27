// L2TPNS: icmp

char const *cvs_id_icmp = "$Id: icmp.c,v 1.11 2006-04-27 09:53:49 bodea Exp $";

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <asm/types.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <netinet/icmp6.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <memory.h>

#include "l2tpns.h"

static uint16_t _checksum(uint8_t *addr, int count);

struct ipv6_pseudo_hdr {
	struct in6_addr src;
	struct in6_addr dest;
	uint32_t ulp_length;
	uint32_t zero    : 24;
	uint32_t nexthdr :  8;
};

void host_unreachable(in_addr_t destination, uint16_t id, in_addr_t source, uint8_t *packet, int packet_len)
{
	char buf[128] = {0};
	struct iphdr *iph;
	struct icmphdr *icmp;
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

	/* ip header + first 8 bytes of payload */
	if (packet_len > (sizeof(struct iphdr) + 8))
		packet_len = sizeof(struct iphdr) + 8;

	memcpy(buf + len, packet, packet_len);
	len += packet_len;

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
	icmp->checksum = _checksum((uint8_t *) icmp, sizeof(struct icmphdr) + packet_len);

	iph->check = _checksum((uint8_t *) iph, sizeof(struct iphdr));

	sendto(icmp_socket, buf, len, 0, (struct sockaddr *)&whereto, sizeof(struct sockaddr));
	close(icmp_socket);
}

static uint16_t _checksum(uint8_t *addr, int count)
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

void send_ipv6_ra(sessionidt s, tunnelidt t, struct in6_addr *ip)
{
	struct nd_opt_prefix_info *pinfo;
	struct ipv6_pseudo_hdr *phdr;
	uint8_t b[MAXETHER + 20];
	uint8_t c[MAXETHER + 20];
	int l;
	uint8_t *o;

	LOG(3, s, t, "Sending IPv6 RA\n");
		
	memset(b, 0, sizeof(b));
	o = makeppp(b, sizeof(b), 0, 0, s, t, PPPIPV6, 0, 0, 0);

	if (!o)
	{
		LOG(3, s, t, "failed to send IPv6 RA\n");
		return;
	}

	*o = 0x60;			// IPv6
	*(o+1) = 0;
	*(o+5) = 48;			// Length of payload (not header)
	*(o+6) = 58;			// icmp6 is next
	*(o+7) = 255;			// Hop limit
	memset(o+8, 0, 16);		// source = FE80::1
	*(o+8) = 0xFE;
	*(o+9) = 0x80;
	*(o+23) = 1;
	if (ip != NULL)
		memcpy(o+24, ip, 16);	// dest = ip
	else
	{
		// FF02::1 - all hosts
		*(o+24) = 0xFF;
		*(o+25) = 2;
		*(o+39) = 1;
	}
	*(o+40) = 134;			// RA message
	*(o+41) = 0;			// Code
	*(o+42) = *(o+43) = 0;		// Checksum
	*(o+44) = 64;			// Hop count
	*(o+45) = 0;			// Flags
	*(o+46) = *(o+47) = 255;	// Lifetime
	*(uint32_t *)(o+48) = 0;	// Reachable time
	*(uint32_t *)(o+52) = 0;	// Retrans timer
	pinfo = (struct nd_opt_prefix_info *)(o+56);
	pinfo->nd_opt_pi_type           = ND_OPT_PREFIX_INFORMATION;
	pinfo->nd_opt_pi_len            = 4;
	pinfo->nd_opt_pi_prefix_len     = 64; // prefix length
	pinfo->nd_opt_pi_flags_reserved = ND_OPT_PI_FLAG_ONLINK;
	pinfo->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
	pinfo->nd_opt_pi_valid_time     = htonl(2592000);
	pinfo->nd_opt_pi_preferred_time = htonl(604800);
	pinfo->nd_opt_pi_reserved2      = 0;
	pinfo->nd_opt_pi_prefix         = config->ipv6_prefix;
	l = sizeof(*pinfo) + 56;

	memset(c, 0, sizeof(c));
	phdr = (struct ipv6_pseudo_hdr *) c;
	memcpy(&phdr->src, o+8, 16);
	memcpy(&phdr->dest, o+24, 16);
	phdr->ulp_length = htonl(l - 40);
	phdr->nexthdr = IPPROTO_ICMPV6;

	memcpy(c + sizeof(*phdr), o + 40, l - 40);

	// Checksum is over the icmp6 payload plus the pseudo header
	*(uint16_t *)(o+42) = _checksum(c, l - 40 + sizeof(*phdr));

	tunnelsend(b, l + (o-b), t); // send it...
	return;
}
