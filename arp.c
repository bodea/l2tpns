#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include "l2tpns.h"

/* Most of this code is based on keepalived:vrrp_arp.c */

struct arp_buf {
	struct ether_header eth;
	struct arphdr arp;

	/* Data bit - variably sized, so not present in |struct arphdr| */
	unsigned char ar_sha[ETH_ALEN];	/* Sender hardware address */
	ipt ar_sip;			/* Sender IP address. */
	unsigned char ar_tha[ETH_ALEN]; /* Target hardware address */
	ipt ar_tip;			/* Target ip */
} __attribute__((packed));

void sendarp(int ifr_idx, const unsigned char* mac, ipt ip)
{
	int fd;
	struct sockaddr_ll sll;
	struct arp_buf buf;

	/* Ethernet */
	memset(buf.eth.ether_dhost, 0xFF, ETH_ALEN);
	memcpy(buf.eth.ether_shost, mac, ETH_ALEN);
	buf.eth.ether_type = htons(ETHERTYPE_ARP);

	/* ARP */
	buf.arp.ar_hrd = htons(ARPHRD_ETHER);
	buf.arp.ar_pro = htons(ETHERTYPE_IP);
	buf.arp.ar_hln = ETH_ALEN;
	buf.arp.ar_pln = 4; //IPPROTO_ADDR_LEN;
	buf.arp.ar_op = htons(ARPOP_REQUEST);

	/* Data */
	memcpy(buf.ar_sha, mac, ETH_ALEN);
	memcpy(&buf.ar_sip, &ip, sizeof(ip));
	memcpy(buf.ar_tha, mac, ETH_ALEN);
	memcpy(&buf.ar_tip, &ip, sizeof(ip));
	
	/* Now actually send the thing */
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_RARP));

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	strncpy(sll.sll_addr, mac, sizeof(sll.sll_addr)); /* Null-pad */
	sll.sll_halen = ETH_ALEN;
	sll.sll_ifindex = ifr_idx;

	sendto(fd, &buf, sizeof(buf), 0, (struct sockaddr*)&sll, sizeof(sll));
}
