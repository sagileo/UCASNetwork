#include "include/ip.h"
#include "include/icmp.h"
#include "include/arp.h"
#include "include/arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	fprintf(stderr, "TODO: handle ip packet.\n");
	struct ether_header * eh = (struct ether_header *)packet;
	struct iphdr* ip_hdr = (struct iphdr*)(packet + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr*)(IP_DATA(ip_hdr));
	//printf("%d, %ld\n", len, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

	// ICMP echo request packet (ping) and this iface is dst_iface
	if(ip_hdr->protocol == IPPROTO_ICMP && icmp_hdr->type == ICMP_ECHOREQUEST && ((iface->ip & iface->mask) == (ntohl(ip_hdr->daddr) & iface->mask))) 
	{
		fprintf(stderr, "Need to send ICMP echo reply\n");
		char *reply_packet = (char*)malloc(len);
		memcpy(reply_packet, packet, len);
		struct ether_header *reply_eh = (struct ether_header *)reply_packet;
		struct iphdr* reply_ip_hdr = (struct iphdr*)(reply_packet + sizeof(struct ether_header));
		struct icmphdr* reply_icmp_hdr = (struct icmphdr*)(IP_DATA(reply_ip_hdr));

		// set ether header
		reply_eh->ether_type = htons(ETH_P_IP);
		memcpy(reply_eh->ether_dhost, eh->ether_shost, ETH_ALEN * sizeof(u8));
		memcpy(reply_eh->ether_shost, eh->ether_dhost, ETH_ALEN * sizeof(u8));

		// set ip header
		//ip_init_hdr(reply_ip_hdr, ntohl(ip_hdr->daddr), ntohl(ip_hdr->saddr), ntohs(ip_hdr->tot_len), IPPROTO_ICMP)
		reply_ip_hdr->daddr = ip_hdr->saddr;
		reply_ip_hdr->saddr = ip_hdr->daddr;
		printf("ping saddr:%x, daddr:%x\n", ntohl(ip_hdr->saddr), ntohl(ip_hdr->daddr));
		printf("reply saddr:%x, daddr:%x\n", ntohl(reply_ip_hdr->saddr), ntohl(reply_ip_hdr->daddr));
		printf("source iface:" ETHER_STRING "\n", ETHER_FMT(eh->ether_shost));
		printf("dest iface:" ETHER_STRING "\n", ETHER_FMT(eh->ether_dhost));
		reply_ip_hdr->ttl = DEFAULT_TTL;
		reply_ip_hdr->checksum = ip_checksum(reply_ip_hdr);

		// set icmp header
		reply_icmp_hdr->code = 0;
		reply_icmp_hdr->type = ICMP_ECHOREPLY;
		reply_icmp_hdr->checksum = icmp_checksum(reply_icmp_hdr, len - sizeof(struct iphdr) - sizeof(struct ether_header));

		ip_send_packet(reply_packet, len);
		//iface_send_packet_by_arp(iface, ntohl(reply_ip_hdr->daddr), reply_packet, len);
		
		printf("icmp reply packet freed\n");
	}
	else if(iface->ip != ntohl(ip_hdr->daddr))	// forward the packet
	{
		printf("ip saddr:%x, daddr:%x\n", ntohl(ip_hdr->saddr), ntohl(ip_hdr->daddr));
		printf("dest iface:" ETHER_STRING "\n", ETHER_FMT(eh->ether_dhost));
		printf("ip id:%d\n", ip_hdr->id);
		printf("totlen:%d\n", ntohs(ip_hdr->tot_len));
		printf("checksum:%d\n", ip_hdr->checksum);
		printf("eh_shost:" ETHER_STRING "\n", ETHER_FMT(eh->ether_shost));
		ip_hdr->ttl--;
		if(ip_hdr->ttl == 0)
		{
			icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
			return;
		}
		ip_hdr->checksum = ip_checksum(ip_hdr);
		ip_send_packet(packet, len);
	}
}
