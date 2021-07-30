#include "include/icmp.h"
#include "include/ip.h"
#include "include/rtable.h"
#include "include/arp.h"
#include "include/arpcache.h"
#include "include/mac.h"
#include "include/base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int pkt_len, u8 type, u8 code)
{
	char *packet = (char*)in_pkt;
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	int len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + ip_hdr->ihl * 4 + 8;
	char *new_packet = (char *)malloc(len);
	printf("LEN: %d %d %x %x %d %d\n", ip_hdr->tot_len, ip_hdr->ihl * 4, ntohl(ip_hdr->daddr), ntohl(ip_hdr->saddr), ip_hdr->ttl,ip_hdr->id);
	ip_hdr->ttl++;
	ip_hdr->checksum = ip_checksum(ip_hdr);

	struct iphdr *new_ip_hdr = (struct iphdr *)(new_packet + sizeof(struct ether_header));
	u16 tot_len = 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8;
	rt_entry_t * rt_entry = longest_prefix_match(ntohl(ip_hdr->saddr));
	new_ip_hdr->version = 4;
	new_ip_hdr->ihl = 5;
	new_ip_hdr->tos = 0;
	new_ip_hdr->tot_len = htons(tot_len);
	new_ip_hdr->id = ip_hdr->id;
	new_ip_hdr->frag_off = htons(IP_DF);
	new_ip_hdr->ttl = DEFAULT_TTL;
	new_ip_hdr->protocol = IPPROTO_ICMP;
	new_ip_hdr->saddr = htonl(rt_entry->iface->ip);
	new_ip_hdr->daddr = ip_hdr->saddr;
	new_ip_hdr->checksum = ip_checksum(new_ip_hdr);
	//ip_init_hdr(new_ip_hdr, rt_entry->iface->ip, ntohl(ip_hdr->saddr), tot_len, IPPROTO_ICMP);

	struct ether_header* eh = (struct ether_header *)packet;
	struct ether_header *new_eh = (struct ether_header *)new_packet;
	printf("eh_shost:" ETHER_STRING "\n", ETHER_FMT(eh->ether_shost));
	memcpy(new_eh->ether_dhost, eh->ether_shost, ETH_ALEN * sizeof(u8));
	memcpy(new_eh->ether_shost, rt_entry->iface->mac, ETH_ALEN * sizeof(u8));
	new_eh->ether_type = htons(ETH_P_IP);

	struct icmphdr *new_icmp_hdr = (struct icmphdr *)(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	printf("BEFORE: " ETHER_STRING "\n", ETHER_FMT(new_eh->ether_dhost));
	memset(&(new_icmp_hdr->u), 0, 4);
	new_icmp_hdr->type = type;
	new_icmp_hdr->code = code;
	memcpy(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, ip_hdr->ihl * 4 + 8);
	new_icmp_hdr->checksum = icmp_checksum(new_icmp_hdr, len - sizeof(struct iphdr) - sizeof(struct ether_header));

	//icmp_send_packet(new_packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
	//printf("DEBUG: Sended ICMP HOST UNREACHABLE packet from %x %s to %x " ETHER_STRING "\n", rt_entry->iface->ip, rt_entry->if_name, ntohl(ip_hdr->saddr), ETHER_FMT(new_eh->ether_dhost));
	//ip_send_packet(new_packet, len);
	printf("DEBUG: Sended ICMP packet from %x %s to %x " ETHER_STRING "\tlen: %d \n", rt_entry->iface->ip, rt_entry->if_name, ntohl(ip_hdr->saddr), ETHER_FMT(new_eh->ether_dhost), len);
	printf("type: %d, code:%d\n", type, code);
	free(packet);
	iface_send_packet(rt_entry->iface, new_packet, len);
}
