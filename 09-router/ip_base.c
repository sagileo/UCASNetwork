#include "include/ip.h"
#include "include/icmp.h"
#include "include/arpcache.h"
#include "include/rtable.h"
#include "include/arp.h"

// #include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// initialize ip header 
void ip_init_hdr(struct iphdr *ip, u32 saddr, u32 daddr, u16 len, u8 proto)
{
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(len);
	ip->id = rand();
	ip->frag_off = htons(IP_DF);
	ip->ttl = DEFAULT_TTL;
	ip->protocol = proto;
	ip->saddr = htonl(saddr);
	ip->daddr = htonl(daddr);
	ip->checksum = ip_checksum(ip);
}

// lookup in the routing table, to find the entry with the same and longest prefix.
// the input address is in host byte order
rt_entry_t *longest_prefix_match(u32 dst)
{
	fprintf(stderr, "TODO: longest prefix match for the packet. dst ip :%x \n", dst);
	rt_entry_t *entry = NULL, *best_entry = NULL;
	u32 longest_mask = 0;
	list_for_each_entry(entry, &rtable, list) {
		if((entry->dest & entry->mask) == (dst & entry->mask) && entry->mask > longest_mask)
		{
			longest_mask = entry->mask;
			best_entry = entry;
		}
	}

	//fprintf(stderr, "gw: %x, iface:%s\n", best_entry->gw, best_entry->if_name);
	return best_entry;
}

// send IP packet
//
// Different from forwarding packet, ip_send_packet sends packet generated by
// router itself. This function is used to send ICMP packets.
void ip_send_packet(char *packet, int len)
{
	fprintf(stderr, "TODO: send ip packet.\n");
	//struct ether_header *eh = (struct ether_header *)packet;
	struct iphdr* ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
	rt_entry_t *rt_entry = NULL;
	if((rt_entry = longest_prefix_match(ntohl(ip_hdr->daddr))) == NULL)
	{
		printf("ip not found\n");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		return;
	}
	
	printf("Sending from iface: %x, %s " ETHER_STRING " to iface: %x\n", rt_entry->iface->ip, rt_entry->iface->name, ETHER_FMT(rt_entry->iface->mac), ntohl(ip_hdr->daddr));

	if(rt_entry->gw != 0)
		iface_send_packet_by_arp(rt_entry->iface, rt_entry->gw, packet, len);
	else
		iface_send_packet_by_arp(rt_entry->iface, ntohl(ip_hdr->daddr), packet, len);
}
