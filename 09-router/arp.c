#include "include/arp.h"
#include "include/base.h"
#include "include/types.h"
#include "include/ether.h"
#include "include/arpcache.h"
#include "include/ip.h"
#include "include/rtable.h"
#include "include/log.h"
#include "include/icmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
	int len = sizeof(struct ether_header) + sizeof(struct ether_arp);
	char *packet = (char *)malloc(len);

	struct ether_header *eh = (struct ether_header *)packet;
	struct ether_arp *arph = (struct ether_arp *)(packet + sizeof(struct ether_header));

	// ether header	
	int i;
	for(i = 0; i < 6; i++)
		eh->ether_dhost[i] = 0xff;		// dhost unknown
	memcpy(eh->ether_shost, iface->mac, 6 * sizeof(u8));
	eh->ether_type = htons(ETH_P_ARP);

	// arp header
	arph->arp_hrd = htons(ARPHRD_ETHER);
	arph->arp_pro = htons(ETH_P_IP);
	arph->arp_hln = ETH_ALEN;
	arph->arp_pln = 4;
	arph->arp_op = htons(ARPOP_REQUEST);
	memcpy(arph->arp_sha, iface->mac, ETH_ALEN * sizeof(u8));
	arph->arp_spa = htonl(iface->ip);
	memset(arph->arp_tha, 0, ETH_ALEN * sizeof(u8));
	arph->arp_tpa = htonl(dst_ip);

	printf("ARP request: spa: %x, tpa: %x\n", ntohl(arph->arp_spa), ntohl(arph->arp_tpa));
	iface_send_packet(iface, packet, len);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
	int len = sizeof(struct ether_header) + sizeof(struct ether_arp);
	// printf("len: %d req header: %p\n", len, req_hdr);
	char *packet = (char *)malloc(len);

	struct ether_header *eh = (struct ether_header *)packet;
	struct ether_arp *arph = (struct ether_arp *)(packet + sizeof(struct ether_header));

	// ether header	
	//rt_entry_t * entry = NULL;
	//entry = longest_prefix_match(arph->arp_spa);
	//memcpy(eh->ether_dhost, entry->iface->mac, 6 * sizeof(u8));
	memcpy(eh->ether_dhost, req_hdr->arp_sha, 6 * sizeof(u8));

	memcpy(eh->ether_shost, iface->mac, 6 * sizeof(u8));
	eh->ether_type = htons(ETH_P_ARP);

	// arp header
	memcpy(arph, req_hdr, sizeof(struct ether_arp));
	arph->arp_op = htons(ARPOP_REPLY);
	memcpy(arph->arp_sha, iface->mac, ETH_ALEN * sizeof(u8));
	arph->arp_spa = htonl(iface->ip);
	memcpy(arph->arp_tha, req_hdr->arp_sha, ETH_ALEN * sizeof(u8));
	arph->arp_tpa = req_hdr->arp_spa;

	printf("request sha: " ETHER_STRING "\n", ETHER_FMT(req_hdr->arp_sha));
	printf("ARP reply sended. tpa: %x tha: " ETHER_STRING, arph->arp_tpa, ETHER_FMT(arph->arp_tha));
	printf(" spa: %x sha: " ETHER_STRING "\n", arph->arp_spa, ETHER_FMT(arph->arp_sha));
	iface_send_packet(iface, packet, len);
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	fprintf(stderr, "TODO: process arp packet: arp request & arp reply.");
	//struct ether_header *eh = (struct ether_header *)packet;
	struct ether_arp *arph = (struct ether_arp *)(packet + sizeof(struct ether_header));
	
	fprintf(stderr, " op: %d\n", ntohs(arph->arp_op));
	fprintf(stderr, " tha:" ETHER_STRING ",", ETHER_FMT(arph->arp_tha));
	fprintf(stderr, " iface:" ETHER_STRING " %s %x\n", ETHER_FMT(iface->mac), iface->name, iface->ip);
	fprintf(stderr, " tpa:%x,", ntohl(arph->arp_tpa) & iface->mask);
	fprintf(stderr, " iface ip:%x,\n", iface->ip & iface->mask);
	fprintf(stderr, " spa:%x\n", ntohl(arph->arp_spa));



	if(ntohs(arph->arp_op) == ARPOP_REQUEST && (ntohl(arph->arp_tpa) & iface->mask) == (iface->ip & iface->mask)) 
	{	// packet is arp request and this iface is dst_iface
		fprintf(stderr, " sha:" ETHER_STRING "\n", ETHER_FMT(arph->arp_sha));
		arp_send_reply(iface, arph);
		free(packet);
	}
	else if(ntohs(arph->arp_op) == ARPOP_REPLY && memcmp(arph->arp_tha, iface->mac, ETH_ALEN * sizeof(u8)) == 0 && (ntohl(arph->arp_tpa) & iface->mask) == (iface->ip & iface->mask))
	{	// packet is arp reply and this iface is dst_iface
		arpcache_insert(ntohl(arph->arp_spa), arph->arp_sha);
		free(packet);
	}
	else
	{	// otherwise, forward the arp packet
		rt_entry_t * entry = NULL;
		if((entry = longest_prefix_match(ntohl(arph->arp_spa))) == NULL)
		{
			icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
			return;
		}

		iface_send_packet(entry->iface, packet, len);
	}

}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		eh->ether_type = htons(ETH_P_IP);
		memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
		//free(packet);
	}
	else {
		log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
