#include "include/arpcache.h"
#include "include/arp.h"
#include "include/ether.h"
#include "include/icmp.h"
#include "include/ip.h"
#include "include/rtable.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;
pthread_t rtable_print;

void *print_rtable_thread(void *arg)
{
	char c;
	while(1)
	{
		if((c = getchar()) == '\n')
		{
			print_rtable();
		}
	}

}

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
	pthread_create(&rtable_print, NULL, print_rtable_thread, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	fprintf(stderr, "TODO: lookup ip address in arp cache.\n");
	printf("arpcache looking up ip: %x\n", ip4);

	if(ip4 == 0)
		return 1;

	int i;
	for(i = 0; i < MAX_ARP_SIZE; i++)
	{
		if(arpcache.entries[i].valid && (arpcache.entries[i].ip4 == ip4))
		{
			memcpy(mac, arpcache.entries[i].mac, 6*sizeof(u8));
			return 1;
		}
	}
	return 0;
}

// append the packet to arpcache
//
// Lookup in the list which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	fprintf(stderr, "TODO: append the ip address if lookup failed, and send arp request if necessary.\n");
	struct arp_req *req_entry = NULL, *req_q;
	struct cached_pkt *pkt = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
	pkt->packet = packet;
	pkt->len = len;
	init_list_head(&pkt->list);

	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		if(req_entry->iface == iface && req_entry->ip4 == ip4)
		{	// found an entry with the same IP address and iface
			list_add_tail(&pkt->list, &req_entry->cached_packets);
			return;
		}
	}
	// otherwise, create a new entry, append packet and send arp request
	struct arp_req *req = (struct arp_req *)malloc(sizeof(struct arp_req));
	init_list_head(&req->cached_packets);
	init_list_head(&req->list);
	list_add_tail(&pkt->list, &req->cached_packets);
	req->iface = iface;
	req->ip4 = ip4;
	req->retries = 0;
	req->sent = time(NULL);
	list_add_tail(&req->list, &arpcache.req_list);

	arp_send_request(iface, ip4);
	return;
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	fprintf(stderr, "TODO: insert ip->mac entry, and send all the pending packets.\n");
	fprintf(stderr, "ip4:%x, mac:" ETHER_STRING "\n", ip4, ETHER_FMT(mac));

	int i;
	for(i = 0; i < MAX_ARP_SIZE; i++)
	{
		if(arpcache.entries[i].valid == 0)
		{
			arpcache.entries[i].added = time(NULL);
			arpcache.entries[i].ip4 = ip4;
			memcpy(arpcache.entries[i].mac, mac, ETH_ALEN * sizeof(u8));
			arpcache.entries[i].valid = 1;
			break;
		}
	}

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		if(req_entry->ip4 == ip4)
		{
			struct cached_pkt *pkt_entry = NULL, *pkt_q;
			list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {

				struct ether_header *eh = (struct ether_header *)(pkt_entry->packet);
				struct iphdr* ip_hdr = (struct iphdr*)((pkt_entry->packet) + sizeof(struct ether_header));
				
				memcpy(eh->ether_dhost, mac, ETH_ALEN * sizeof(u8));
				memcpy(eh->ether_shost, req_entry->iface->mac, ETH_ALEN * sizeof(u8));
				printf("pending packet sended. src:%x dest: %x len:%d\n", ntohl(ip_hdr->saddr), ntohl(ip_hdr->daddr), pkt_entry->len);
				printf("pending packet sended. src:" ETHER_STRING " dest: " ETHER_STRING " \n", ETHER_FMT(eh->ether_shost), ETHER_FMT(eh->ether_dhost));
				iface_send_packet(req_entry->iface, pkt_entry->packet, pkt_entry->len);

				list_delete_entry(&(pkt_entry->list));
				free(pkt_entry);
			}

			list_delete_entry(&(req_entry->list));
			free(req_entry);
			return;
		}
	}
	return;
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
	int i;
	while (1) {
		sleep(1);
		fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");
		time_t now = time(NULL);
		for(i = 0; i < MAX_ARP_SIZE; i++)
		{
			if(now - arpcache.entries[i].added > 15)
				arpcache.entries[i].valid = 0;
		}
		i = 0;

		now = time(NULL);
		struct arp_req *req_entry = NULL, *req_q;
		list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
			if(now - req_entry->sent >= 1 && req_entry->retries < 5)
			{
				arp_send_request(req_entry->iface, req_entry->ip4);
				printf("DEBUG: Resended arp request\n");
				req_entry->retries += 1;
			}
			else if(req_entry->retries >= 5)
			{
				struct cached_pkt *pkt_entry = NULL, *pkt_q;
				list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
					list_delete_entry(&(pkt_entry->list));
					
					icmp_send_packet(pkt_entry->packet, pkt_entry->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);

					free(pkt_entry);
				}

				list_delete_entry(&(req_entry->list));
				free(req_entry);
			}
		}
	}

	return NULL;
}
