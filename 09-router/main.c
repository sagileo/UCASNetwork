#include "include/base.h"
#include "include/ether.h"
#include "include/arp.h"
#include "include/arpcache.h"
#include "include/ip.h"
#include "include/icmp.h"
#include "include/rtable.h"

#include "include/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// handle packet, hand the packet to handle_ip_packet or handle_arp_packet
// according to ether_type
void handle_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;

	log(DEBUG, "got packet from %s, %d bytes, proto: 0x%04hx\n", 
			iface->name, len, ntohs(eh->ether_type));
	switch (ntohs(eh->ether_type)) {
		case ETH_P_IP:
			handle_ip_packet(iface, packet, len);
			break;
		case ETH_P_ARP:
			handle_arp_packet(iface, packet, len);
			break;
		default:
			log(ERROR, "Unknown packet type 0x%04hx, ingore it.", \
					ntohs(eh->ether_type));
			break;
	}
}

// run user stack, receive packet on each interface, and handle those packet
// like normal TCP/IP stack
void ustack_run()
{
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);
	char buf[ETH_FRAME_LEN];
	int len;

	while (1) {
		int ready = poll(instance->fds, instance->nifs, -1);
		if (ready < 0) {
			perror("Poll failed!");
			break;
		}
		else if (ready == 0)
			continue;

		for (int i = 0; i < instance->nifs; i++) {
			if (instance->fds[i].revents & POLLIN) {
				len = recvfrom(instance->fds[i].fd, buf, ETH_FRAME_LEN, 0, \
						(struct sockaddr*)&addr, &addr_len);
				if (len <= 0) {
					log(ERROR, "receive packet error: %s", strerror(errno));
				}
				else if (addr.sll_pkttype == PACKET_OUTGOING) {
					// XXX: Linux raw socket will capture both incoming and
					// outgoing packets, while we only care about the incoming ones.

					// log(DEBUG, "received packet which is sent from the "
					// 		"interface itself, drop it.");
				}
				else {
					iface_info_t *iface = fd_to_iface(instance->fds[i].fd);
					if (!iface)
						continue;

					char *packet = malloc(len);
					if (!packet) {
						log(ERROR, "malloc failed when receiving packet.");
						continue;
					}
					memcpy(packet, buf, len);
					handle_packet(iface, packet, len);
				}
			}
		}
	}
}

int main(int argc, const char **argv)
{
	if (getuid() && geteuid()) {
		printf("Permission denied, should be superuser!\n");
		exit(1);
	}

	init_ustack();

	arpcache_init();

	init_rtable();
	load_rtable_from_kernel();

	ustack_run();

	return 0;
}
