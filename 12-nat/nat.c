#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry (iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

static int is_internal_ipaddr(u32 ip)
{
	if (((ip & 0xff000000) == 0x0a000000) || ((ip & 0xfff00000) == 0xac100000) || ((ip & 0xffff0000) == 0xc0a80000))
		return 1;
	else return 0;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	// fprintf(stdout, "TODO: determine the direction of this packet.\n");
	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (is_internal_ipaddr(ntohl(ip->saddr)) && !is_internal_ipaddr(ntohl(ip->daddr)))
		return DIR_OUT;
	else if (!is_internal_ipaddr(ntohl(ip->saddr)) && ntohl(ip->daddr) == nat.external_iface->ip)
		return DIR_IN;
	else
		return DIR_INVALID;
}

static u16 assign_external_port()
{
	u16 i;
	for(i = NAT_PORT_MIN; i < NAT_PORT_MAX; i++)
	{
		if(nat.assigned_ports[i])
			continue;
		nat.assigned_ports[i] = 1;
		return i;
	}
	return 0;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	// fprintf(stdout, "TODO: do translation for this packet.\n");
	u8 hashval;
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = packet_to_tcp_hdr(packet);
	struct sock_addr skaddr;
	struct nat_mapping *nat_entry = NULL;

	pthread_mutex_lock(&(nat.lock));

	if (dir == DIR_OUT)	// SNAT
	{
		skaddr.ip = ntohl(ip->daddr);
		skaddr.port = ntohs(tcp->dport);
		hashval = hash8((char*)&skaddr, 6);
		list_for_each_entry (nat_entry, &(nat.nat_mapping_list[hashval]), list) 
		{
			if (nat_entry->internal_ip == ntohl(ip->saddr) && nat_entry->internal_port == ntohs(tcp->sport))
			{
				nat_entry->conn.internal_ack = ntohl(tcp->ack);
				if(nat_entry->conn.internal_fin == 0)
					nat_entry->conn.internal_fin = tcp->flags & TCP_FIN;
				nat_entry->conn.internal_seq_end = tcp_seq_end(ip, tcp);
				goto DIR_OUT_TRANS;
			}
		}
		// not found, add a link
		nat_entry = (struct nat_mapping*)malloc(sizeof(struct nat_mapping));
		memset(&nat_entry->conn, 0, sizeof(nat_entry->conn));
		nat_entry->conn.internal_ack = ntohl(tcp->ack);
		nat_entry->conn.internal_seq_end = tcp_seq_end(ip, tcp);
		nat_entry->external_ip = nat.external_iface->ip;
		nat_entry->external_port = assign_external_port();
		nat_entry->internal_ip = ntohl(ip->saddr);
		nat_entry->internal_port = ntohs(tcp->sport);
		nat_entry->remote_ip = ntohl(ip->daddr);
		nat_entry->remote_port = ntohl(tcp->dport);
		nat_entry->update_time = time(NULL);
		init_list_head(&nat_entry->list);
		list_add_tail(&(nat_entry->list), &(nat.nat_mapping_list[hashval]));
		// translate packet
	DIR_OUT_TRANS:
		ip->saddr = htonl(nat_entry->external_ip);
		ip->checksum = ip_checksum(ip);
		tcp->sport = htons(nat_entry->external_port);
		tcp->checksum = tcp_checksum(ip, tcp);
	} else if (dir == DIR_IN) {	// DNAT
		skaddr.ip = ntohl(ip->saddr);
		skaddr.port = ntohs(tcp->sport);
		hashval = hash8((char*)&skaddr, 6);
		list_for_each_entry (nat_entry, &(nat.nat_mapping_list[hashval]), list) 
		{
			if(nat_entry->external_ip == ntohl(ip->daddr) && nat_entry->external_port == ntohs(tcp->dport))
			{
				nat_entry->conn.external_ack = ntohl(tcp->ack);
				if(nat_entry->conn.external_fin == 0)
					nat_entry->conn.external_fin = tcp->flags & TCP_FIN;
				nat_entry->conn.external_seq_end = tcp_seq_end(ip, tcp);
				goto DIR_IN_TRANS;
			}
		}
		// not found, look for dnat rules and add a link
		struct dnat_rule* rule = NULL;
		list_for_each_entry(rule, &(nat.rules), list)
		{
			if(rule->external_ip == ntohl(ip->daddr) && rule->external_port == ntohs(tcp->dport))
				goto rule_found;
		}
		log(ERROR, "dnat rule not found: %x:%d\n", ntohl(ip->daddr), ntohs(tcp->dport));
		exit(1);
	rule_found:
		// hash a new link
		nat_entry = (struct nat_mapping*)malloc(sizeof(struct nat_mapping));
		memset(&nat_entry->conn, 0, sizeof(nat_entry->conn));
		nat_entry->conn.external_ack = ntohl(tcp->ack);
		nat_entry->conn.external_seq_end = tcp_seq_end(ip, tcp);
		nat_entry->external_ip = rule->external_ip;
		nat_entry->external_port = rule->external_port;
		nat_entry->internal_ip = rule->internal_ip;
		nat_entry->internal_port = rule->internal_port;
		nat_entry->remote_ip = ntohl(ip->saddr);
		nat_entry->remote_port = ntohl(tcp->sport);
		nat_entry->update_time = time(NULL);
		init_list_head(&nat_entry->list);
		list_add_tail(&(nat_entry->list), &(nat.nat_mapping_list[hashval]));
		// translate packet
	DIR_IN_TRANS:
		ip->daddr = htonl(nat_entry->internal_ip);
		ip->checksum = ip_checksum(ip);
		tcp->dport = htons(nat_entry->internal_port);
		tcp->checksum = tcp_checksum(ip, tcp);
	}
	if(tcp->flags & TCP_RST)
	{
		list_delete_entry(&(nat_entry->list));
		free(nat_entry);
	}

	pthread_mutex_unlock(&(nat.lock));

	ip_send_packet(packet, len);
	return;
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// check whether the flow is finished according to FIN bit and sequence number
// XXX: seq_end is calculated by `tcp_seq_end` in tcp.h
static int is_flow_finished(struct nat_connection *conn)
{
    return (conn->internal_fin && conn->external_fin) && \
            (conn->internal_ack >= conn->external_seq_end) && \
            (conn->external_ack >= conn->internal_seq_end);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	struct nat_mapping *nat_entry = NULL, *nat_entry_q = NULL;
	int i;
	while (1) {
		// fprintf(stdout, "TODO: sweep finished flows periodically.\n");
		sleep(1);

		pthread_mutex_lock(&(nat.lock));
		for (i = 0; i < HASH_8BITS; i++)
		{
			list_for_each_entry_safe (nat_entry, nat_entry_q, &(nat.nat_mapping_list[i]), list)
			{
				if (is_flow_finished(&(nat_entry->conn)) || time(NULL) - (nat_entry->update_time) >= TCP_ESTABLISHED_TIMEOUT)
				{
					nat.assigned_ports[nat_entry->external_port] = 0;		// free port
					list_delete_entry(&(nat_entry->list));
					free(nat_entry);
				}
			}
		}
		pthread_mutex_unlock(&(nat.lock));
	}

	return NULL;
}

static void parse_ip_port(char *str, u32 *ex_ip, u16 *ex_port, u32 *in_ip, u16 *in_port)
{
	// 159.226.39.43:8000 -> 10.21.0.1:8000
	u32 ex_ip_3, ex_ip_2, ex_ip_1, ex_ip_0;
	u32 in_ip_3, in_ip_2, in_ip_1, in_ip_0;
	sscanf(str, "%d.%d.%d.%d:%hd -> %d.%d.%d.%d:%hd", \
			&ex_ip_3, &ex_ip_2, &ex_ip_1, &ex_ip_0, ex_port, &in_ip_3, &in_ip_2, &in_ip_1, &in_ip_0, in_port);
	*ex_ip = (ex_ip_3 << 24) + (ex_ip_2 << 16) + (ex_ip_1 << 8) + ex_ip_0;
	*in_ip = (in_ip_3 << 24) + (in_ip_2 << 16) + (in_ip_1 << 8) + in_ip_0;
}

int parse_config(const char *filename)
{
	// fprintf(stdout, "TODO: parse config file, including i-iface, e-iface (and dnat-rules if existing).\n");
	FILE * fp;
	fp = fopen(filename, "r");
	char line[1000];
	char name[20];
	while (1)
	{
		if (fgets(line, 1000, fp) == NULL)
			break;
		line[strlen(line) - 1] = 0;		// remove '\n' at end
		if (memcmp(line, "internal-iface: ", strlen("internal-iface: ")) == 0)
		{
			memcpy(name, line + strlen("internal-iface: "), strlen(line) - strlen("internal-iface: ") + 1);
			nat.internal_iface = if_name_to_iface(name);
		} else if (memcmp(line, "external-iface: ", strlen("external-iface: ")) == 0) {
			memcpy(name, line + strlen("external-iface: "), strlen(line) - strlen("external-iface: ") + 1);
			nat.external_iface = if_name_to_iface(name);
		} else if (memcmp(line, "dnat-rules: ", strlen("dnat-rules: ")) == 0) {
			u32 external_ip, internal_ip;
			u16 external_port, internal_port;
			parse_ip_port(line + strlen("dnat-rules: "), &external_ip, &external_port, &internal_ip, &internal_port);
			struct dnat_rule *nat_rule = (struct dnat_rule *)malloc(sizeof(struct dnat_rule));
			nat_rule->external_ip = external_ip;
			nat_rule->external_port = external_port;
			nat_rule->internal_ip = internal_ip;
			nat_rule->internal_port = internal_port;
			init_list_head(&nat_rule->list);
			list_add_tail(&(nat_rule->list), &(nat.rules));
		}
	}
	return 0;
}

// initialize
void nat_init(const char *config_file)
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	init_list_head(&nat.rules);

	// seems unnecessary
	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	parse_config(config_file);

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

void nat_exit()
{
	// fprintf(stdout, "TODO: release all resources allocated.\n");
	struct nat_mapping *nat_entry = NULL, *nat_entry_q = NULL;
	int i;
	
	for (i = 0; i < HASH_8BITS; i++)
	{
		list_for_each_entry_safe (nat_entry, nat_entry_q, &(nat.nat_mapping_list[i]), list)
		{
			nat.assigned_ports[nat_entry->external_port] = 0;		// free port
			list_delete_entry(&(nat_entry->list));
			free(nat_entry);
		}
	}

	return ;
}
