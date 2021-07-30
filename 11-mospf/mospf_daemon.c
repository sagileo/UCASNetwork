#include "include/mospf_daemon.h"
#include "include/mospf_proto.h"
#include "include/mospf_nbr.h"
#include "include/mospf_database.h"

#include "include/arp.h"
#include "include/arpcache.h"

#include "include/rtable.h"

#include "include/ip.h"

#include "include/list.h"
#include "include/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;
extern pthread_mutex_t getch_lock;

int db_changed;


void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);
	pthread_mutex_init(&getch_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->num_nbr = 0;
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *print_db_thread(void *arg);
void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);
void *renew_rtable_thread(void *param);

void mospf_run()
{
	pthread_t hello, lsu, nbr, db, db_print, renew_rtable;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);
	pthread_create(&renew_rtable, NULL, renew_rtable_thread, NULL);
	pthread_create(&db_print, NULL, print_db_thread, NULL);
}


void *renew_rtable_thread(void *param)
{
	mospf_db_entry_t *db = NULL;
	int num_router;
	int max_router = 20;
	while(1)
	{
		sleep(1);
		if(!db_changed)
			continue;
		num_router = 1;
		list_for_each_entry(db, &mospf_db, list){
			num_router++;
		}
		if(num_router > max_router)
			log(ERROR, "too many routers! max number: %d", max_router);
		int graph[num_router][num_router];
		int dist[num_router];
		int visited[num_router];
		int prev[num_router];
		u32 rid[num_router];

		int i, j;
		for(i = 0; i < num_router; i++)
		{
			dist[i] = INT32_MAX;
			visited[i] = 0;
			prev[i] = -1;
		}
		dist[0] = 0;
		visited[0] = 1;
		rid[0] = instance->router_id;
		i = 1;
		pthread_mutex_lock(&mospf_lock);
		list_for_each_entry(db, &mospf_db, list){
			rid[i++] = db->rid;
		}
		for(i = 0; i < num_router; i++)
			for(j = 0; j < num_router; j++)
			{
				graph[i][j] = i == j ? 0 : -1;
			}
		
		i = 1;
		int k;
		list_for_each_entry(db, &mospf_db, list){
			for(j = 0; j < db->nadv; j++)
			{
				for(k = 0; k < num_router; k++)
				{
					if(db->array[j].rid == rid[k])
						break;
				}
				graph[i][k] = 1;
				graph[k][i] = 1;
			}
			i++;
		}
		pthread_mutex_unlock(&mospf_lock);
		for(i = 0; i < num_router; i++)
		{
			if(graph[0][i] >= 0)
				dist[i] = graph[0][i];
			if(graph[0][i] == 1)
				prev[i] = 0;
		}
			

		log(DEBUG, "Printing initialized graph, num of router: %d", num_router);
		for(i = 0; i < num_router; i++)
			for(j = 0; j < num_router; j++)
				printf("%d%s", graph[i][j], j == num_router - 1 ? "\n" : "\t");
		printf("\n");
		
		// dijstra algorithm
		int u, v;
		for(i = 1; i < num_router; i++)
		{	
			// u = min_dist(dist, visited, graph, num_router);
			int min_dist = INT32_MAX;
			int m, n;
			for(m = 0; m < num_router; m++)
			{
				if(visited[m])
					continue;
				for(n = 0; n < num_router; n++)
				{
					if(!visited[n])
						continue;
					if(min_dist > graph[m][n] && graph[m][n] > 0)
					{
						min_dist = graph[m][n];
						u = m;
					}
				}
			}
			visited[u] = 1;
			for(v = 0; v < num_router; v++)
			{
				if(visited[v] == 0 && graph[u][v] > 0 && (u32)(dist[u] + graph[u][v]) < (u32)dist[v])
				{
					dist[v] = dist[u] + graph[u][v];
					prev[v] = u;
				}
			}
		}

		// renew rtable
		for(i = 1; i < num_router; i++)
		{
			if(prev[i] == -1)
				continue;
			j = i;
			while(prev[j] != 0)
			{
				j = prev[j];
			}
			// from this router to rid[i], gw is one port of rid[j]
			list_for_each_entry(db, &mospf_db, list){
				if(rid[i] == db->rid)
				{
					printf("adding rt entry to rid %x\n", rid[i]);
					for(k = 0; k < db->nadv; k++)
					{
						rt_entry_t *rt_entry = NULL;
						rt_entry = (rt_entry_t *)malloc(sizeof(rt_entry_t));
						rt_entry->dest = db->array[k].network;
						rt_entry->mask = db->array[k].mask;
						iface_info_t *iface = NULL;
						mospf_nbr_t *nbr_entry = NULL;
						list_for_each_entry(iface, &instance->iface_list, list) {
							list_for_each_entry(nbr_entry, &(iface->nbr_list), list) {
								if(nbr_entry->nbr_id == rid[j])
								{
									rt_entry->gw = nbr_entry->nbr_ip;
									rt_entry->iface = iface;
									log(DEBUG, "adding rtable entry: dest: %x, gw: %x", rt_entry->dest, rt_entry->gw);
									memcpy(rt_entry->if_name, iface->name, 16);
									goto found;
								}
							}
						}
						log(ERROR, "rid %x not found in nbr list", rid[j]);
						found:
						nbr_entry = NULL;
						rt_entry_t *entry = NULL;
						int new = 1, old = 0;
						list_for_each_entry(entry, &rtable, list) {
							if(entry->dest == rt_entry->dest && entry->gw == rt_entry->gw && \
									entry->mask == rt_entry->mask && entry->iface == rt_entry->iface)
							{
								new = 0;
								break;
							}
							else if(entry->dest == rt_entry->dest) 	
							{
								old = 1;
								break;
							}
						}
						if(new)
						{
							list_add_tail(&(rt_entry->list), &rtable);
							log(DEBUG, "added rtable entry: dest: %x, gw: %x", rt_entry->dest, rt_entry->gw);
							if(old)
							{
								list_delete_entry(&(entry->list));
								free(entry);
							}
						}
						else
							free(rt_entry);
					}
				}
			}
		}
		db_changed = 0;
	}
	return NULL;
}

void *print_db_thread(void *arg)
{
	char str[100];
	int i;
	while(1)
	{
		scanf("%s\n", str);
		if(strcmp(str, "db") == 0)
		{
			printf("router\tnetwork\tmask\trid\n");
			mospf_db_entry_t *db = NULL;
			list_for_each_entry(db, &mospf_db, list){
				for(i = 0; i < db->nadv; i++)
				{
					printf("%x\t%x\t%x\t%x\n",db->rid, db->array[i].network, db->array[i].mask, db->array[i].rid);
				}
				printf("\n");
			}
		} else if(strcmp(str, "r") == 0)
			print_rtable();
	}
}

void *sending_mospf_hello_thread(void *param)
{
	int len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
	char* wrapper = (char *)malloc(len);
	struct ether_header* eh = (struct ether_header*)wrapper;
	struct iphdr* iph = (struct iphdr*)(wrapper + ETHER_HDR_SIZE);
	struct mospf_hdr* mospfh = (struct mospf_hdr*)(wrapper + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	struct mospf_hello* mospf_hello = (struct mospf_hello*)(wrapper + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
	u8 hello_dhost[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x05};

	memcpy(eh->ether_dhost, hello_dhost, 6);
	eh->ether_type = ntohs(ETH_P_IP);

	iface_info_t *iface = NULL;
	while(1)
	{
		sleep(MOSPF_DEFAULT_HELLOINT);
		// fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");
		list_for_each_entry(iface, &instance->iface_list, list) {
			memcpy(eh->ether_shost, iface->mac, 6); 

			ip_init_hdr(iph, iface->ip, MOSPF_ALLSPFRouters, IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, IPPROTO_MOSPF);
			mospf_init_hdr(mospfh, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, instance->area_id);
			mospf_init_hello(mospf_hello, iface->mask);
			mospfh->checksum = mospf_checksum(mospfh);
			char *pkt = (char *)malloc(len);
			memcpy(pkt, wrapper, len);
			iface_send_packet(iface, pkt, len);
		}	
	}
	return NULL;
}

void *checking_nbr_thread(void *param)
{
	while(1)
	{
		sleep(1);
		// fprintf(stdout, "TODO: neighbor list timeout operation.\n");
		pthread_mutex_lock(&mospf_lock);
		iface_info_t *iface = NULL;
		mospf_nbr_t *nbr_entry = NULL, *nbr_entry_q = NULL;
		list_for_each_entry(iface, &instance->iface_list, list) {
			list_for_each_entry_safe(nbr_entry, nbr_entry_q, &(iface->nbr_list), list)
			{
				if(nbr_entry->alive >= 3 * iface->helloint)
				{
					list_delete_entry(&(nbr_entry->list));
					log(DEBUG, "deleted nbr entry rid %x, nbr ip %x", nbr_entry->nbr_id ,nbr_entry->nbr_ip);
					free(nbr_entry);
					continue;
				}
				nbr_entry->alive++;
			}
		}	
		pthread_mutex_unlock(&mospf_lock);
	}
	return NULL;
}

void *checking_database_thread(void *param)
{
	while(1)
	{
		sleep(1);
		// fprintf(stdout, "TODO: link state database timeout operation.\n");
		pthread_mutex_lock(&mospf_lock);
		mospf_db_entry_t *db = NULL, *db_q = NULL;
		list_for_each_entry_safe(db, db_q, &mospf_db, list){
			if(db->alive >= MOSPF_DATABASE_TIMEOUT)
			{
				free(db->array);
				list_delete_entry(&db->list);
				free(db);
				db_changed = 1;
				continue;
			}
			db->alive++;
		}
		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	// fprintf(stdout, "TODO: handle mOSPF Hello message.\n");
	struct ether_header* eh = (struct ether_header*)packet;
	struct iphdr* iph = (struct iphdr*)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr* mospfh = (struct mospf_hdr*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	struct mospf_hello* mospf_hello = (struct mospf_hello*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);

	mospf_nbr_t* nbr_entry = NULL;
	int found = 0;
	pthread_mutex_lock(&mospf_lock);
	list_for_each_entry(nbr_entry, &(iface->nbr_list), list)
	{
		if(nbr_entry->nbr_id == ntohl(mospfh->rid))
		{
			nbr_entry->alive = 0;
			found = 1;
			break;
		}
	}
	if(!found)
	{
		mospf_nbr_t* new_nbr_entry = (mospf_nbr_t*)malloc(sizeof(mospf_nbr_t));
		new_nbr_entry->alive = 0;
		new_nbr_entry->nbr_id = ntohl(mospfh->rid);
		new_nbr_entry->nbr_ip = ntohl(iph->saddr);
		new_nbr_entry->nbr_mask = ntohl(mospf_hello->mask);
		list_add_tail(&(new_nbr_entry->list), &(iface->nbr_list));
		iface->num_nbr++;
	}
	pthread_mutex_unlock(&mospf_lock);
}

void *sending_mospf_lsu_thread(void *param)
{
	iface_info_t *iface = NULL;
	mospf_nbr_t *nbr = NULL;
	while(1)
	{
		// sleep(MOSPF_DEFAULT_LSUINT);
		sleep(5);
		instance->sequence_num++;
		// fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
		pthread_mutex_lock(&mospf_lock);
		
		int num_nbr = 0;
		list_for_each_entry(iface, &instance->iface_list, list) {
			num_nbr += iface->num_nbr == 0 ? 1 : iface->num_nbr;
		}
		int i = 0;
		struct mospf_lsa *lsa_wrapper = (struct mospf_lsa *)malloc(num_nbr * MOSPF_LSA_SIZE);
		list_for_each_entry(iface, &instance->iface_list, list) {
			if(iface->num_nbr == 0)
			{
				lsa_wrapper[i].mask = htonl(iface->mask);
				lsa_wrapper[i].network = htonl(iface->ip);
				lsa_wrapper[i].rid = htonl(0);
				i++;
				continue;
			}
			list_for_each_entry(nbr, (&iface->nbr_list), list) {
				lsa_wrapper[i].mask = htonl(nbr->nbr_mask);
				lsa_wrapper[i].network = htonl(nbr->nbr_ip);
				lsa_wrapper[i].rid = htonl(nbr->nbr_id);
				i++;
			}
		}
		int len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + num_nbr * MOSPF_LSA_SIZE;
		list_for_each_entry(iface, &instance->iface_list, list) {
			list_for_each_entry(nbr, (&iface->nbr_list), list){
				char *packet = (char *)malloc(len);
				struct ether_header *eh = (struct ether_header*)packet;
				struct iphdr *iph = (struct iphdr*)(packet + ETHER_HDR_SIZE);
				struct mospf_hdr *mospfh = (struct mospf_hdr*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
				struct mospf_lsu *mospf_lsu = (struct mospf_lsu*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
				struct mospf_lsa *mospf_lsa = (struct mospf_lsa*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE \
																			+ MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);
				eh->ether_type = ntohs(ETH_P_IP);
				memcpy(eh->ether_shost, iface->mac, 6); 
				ip_init_hdr(iph, iface->ip, nbr->nbr_ip, len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
				mospf_init_hdr(mospfh, MOSPF_TYPE_LSU, len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE, instance->router_id, instance->area_id);
				mospf_init_lsu(mospf_lsu, num_nbr);
				memcpy(mospf_lsa, lsa_wrapper, num_nbr * MOSPF_LSA_SIZE);
				mospfh->checksum = mospf_checksum(mospfh);

				iface_send_packet_by_arp(iface, nbr->nbr_ip, packet, len);
				// log(DEBUG, "sended lsu packet from %x to %x", iface->ip, nbr->nbr_ip);
			}
			
		}	
		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}


void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	// fprintf(stdout, "TODO: handle mOSPF LSU message.\n");
	struct ether_header* eh = (struct ether_header*)packet;
	struct iphdr* iph = (struct iphdr*)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr* mospfh = (struct mospf_hdr*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	struct mospf_lsu* mospf_lsu = (struct mospf_lsu*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);
	struct mospf_lsa *mospf_lsa = (struct mospf_lsa*)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);

	mospf_db_entry_t *db = NULL;
	struct mospf_lsa *lsa = NULL;
	int found = 0, new = 1, i, j, new_lsa_num = 0, renew = 0;
	struct mospf_lsa *new_lsa_array = (struct mospf_lsa *)malloc(MOSPF_LSA_SIZE * ntohl(mospf_lsu->nadv));

	pthread_mutex_lock(&mospf_lock);

	list_for_each_entry(db, &mospf_db, list){
		found = 0;
		if(db->rid == ntohl(mospfh->rid))		// found router info in database
		{
			found = 1;
			if(db->seq < ntohs(mospf_lsu->seq))		// database seq older(no bigger) than mospf seq, renew database
			{
				renew = 1;
				db->alive = 0;
				db->seq = ntohs(mospf_lsu->seq);
				new_lsa_num = 0;
				for(i = 0; i < ntohl(mospf_lsu->nadv); i++)
				{
					new = 1;
					for(j = 0; j < db->nadv; j++)
					{
						if(ntohl(mospf_lsa[i].rid) == db->array[j].rid)
						{
							new = 0;
							break;
						}
					}
					if(new)
					{
						memcpy(&new_lsa_array[new_lsa_num++], &mospf_lsa[i], MOSPF_LSA_SIZE);
						// log(DEBUG, "new lsa: network: %x, rid: %x", ntohl(mospf_lsa[i].network), ntohl(mospf_lsa[i].rid));
					}
				}
				if(new_lsa_num)
				{
					db->array = (struct mospf_lsa *)realloc(db->array, MOSPF_LSA_SIZE * (new_lsa_num + db->nadv));
					for(i = 0; i < new_lsa_num; i++)
					{
						db->array[db->nadv+i].mask = ntohl(new_lsa_array[i].mask);
						db->array[db->nadv+i].network = ntohl(new_lsa_array[i].network);
						db->array[db->nadv+i].rid = ntohl(new_lsa_array[i].rid);
					}
					db->nadv += new_lsa_num;
					db_changed = 1;
				}
			}
			break;
		}
	}
	if(!found && ntohl(mospfh->rid) != instance->router_id)
	{
		// printf("not found\nnew nadv: %d\n", ntohl(mospf_lsu->nadv));
		mospf_db_entry_t *entry = (mospf_db_entry_t *)malloc(sizeof(mospf_db_entry_t));
		entry->alive = 0;
		entry->array = (struct mospf_lsa *)malloc(MOSPF_LSA_SIZE * ntohl(mospf_lsu->nadv));
		for(i = 0; i < ntohl(mospf_lsu->nadv); i++)
		{
			entry->array[i].mask = ntohl(mospf_lsa[i].mask);
			entry->array[i].network = ntohl(mospf_lsa[i].network);
			entry->array[i].rid = ntohl(mospf_lsa[i].rid);
		}
		entry->nadv = ntohl(mospf_lsu->nadv);
		entry->rid = ntohl(mospfh->rid);
		entry->seq = ntohs(mospf_lsu->seq);
		list_add_tail(&(entry->list), &(mospf_db));
		db_changed = 1;
	}
	pthread_mutex_unlock(&mospf_lock);

	if(renew)
	{
		iface_info_t *iface_to_send = NULL;
		mospf_nbr_t *nbr_entry = NULL;
		list_for_each_entry(iface_to_send, &instance->iface_list, list) {
			if(iface_to_send == iface)
				continue;
			// log(DEBUG, "%d neighbor\n", iface_to_send->num_nbr);
			list_for_each_entry(nbr_entry, &(iface_to_send->nbr_list), list)
			{
				memcpy(eh->ether_shost, iface_to_send->mac, 6);
				ip_init_hdr(iph, iface_to_send->ip, nbr_entry->nbr_ip, len - ETHER_HDR_SIZE, IPPROTO_MOSPF);
				char *pkt = (char*)malloc(len);
				
				memcpy(pkt, packet, len);

				iface_send_packet_by_arp(iface_to_send, nbr_entry->nbr_ip, pkt, len);
				// printf("DEBUG: forwarded lsu packet from %x to %x\n", iface->ip, nbr_entry->nbr_ip);
				// log(DEBUG, "forwarded lsu packet from %x to %x\n", iface_to_send->ip, nbr_entry->nbr_ip);
			}
		}
	}
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}
