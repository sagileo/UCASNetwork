#include "include/mac.h"
#include "include/log.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

mac_port_map_t mac_port_map;

static void *dumping_mac_port_thread(void *nil);

// initialize mac_port table
void init_mac_port_table()
{
	pthread_t dump_thread;

	bzero(&mac_port_map, sizeof(mac_port_map_t));

	for (int i = 0; i < HASH_8BITS; i++) {
		init_list_head(&mac_port_map.hash_table[i]);
	}

	pthread_mutex_init(&mac_port_map.lock, NULL);

	pthread_create(&mac_port_map.thread, NULL, sweeping_mac_port_thread, NULL);
	pthread_create(&dump_thread, NULL, dumping_mac_port_thread, NULL);
}

// destroy mac_port table
void destory_mac_port_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry, *q;
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[i], list) {
			list_delete_entry(&entry->list);
			free(entry);
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

// lookup the mac address in mac_port table
iface_info_t *lookup_port(u8 mac[ETH_ALEN], int renew)
{
	// TODO: implement the lookup process here
	// fprintf(stdout, "TODO: implement the lookup process here.\n");
	
	int hash = hash8((char *)mac, ETH_ALEN);
	mac_port_entry_t *entry, *q;

	pthread_mutex_lock(&mac_port_map.lock);

	list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[hash], list)
	{
		//printf(ETHER_STRING ETHER_STRING "\n", ETHER_FMT(entry->mac), ETHER_FMT(mac));
		if(entry->mac[0] == mac[0] && entry->mac[1] == mac[1] && entry->mac[2] == mac[2] && entry->mac[3] == mac[3] && entry->mac[4] == mac[4] && entry->mac[5] == mac[5])
		{
			if(renew)
				entry->visited = time(NULL);
			//printf("%s\n", entry->iface->name);
			pthread_mutex_unlock(&mac_port_map.lock);
			return entry->iface;
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);

	return NULL;
}

// insert the mac -> iface mapping into mac_port table
void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	// TODO: implement the insertion process here
	// fprintf(stdout, "TODO: implement the insertion process here.\n");

	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	// set the mac_port entry
	entry = (mac_port_entry_t *)malloc(sizeof(mac_port_entry_t));
	entry->iface = iface;
	memcpy(entry->mac, mac, ETH_ALEN * sizeof(u8));
	entry->visited = now;

	// insert the entry
	int hash = hash8((char *)mac, ETH_ALEN);

	pthread_mutex_lock(&mac_port_map.lock);

	entry->list.prev = mac_port_map.hash_table[hash].prev;
	entry->list.next = &mac_port_map.hash_table[hash];
	mac_port_map.hash_table[hash].prev->next = &entry->list;
	mac_port_map.hash_table[hash].prev = &entry->list;

	pthread_mutex_unlock(&mac_port_map.lock);

	//printf("iface pointer: %d\n", iface);
	printf("inserted entry: %02x:%02x:%02x:%02x:%02x:%02x:\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(mac), \
					iface->name, (int)(now - entry->visited));
}

// dumping mac_port table
void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");

	pthread_mutex_lock(&mac_port_map.lock);

	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry(entry, &mac_port_map.hash_table[i], list) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

// sweeping mac_port table, remove the entry which has not been visited in the
// last 30 seconds.
int sweep_aged_mac_port_entry()
{
	// TODO: implement the sweeping process here
	// fprintf(stdout, "TODO: implement the sweeping process here.\n");
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);
	int n = 0;

	pthread_mutex_lock(&mac_port_map.lock);

	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry(entry, &mac_port_map.hash_table[i], list) {
			if(now - entry->visited >= MAC_PORT_TIMEOUT)		// delete the timeout entry
			{
				list_delete_entry(&entry->list);
				printf("deleted " ETHER_STRING "\n", ETHER_FMT(entry->mac));
				//free(entry);
				n++;
			}
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);

	return n;
}

// sweeping mac_port table periodically, by calling sweep_aged_mac_port_entry
void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.", n);
	}

	return NULL;
}

// dumping mac_port table periodically, by calling dump_mac_port_table
void *dumping_mac_port_thread(void *nil)
{
	char c;

	while (1) {
		printf("> ");
		while((c = getchar()) != '\n')
			;

		dump_mac_port_table();
	}

	return NULL;
}