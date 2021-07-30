#include "tcp.h"
#include "tcp_hash.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "ip.h"
#include "rtable.h"
#include "log.h"

// TCP socks should be hashed into table for later lookup: Those which
// occupy a port (either by *bind* or *connect*) should be hashed into
// bind_table, those which listen for incoming connection request should be
// hashed into listen_table, and those of established connections should
// be hashed into established_table.

struct tcp_hash_table tcp_sock_table;
#define tcp_established_sock_table	tcp_sock_table.established_table
#define tcp_listen_sock_table		tcp_sock_table.listen_table
#define tcp_bind_sock_table			tcp_sock_table.bind_table


inline void tcp_set_state(struct tcp_sock *tsk, int state)
{
	log(DEBUG, IP_FMT":%hu switch state, from %s to %s.", \
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport, \
			tcp_state_str[tsk->state], tcp_state_str[state]);
	tsk->state = state;
}

// init tcp hash table and tcp timer
void init_tcp_stack()
{
	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_established_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_listen_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_bind_sock_table[i]);

	pthread_t timer;
	pthread_create(&timer, NULL, tcp_timer_thread, NULL);
	sleep(0);
}

// allocate tcp sock, and initialize all the variables that can be determined
// now
struct tcp_sock *alloc_tcp_sock()
{
	struct tcp_sock *tsk = (struct tcp_sock *)malloc(sizeof(struct tcp_sock));

	memset(tsk, 0, sizeof(struct tcp_sock));

	tsk->state = TCP_CLOSED;
	tsk->rcv_wnd = TCP_DEFAULT_WINDOW;

	init_list_head(&tsk->list);
	init_list_head(&tsk->listen_queue);
	init_list_head(&tsk->accept_queue);
	init_list_head(&tsk->send_buf);
	init_list_head(&tsk->rcv_ofo_buf);

	tsk->rcv_buf = alloc_ring_buffer(tsk->rcv_wnd);

	tsk->wait_connect = alloc_wait_struct();
	tsk->wait_accept = alloc_wait_struct();
	tsk->wait_recv = alloc_wait_struct();
	tsk->wait_send = alloc_wait_struct();

	return tsk;
}

/***
 * @return	> 0: length of read data;
 * 		   	= 0: read the end of stream which means peer has shut down the connection
 * 			=-1: error occurred
 */ 
int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len)
{
	// printf("DEBUG: enter tcp_sock_read\n");
	while(ring_buffer_empty(tsk->rcv_buf))
	{
		if(tsk->state == TCP_TIME_WAIT || tsk->state == TCP_CLOSE_WAIT)
			return 0;
		// printf("DEBUG: tcp_sock_read sleeping on wait_recv\n");
		sleep_on(tsk->wait_recv);
		if(tsk->state == TCP_TIME_WAIT || tsk->state == TCP_CLOSE_WAIT)
			return 0;
	}
	
	int ret = read_ring_buffer(tsk->rcv_buf, buf, len);
	tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
	buf[ret] = 0;
	// printf("DEBUG: leave tcp_sock_read with return value %d\n", ret);
	tcp_send_control_packet(tsk, TCP_ACK);
	return ret;
}

/***
 * @return	> 0: length of written data;
 * 			=-1: error occurred
 */ 
int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len)
{
	int left = len;
	while(1)
	{
		int data_len, EffWnd;
		while(tsk->snd_wnd <= 0)
		{
			// printf("DEBUG: tcp_sock_write sleep on wait_send\n");
			// printf("DEBUG: snd_wnd = %d, snd_nxt = %x, snd_una = %x\n", tsk->snd_wnd, tsk->snd_nxt, tsk->snd_una);
			sleep_on(tsk->wait_send);
		}
		EffWnd = tsk->snd_wnd - (tsk->snd_nxt - tsk->snd_una);
		data_len = min(left, EffWnd);
		if(data_len <= 0)
			continue;
		// printf("left = %d, EffWnd = %d\n", left, EffWnd);
		data_len = min(data_len, ETH_FRAME_LEN - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE);
		// printf("sending data: %p, len: %d\n", buf, data_len);
		tcp_send_data(tsk, buf, data_len);
		left -= data_len;
		buf += data_len;
		if(left <= 0)
			break;
		// usleep(10000);
	}
	while(tsk->send_buf.next != tsk->send_buf.prev)
		;
	return len;
}

// release all the resources of tcp sock
//
// To make the stack run safely, each time the tcp sock is refered (e.g. hashed), 
// the ref_cnt is increased by 1. each time free_tcp_sock is called, the ref_cnt
// is decreased by 1, and release the resources practically if ref_cnt is
// decreased to zero.
void free_tcp_sock(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	tsk->ref_cnt--;
	if (tsk->ref_cnt <= 0)
	{
		free(tsk);
		exit(0);
	}
}

// lookup tcp sock in established_table with key (saddr, daddr, sport, dport)
struct tcp_sock *tcp_sock_lookup_established(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	int established_hash_value = tcp_hash_function(saddr, daddr, sport, dport);
	struct list_head *list = &tcp_established_sock_table[established_hash_value];
	if (list->next == list->prev && list->next == list)	// list empty
		return NULL;
	struct tcp_sock* tsk = NULL;	
	list_for_each_entry(tsk, list, hash_list) {
		if (tsk->sk_sip == saddr && tsk->sk_dip == daddr && tsk->sk_sport == sport && tsk->sk_dport == dport)
		{
			return tsk;
		}
	}
	// log(ERROR, "4-ary key hash not found in established table");
	return NULL;
}

// lookup tcp sock in listen_table with key (sport)
//
// In accordance with BSD socket, saddr is in the argument list, but never used.
struct tcp_sock *tcp_sock_lookup_listen(u32 saddr, u16 sport)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	int listen_hash_value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_listen_sock_table[listen_hash_value];
	if (list->next == list->prev && list->next == list)	// list empty
		return NULL;
	struct tcp_sock* tsk = NULL;	
	list_for_each_entry(tsk, list, hash_list) {
		if (tsk->sk_sport == sport)
		{
			return tsk;
		}
	}
	// log(ERROR, "4-ary key hash not found in listen table");
	return NULL;
}

// lookup tcp sock in both established_table and listen_table
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb)
{
	u32 saddr = cb->daddr,
		daddr = cb->saddr;
	u16 sport = cb->dport,
		dport = cb->sport;

	struct tcp_sock *tsk = tcp_sock_lookup_established(saddr, daddr, sport, dport);
	if (!tsk)
		tsk = tcp_sock_lookup_listen(saddr, sport);

	if(!tsk)
		printf("tsk not found when lookup\n");

	return tsk;
}

// hash tcp sock into bind_table, using sport as the key
int tcp_bind_hash(struct tcp_sock *tsk)
{
	int bind_hash_value = tcp_hash_function(0, 0, tsk->sk_sport, 0);
	struct list_head *list = &tcp_bind_sock_table[bind_hash_value];
	list_add_head(&tsk->bind_hash_list, list);

	tsk->ref_cnt += 1;

	return 0;
}

// unhash the tcp sock from bind_table
void tcp_bind_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->bind_hash_list)) {
		list_delete_entry(&tsk->bind_hash_list);
		free_tcp_sock(tsk);
	}
}

// lookup bind_table to check whether sport is in use
static int tcp_port_in_use(u16 sport)
{
	int value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_bind_sock_table[value];
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, bind_hash_list) {
		if (tsk->sk_sport == sport)
			return 1;
	}

	return 0;
}

// find a free port by looking up bind_table
static u16 tcp_get_port()
{
	for (u16 port = PORT_MIN; port < PORT_MAX; port++) {
		if (!tcp_port_in_use(port))
			return port;
	}

	return 0;
}

// tcp sock tries to use port as its source port
static int tcp_sock_set_sport(struct tcp_sock *tsk, u16 port)
{
	if ((port && tcp_port_in_use(port)) ||
			(!port && !(port = tcp_get_port())))
		return -1;

	tsk->sk_sport = port;

	tcp_bind_hash(tsk);

	return 0;
}

// hash tcp sock into either established_table or listen_table according to its
// TCP_STATE
int tcp_hash(struct tcp_sock *tsk)
{
	struct list_head *list;
	int hash;

	if (tsk->state == TCP_CLOSED)
		return -1;

	if (tsk->state == TCP_LISTEN) {
		hash = tcp_hash_function(0, 0, tsk->sk_sport, 0);
		list = &tcp_listen_sock_table[hash];
		// printf("DEBUG: hash into listen table with (0, 0, %hu, 0)\n", tsk->sk_sport);
	}
	else {
		int hash = tcp_hash_function(tsk->sk_sip, tsk->sk_dip, \
				tsk->sk_sport, tsk->sk_dport); 
		list = &tcp_established_sock_table[hash];

		struct tcp_sock *tmp;
		list_for_each_entry(tmp, list, hash_list) {
			if (tsk->sk_sip == tmp->sk_sip &&
					tsk->sk_dip == tmp->sk_dip &&
					tsk->sk_sport == tmp->sk_sport &&
					tsk->sk_dport == tmp->sk_dport)
				return -1;
		}
		// printf("DEBUG: hash into established table with ("IP_FMT", "IP_FMT", %hu, %hu)\n", NET_IP_FMT_STR(tsk->sk_sip), NET_IP_FMT_STR(tsk->sk_dip), 
		//		tsk->sk_sport, tsk->sk_dport);
	}

	list_add_head(&tsk->hash_list, list);
	tsk->ref_cnt += 1;

	return 0;
}

// unhash tcp sock from established_table or listen_table
void tcp_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->hash_list)) {
		list_delete_entry(&tsk->hash_list);
		free_tcp_sock(tsk);
	}
}

// XXX: skaddr here contains network-order variables
int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	int err = 0;
	
	// omit the ip address, and only bind the port
	err = tcp_sock_set_sport(tsk, ntohs(skaddr->port));

	return err;
}

// connect to the remote tcp sock specified by skaddr
//
// XXX: skaddr here contains network-order variables
// 1. initialize the four key tuple (sip, sport, dip, dport);
// 2. hash the tcp sock into bind_table;
// 3. send SYN packet, switch to TCP_SYN_SENT state, wait for the incoming
//    SYN packet by sleep on wait_connect;
// 4. if the SYN packet of the peer arrives, this function is notified, which
//    means the connection is established.
int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	// printf("skaddr->ip " IP_FMT " ,skaddr->port %hu\n", NET_IP_FMT_STR(skaddr->ip), skaddr->port);
	tsk->sk_dip = ntohl(skaddr->ip);
	tsk->sk_dport = ntohs(skaddr->port);
	tsk->sk_sip = (list_entry(instance->iface_list.next, iface_info_t, list))->ip;
	if ((tsk->sk_sport = tcp_get_port()) == 0)
		return -1;
	// printf("("IP_FMT", "IP_FMT", %hu, %hu)\n", NET_IP_FMT_STR(tsk->sk_sip), NET_IP_FMT_STR(tsk->sk_dip), tsk->sk_sport, tsk->sk_dport);

	// hash tsk to tcp_bind_sock_table
	struct sock_addr sk_saddr;
	sk_saddr.ip = htonl(tsk->sk_sip);
	sk_saddr.port = htonl(tsk->sk_sport);
	int err;
	if ((err = tcp_sock_bind(tsk, &sk_saddr)) == 1)
		return -1;

	// snd_nxt set randomly
	tsk->snd_nxt = tcp_new_iss();
	// send syn packet to peer and switch state to TCP_SYN_SENT
	tcp_send_control_packet(tsk, TCP_SYN);
	tcp_set_state(tsk, TCP_SYN_SENT);

	// hash tsk into tcp_established_sock_table
	if (tcp_hash(tsk) == -1)
		return -1;

	// wait for server's syn|ack reply
	sleep_on(tsk->wait_connect);

	// syn|ack received, switch state to TCP_ESTABLISHED
	tcp_set_state(tsk, TCP_ESTABLISHED);

	// send ACK packet to server
	tcp_send_control_packet(tsk, TCP_ACK | TCP_ACK);

	return 0;
}

// set backlog (the maximum number of pending connection requst), switch the
// TCP_STATE, and hash the tcp sock into listen_table
int tcp_sock_listen(struct tcp_sock *tsk, int backlog)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	tsk->backlog = backlog;
	tcp_set_state(tsk, TCP_LISTEN);

	return tcp_hash(tsk);
}

// check whether the accept queue is full
inline int tcp_sock_accept_queue_full(struct tcp_sock *tsk)
{
	if (tsk->accept_backlog >= tsk->backlog) {
		log(ERROR, "tcp accept queue (%d) is full.", tsk->accept_backlog);
		return 1;
	}

	return 0;
}

// push the tcp sock into accept_queue
inline void tcp_sock_accept_enqueue(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->list))
		list_delete_entry(&tsk->list);
	list_add_tail(&tsk->list, &tsk->parent->accept_queue);
	tsk->parent->accept_backlog += 1;
}

// pop the first tcp sock of the accept_queue
inline struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk)
{
	struct tcp_sock *new_tsk = list_entry(tsk->accept_queue.next, struct tcp_sock, list);
	list_delete_entry(&new_tsk->list);
	init_list_head(&new_tsk->list);
	tsk->accept_backlog -= 1;

	return new_tsk;
}

// if accept_queue is not emtpy, pop the first tcp sock and accept it,
// otherwise, sleep on the wait_accept for the incoming connection requests
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	if (tsk->accept_queue.next == &tsk->accept_queue && tsk->accept_queue.next == tsk->accept_queue.prev)	
	{	// accept_queue is empty
		sleep_on(tsk->wait_accept);
	}
	return tcp_sock_accept_dequeue(tsk);
}

// close the tcp sock, by releasing the resources, sending FIN/RST packet
// to the peer, switching TCP_STATE to closed
void tcp_sock_close(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	usleep(8*TCP_RETRANS_INTERVAL_INITIAL);
	// set state according to current state
	if (tsk->state == TCP_CLOSE_WAIT)	// server socket
	{
		tcp_set_state(tsk, TCP_LAST_ACK);
	}
	else if (tsk->state == TCP_ESTABLISHED)	{// client socket
		tcp_set_state(tsk, TCP_FIN_WAIT_1);
	} else {
		log(ERROR, "%s is called at wrong state: %d", __FUNCTION__, tsk->state);
		exit(1);
	} 
	// send FIN packet to peer
	tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
	// free tsk to decrease ref_cnt to zero. When call free_tcp_sock again, tsk is freed.
	// free_tcp_sock(tsk);
	// tcp_unhash(tsk);
}
