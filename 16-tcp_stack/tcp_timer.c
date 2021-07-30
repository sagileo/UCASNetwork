#include "include/tcp.h"
#include "include/tcp_timer.h"
#include "include/tcp_sock.h"
#include "include/arpcache.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;

// scan the timer_list, find the tcp sock which stays for at least 2*MSL, release it
void tcp_scan_timer_list()
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	struct tcp_timer *timer = NULL, *timer_q = NULL;
	list_for_each_entry_safe(timer, timer_q, &timer_list, list) {
		timer->lasted += TCP_TIMER_SCAN_INTERVAL / 1000;
		if(timer->enable == 0)
			list_delete_entry(&(timer->list));
		else if(timer->type == 0 && timer->lasted >= timer->timeout)	// timer stays for at least 2*MSL
		{	
			list_delete_entry(&(timer->list));
			// get the corresponding tcp sock 
			struct tcp_sock *tsk = timewait_to_tcp_sock(timer);
			// set tsk state to TCP_CLOSED 
			tcp_set_state(tsk, TCP_CLOSED);
			// unhash tsk from bind_table and established table, and to release tsk resources.
			tcp_unhash(tsk);
			tcp_bind_unhash(tsk);
			// decrease tsk->ref_cnt to -1 to free(tsk)
			// free_tcp_sock(tsk);
		} else if (timer->type == 1 && timer->lasted >= timer->timeout) {
			int retrans_times;
			struct tcp_sock *tsk = retranstimer_to_tcp_sock(timer);
			if(tsk->send_buf.next == tsk->send_buf.prev)
				continue;
			switch(timer->timeout / (TCP_RETRANS_INTERVAL_INITIAL / 1000))
			{
				case 1: retrans_times = 0; break;
				case 2: retrans_times = 1; break;
				case 4: retrans_times = 2; break;
				case 8: retrans_times = 3; break;
				default: break;
			}
			if(retrans_times >= 3)
			{
				tcp_send_control_packet(tsk, TCP_RST);
				list_delete_entry(&(timer->list));
				return;
			}
			timer->timeout *= 2;
			struct cached_pkt *pkt = NULL;
			pkt = list_entry(tsk->send_buf.next, struct cached_pkt, list);
			char *p = (char *)malloc(pkt->len);
			memcpy(p, pkt->packet, pkt->len);
			ip_send_packet(p, pkt->len);
		}
	}
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	tsk->timewait.enable = 1;
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT / 1000;
	tsk->timewait.lasted = 0;
	tsk->timewait.type = 0;
	init_list_head(&(tsk->timewait.list));
	list_add_tail(&(tsk->timewait.list), &timer_list);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}

void tcp_set_retrans_timer(struct tcp_sock *tsk)
{
	tsk->retrans_timer.enable = 1;
	tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL / 1000;
	tsk->retrans_timer.lasted = 0;
	tsk->retrans_timer.type = 1;
	init_list_head(&(tsk->retrans_timer.list));
	if(tsk->retrans_timer.list.next == tsk->retrans_timer.list.prev)
		list_add_tail(&(tsk->retrans_timer.list), &timer_list);
}

void tcp_unset_retrans_timer(struct tcp_sock *tsk)
{
	tsk->retrans_timer.enable = 0;
}