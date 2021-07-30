#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;

// scan the timer_list, find the tcp sock which stays for at least 2*MSL, release it
void tcp_scan_timer_list()
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	struct tcp_timer *timer = NULL, *timer_q = NULL;
	list_for_each_entry_safe(timer, timer_q, &timer_list, list) {
		timer->timeout += TCP_TIMER_SCAN_INTERVAL;
		if(timer->timeout >= TCP_TIMEWAIT_TIMEOUT)	// timer stays for at least 2*MSL
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
		}
	}
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
	tsk->timewait.enable = 1;
	tsk->timewait.type = 0;
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
