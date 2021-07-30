#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	printf("DEBUG: tsk->state = %d, cb->flags = 0x%x\n", tsk->state, cb->flags);
	if (tsk->state == TCP_LISTEN && (cb->flags & TCP_SYN))		
	{	// it's server parent socket receiving SYN packet when passively set up connection
		// produce a child socket to serve the connection
		struct tcp_sock *csk = alloc_tcp_sock();
		csk->sk_sip = cb->daddr;
		csk->sk_sport = cb->dport;
		csk->sk_dip = cb->saddr;
		csk->sk_dport = cb->sport;
		csk->parent = tsk;
		// snd_nxt set randomly
		csk->snd_nxt = tcp_new_iss();
		// rcv_nxt is cb->seq increment by 1
		csk->rcv_nxt = cb->seq + 1;
		tcp_set_state(csk, TCP_SYN_RECV);
		// hash child socket into established table and bind table
		tcp_hash(csk);
		tcp_bind_hash(csk);
		// put csk into parent socket's listen queue
		list_add_tail(&csk->list, &csk->parent->listen_queue);
		// send SYN|ACK packet to peer client
		tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);
	} else if (tsk->state == TCP_SYN_SENT && (cb->flags & (TCP_SYN | TCP_ACK))) {
		// it's client socket receiving SYN|ACK packet when state is SYN_SENT
		// rcv_nxt is cb->seq increment by 1
		tsk->rcv_nxt = cb->seq + 1;
		// set snd_una to cb->ack
		tsk->snd_una = cb->ack;
		// wake up tsk
		wake_up(tsk->wait_connect);
	} else if (tsk->state == TCP_SYN_RECV && (cb->flags & TCP_ACK)) {
		// it's server child socket receiving ACK packet when state is SYN_RECV
		// put tsk from parent socket's listen_queue to accept_queue
		list_delete_entry(&tsk->list);
		list_add_tail(&tsk->list, &tsk->parent->accept_queue);
		tsk->parent->accept_backlog += 1;
		if (tsk->parent->accept_backlog >= tsk->parent->backlog)
			log(ERROR, "accept backlog exceeds max num");
		// set tsk state to TCP_ESTABLISHED 
		tcp_set_state(tsk, TCP_ESTABLISHED);
		// wake up tsk's parent from wait_accept
		wake_up(tsk->parent->wait_accept);
	} else if (tsk->state == TCP_ESTABLISHED && (cb->flags & TCP_FIN)) {
		// it's server child socket receiving FIN packet when state is TCP_ESTABLISHED
		tsk->rcv_nxt = cb->seq + 1;
		// reply peer with ACK
		tcp_send_control_packet(tsk, TCP_ACK);
		// set state to TCP_CLOSE_WAIT
		tcp_set_state(tsk, TCP_CLOSE_WAIT);
	} else if (tsk->state == TCP_FIN_WAIT_1 && (cb->flags & TCP_ACK)) {
		// it's client socket receiving ACK packet when state is TCP_FIN_WAIT_1
		// set state to TCP_FIN_WAIT_2
		tcp_set_state(tsk, TCP_FIN_WAIT_2);
	} else if (tsk->state == TCP_FIN_WAIT_2 && (cb->flags & TCP_FIN)) {
		// it's client socket receiving FIN packet when state is TCP_FIN_WAIT_2
		// reply peer with ACK
		tsk->rcv_nxt = cb->seq + 1;
		tcp_send_control_packet(tsk, TCP_ACK);
		// set state to TCP_TIME_WAIT
		tcp_set_state(tsk, TCP_TIME_WAIT);
		// add the timer of tsk to timer_list
		tcp_set_timewait_timer(tsk);
	} else if (tsk->state == TCP_LAST_ACK && (cb->flags & TCP_ACK)) {
		// it's server child socket receiving ACK packet when state is TCP_LAST_ACK
		// set state to TCP_CLOSED
		tcp_set_state(tsk, TCP_CLOSED);
		// unhash tsk from bind table and established table
		tcp_bind_unhash(tsk);
		tcp_unhash(tsk);
		// decrease tsk->ref_cnt to -1 to free(tsk)
		// free_tcp_sock(tsk);
	} else {
		log(ERROR, "unexpected situation when executing %s", __FUNCTION__);
		exit(1);
	}
}
