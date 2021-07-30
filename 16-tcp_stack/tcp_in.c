#include "include/tcp.h"
#include "include/tcp_sock.h"
#include "include/tcp_timer.h"
#include "include/arpcache.h"

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
	// printf("DEBUG: updating snd_wnd: from %d to %d\n", old_snd_wnd, tsk->snd_wnd);
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
	// printf("DEBUG: tsk->state = %d, cb->flags = 0x%x\n", tsk->state, cb->flags);
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
		// set advertised window 
		tsk->adv_wnd = cb->rwnd;
		tcp_update_window_safe(tsk, cb);
		tsk->snd_una = cb->ack;
		// set retrans_timer
		tcp_set_retrans_timer(tsk);
		// wake up tsk
		wake_up(tsk->wait_connect);
	} else if (tsk->state == TCP_SYN_RECV && (cb->flags & TCP_ACK)) {
		// it's server child socket receiving ACK packet when state is SYN_RECV
		// set advertised window 
		tsk->adv_wnd = cb->rwnd;
		tcp_update_window_safe(tsk, cb);
		tsk->snd_una = cb->ack;
		// put tsk from parent socket's listen_queue to accept_queue
		list_delete_entry(&tsk->list);
		list_add_tail(&tsk->list, &tsk->parent->accept_queue);
		tsk->parent->accept_backlog += 1;
		if (tsk->parent->accept_backlog >= tsk->parent->backlog)
			log(ERROR, "accept backlog exceeds max num");
		// set tsk state to TCP_ESTABLISHED 
		tcp_set_state(tsk, TCP_ESTABLISHED);
		// set retrans_timer
		tcp_set_retrans_timer(tsk);
		// wake up tsk's parent from wait_accept
		wake_up(tsk->parent->wait_accept);
	} else if (tsk->state == TCP_ESTABLISHED) {
		if(cb->flags & TCP_ACK) {
			// received ACK packet, renew adv_wnd
			tsk->adv_wnd = cb->rwnd;
			tcp_update_window_safe(tsk, cb);
			int old_una = tsk->snd_una;
			tsk->snd_una = cb->ack;
			// renew retrans_timer and drop acked packets out of send_buf list
			if(less_than_32b(old_una, tsk->snd_una))
			{
				tcp_set_retrans_timer(tsk);
				struct cached_pkt *pkt = NULL, *pkt_q = NULL;
				list_for_each_entry_safe(pkt, pkt_q, &(tsk->send_buf), list)
				{
					struct tcphdr *tcp = packet_to_tcp_hdr(pkt->packet);
					if(less_than_32b(ntohl(tcp->seq), tsk->snd_una))
					{
						// printf("DEBUG: deleted pkt, seq = %x\n", ntohl(tcp->seq));
						list_delete_entry(&(pkt->list));
						free(pkt->packet);
						free(pkt);
					}
				}
			}
		} 

		if(less_than_32b(cb->seq, tsk->rcv_nxt)) {
			// log(WARNING, "received OUT-OF-DATE packet, send ack\n");
			if(cb->pl_len > 0)
				tcp_send_control_packet(tsk, TCP_ACK);
			return;
		} else if(less_than_32b(tsk->rcv_nxt, cb->seq)) {
			// log(DEBUG, "received OUT-OF-ORDER packet, seq: %x, pend it\n", cb->seq);
			struct cached_pkt *pkt = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
			pkt->len = ntohs(cb->ip->tot_len) + ETHER_HDR_SIZE;
			pkt->packet = (char*)malloc(pkt->len);
			memcpy(pkt->packet, packet, pkt->len);
			list_add_tail(&(pkt->list), &(tsk->rcv_ofo_buf));
			tcp_send_control_packet(tsk, TCP_ACK);
			goto fin;
		}

		int renew_ring_buf = 0;
		// now the packet is the expected one (tsk->rcv_nxt == cb->seq)
		if(cb->pl_len == 0)
		{
			goto fin;
		}
		else if(ring_buffer_free(tsk->rcv_buf) >= cb->pl_len)
		{
			// printf("in-order write\n");
			write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
			if(tsk->wait_recv->sleep == 1)
			{
				// printf("DEBUG: wake up tcp_sock_read\n");
				wake_up(tsk->wait_recv);
			}
		}
		else {
			log(ERROR, "received data exceeds buffer\n");
			exit(1);
		}
		// printf("cb: seq = %x, seq_end = %x\n", cb->seq, cb->seq_end);
		// set rcv_nxt
		tsk->rcv_nxt = cb->seq_end;
		// renew rcv_wnd
		tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);


		struct cached_pkt *pkt = NULL, *pkt_q = NULL;
		// deal with out-of-order packets
		while(1)
		{
			list_for_each_entry_safe(pkt, pkt_q, &tsk->rcv_ofo_buf, list) {
				struct iphdr *ip = packet_to_ip_hdr(pkt->packet);
				struct tcphdr *tcp = (struct tcphdr *)(IP_DATA(ip));
				// printf("rcv_nxt: %x, seq: %x\n", tsk->rcv_nxt, ntohl(tcp->seq));
				if(tsk->rcv_nxt == ntohl(tcp->seq))
				{
					int data_len = ntohs(ip->tot_len) - IP_HDR_SIZE(ip) - TCP_HDR_SIZE(tcp);
					if(ring_buffer_free(tsk->rcv_buf) >= data_len)
					{
						// printf("out-of-order write\n");
						write_ring_buffer(tsk->rcv_buf, (char*)tcp + tcp->off * 4, data_len);
						if(tsk->wait_recv->sleep == 1)
						{
							// printf("DEBUG: wake up tcp_sock_read\n");
							wake_up(tsk->wait_recv);
						}
					}
					else {
						log(ERROR, "received data exceeds buffer\n");
						exit(1);
					}
					int seq_end = ntohl(tcp->seq) + data_len + ((tcp->flags & (TCP_SYN|TCP_FIN)));
					tsk->rcv_nxt = seq_end;
					tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
					list_delete_entry(&(pkt->list));
					free(pkt->packet);
					free(pkt);
					goto next;
				}
			}
			break;
			next: ;
		}

		// reply peer with ACK
		// printf("sending ack packet with ack = %x\n", tsk->rcv_nxt);
		tcp_send_control_packet(tsk, TCP_ACK);
		// wake up tcp_sock_read


		fin:
		if(cb->flags & TCP_FIN) {
			// set state to TCP_CLOSE_WAIT
			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_set_state(tsk, TCP_CLOSE_WAIT);
			if(tsk->wait_recv->sleep == 1)
			{
				// printf("DEBUG: wake up tcp_sock_read : state = TCP_CLOSE_WAIT\n");
				wake_up(tsk->wait_recv);
			}
		}
		if(tsk->rcv_wnd == 0)
			sleep(0);
	} else if (tsk->state == TCP_FIN_WAIT_1 && (cb->flags & TCP_ACK)) {
		// it's client socket receiving ACK packet when state is TCP_FIN_WAIT_1
		// set advertised window 
		tsk->adv_wnd = cb->rwnd;
		tcp_update_window_safe(tsk, cb);
		tsk->snd_una = cb->ack;
		// set state to TCP_FIN_WAIT_2
		tcp_set_state(tsk, TCP_FIN_WAIT_2);
	} else if (tsk->state == TCP_FIN_WAIT_2 && (cb->flags & TCP_FIN)) {
		// it's client socket receiving FIN packet when state is TCP_FIN_WAIT_2
		// set advertised window 
		tsk->adv_wnd = cb->rwnd;
		tcp_update_window_safe(tsk, cb);
		tsk->snd_una = cb->ack;
		// reply peer with ACK
		tsk->rcv_nxt = cb->seq + 1;
		tcp_send_control_packet(tsk, TCP_ACK);
		// set state to TCP_TIME_WAIT
		tcp_set_state(tsk, TCP_TIME_WAIT);
		if(tsk->wait_recv->sleep == 1)
		{
			// printf("DEBUG: wake up tcp_sock_read\n");
			wake_up(tsk->wait_recv);
		}
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
