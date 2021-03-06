#include "tcp_sock.h"

#include "log.h"

#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	FILE *fp;
	fp = fopen("server-output.dat", "w");
	char rbuf[65536];
	int rlen = 0;


	while (1) {
		rlen = tcp_sock_read(csk, rbuf, 65535);
		if (rlen == 0) {
			log(DEBUG, "tcp_sock_read return 0, finish transmission.");
			break;
		} 
		else if (rlen > 0) {
			fputs(rbuf, fp);
			// printf("written %d bytes\n", rlen);
		}
		else {
			log(DEBUG, "tcp_sock_read return negative value, something goes wrong.");
			exit(1);
		}
	}

	log(DEBUG, "close this connection.");

	tcp_sock_close(csk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	printf("DEBUG: connection established\n");

	int fd;
	fd = open("client-input.dat", O_RDONLY | O_CREAT);
	char buf[655360];
	int len = 0;

	
	// if ((len = read(fd, buf, 20000)) == 0)
	// 	;
	// buf[len] = 0;
	// if (tcp_sock_write(tsk, buf, strlen(buf)) < 0)
	// 	;
	// usleep(100*1000);
	

	while(1)
	{
		if ((len = read(fd, buf, 60000)) == 0)
			break;
		buf[len] = 0;
		if (tcp_sock_write(tsk, buf, strlen(buf)) < 0)
		{
			printf("write return < 0\n");
			break;
		}
		usleep(100*1000);
	}

	tcp_sock_close(tsk);

	return NULL;
}
