all: echo-client echo-server http-client http-server

http-client: http-client.c
	gcc -Wall -g http-client.c -o http-client

http-server: http-server.c
	gcc -Wall -g http-server.c -o http-server -lpthread

echo-client: echo-client.c
	gcc -Wall -g echo-client.c -o echo-client

echo-server: echo-server.c
	gcc -Wall -g echo-server.c -o echo-server

clean:
	@rm -f echo-client echo-server http-client http-server
