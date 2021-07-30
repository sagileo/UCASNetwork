/* client application */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAXLEN 2000
 
char *strip_inet_addr(char *ip_addr)
{
    int i = 0, j = 0;
    while(ip_addr[i] != '/')
        i++;
    while(ip_addr[i] == '/')
        i++;
    char* inet_addr = (char *)malloc(20);
    while(ip_addr[i] != ':'){
        inet_addr[j] = ip_addr[i];
        i++;j++;
    }
    inet_addr[j] = 0;
    return inet_addr;
}

int strip_port(char *ip_addr)
{
    int i = 0, j = 0, port;
    while(ip_addr[i++] != ':');
    while(ip_addr[i++] != ':');
    char* port_s = (char*)malloc(10);
    while(ip_addr[i] != '/'){
        port_s[j] = ip_addr[i];
        i++;j++;
    }
    port_s[j] = 0;
    port = atoi(port_s);

    free(port_s);
    return port;
}

char *strip_filename(char *ip_addr)
{
    int i = 0, j = 0;
    while(ip_addr[i++] != ':');
    while(ip_addr[i++] != ':');
    while(ip_addr[i++] != '/');
    char *filename = (char *)malloc(20);
    while(ip_addr[i] != 0)
        filename[j++] = ip_addr[i++];
    filename[j] = 0;
    return filename;
}

void strip_content(char *reply, char *content)
{
    int i = 0;
    while(1)
    {
        if(reply[i] == '\r' && reply[i+1] == '\n' && reply[i+2] == '\r' && reply[i+3] == '\n')
            break;
        else i++;
    }
    strcpy(content, reply+i+4);
}

char * itoa(int n)
{
	char *s = NULL;
	int i = 0;
	int num = n;

	while (num)
	{
		num /= 10;
		++i;
	}

	s = (char *)malloc(i + 1);
	s[i] = '\0';
	num = n;

	while (num)
	{
		s[--i] = num % 10 + 48;
		num /= 10;
	}

	if (!i)
		return s;
    else
        return 0;
}

int main(int argc, char *argv[])
{
    int sock;
    char ip_addr[200];
    char filename[20];
    struct sockaddr_in server;
    char message[MAXLEN];
    char server_reply[MAXLEN];
     
    if(argc == 2)
        strcpy(ip_addr, argv[1]);
    else if(argc == 1)
        strcpy(ip_addr, "http://10.0.0.1:80/test.html");
    else{
        printf("too many parameters\n");
        return 1;
    }

    printf("%s\n", ip_addr);

    // create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("create socket failed\n");
		return -1;
    }
    printf("socket created\n");

    char inet_s[50];
    int port = strip_port(ip_addr);
    strcpy(inet_s, strip_inet_addr(ip_addr));

    server.sin_addr.s_addr = inet_addr(inet_s);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
 

    printf("Connecting to %s:%d ...", inet_s, port);
    // connect to server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect failed\n");
        return 1;
    }
     
    printf("connected\n");

    // form message
    strcpy(filename, strip_filename(ip_addr));
    strcpy(message, "GET /");
    strcat(message, filename);
    strcat(message, " HTTP/1.1\r\n\r\n");
    

    printf("message:\n%s\n", message);


    // send message to server
    if (send(sock, message, strlen(message), 0) < 0) {
        printf("send failed\n");
        return 1;
    }

    // recv content of file from server
    int len = recv(sock, server_reply, MAXLEN, 0);
    if(len < 0){
        printf("recv failed\n");
        return 1;
    }
    server_reply[len] = 0;

    printf("server reply : \n");
    printf("%s\n", server_reply);

    if(strcmp(server_reply, "HTTP/1.1 404 FILE NOT FOUND\r\n\r\n") == 0)
        return 1;
    
    char content[2000];
    strip_content(server_reply, content);

    // write to local file
    if(access(filename, 0) == -1)       //文件不存在
    {
        FILE *fp = NULL;
        fp = fopen(filename, "wb");
        fwrite(content, strlen(content), 1, fp);
        fclose(fp);
    }
    else if(access(filename, 0) == 0)   //文件已存在
    {
        int i = 1;
        char filename_cp[20];
        strcat(filename, ".");
        strcpy(filename_cp, filename);
        //char i_s[5];
        while(access( strcat(filename_cp, itoa(i)), 0) == 0)
        {
            strcpy(filename_cp, filename);
            i++;
        }
        FILE *fp = NULL;
        fp = fopen(filename_cp, "wb");
        fwrite(content, strlen(content), 1, fp);
        fclose(fp);
    }

    printf("Download Successful\n");
     
    close(sock);
    return 0;
}
