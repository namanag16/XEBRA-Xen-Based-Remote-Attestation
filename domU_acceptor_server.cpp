/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
// this ia a test commit

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#define SERVER_SOCKET_CODE \
    /*create a socket file descriptor */ \
    sockfd = socket(AF_INET, SOCK_STREAM, 0); \
    if (sockfd < 0) \
       error("ERROR opening socket"); \
    bzero((char *) &serv_addr, sizeof(serv_addr));    /* set server address bits to zero*/ \
    portno = atoi(argv[1]); \
    serv_addr.sin_family = AF_INET;  \
    serv_addr.sin_addr.s_addr = INADDR_ANY;  /* INADDR_ANY is server ip address*/ \
    serv_addr.sin_port = htons(portno);   /* htons converts port number in host byte order to a port number in network byte order.*/ \
    /* bind the server to port and host ... this steps makes it a server socket */ \
    if (bind(sockfd, (struct sockaddr *) &serv_addr, \
              sizeof(serv_addr)) < 0)  \
              error("ERROR on binding"); 


typedef unsigned char byte;

struct bundle{
    int a,b;
    byte eflag;
    byte nonce[16];
    byte content_ab[32];  // fixing the content size to 32 bytes for now
    byte hmac[256];

};

typedef struct bundle packet;

int block_recv(const int fd, char* data, unsigned int len)
{
    int i, j = 0;

    while (len > 0) {
        i = recv(fd, data, len, 0);
        if (i <= 0) {
            return -1;
        }
        data += i;
        len -= i;
        j += i;
    }

    return j;
}


void error(const char *msg)
{
    perror(msg);
    exit(1);
}
void fetch_content(packet* p, int a, int b)
{
    byte mem[1000];
    for(int i = 0; i < 1000;i++)
    {
        mem[i] = i;
    }

    for(int i = a;i<=b;i++)
        p->content_ab[i] = mem[i];
}

int main(int argc, char *argv[])
{
    //Declaration section 
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;

    packet p;
    byte buffer[256];

    int x[10] = {0,32,64,96,128,170,192,224,256,288};
    int y[10] = {31,63,95,127,169,191,223,255,287,319};

    if (argc < 2) {
        fprintf(stderr,"ERROR, no port provided\n");
        exit(1);
    }

    SERVER_SOCKET_CODE;; // creates and binds the server socket

    //while(1){     /* listen continuously */
     	listen(sockfd,5);

	    // accept a connection 
	    clilen = sizeof(cli_addr);
	    newsockfd = accept(sockfd, 
	                (struct sockaddr *) &cli_addr, 
	                &clilen);
	    if (newsockfd < 0) 
	         error("ERROR on accept");


        // n = read(newsockfd,buffer,sizeof(buffer)-1);
        // if (n < 0) error("ERROR reading from socket");
        // printf("Here is the message: %s\n",buffer);
        // printf("n is : %d\n ",n);
	    // read data 
        // unsigned char size;
        // n = read(newsockfd,&size,1);
        // if (n < 0) error("ERROR reading size from socket");

        // int32_t a=0,b=0;
        // unsigned char nonce[16],eflag;

        if(block_recv(newsockfd, (char*)(&p), sizeof(p)) != sizeof(p)) 
        {
            error("ERROR while reading from socket");
            // whatever error handling you need...
        }
        p.a = ntohl(p.a);
        printf("\na: %d\n",p.a);
        
        // if(block_recv(newsockfd, (char*)&b, sizeof(b)) != sizeof(b)) 
        // {
        //     error("ERROR while reading b");
        //     // whatever error handling you need...
        // }
        p.b = ntohl(p.b);
        printf("b: %d\n\n",p.b);

        // if(block_recv(newsockfd, (char*)&nonce, sizeof(nonce)) != sizeof(nonce)) 
        // {
        //     error("ERROR while reading nonce");
        //     // whatever error handling you need...
        // }
        for(int i =0 ;i<16;i++)
            printf("%d\n",p.nonce[i]);

        // if(block_recv(newsockfd, (char*)&eflag, sizeof(eflag)) != sizeof(eflag)) 
        // {
        //     error("ERROR while reading nonce");
        //     // whatever error handling you need...
        // }
        printf("eflag: %d\n", p.eflag);
        
	    int n = write(newsockfd,"I got your message",18);
	    if (n < 0) error("ERROR writing to socket");
	    close(newsockfd);
	    close(sockfd);
 	 //}
     return 0; 
}


