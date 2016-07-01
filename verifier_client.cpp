
#include <stdio.h>
#include <stdlib.h> // defines rand()
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define CLIENT_SOCKET_CODE  \
    sockfd = socket(AF_INET, SOCK_STREAM, 0); \
    if (sockfd < 0) \
        error("ERROR opening socket");\
    /*Get the port number and server */ \
    portno = atoi(argv[2]); \
    server = gethostbyname(argv[1]); \
    if (server == NULL) { \ 
        fprintf(stderr,"ERROR, no such host\n"); \
        exit(0); \
    } \
    /*Initialie socket port, address and address family */ \
    bzero((char *) &serv_addr, sizeof(serv_addr)); \
    serv_addr.sin_family = AF_INET; \
    bcopy((char *)server->h_addr, \
         (char *)&serv_addr.sin_addr.s_addr, \
         server->h_length); \
    serv_addr.sin_port = htons(portno); \
    /*connect to server */ \
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)  \
        error("ERROR connecting"); 



typedef unsigned char byte;

struct bundle{
    int a,b;
    byte eflag;
    byte nonce[16];
    byte content_ab[32];
    byte hmac[256];

};

typedef struct bundle packet;

void inttobuff(int32_t num, char* buff, int offset)
{
    int32_t conv = htonl(num);
    char *data = (char*)&conv;
    for(int i = 0;i<4;i++){
        buff[offset++] = data[i];
    }
}

void chararrtobuff(unsigned char* arr, int len, unsigned char* buff,int offset)
{
    for(int i = 0;i<len;i++)
    {
        buff[offset++] = arr[i];
    }
}

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[])
{


	// Declaration section
    int32_t sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    packet p; // store data into p and send_it
    int x[10] = {0,32,64,96,128,170,192,224,256,288};
    int y[10] = {31,63,95,127,169,191,223,255,287,319};

    
    
    if (argc < 3) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }

    // create and initialize socket 
    CLIENT_SOCKET_CODE;
    bzero((byte*)&p,sizeof(p));


    // generate a,b boundaries 
    srand(time(NULL)); // initialize random seed 
    short r = rand() % 10;
    p.a = htonl(x[r]);
    p.b = htonl(y[r]);
    printf("a: %d   \nb: %d\n\n",x[r],y[r]);

    
    // initialie openssl library
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();


    // generate nonce
    unsigned char nonce[16];
	int rc = RAND_bytes(p.nonce, sizeof(p.nonce));
	unsigned long err = ERR_get_error();
	if(rc != 1) {
	    printf("RAND_bytes failed\n");
	}

    for(int i =0 ;i<16;i++)
        printf("%d\n",p.nonce[i]);


    // generate exec flag 
    p.eflag = rand() % 2;
    printf("eflag: %d\n", p.eflag);
    
    // bundle the data
    // inttobuff(x[r],(char*)sendBuffer,offset);
    // offset+=4;
    // inttobuff(y[r],(char*)sendBuffer,offset);
    // offset+=4;

    // //snprintf((char*)sendBuffer+offset,sizeof(sendBuffer)-offset,"%d%d",htonl(x[r]),htonl(y[r]));
    // //offset+=8;
    // chararrtobuff(nonce,sizeof(nonce),sendBuffer,offset);
    // offset= offset+sizeof(nonce);
    // sendBuffer[offset++] = eflag;
    
    // n = write(sockfd,sendBuffer,strlen(sendBuffer));
    // if (n < 0) 
    //      error("ERROR writing to socket");


    // start sending
    // sendBuffer[0] = offset;


    int left = sizeof(p);
    int wc;
    while (left) {
        wc = write(sockfd, (byte*)(&p) + sizeof(p) - left, left);
        if (wc < 0) 
            error("ERROR writing to socket");
        left -= wc;
    }


    // receive data from socket 
    byte sendBuffer[256];
    bzero(sendBuffer,sizeof(sendBuffer));
    n = read(sockfd,sendBuffer,sizeof(sendBuffer) -1 );
    if (n < 0) 
         error("ERROR reading from socket");
    printf("%s\n",sendBuffer);
    close(sockfd);
    return 0;
}

