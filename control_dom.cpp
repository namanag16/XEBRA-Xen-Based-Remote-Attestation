
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>


#include </home/scorpion/mtechProj/hmac.cpp>     // include crypto functions 

#define CREATE_SERVER_SOCKET(port) \
    int sockfd, newsockfd, portno;\
    socklen_t clilen;\
    struct sockaddr_in serv_addr, cli_addr;\
    /*create a socket file descriptor */ \
    sockfd = socket(AF_INET, SOCK_STREAM, 0); \
    if (sockfd < 0) \
       error("ERROR opening socket"); \
    bzero((char *) &serv_addr, sizeof(serv_addr));    /* set server address bits to zero*/ \
    portno = port; \
    serv_addr.sin_family = AF_INET;  \
    serv_addr.sin_addr.s_addr = INADDR_ANY;  /* INADDR_ANY is server ip address*/ \
    serv_addr.sin_port = htons(portno);   /* htons converts port number in host byte order to a port number in network byte order.*/ \
    /* bind the server to port and host ... this steps makes it a server socket */ \
    if (bind(sockfd, (struct sockaddr *) &serv_addr, \
              sizeof(serv_addr)) < 0)  \
              error("ERROR on binding"); 

#define CREATE_CLIENT_SOCKET(port,ser)  \
    int32_t sockfd, portno, n;\
    struct sockaddr_in serv_addr;\
    struct hostent *server;\
    sockfd = socket(AF_INET, SOCK_STREAM, 0); \
    if (sockfd < 0) \
        error("ERROR opening socket");\
    /*Get the port number and server */ \
    portno = port; \
    server = ser; \
    if (server == NULL) {\
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
    byte content_ab[32];  // fixing the content size to 32 bytes for now
    byte hmac[32];
    byte inputs;
    int outputs;
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

void chararrtobuff(byte* arr, int len, byte* buff,int offset)
{
    for(int i = 0;i<len;i++)
    {
        buff[offset++] = arr[i];
    }
}

void generate_mac(byte* msg, int len, byte* sign)
{
    EVP_PKEY *skey = NULL;
    
    int rc = make_skey(&skey);
    
    assert(rc == 0);
    if(rc != 0)
        exit(1);
    
    assert(skey != NULL);
    if(skey == NULL)
        exit(1);

    byte* ssign = NULL;
    size_t slen = 0;

    rc = sign_it(msg, len, &ssign, &slen, skey);
    assert(rc == 0);
    if(rc == 0) {
        printf("Created signature\n");
    } else {
        printf("Failed to create signature, return code %d\n", rc);
        exit(1); /* Should cleanup here */
    }
    
    //print_it("Signature", ssign, slen);
    chararrtobuff(ssign,slen,sign,0); // copy signature into the packet
}

void sendToVerifier(packet p)
{
	CREATE_CLIENT_SOCKET(7892,gethostbyname("localhost"))

    // send packet
    int left = sizeof(p);
    int wc;
    while (left) {
        wc = write(sockfd, (byte*)(&p) + sizeof(p) - left, left);
        if (wc < 0) 
            error("ERROR writing to socket");
        left -= wc;
    }

    byte sendBuffer[256];
    bzero(sendBuffer,sizeof(sendBuffer));
    n = read(sockfd,sendBuffer,sizeof(sendBuffer) -1 );
    if (n < 0) 
         error("ERROR reading from socket");
    printf("%s\n",sendBuffer);
    close(sockfd);
}

int main(int argc, char *argv[])
{
	// Basic Declarations 
    packet p;
    byte buffer[256];

    // if (argc < 2) {
    //     fprintf(stderr,"ERROR, no port provided\n");
    //     exit(1);
    // }

    CREATE_SERVER_SOCKET(7891) // creates and binds the server socket



    // while(1){     /* listen continuously */
        listen(sockfd,2);

        // accept a connection 
        clilen = sizeof(cli_addr);
        newsockfd = accept(sockfd, 
                    (struct sockaddr *) &cli_addr, 
                    &clilen);
        if (newsockfd < 0) 
             error("ERROR on accept");

        if(block_recv(newsockfd, (char*)(&p), sizeof(p)) != sizeof(p)) 
        {
            error("ERROR while reading from socket");
        }
        print_it("nonce",p.nonce,sizeof(p.nonce));
        printf("eflag: %d\n", p.eflag);
        printf("inputs: %d\n",p.inputs);
        print_it("Content[a,b]",p.content_ab,sizeof(p.content_ab));

        int n = write(newsockfd,"control dom received data",25);
        if (n < 0) error("ERROR writing to socket");
        close(newsockfd);
        close(sockfd);

        // process data 
        bzero((char *)p.hmac, sizeof(p.hmac)); 
        generate_mac((byte*)p.nonce,sizeof(p.nonce)+sizeof(p.content_ab),p.hmac);

        print_it("Signature",p.hmac,sizeof(p.hmac));
        if(p.eflag == 1)
        {
        	/*Execute content_ab*/
        	p.outputs = htonl(165); // give a random output for now	
        }
        

        // send reply to verifier
        sendToVerifier(p);

        
     // }
     return 0; 
}