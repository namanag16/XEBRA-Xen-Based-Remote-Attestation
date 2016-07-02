/* A simple client in the internet domain using TCP
   Server ip and port number are passed as arguments */

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

#include </usr/local/include/openssl/bio.h>
#include </usr/local/include/openssl/ssl.h>
#include </usr/local/include/openssl/err.h>
#include </usr/local/include/openssl/rand.h>

#include </home/scorpion/mtechProj/hmac.cpp>     // include crypto functions 

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


typedef unsigned char byte;

struct bundle{
    int a,b;
    byte eflag;
    byte nonce[16];
    byte content_ab[32];
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

void inttobuff(int32_t num, char* buff, int offset)
{
    int32_t conv = htonl(num);
    char *data = (char*)&conv;
    for(int i = 0;i<4;i++){
        buff[offset++] = data[i];
    }
}
void chararrtobuff(byte* arr, int len, byte* buff,int offset)
{
    for(int i = 0;i<len;i++)
    {
        buff[offset++] = arr[i];
    }
}

// generate mac of data contents starting at "msg" till length "len" and output in "sign"
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
    
    print_it("Signature", ssign, slen);
    chararrtobuff(ssign,slen,sign,0); // copy signature into the packet
}

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

void fetch_content(packet* p, int a, int b)
{
    byte mem[1000];
    for(int i = 0; i < 1000;i++)
    {
        mem[i] = i;
    }
    int count = 0;
    for(int i = a;i<=b;i++)
        p->content_ab[count++] = mem[i];
}

int verify_sign(byte* msg, int len, byte* sign)
{
        EVP_PKEY *vkey = NULL;
        int rc = make_skey(&vkey); /* generate vkey */
        assert(rc == 0);
        if(rc != 0)
            exit(1);
        
        assert(vkey != NULL);
        if(vkey == NULL)
            exit(1); 
        printf("%d\n", sizeof(sign));
        rc = verify_it(msg, len, sign, 32, vkey);
        return rc;
}

void waitForResponse(packet* req)
{
    packet res;
    CREATE_SERVER_SOCKET(7892)

    printf("Verifier waiting for response\n");
    listen(sockfd,5);

    // accept a connection 
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, 
                (struct sockaddr *) &cli_addr, 
                &clilen);
    if (newsockfd < 0) 
         error("ERROR on accept");

    if(block_recv(newsockfd, (char*)(&res), sizeof(res)) != sizeof(res)) 
    {
        error("ERROR while reading from socket");
    }


    print_it("signature",res.hmac,sizeof(res.hmac));
    printf("output: %d\n", ntohl(res.outputs));

    // verify the signature to check integrity of memory contents of the device
    fetch_content(req,ntohl(req->a),ntohl(req->b));

    printf("size of res.hmac %d\n", sizeof(res.hmac));
    int rc = verify_sign((byte*)req->nonce,sizeof(req->nonce)+sizeof(req->content_ab),res.hmac);
    if(rc == 0) {
        printf("Verified signature\n");
    } else {
        printf("Failed to verify signature, return code %d\n", rc);
        close(newsockfd);
        close(sockfd);
    }

    int n = write(newsockfd,"verifier received response",26);
    if (n < 0) error("ERROR writing to socket");
    close(newsockfd);
    close(sockfd);

}

int main(int argc, char *argv[])
{
    
    packet p; // store data into p and send_it
    int x[10] = {0,32,64,96,128,170,192,224,256,288};
    int y[10] = {31,63,95,127,169,191,223,255,287,319};


    if (argc < 3) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }

    // create and initialize client socket 
    CREATE_CLIENT_SOCKET(atoi(argv[2]),gethostbyname(argv[1]))
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
	int rc = RAND_bytes(p.nonce, sizeof(p.nonce));
	unsigned long err = ERR_get_error();
	if(rc != 1) {
	    printf("RAND_bytes failed\n");
	}
    print_it("nonce",p.nonce,sizeof(p.nonce));


    // generate exec flag 
    p.eflag = rand() % 2;
    printf("eflag: %d\n", p.eflag);

    // generate mac of data 

    generate_mac((byte*)&p,(sizeof(int)*2)+17,p.hmac);
    // print_it("in main .. signature is",p.hmac,32/*sizeof(p.hmac)*/);



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

    // wait for response from corresponding control dom 
    waitForResponse(&p);
    return 0;
}