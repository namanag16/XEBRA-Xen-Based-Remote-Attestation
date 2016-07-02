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
#include <iostream>
#include <fstream>
#include <assert.h>

#include </usr/local/include/openssl/bio.h>
#include </usr/local/include/openssl/ssl.h>
#include </usr/local/include/openssl/err.h>
#include </usr/local/include/openssl/rand.h>
// #include </usr/local/include/openssl/crypto.h>
// #include </usr/include/boost/array.hpp>

// #include </home/scorpion/mtechProj/crypto_wrapper.h>
// using namespace ajd;

using namespace std;

#include </home/scorpion/mtechProj/hmac.cpp>     // include crypto functions 
typedef unsigned char byte;

// takes msg as input .. produces mac into sign
void generate_mac(unsigned char * msg, byte* sign = NULL)
{
    EVP_PKEY *skey = NULL, *vkey = NULL;
    
    int rc = make_skey(&skey);
    
    assert(rc == 0);
    if(rc != 0)
        exit(1);
    
    assert(skey != NULL);
    if(skey == NULL)
        exit(1);

    // byte* sign = NULL;
    size_t slen = 0;

    rc = sign_it(msg, sizeof(msg), &sign, &slen, skey);
    assert(rc == 0);
    if(rc == 0) {
        printf("Created signature\n");
    } else {
        printf("Failed to create signature, return code %d\n", rc);
        exit(1); /* Should cleanup here */
    }
    
    print_it("Signature", sign, slen);
}

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
    unsigned char sendBuffer[256];
    int offset = 1; // next free byte in buffer
    
    int x[10] = {1,101,201,301,401,501,601,701,801,901};
    int y[10] = {100,200,300,400,500,600,700,800,900,1000};

    short r;
    
    if (argc < 3) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }


    //Create Socket file descriptor 
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    //Get the port number and server 
    portno = atoi(argv[2]);
    server = gethostbyname(argv[1]);
	if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    //Initialie socket port, address and address family 
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);


    // connect to server 
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");



    srand(time(NULL)); // initialize random seed 
    r = rand() % 10;
    printf("a: %d   b: %d\n\n",x[r],y[r]);

    
    // initialize openssl library
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();


    // generate nonce
    unsigned char nonce[16];
	int rc = RAND_bytes(nonce, sizeof(nonce));
	unsigned long err = ERR_get_error();



	if(rc != 1) {
	    /* RAND_bytes failed */
	    /* `err` is valid    */
	} 
    for(int i =0 ;i<16;i++)
        printf("%d\n",nonce[i]);


    // generate exec flag 
    unsigned char eflag = rand() % 2;
    printf("eflag: %d\n", eflag);
    
    // bundle the data
    bzero(sendBuffer,sizeof(sendBuffer));

    inttobuff(x[r],(char*)sendBuffer,offset);
    offset+=4;
    inttobuff(y[r],(char*)sendBuffer,offset);
    offset+=4;

    //snprintf((char*)sendBuffer+offset,sizeof(sendBuffer)-offset,"%d%d",htonl(x[r]),htonl(y[r]));
    //offset+=8;
    chararrtobuff(nonce,sizeof(nonce),sendBuffer,offset);
    offset= offset+sizeof(nonce);
    sendBuffer[offset++] = eflag;
    sendBuffer[0] = offset;


    
    



    // n = write(sockfd,sendBuffer,strlen(sendBuffer));
    // if (n < 0) 
    //      error("ERROR writing to socket");


    // start sending
    
    int left = offset;
    int wc;
    while (left) {
        wc = write(sockfd, sendBuffer + offset - left, left);
        if (wc < 0) 
            error("ERROR writing to socket");
        left -= wc;
    }


    // receive data from socket 
    bzero(sendBuffer,sizeof(sendBuffer));
    n = read(sockfd,sendBuffer,sizeof(sendBuffer) -1 );
    if (n < 0) 
         error("ERROR reading from socket");
    printf("%s\n",sendBuffer);
    close(sockfd);
    return 0;
}

