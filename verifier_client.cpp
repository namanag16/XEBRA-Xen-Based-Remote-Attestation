
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
#include "/usr/local/include/openssl/crypto.h"
#include </usr/include/array.hpp>

namespace ajd { 
    namespace crypto {
    /// A convenience typedef for a 128 bit block.
    typedef boost::array<unsigned char, 16> block;
    /// Remove sensitive data from the buffer
    template<typename C> void cleanse(C &c)
    }
};

typedef unsigned char memory;


void key_generation()
{
  crypto::block key;                         // 128 bit key
  crypto::block salt;                        // 128 bit salt
  crypto::fill_random(salt);                 // random salt
  crypto::derive_key(key, "password", salt); // password derived key
  crypto::cleanse(key)                       // clear sensitive data
}


void message_authentication_code()
{
  crypto::block key;            // the hash key
  crypto::fill_random(key);     // random key will do (for now)
  crypto::hash h(key);          // the keyed-hash object
  crypto::hash::value mac;      // the mac value
  h.update("hello world!");     // add data
  h.update("see you world!");   // more data
  h.finalize(mac);              // get the MAC code
  crypto::cleanse(key)          // clean senstive data
}

void showbits ( int n )
{
    int i, k, andmask ;

    for(i =(sizeof(n)*2)-1 ; i >= 0 ; i-- )
    {
        andmask = 1 << i ;
        k = n & andmask ;
    }

    k == 0 ? printf ( "0" ) : printf ( "1" ) ;
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

    // generate a,b boundaries 
    srand(time(NULL)); // initialize random seed 
    r = rand() % 10;
    printf("a: %d   b: %d\n\n",x[r],y[r]);

    
    // initialie openssl library
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
    
    // n = write(sockfd,sendBuffer,strlen(sendBuffer));
    // if (n < 0) 
    //      error("ERROR writing to socket");


    // start sending
    sendBuffer[0] = offset;
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

