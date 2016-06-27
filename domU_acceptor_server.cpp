/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

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

int main(int argc, char *argv[])
{
    //Declaration section 
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    unsigned char buffer[1024];
    struct sockaddr_in serv_addr, cli_addr;
    int n;

    int x[10] = {1,101,201,301,401,501,601,701,801,901};
    int y[10] = {100,200,300,400,500,600,700,800,900,1000};

    unsigned char mem[1000];

    for(int i = 0; i < 1000;i++)
    {
        mem[i] = i;
    }

    if (argc < 2) {
        fprintf(stderr,"ERROR, no port provided\n");
        exit(1);
    }


    
    // create a socket file descriptor 
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
       error("ERROR opening socket");

    bzero((char *) &serv_addr, sizeof(serv_addr));    // set server address bits to zero

    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_addr.s_addr = INADDR_ANY;  // INADDR_ANY is server ip address
    serv_addr.sin_port = htons(portno);   // htons converts port number in host byte order to a port number in network byte order.


    // bind the server to port and host ... this steps makes it a server socket 
    if (bind(sockfd, (struct sockaddr *) &serv_addr,
              sizeof(serv_addr)) < 0) 
              error("ERROR on binding");


    //while(1){
        // start listening  
        
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
        unsigned char size;
        n = read(newsockfd,&size,1);
        if (n < 0) error("ERROR reading size from socket");

        int32_t a=0,b=0;
        unsigned char nonce[16],eflag;

        if(block_recv(newsockfd, (char*)&a, sizeof(a)) != sizeof(a)) 
        {
            error("ERROR while reading a");
            // whatever error handling you need...
        }
        a = ntohl(a);
        printf("\na: %d\n",a);
        
        if(block_recv(newsockfd, (char*)&b, sizeof(b)) != sizeof(b)) 
        {
            error("ERROR while reading b");
            // whatever error handling you need...
        }
        b = ntohl(b);
        printf("b: %d\n\n",b);

        if(block_recv(newsockfd, (char*)&nonce, sizeof(nonce)) != sizeof(nonce)) 
        {
            error("ERROR while reading nonce");
            // whatever error handling you need...
        }
        for(int i =0 ;i<16;i++)
            printf("%d\n",nonce[i]);

        if(block_recv(newsockfd, (char*)&eflag, sizeof(eflag)) != sizeof(eflag)) 
        {
            error("ERROR while reading nonce");
            // whatever error handling you need...
        }
        printf("eflag: %d\n", eflag);
        
	    n = write(newsockfd,"I got your message",18);
	    if (n < 0) error("ERROR writing to socket");
	    close(newsockfd);
	    close(sockfd);
 	 //}
     return 0; 
}


