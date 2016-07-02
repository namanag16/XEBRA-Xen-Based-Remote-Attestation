#include <stdio.h>
#include <iostream>
#include <fstream>
#include </usr/local/include/openssl/bio.h>
#include </usr/local/include/openssl/ssl.h>
#include </usr/local/include/openssl/err.h>
#include </usr/local/include/openssl/rand.h>

using namespace std;

int main()
{


	ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();


    // generate nonce
    unsigned char nonce[32];
	int rc = RAND_bytes(nonce, sizeof(nonce));
	unsigned long err = ERR_get_error();


	if(rc != 1) {
	    /* RAND_bytes failed */
	    /* `err` is valid    */
	    printf("there is some error dude\n");
	} 

	printf("nonce: \n");
	for(int i =0 ;i<32;i++)
        printf("%03d ",nonce[i]);


	ofstream test;	
	test.open("test.key",ios::binary|ios::trunc);


    
    test.write((char*)nonce,sizeof(nonce));
    test.close();

    ifstream getit;
    getit.open("test.key",ios::binary|ios::ate);
    int size = getit.tellg();
    printf("\nsize: %d",size);
    getit.seekg(0,ios::beg);
    unsigned char data[size];
    getit.seekg(0,ios::beg);
    getit.read((char*) data , size);
    getit.close();

    printf("\ndata: \n");
    for(int i=0; i < size; ++i)
        printf("%03d ", data[i]);


    printf("\n");
    return 0;
}