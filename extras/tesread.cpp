#include <stdio.h>
#include <iostream>
#include <fstream>

using namespace std;

int main()
{

    ifstream getit;
    getit.open("test.key",ios::in | ios::binary);
    int size = getit.tellg();
    printf("size: %d\n",size);
    unsigned char data[32];
    getit.seekg(0,ios::beg);
    getit.read((char*) data , 32);
    getit.close();

    printf("\n data: \n");
    for(int i=0; i < size; ++i)
        printf("%03d ", data[i]);


    printf("\n");
    return 0;


}