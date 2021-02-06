#include <stdio.h>
#include <stdlib.h>
#include <crypt.h>


int main(int argc,char** argv)
{
    if( argc != 3 ) {
        printf("Usage:%s <PlainTextPassword> <Salt>\n",argv[0]);
        return -1;
    }
    printf("Crypted Password for %s is %s\n",argv[1],crypt(argv[1],argv[2]));
} 
