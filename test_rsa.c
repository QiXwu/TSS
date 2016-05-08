#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa-openssl.h"

#define OPENSSLKEY "test.key"
#define PUBLICKEY "test_pub.key"

int main(void){
    char *source="A test string.";
    char *ptr_en,*ptr_de;
    printf("source is    :%s\n",source);
    ptr_en=RSA_encrypt(source,PUBLICKEY);
    printf("after encrypt:%s\n",ptr_en);
    ptr_de=RSA_decrypt(ptr_en,OPENSSLKEY);
    printf("after decrypt:%s\n",ptr_de);
    if(ptr_en!=NULL){
        free(ptr_en);
    }   
    if(ptr_de!=NULL){
        free(ptr_de);
    }   
    return 0;
}
