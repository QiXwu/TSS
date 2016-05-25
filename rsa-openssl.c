
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "rsa-openssl.h"

int rsa(){
    return 0;
}


// char *RSA_decrypt(char *str,char *path_key){
//     char *p_de;
//     RSA *p_rsa;
//     FILE *file;
//     int rsa_len;
//     if((file=fopen(path_key,"r"))==NULL){
//         perror("open key file error");
//         return NULL;
//     }
//     if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){
//         ERR_print_errors_fp(stdout);
//         return NULL;
//     }
//     rsa_len=RSA_size(p_rsa);
//     p_de=(unsigned char *)malloc(rsa_len+1);
//     memset(p_de,0,rsa_len+1);
//     if(RSA_private_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
//         return NULL;
//     }
//     RSA_free(p_rsa);
//     fclose(file);
//     return p_de;
// }