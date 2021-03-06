
#ifndef _RSA_OPENSSL_H_
#define _RSA_OPENSSL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>




#define BUFFSIZE 1024



int RSA_encrypt(char *str,char *path_key,unsigned char *p_en);
int RSA_decrypt(char *str,char *path_key,unsigned char *p_de);

#endif
