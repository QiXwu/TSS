
#ifndef _AES_OPENSSL_H_
#define _AES_OPENSSL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>



#define AES_BLOCK_SIZE 16


int AES_Encrypt();

int AES_Decrypt();

int AES_Generate_Key(int keylength,unsigned char* key);



#endif