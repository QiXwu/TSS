#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "AES_openssl.h"

// a simple hex-print routine. could be modified to print 16 bytes-per-line
static void hex_print(const void* pv, size_t len)
{
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i<len;++i)
            printf("%02X ", *p++);
    }
    printf("\n");
}



int main(){
    int keylength,res;
    printf("Give a key length [only 128 or 192 or 256!]:\n");
    scanf("%d", &keylength);
    
    unsigned char aes_key[keylength/8];
    res = AES_Generate_Key(keylength,aes_key);

    size_t inputslength = 0;
    printf("Give an input's length:\n");
    scanf("%lu", &inputslength);

    /* generate input with a given length */
    unsigned char inputdata[inputslength];
    memset(inputdata, 'X', inputslength);
    
    const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char enc_out[encslength];
    unsigned char dec_out[inputslength];
    memset(enc_out, 0, sizeof(enc_out));
    memset(dec_out, 0, sizeof(dec_out));
    
    /* init vector */
    unsigned char iv_enc[AES_BLOCK_SIZE], iv_dec[AES_BLOCK_SIZE];
    RAND_bytes(iv_enc, AES_BLOCK_SIZE);
    memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);
    
    AES_Encrypt(keylength,aes_key,iv_enc,inputslength,inputdata,enc_out);
    
    AES_Decrypt(keylength,aes_key,iv_dec,encslength,enc_out,dec_out);
    
    printf("original:\t");
    hex_print(inputdata, sizeof(inputdata));

    printf("encrypt:\t");
    hex_print(enc_out, sizeof(enc_out));

    printf("decrypt:\t");
    hex_print(dec_out, sizeof(dec_out));

    return 0;
}
