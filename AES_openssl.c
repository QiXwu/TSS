#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "AES_openssl.h"


int AES_Encrypt(int keylength,unsigned char* aes_key,unsigned char* iv_enc,int inputslength,unsigned char* inputdata,unsigned char* out){
    
    unsigned char aes_input[inputslength];
    memcpy(aes_input,inputdata,inputslength);
    
    // buffers for encryption 
    const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char enc_out[encslength];

    memset(enc_out, 0, sizeof(enc_out));

    
    AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(aes_key, keylength, &enc_key);
    AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);

    memcpy(out,enc_out,encslength);
    return 0;
}

int AES_Decrypt(int keylength,unsigned char* aes_key,unsigned char* iv_dec,int inputslength,unsigned char* inputdata,unsigned char* out){
    
    unsigned char aes_input[inputslength];
    memcpy(aes_input,inputdata,inputslength);

    unsigned char dec_out[inputslength];
    memset(dec_out, 0, sizeof(dec_out));
    
    AES_KEY  dec_key;
    AES_set_decrypt_key(aes_key, keylength, &dec_key);
    AES_cbc_encrypt(aes_input, out, inputslength, &dec_key, iv_dec, AES_DECRYPT);
    
    //memcpy(out,dec_out,sizeof(out));
    return 0;
}

int AES_Generate_Key(int keylength,unsigned char* key){
    
    int i,len;
    len = keylength;
    /* generate a key with a given length */
    unsigned char aes_key[len/8];
    memset(aes_key, 0, len/8);
    if (!RAND_bytes(aes_key, len/8))
        return -1;
    else{
        for(i=0;i<len/8;i++)
            *(key + i) = aes_key[i];
    }
    return 0;
    
}
