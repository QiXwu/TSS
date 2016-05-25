#include <string.h>
#include "rsa_openssl.h"




int RSA_encrypt(char *str,char *path_key,unsigned char *p_en){
    int i;
    RSA *p_rsa;
    FILE *file;
    int flen,rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        perror("open key file error");
        return 0;    
    }   
    if((p_rsa=PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL))==NULL){
    //if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){   ***sub pubek
        ERR_print_errors_fp(stdout);
        return 0;
    }   
    flen=strlen(str);
    rsa_len=RSA_size(p_rsa);
    memset(p_en,0,sizeof(p_en));

    if(RSA_public_encrypt(rsa_len,(unsigned char *)str,p_en,p_rsa,RSA_NO_PADDING)<0){
        return 0;
    }


    RSA_free(p_rsa);
    fclose(file);
    return rsa_len;
}


int RSA_decrypt(char *str,char *path_key,unsigned char *p_de){
    RSA *p_rsa;
    FILE *file;
    int rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        perror("open key file error");
        return 0;
    }
    if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){
        ERR_print_errors_fp(stdout);
        return 0;
    }
    rsa_len=RSA_size(p_rsa);
    memset(p_de,0,sizeof(p_de));

    if(RSA_private_decrypt(rsa_len,(unsigned char *)str,p_de,p_rsa,RSA_NO_PADDING)<0){
        return 0;
    }
    RSA_free(p_rsa);
    fclose(file);
    rsa_len =strlen(p_de);
    printf("%d\n", rsa_len);
    return rsa_len;
}


int RSA_GetpubKey(unsigned char *key){
    FILE * fp_input = NULL;
    char ch;
    int i= 0;
    fp_input = fopen("test_pub.key", "rb");

    while((ch=fgetc(fp_input))!=EOF){
    // fputc(ch,stdout);  
        *(key+i) = ch;
        i++; 
    }  
    fclose(fp_input);
    return i;
}