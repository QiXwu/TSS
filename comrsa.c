#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_openssl.h"



#define AES_GENERATEKEY  244
#define AES_ENC  245
#define AES_DEC  246
#define RSA_ENC  174
#define RSA_DEC  175
#define RSA_GET  176







int excute_crypto(unsigned char* req,unsigned char*rsp){
	int cmd;
	int ret;
	cmd = req[9];
	printf("%d\n",cmd );
	switch(cmd){
	// 	case AES_GENERATEKEY:
	// 	excute_AES_Generate_Key(req,rsp);
	// 	break;
		
	// case AES_ENC:
	//  	excute_AES_Encrypt(req,rsp);
	//  	break;
	// case AES_DEC:
	//  	//excute_AES_Decrypt(req,rsp);
	// 	printf("1\n");
	//  	break;
	// case RSA_GET:
	//  	ret = excute_RSA_GetpubKey(req,rsp);
	// 	return ret;
	//  	break;

	case RSA_ENC:
		ret = excute_RSA_encrypt(req,rsp);
		return ret;
	 	break;
	case RSA_DEC:
		ret = excute_RSA_decrypt(req,rsp);
		return ret;
	 	break;

	case RSA_GET:
		ret = excute_RSA_GetpubKey(req,rsp);
		return ret;
	 	break;
	default:
		printf("default\n");
		printf("Command Error. \n");
		break;
	}
	
}


int excute_RSA_GetpubKey(unsigned char* req,unsigned char*rsp){
	int len,i,j;
	unsigned char key[1024];
	len = RSA_GetpubKey(key);
	printf("%d\n",len );
	
	memset(rsp,0,sizeof(rsp));

	for(i=10,j=0;j<len;i++,j++)
        *(rsp + i) = key[j];
	
    for (i=0;i<len+10;i++)
        printf("%02x ", rsp[i]);
    printf("\n");

	return len+10;
}

int excute_RSA_encrypt(unsigned char* req,unsigned char*rsp){
	int len,i,j;
	int datalength;
	unsigned char data[1024];
	unsigned char enc_data[1024];

	datalength = req[10];
	for (i=0;i<datalength;i++)
		data[i]=req[11+i];
	
	len=RSA_encrypt(data,"test_pub.key",enc_data);


	printf("%d\n",len);


	for(i=10,j=0;j<len;i++,j++)
        *(rsp + i) = enc_data[j];
	

	rsp[9] = len;
	rsp[5] = len + 10;


	for (i=0;i<=len+10;i++)
        printf("%02x ", rsp[i]);
    printf("\n");

	return len + 10;
}


int excute_RSA_decrypt(unsigned char* req,unsigned char*rsp){
	int len,i,j;
	int datalength;
	unsigned char data[1024];
	unsigned char dec_data[1024];

	datalength = req[10];
	for (i=0;i<datalength;i++)
		data[i]=req[11+i];
	
	len=RSA_decrypt(data,"test.key",dec_data);

	for(i=10,j=0;j<len;i++,j++)
        *(rsp + i) = dec_data[j];
	

	rsp[9] = len;
	rsp[5] = len + 10;
	
	return len + 10;
}





int main(){
	int i,j,ret;
	// unsigned char ge_key[]={0,193,0,0,0,11,0,0,0,244,128};
	unsigned char enc[1024];
	unsigned char dec[1024];
	unsigned char buf[1024];
	unsigned char key[1024];

	memset(key,0,sizeof(key));
	key[9]=176;
	ret = excute_crypto(key,buf);

	printf("after enc :\n");
	for (i=0;i<ret;i++)
		printf("%02x ", buf[i]);
	printf("\n");



	memset(enc,0,sizeof(enc));
	enc[1]=193;
	enc[5]=26;
	enc[9]=174;
	enc[10]= 15;

	for(i=11;i<11+15;i++)
           enc[i] = 'X';


	printf("enc cmd:\n");
	for (i=0;i<26;i++)
		printf("%02x ", enc[i]);
	printf("\n");

	memset(buf,0,sizeof(buf));

	ret = excute_crypto(enc,buf);

	printf("%d\n", ret);

	printf("after enc :\n");
	for (i=0;i<ret;i++)
		printf("%02x ", buf[i]);
	printf("\n");




	memset(dec,0,sizeof(dec));
	dec[1]=193;
	dec[5]=139;
	dec[9]=175;


    /*init data*/
	dec[10] = buf[9];
	for(i=11,j=10;i<11+dec[10];j++,i++)
           dec[i] = buf[j];       	
	
	printf("before dec :\n");
	for (i=0;i<139;i++)
		printf("%02x ", dec[i]);
	printf("\n");

	ret = excute_crypto(dec,buf);

	printf("after dec :\n");
	for (i=0;i<ret;i++)
		printf("%02x ", buf[i]);
	printf("\n");



	return 0;
}

