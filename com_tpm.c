#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include "AES_openssl.h"
#include "RSA_openssl.h"

#define AES_BLOCK_SIZE  16

#define AES_GENERATEKEY  171
#define AES_ENC  172
#define AES_DEC  173
#define RSA_ENC  174
#define RSA_DEC  175
#define RSA_GET  176



int set_opt(int,int,int,char,int);
int raise_error(int fd,int error);
int substring(unsigned char* s1,unsigned char* s2,int c,int len);

int excute_crypto(unsigned char* req,unsigned char*rsp);
int excute_AES_Generate_Key(unsigned char* req,unsigned char*rsp);
int excute_AES_Encrypt(unsigned char* req,unsigned char*rsp);
int excute_AES_Decrypt(unsigned char* req,unsigned char*rsp);



void main()
{
	int flag = 0;
	int len = 0;
	int t = 0;
	int fd,nByte;
	char *uart4 = "/dev/ttySAC1";
	unsigned char buffer[1024];
	memset(buffer, 0, sizeof(buffer));
    
    unsigned int i,j,fdd;
    int res,ret;
    unsigned char buf[1024];
	int buf_size = sizeof(buf);
	memset(buf,0,sizeof(buf));    

    if((fd = open(uart4, O_RDWR|O_NOCTTY))<0)
		printf("open %s is failed",uart4);
	else{
		set_opt(fd, 9600, 8, 'N', 1);

		while(1){	
			
			while((nByte = read(fd, buffer, 1024))>0 || len < buf[5]){
				flag =1;
				//printf("in\n");				
				for(i = len; i < (len + nByte); i++){
					buf[i] = buffer[i - len];
				}
					len += nByte;
			/*	if (t++>100000){
					unsigned char ercode[]={0.179,0,0,0,10,0,0,0,1};				
					flag = 0;
					t = 0;
					len = 0;		
 					write(fd,ercode,10);
					memset(buffer, 0, sizeof(buffer));
					memset(buf,0,sizeof(buf));
					break;
				}*/					
			}
			
			if(flag == 1){
			flag =0; 
 
				for(i = 0; i < len; i++)
                			printf("%02x ", buf[i]);
       				printf("\n");
                
				if (buf[9]<=170 || buf[9]>=180 ){
					fdd = open("/dev/tpm0",O_RDWR);
                		if(fdd < 0){
                    		printf("Error: Open() failed: (%02x )\n ", fd);
					}
					printf("Opened\n");
					res = write(fdd, buf, len);
					printf("%d write to tpm.\n",res);
					buf_size = 1024;
					ret = read(fdd, &buffer, buf_size);
					printf("%d read from tpm.\n",ret);
					close(fdd);
					
				}
				else{
					memset(buffer,0,sizeof(buffer));					
					ret = excute_crypto(buf,buffer);
				}
				/*write back to TSS*/
				write(fd,buffer,ret);
                
				memset(buffer, 0, sizeof(buffer));
				memset(buf,0,sizeof(buf));
				nByte = 0;
				len = 0;
			}
		}
	}
}

// int raise_error(int fd,int error){
// 	unsigned char buf[128];
	
// 	switch(error){
// 		case 1:
// 			buf = {0,179,0,0,0,10,0,0,0,1};
// 			write(fd,buf,10);
// 			break;
// 		default:
// 			printf("Error.");
// 			break;
// 	}
	
// }


int substring(unsigned char* s1,unsigned char* s2,int c,int len){
    int i,j;
    for (i=c,j=0;i<len;i++,j++){
        s2[j]=s1[i];
    }
    s2[j]='\0';
    return 0;
}



int excute_crypto(unsigned char* req,unsigned char*rsp){
	int cmd;
	int ret;
	cmd = req[9];
	printf("%d\n",cmd );
	switch(cmd){
		case AES_GENERATEKEY:
printf("in\n");
		ret = excute_AES_Generate_Key(req,rsp);
		return ret;
		break;
		
	case AES_ENC:
	 	ret = excute_AES_Encrypt(req,rsp);
		return ret;	 	
		break;
	case AES_DEC:
	 	ret = excute_AES_Decrypt(req,rsp);
		return ret;
	 	break;
	case RSA_GET:
	 	ret = excute_RSA_GetpubKey(req,rsp);
		return ret;
	 	break;
	case RSA_ENC:
		ret = excute_RSA_encrypt(req,rsp);
		return ret;
	 	break;
	case RSA_DEC:
		ret = excute_RSA_decrypt(req,rsp);
		return ret;
	 	break;
	default:
		printf("Command Error. \n");
		break;
	}
	
}


int excute_AES_Generate_Key(unsigned char* req,unsigned char*rsp){
	int len;
	int i,j;
	unsigned char key[128];
	len = req[10];
	AES_Generate_Key(len,key);
	len = len/8;
	rsp[5]=len + 10;
	rsp[9]=len;

	for(i=10,j=0;j<len;i++,j++)
        *(rsp + i) = key[j];
	
	for(i = 0; i < len+10; i++)
	printf("%02x ", rsp[i]);
	printf("\n");
                

    return len+10;
}

int excute_AES_Encrypt(unsigned char* req,unsigned char*rsp){
	int keylength;
	int datalength;
	int i,j;
	unsigned char key[128];
	unsigned char iv_enc[128];
	unsigned char data[128];
	unsigned char out[128];
	

	memset(out,0,sizeof(out));
	memset(key,0,sizeof(key));
	keylength = req[10];

	
	for(i=0;i<keylength/8;i++)
		key[i]=req[i+11];
	
	for (i = keylength/8; i < keylength/8+16; ++i)
		iv_enc[i-keylength/8]=req[i+11];
	datalength = req[11+keylength/8+16];
	
	for (i=0;i<datalength;i++)
		data[i]=req[11+keylength/8+16+1+i];

	AES_Encrypt(keylength,key,iv_enc,datalength,data,out);
	const size_t encslength = ((datalength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

	rsp[5]=encslength+10;
	rsp[9]=encslength;

	for(i=10,j=0;j<encslength;i++,j++)

        *(rsp + i) = out[j];
	for(i = 0; i < encslength+10; i++)
		printf("%02x ", rsp[i]);
	printf("\n");


    return encslength+10;
}


int excute_AES_Decrypt(unsigned char* req,unsigned char*rsp){
	int keylength;
	int datalength;
	int i,j;
	unsigned char key[128];
	unsigned char iv_enc[128];
	unsigned char data[128];
	unsigned char out[128];

	memset(out,0,sizeof(out));
	memset(key,0,sizeof(key));
	keylength = req[10];

	for(i=0;i<keylength/8;i++)
		key[i]=req[i+11];
	
	for (i = keylength/8; i < keylength/8+16; ++i)
		iv_enc[i-keylength/8]=req[i+11];
	datalength = req[11+keylength/8+16];

	for (i=0;i<datalength;i++)
		data[i]=req[11+keylength/8+16+1+i];

	AES_Decrypt(keylength,key,iv_enc,datalength,data,out);

	int dec_length = strlen(out);

	rsp[5]=dec_length+10;
	rsp[9]=dec_length;

	for(i=10,j=0;j<dec_length;i++,j++)
        *(rsp + i) = out[j];

	for(i = 0; i < dec_length+10; i++)
		printf("%02x ", rsp[i]);
	printf("\n");

	return dec_length + 10 ;
}

int excute_RSA_GetpubKey(unsigned char* req,unsigned char*rsp){
	int len;
	unsigned char* key;
	len = RSA_GetpubKey(key);
	rsp[5]=len + 10;
	rsp[9]=len;
	
	for(i=10,j=0;j<len;i++,j++)
        *(rsp + i) = key[j];
	
	return len+10;
}

int excute_RSA_encrypt(unsigned char* req,unsigned char*rsp){
	int len,i;
	int datalength;
	unsigned char* data;
	unsigned char* enc_data;

	datalength = req[10];
	for (i=0;i<datalength;i++)
		data[i]=req[11+i];
	
	enc_data=RSA_encrypt(data,"test_pub.key");
	
	len = strlen(enc_data);
	rsp[9] = len;
	rsp[5] = len + 10;
	
	return len + 10;
}


int excute_RSA_decrypt(unsigned char* req,unsigned char*rsp){
	int len,i;
	int datalength;
	unsigned char* data;
	unsigned char* dec_data;

	datalength = req[10];
	for (i=0;i<datalength;i++)
		data[i]=req[11+i];
	
	dec_data=RSA_decrypt(data,"test.key");
	
	len = strlen(dec_data);
	rsp[9] = len;
	rsp[5] = len + 10;
	
	return len + 10;
}



int set_opt(int fd,int nSpeed, int nBits, char nEvent, int nStop)
{
	struct termios newtio,oldtio;
	if  ( tcgetattr( fd,&oldtio)  !=  0) { 
		perror("SetupSerial 1");
//		return -1;
	}
	bzero( &newtio, sizeof( newtio ) );
	newtio.c_cflag  |=  CLOCAL | CREAD;
	newtio.c_cflag &= ~CSIZE;

	switch( nBits )
	{
		case 7:
			newtio.c_cflag |= CS7;
			break;
		case 8:
			newtio.c_cflag |= CS8;
			break;
	}

	switch( nEvent )
	{
	case 'O':
		newtio.c_cflag |= PARENB;
		newtio.c_cflag |= PARODD;
		newtio.c_iflag |= (INPCK | ISTRIP);
		break;
	case 'E': 
		newtio.c_iflag |= (INPCK | ISTRIP);
		newtio.c_cflag |= PARENB;
		newtio.c_cflag &= ~PARODD;
		break;
	case 'N':  
		newtio.c_cflag &= ~PARENB;
		break;
	}

	switch( nSpeed )
	{
		case 2400:
			cfsetispeed(&newtio, B2400);
			cfsetospeed(&newtio, B2400);
			break;
		case 4800:
			cfsetispeed(&newtio, B4800);
			cfsetospeed(&newtio, B4800);
			break;
		case 9600:
			cfsetispeed(&newtio, B9600);
			cfsetospeed(&newtio, B9600);
			break;
		case 115200:
			cfsetispeed(&newtio, B115200);
			cfsetospeed(&newtio, B115200);
			break;
		case 460800:
			cfsetispeed(&newtio, B460800);
			cfsetospeed(&newtio, B460800);
			break;
		default:
			cfsetispeed(&newtio, B9600);
			cfsetospeed(&newtio, B9600);
			break;
	}
	if( nStop == 1 )
		newtio.c_cflag &=  ~CSTOPB;
	else if ( nStop == 2 )
		newtio.c_cflag |=  CSTOPB;
		newtio.c_cc[VTIME]  = 0;
		newtio.c_cc[VMIN] = 0;
		tcflush(fd,TCIFLUSH);
	if((tcsetattr(fd,TCSANOW,&newtio))!=0)
	{
		perror("com set error");
		return -1;
	}
	
	//	printf("set done!\n\r");
	return 0;
}
