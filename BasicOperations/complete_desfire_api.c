#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <nfc/nfc.h>
#include <openssl/des.h>
#include <string.h>
#include <sys/types.h>
#include <endian.h>

#define MAX_FRAME_LEN 264
/*#define DEBUG*/

/*zero key*/
uint8_t defaultkey[8]        = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
uint8_t defaultkey1[8]        = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
/*test challenge*/
uint8_t datatest[8]          = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};

uint8_t session_key[16] ;
uint8_t MAC[4] ;

/*APDU Declaration*/
uint8_t auth_pass1[7]             = {0x90,0x0A,0x00,0x00,0x01,0x00,0x00};
uint8_t auth_pass2[22]            = {0x90,0xAF,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
uint8_t createApplication_apdu[11]= {0x90,0xCA,0x00,0x00,0x05,0x00,0x00,0x00,0x0f,0x0e,0x00};
uint8_t selectApplication_apdu[9] = {0x90,0x5A,0x00,0x00,0x03,0x00,0x00,0x00,0x00};
uint8_t deleteApplication_apdu[9] = {0x90,0xDA,0x00,0x00,0x03,0x00,0x00,0x00,0x00};
uint8_t deleteFile_apdu[7]        = {0x90,0xDF,0x00,0x00,0x01,0x00,0x00};
uint8_t resetTag_apdu[5]          = {0x90,0xFC,0x00,0x00,0x00};
uint8_t listApp_apdu[5]           = {0x90,0x6a,0x00,0x00,0x00};
/*uint8_t createFile_apdu[13]       = {0x90,0xCD,0x00,0x00,0x07,0x00,0x00,0xEE,0xEE,0x00,0x00,0x00,0x00};*/
uint8_t createFile_apdu[13] = {0x90,0xCD,0x00,0x00,0x07,0x00,0x03,0x00,0x00,0x60,0x00,0x00,0x00};
uint8_t listFile_apdu[5]          = {0x90,0x6f,0x00,0x00,0x00};
uint8_t getMoreData_apdu[5]       = {0x90,0xAF,0x00,0x00,0x00};
uint8_t getKeySettings_apdu[5] = {0x90,0x45,0x00,0x00,0x00};
uint8_t changeKeySettings_apdu[5] = {0x90,0x54,0x00,0x00,0x08};
uint8_t changeKey_apdu[5] = {0x90, 0xC4, 0x00,0x00,0x19};
uint8_t readFile1_apdu[5] = {0x90,0xBD,0x00,0x00,0x07};
uint8_t readFile2_apdu[5] = {0x90,0xAF,0x00,0x00,0x00};
uint8_t writeFile1_apdu[4] = {0x90,0x3D,0x00,0x00};
uint8_t writeFile2_apdu[4] = {0x90,0xAF,0x00,0x00};
/*LibNFC global variable*/
nfc_context *context = NULL;    /*context pointer          */
nfc_device  *pnd     = NULL;    /*device pointer           */
uint8_t newkey1[8] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
uint8_t newkey2[8] = {0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

/*desfire command prototypes*/
int selectApplication(unsigned int AID);
int authentification(uint8_t key_index,  uint8_t * key1, uint8_t * key2, uint8_t * challenge);
unsigned short crc16(uint8_t* addr, int count);
void desfire_crc32 (const uint8_t *data, const size_t len, uint16_t *crc);
/************************************************/
/***** TODO add your command prototypes here*****/
/************************************************/

int createApplication(unsigned int AID);
int deleteApplication(unsigned int AID);
int listApplication(unsigned int *outputList, int *outputCount);
int createFile(unsigned int FID, unsigned int Size);
int deleteFile(unsigned int FID);
int listFile(unsigned int *outputList, int *outputCount);
int readFile(unsigned int  FID, uint8_t *buf, int nbyte);
int writeFile(unsigned int  FID, uint8_t *buf, int nbyte);
int writeFile1(unsigned int  FID, uint8_t *buf, int nbyte);
int resetDesfire();
int getkeySettings(uint8_t *keysettings);
int changeKey(uint8_t keyNo);
int changekeySettings(uint8_t settings);
int readFile1(unsigned int  FID, uint8_t *buf, int nbyte);
/*utils command prototypes*/
int sendRequest(uint8_t * abtTx, size_t abtTx_size, uint8_t * abtRx, size_t * abtRx_size,unsigned int * expected_status_word, int expected_data_length);
void onExit          (void);
static void print_hex(const uint8_t *pbtData, const size_t szBytes);
void init            (void);
int  isValidPrim     (uint8_t * noPrim, uint8_t * Prim);
void xor             (uint8_t * input1, uint8_t * input2, uint8_t * output);
void buildPrim       (uint8_t * data);
void encrypt         (uint8_t * input, uint8_t * output, uint8_t *key1, uint8_t *key2);
unsigned short crc_16(unsigned char *data, unsigned int len);
unsigned short update_crc16(unsigned short crc, unsigned char c);
void cypher2MAC(uint8_t *output, uint8_t *input, unsigned int nbrIter);
/**
 * The main method
 *
 * @param argc, the number of element in the array argv
 * @param argv, the list of argument of this program.  The first item is the program name
 * @return EXIT_FAILURE if an error occurs, EXIT_SUCCESS otherwise
 *
 */
int main(int argc, char *argv[])
{
    unsigned int b[256];
    int counter,iterator;

    /*libnfc initialization + tag polling*/
    init();
    if(createApplication(0x0000002)!=0)
	{
		printf("creation failure\n");
	}
    if(listApplication(b, &counter) == 0)
    {
        for(iterator = 0;iterator<counter;iterator++)
        {
            printf("%d : %0.6x\n",(iterator+1), b[iterator]);
        }
    }

    /*example of select application, the following statement select the application 0x00 0x00 0x42 if it exist*/    
    if(selectApplication(0x000042) == 0)/*will print 0x91a0 if the application does not exist, otherwise 0x9100*/
    {printf("select application 0x000042, result: success\n");}
    else
    {printf("select application 0x000042, result: failed\n");}

    /*the following statement select the root application then try to make an authentication on the key zero with the default key*/
    /*if(selectApplication(0x000000) == 0)
    {
        printf("select application 0x000000, result: success\n");
        example of authentication with the default key and with 
        if(authentification(0, defaultkey, defaultkey, datatest) == 0)
        {
            printf("Authentication success\n");
        }
        else
        {
            printf("Authentication failed\n");
        }
    }
  
	
    else
    {printf("select application 0x000000, result: failed\n");}*/

    if(selectApplication(0x000002) == 0)
	{
		printf("select application 0x000002, result: success\n");
		deleteFile(7);
		deleteFile(8);
		createFile(7,0x60);
		createFile(8,0x60);
		/*if(getkeySettings()!=0)
			{
				printf("getSettings Failure\n");
			}*/
		/*if(changeKey(0x00) == 0) {
		printf("change key 0x00 success \n");
	} */
	/*if(changeKey(0x04) == 0) {
		printf("change key 0x00 success \n");
	} */

	/*if(changekeySettings(0xEF)==0)
	{
		printf("change success\n");
		uint8_t keysettings;
		if(getkeySettings(&keysettings)==0)
			{
				printf("getSettings success %02x\n",(keysettings >> 4));
			}
	}*/
	/*if(createFile(5, 0x60) == 0)
	{
		printf("create file success\n");*/
		uint8_t buf[39] = {0x68,0x74,0x74,0x70, 0x73, 0x3a, 0x2f, 0x2f ,0x6d, 0x61 , 0x69, 0x6c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e , 0x63, 0x6f, 0x6d ,0x2f ,0x6d ,0x61 ,0x69 ,0x6c ,0x2f ,0x75 ,0x2f ,0x30 ,0x2f ,0x23 ,0x69 ,0x6e ,0x62 ,0x6f ,0x78};
  		/*if(writeFile(3, buf,39) != 0)
			{
				printf("write Failure\n");
        			return EXIT_FAILURE;
			}*/
	uint8_t buf2[60] = {0x68,0x74,0x74,0x70, 0x73, 0x3a, 0x2f, 0x2f ,0x6d, 0x61 , 0x69, 0x6c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e , 0x63, 0x6f, 0x6d ,0x2f ,0x6d ,0x61 ,0x69 ,0x6c ,0x2f ,0x75 ,0x2f ,0x30 ,0x2f ,0x23 ,0x69 ,0x6e ,0x62 ,0x6f ,0x78,0x65, 0x2e , 0x63, 0x6f, 0x6d ,0x2f ,0x6d ,0x61 ,0x69 ,0x6c ,0x2f ,0x75 ,0x2f ,0x30 ,0x2f ,0x23 ,0x69 ,0x6e ,0x62 ,0x6f ,0x78};
	uint8_t buf1[59];
	if(authentification(0, newkey1, newkey2, datatest) == 0)
        {
	if(writeFile1(7, buf2,60) != 0)
	{
		printf("Failure\n");
        	return EXIT_FAILURE;
	}
	if(writeFile1(8, buf2,60) != 0)
	{
		printf("Failure\n");
        	return EXIT_FAILURE;
	}
	/*if(writeFile(3, buf,39) != 0)
	{
		printf("Failure\n");
        	return EXIT_FAILURE;
	}*/

	/*if(readFile(3, buf1,43) != 0)
	{
	printf("Failure\n");
        return EXIT_FAILURE;
	}
	printf("\n");*/
	if(readFile1(7, buf1, 64) != 0)
	{
	printf("Failure\n");
        return EXIT_FAILURE;
	}
	printf("\n");
	if(readFile1(8, buf1, 60) != 0)
	{
	printf("Failure\n");
        return EXIT_FAILURE;
	}
	printf("\n");
	}
	/*printf("*****authentication\n");
	if(authentification(0, newkey1, newkey2, datatest) == 0)
        {
	printf("*****write to 05\n");
	if(writeFile1(5, buf2,60) != 0)
	{
		printf("Failure\n");
        	return EXIT_FAILURE;
	}
	if(readFile1(5, buf1, 64) != 0)
	{
	printf("*****read from 05\n");
	printf("Failure\n");
        return EXIT_FAILURE;
	}
}*/
/*}
}*/
}
	else
    {printf("select application 0x000002, result: failed\n");}
    
    /***************************************/
    /***** TODO add your commands here *****/
    /***************************************/

    return EXIT_SUCCESS;
}
/*secure write data*/
int writeFile1(unsigned int  FID, uint8_t *buf1, int nbyte)
{
    uint8_t abtRx[MAX_FRAME_LEN];
    uint8_t abtTx[MAX_FRAME_LEN];
    size_t abtTx_size;
    abtTx_size =4;
    unsigned int off;
    memcpy(abtTx,writeFile1_apdu,abtTx_size);
    abtTx[5] = FID;
    abtTx[6] = 0x00;
    abtTx[7] = 0x00;
    abtTx[8] = 0x00;
    unsigned int padding = 0;
    if((nbyte + 2) %8 !=0){ padding = ((((nbyte +2)/8) + 1)*8) - (nbyte+2);}
    uint8_t buf[nbyte+padding+2];
    memcpy(buf, buf1, nbyte);
    unsigned short crc = crc_16(buf, nbyte);
    buf[nbyte] = ( uint8_t) crc;
    buf[nbyte+1] = ( uint8_t) (crc >> 8);
    memset(buf+nbyte+2, 0, padding);
    print_hex(buf, nbyte+padding+2);

    
    abtTx[11] = (nbyte >> 16) & 0xff; 
    abtTx[10] = (nbyte >> 8) & 0xff;
    abtTx[9] = (nbyte) & 0xff;
    unsigned int i = 0, j=0;
    unsigned int response_size = 0;
    int status_word_O = 0;
    int result ;
    
    uint8_t ciphered[nbyte+padding+2];   
    /*if(authentification(0, newkey1, newkey2, datatest) == 0)
        {*/
    cypher2(ciphered, buf, (nbyte + padding +2)/8);
	print_hex(ciphered,nbyte+padding+2);
	/*}*/
    nbyte += (padding+2);
    for(i=0; i < nbyte && i < 52; i ++)
	{
	  abtTx[12+i] =ciphered[i]; 
	}	
    abtTx[12+i] = 0x00;
    abtTx[4] = 7+i;
    abtTx_size = 12+i+1;
    result = sendRequest(abtTx, abtTx_size, abtRx,&response_size,&status_word_O,0);
    if(nbyte > 52){
	nbyte = nbyte - 52;
	off = 52;
   }
    while(result == 0 && status_word_O==0x91AF)
	{
		abtTx_size = 4;
		memcpy(abtTx,writeFile2_apdu,abtTx_size);
		for(i=0; i < nbyte && i < 0x3B; i ++)
		{
	 		 abtTx[5+i] =ciphered[i+off]; 
		}	
		abtTx[5+i] = 0x00;
		abtTx[4] = i;
         	abtTx_size = 5+i+1;
	  	result = sendRequest(abtTx, abtTx_size, abtRx,&response_size,&status_word_O,0);

		if(nbyte > 0x3B) {
			nbyte = nbyte -59;
			off += 59;
		}
	}

    if(result == 0 &&  status_word_O == 0x9100)
	{
		return 0;	
	}
    return -1;
}
/*normal read file */
int readFile(unsigned int  FID, uint8_t *buf, int nbyte)/**/
{
    unsigned int outputList [16];
    unsigned int outputCount = 0;
    unsigned int i = 0;
   
   uint8_t abtRx[MAX_FRAME_LEN];
   uint8_t abtTx[MAX_FRAME_LEN];
   uint8_t response[MAX_FRAME_LEN];
   size_t abtTx_size;
   abtTx_size =5;
   memcpy(abtTx,readFile1_apdu,abtTx_size);
   abtTx[5] = FID;
   abtTx[6] = 0x00;
   abtTx[7] = 0x00;
   abtTx[8] = 0x00;
   abtTx[11] = (nbyte >> 16) & 0xff; 
   abtTx[10] = (nbyte >> 8) & 0xff;
   abtTx[9] = nbyte & 0xff;
   abtTx[12] = 0x00;	
   abtTx_size = 13;
   unsigned int response_size = 0;
   int status_word_O = 0;
   unsigned int index = 0;
   int result = sendRequest(abtTx, abtTx_size, abtRx,&response_size,&status_word_O,0);
   /*buf = malloc ( response_size);*/
   if( result == 0 && status_word_O == 0x9100)
	{
		
		memcpy(buf,abtRx,response_size);
		/*for(i= 0; i< response_size; i++)
		{
			printf("%c", buf[i]);
		}*/
		
	}

  while( result == 0 && status_word_O == 0x91AF)
	{
		memcpy(buf,abtRx,response_size);
		memcpy(response + index, abtRx,response_size);
		index += response_size;
		abtTx_size =5;
   		memcpy(abtTx,readFile2_apdu,abtTx_size);
		result = sendRequest(abtTx, abtTx_size, abtRx,&response_size,&status_word_O,0);
		/*for(i= 0; i< 59; i++)
		{
			printf("%c", buf[i]);
		}*/
		
	}
	
	if(result == 0 && status_word_O == 0x9100){
		memcpy(response + index, abtRx,response_size);
		index +=response_size;
		
		for(i= 0; i< index; i++)
		{
			printf("%02x", response[i]);
		}
		return 0;
	}
	
    return -1;
}
/*secure lecture data */
int readFile1(unsigned int  FID, uint8_t *buf, int nbyte)/**/
{
    unsigned int outputList [16];
    unsigned int outputCount = 0;
    unsigned int i = 0;
   
   uint8_t abtRx[MAX_FRAME_LEN];
   uint8_t abtTx[MAX_FRAME_LEN];
   uint8_t response[MAX_FRAME_LEN];
   size_t abtTx_size;
   abtTx_size =5;
   memcpy(abtTx,readFile1_apdu,abtTx_size);
   abtTx[5] = FID;
   abtTx[6] = 0x00;
   abtTx[7] = 0x00;
   abtTx[8] = 0x00;
   abtTx[11] = (nbyte >> 16) & 0xff; 
   abtTx[10] = (nbyte >> 8) & 0xff;
   abtTx[9] = nbyte & 0xff;
   abtTx[12] = 0x00;	
   abtTx_size = 13;
   unsigned int response_size = 0;
   int status_word_O = 0;
   unsigned int index = 0;
   int result = sendRequest(abtTx, abtTx_size, abtRx,&response_size,&status_word_O,0);
   /*buf = malloc ( response_size);*/
   if( result == 0 && status_word_O == 0x9100)
	{
		
		memcpy(buf,abtRx,response_size);
		/*for(i= 0; i< response_size; i++)
		{
			printf("%c", buf[i]);
		}*/
		
	}

  while( result == 0 && status_word_O == 0x91AF)
	{
		memcpy(buf,abtRx,response_size);
		memcpy(response + index, abtRx,response_size);
		index += response_size;
		abtTx_size =5;
   		memcpy(abtTx,readFile2_apdu,abtTx_size);
		result = sendRequest(abtTx, abtTx_size, abtRx,&response_size,&status_word_O,0);
		/*for(i= 0; i< 59; i++)
		{
			printf("%c", buf[i]);
		}*/
		
	}
	
	if(result == 0 && status_word_O == 0x9100){
		memcpy(response + index, abtRx,response_size);
		index +=response_size;
		printf ("index %u\n",index);
		for(i= 0; i< index; i++)
		{
			printf("%02x", response[i]);
		}
		cypher3(abtRx,response,index/8);
		print_hex(abtRx,index);
		return 0;
	}
	
    return -1;
}
void cypher3(uint8_t *output, uint8_t *input, unsigned int nbrIter)
{
	uint8_t k1[8];
	uint8_t k2[8];
	memcpy(k1, session_key, 8);
	memcpy(k2, session_key+8,8);
	print_hex(session_key,16);
	
	
	uint8_t output1[8];
	uint8_t input1[8];
	memcpy(input1, input,8);	
	encrypt(input1, output1, k1, k2);
	memcpy(output, output1, 8);
	unsigned int i;
	for(i=0; i < nbrIter -1; i++)
	{
		encrypt(input+(8 * (i+1)), output1, k1, k2);
		xor(input+(8 * i), output1, input1);
		memcpy(output+(8 * (i+1)) , input1, 8);	
	}
}
/*mac write data */
int writeFile(unsigned int  FID, uint8_t *buf, int nbyte)
{
    uint8_t abtRx[MAX_FRAME_LEN];
    uint8_t abtTx[MAX_FRAME_LEN];
    size_t abtTx_size;
    abtTx_size =4;
    unsigned int off;
    memcpy(abtTx,writeFile1_apdu,abtTx_size);
    abtTx[5] = FID;
    abtTx[6] = 0x00;
    abtTx[7] = 0x00;
    abtTx[8] = 0x00;
    abtTx[11] = (nbyte >> 16) & 0xff; 
    abtTx[10] = (nbyte >> 8) & 0xff;
    abtTx[9] = (nbyte) & 0xff;
    unsigned int i = 0, j=0;
    unsigned int response_size = 0;
    int status_word_O = 0;
    int result ;
    uint8_t input[MAX_FRAME_LEN];
    memcpy(input, buf, nbyte);
    for(i=0; i < nbyte && i < 52; i ++)
	{
	  abtTx[12+i] =buf[i]; 
	}
    unsigned int padding = 0;
    unsigned int nbrIter = 0;
    if(nbyte %8 !=0)
	{
		padding = ((nbyte/8)+1)*8- nbyte;
		memset(input+nbyte,0, padding);
		nbrIter = (nbyte/8)+1;
	}
    else if(nbyte%8==0){nbrIter = (i/8); }
    if(authentification(0, newkey1, newkey2, datatest) == 0)
        {
            printf("Authentication success\n");
	    cypher2MAC(abtRx,input,nbrIter);
	    if(nbyte > 52 || i + 4 > 52){	    
	    abtTx[12+i] = 0x00;
	    abtTx[4] = 7+i;
	    abtTx_size = 12+i+1;
	    int result = sendRequest(abtTx, abtTx_size, abtRx, &response_size, &status_word_O,0) ;    
	    if(nbyte > 52){
	    nbyte = nbyte - 52;
            off = 52;}
  	   }
	   else if(i + 4 <= 52)
		{
			memcpy(abtTx+12+i, MAC, 4);
			abtTx[12+i+4] = 0x00;
	    		abtTx[4] = 7+i+4;
	    		abtTx_size = 12+i+1+4;
	    		result = sendRequest(abtTx, abtTx_size, abtRx, &response_size, &status_word_O,0) ; 
		}

	while(result == 0 && status_word_O==0x91AF)
	{
		abtTx_size = 4;
		memcpy(abtTx,writeFile2_apdu,abtTx_size);
		for(i=0; i < nbyte && i < 59; i ++)
		{
			abtTx[5+i] = buf[i+off];
	 	
		}
		
		if(nbyte > 59 || i +4 > 59)
		{
			abtTx[5+i] = 0x00;
			abtTx[4] = i;
         		abtTx_size = 5+i+1;
	  		result = sendRequest(abtTx, abtTx_size, abtRx,&response_size,&status_word_O,0);	
			nbyte = nbyte -59;
			off += 59;
		}
		else if(i +4 <= 59)
		{
			memcpy(abtTx+5+i, MAC, 4);
			abtTx[5+i+4] = 0x00;
			abtTx[4] = i+4;
         		abtTx_size = 5+i+1+4;
	  		result = sendRequest(abtTx, abtTx_size, abtRx,&response_size,&status_word_O,0);	
		}
			
		
	}

    	if(result == 0 &&  status_word_O == 0x9100)
		{
			return 0;	
		}
	    
        }
	
    return -1;
}

int changekeySettings(uint8_t settings)

{

	uint8_t abtRx[MAX_FRAME_LEN]; /*output buffer         */
 	uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    	size_t abtTx_size;
    	abtTx_size = 5;
    	size_t abtRx_size;
    	unsigned int status_word;
    	memcpy(abtTx,changeKeySettings_apdu,abtTx_size);
	uint8_t new_key_settings[8];
	new_key_settings[0] = settings;
	unsigned short crc;
	crc = crc_16(new_key_settings,1);
	new_key_settings[1] = (uint8_t) crc;
	new_key_settings[2] =  (uint8_t)(crc >> 8) ;
	new_key_settings[3] = 0x00;
	new_key_settings[4] = 0x00;
	new_key_settings[5] = 0x00;
	new_key_settings[6] = 0x00;
	new_key_settings[7] = 0x00;
	print_hex(new_key_settings,8);
	if(authentification(0, newkey1, newkey2, datatest) == 0)
        {
            printf("Authentication success\n");
	    cypher(abtTx+5,new_key_settings);
	    abtTx[13] = 0x00;
	    abtTx_size = 14;
	    int rslt = sendRequest(abtTx, abtTx_size, abtRx, &abtRx_size, &status_word,0) ;
	    if(rslt!= 0 || status_word != 0x9100) {return -1;}
	    
        }
        else
        {
            printf("Authentication failed\n");
        }

return 0;

}
int changeKey(uint8_t keyNo)
{
 	uint8_t abtRx[MAX_FRAME_LEN]; /*output buffer         */
    	uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    	size_t abtTx_size;
    	abtTx_size = 5;
    	size_t abtRx_size;
    	unsigned int status_word;
    	memcpy(abtTx,changeKey_apdu,abtTx_size);
	abtTx[5] = keyNo;
	uint8_t keysettings;
	uint8_t changekey;

	uint8_t cmd_data [24];
	unsigned short crc;
	unsigned short crc_new_key;
		
		if(getkeySettings(&keysettings) !=0)
		{
			printf("getKeySettings Failure !\n");
		}
		else
		{
			changekey = (keysettings >> 4);
			printf(" the change key is  %02x\n", changekey);
			if(changekey == 0x0E || changekey == keyNo || keyNo == 0x00)
			{
				/*authentifier avec le numero de clef keyNo --> procedure 2 de changeKey cmd*/
				if(authentification(keyNo, defaultkey, defaultkey1, datatest) == 0)
				{
					memcpy(cmd_data, newkey1,8); /*je dois faire un xor avant et calculer le crc sur new_key seulement, mais ca revient au meme pour ce test car defaultkey =0*/
					memcpy(cmd_data+8,newkey2,8);
					crc = crc_16(cmd_data, 16);
					cmd_data[16] = (uint8_t) crc;
					cmd_data[17] = (uint8_t) (crc >> 8);
					uint8_t init[6] = {0x00,0x00,0x00,0x00,0x00,0x00};	
					memcpy(cmd_data+18, init, 6);
					print_hex(cmd_data,24);
					cypher(abtTx+6,cmd_data);	
				}

					
			}
			else if(changekey == 0x0F)
			{
				printf("change basic key is not allowed\n");
				return -1;
			}

			else 
			{
			   
				/*authentifier avec la changeKey --> procedure 1 de changekey cmd*/
				if(authentification(changekey, newkey1, newkey2,datatest)==0)
				{
					xor(defaultkey, newkey1, cmd_data);
					xor(defaultkey, newkey2, cmd_data+8);
					crc = crc_16(cmd_data, 16);
					cmd_data[16] = (uint8_t) crc ;
					cmd_data[17 ]  =  (uint8_t) (crc >> 8);
					/* dans ces deux octets il faut mettre le crc de la new key */
					cmd_data[18] = (uint8_t) crc;
					cmd_data[19] = (uint8_t) (crc >> 8);
					uint8_t init[4] = {0x00,0x00,0x00,0x00};	
					memcpy(cmd_data+20, init, 4);
					cypher(abtTx+6,cmd_data);
				}
			
			}
		}
	abtTx[30]= 0x00;
	abtTx_size = 31;
	if(sendRequest(abtTx, abtTx_size, abtRx, &abtRx_size, &status_word,0) != 0 || status_word != 0x9100) {return -1;}
	if(authentification(keyNo, newkey1, newkey2, datatest) == 0)
        			{
            				printf("Authentication success\n");
        			}
        	else
        			{
            				printf("Authentication failed\n");
        			}
			
	
}

void cypher(uint8_t *output, uint8_t *input)
{
	uint8_t k1[8];
	uint8_t k2[8];
	memcpy(k1, session_key, 8);
	memcpy(k2, session_key+8,8);
	print_hex(session_key,16);
	uint8_t output1[8];
	uint8_t input1[8];
	memcpy(input1, input,8);
	print_hex(input1,8);
	encrypt(input1, output1, k1, k2);
	print_hex(output1,8);
	memcpy(output, output1, 8);
	xor(output1, input+8, input1);
	encrypt(input1, output1, k1, k2);
	memcpy(output+8 , output1, 8);	
	xor(output1, input+16, input1);
	encrypt(input1, output1, k1, k2);
	memcpy(output+16 , output1, 8);
}

void cypher2MAC(uint8_t *output, uint8_t *input, unsigned int nbrIter)
{
	uint8_t k1[8];
	uint8_t k2[8];
	memcpy(k1, session_key, 8);
	memcpy(k2, session_key+8,8);
	print_hex(session_key,16);
	DES_key_schedule ks1, ks2;
    
    	DES_set_key_unchecked((DES_cblock*)k1,&ks1);
    	DES_set_key_unchecked((DES_cblock*)k2,&ks2);
	uint8_t output1[8];
	uint8_t input1[8];
	memcpy(input1, input,8);	
	DES_ecb2_encrypt((DES_cblock*)input1, (DES_cblock*)output1,&ks1,&ks2, DES_ENCRYPT);	
	memcpy(output, output1, 8);
	unsigned int i;
	for(i=0; i < nbrIter -1; i++)
	{
		xor(output1, input+(8 * (i+1)), input1);
		/*encrypt(input1, output1, k1, k2);*/
		DES_ecb2_encrypt((DES_cblock*)input1, (DES_cblock*)output1,&ks1,&ks2, DES_ENCRYPT);
		memcpy(output+(8 * (i+1)) , output1, 8);	
	}
	memcpy(MAC, output1, 4);
	printf("****MAC\n");
	print_hex(MAC,4);
}

void cypher2(uint8_t *output, uint8_t *input, unsigned int nbrIter)
{
	uint8_t k1[8];
	uint8_t k2[8];
	memcpy(k1, session_key, 8);
	memcpy(k2, session_key+8,8);
	print_hex(session_key,16);
	uint8_t output1[8];
	uint8_t input1[8];
	memcpy(input1, input,8);
	print_hex(input1,8);
	encrypt(input1, output1, k1, k2);
	memcpy(output , output1, 8);
	unsigned int i;
	for(i=0; i < nbrIter -1; i++)
	{
		xor(output1, input+(8 * (i+1)), input1);
		encrypt(input1, output1, k1, k2);
		memcpy(output+(8 * (i+1)) , output1, 8);	
	}
	
}
unsigned short crc_16(unsigned char *data, unsigned int len)
{
        unsigned int i;
        unsigned short crc= 0x6363;

        for(i= 0; i < len ; ++i)
                crc=  update_crc16(crc, data[i]);
        return crc;
}

unsigned short update_crc16(unsigned short crc, unsigned char c)   
{
        unsigned short i, v, tcrc = 0;

        v = (crc ^ c) & 0xff;
        for (i = 0; i < 8; i++) 
                {
                tcrc = ( (tcrc ^ v) & 1 ) ? ( tcrc >> 1 ) ^ 0x8408 : tcrc >> 1;
                v >>= 1;
                }
        return ((crc >> 8) ^ tcrc) & 0xffff;
}

int getkeySettings(uint8_t *keysettings)
{
    uint8_t abtRx[MAX_FRAME_LEN]; /*output buffer         */
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size;
    abtTx_size = 5;
    size_t abtRx_size;
    unsigned int status_word;
    memcpy(abtTx,getKeySettings_apdu,abtTx_size);
    if(sendRequest(abtTx, abtTx_size, abtRx, &abtRx_size, &status_word,0) != 0) {return -1;}
    print_hex(abtRx,abtRx_size);
    *keysettings = abtRx[0];
    return 0;
}

/**************************************/
/***** TODO add your commands here*****/
/**************************************/

/**
 * this function create a new application
 *
 * @param AID, the application identifier to create, it must be a value between 0x000001 and 0xffffff
 * @return the status word, or -1 if an error has occured
 */
int createApplication(unsigned int AID)
{
    uint8_t abtRx[MAX_FRAME_LEN]; /*output buffer         */
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size,abtRx_size;
    unsigned int status_word;
    
    /*check the AID*/
    if(AID > 0xffffff || AID < 0x000001)
    {
        fprintf(stderr, "Invalid AID, expected a value between 0x000001 and 0xffffff, got 0x%06x\n",AID);
        return -1;
    }
    
    /*prepare the data*/
    abtTx_size = 11;
    memcpy(abtTx,createApplication_apdu,abtTx_size);
    abtTx[7] = (AID >> 16) & 0xff; /*data 0*/
    abtTx[6] = (AID >> 8 ) & 0xff; /*data 1*/
    abtTx[5] = AID & 0xff;         /*data 2*/
    
    #ifdef DEBUG
    /*debug message*/
    printf("Create Application 0x%06x\n",AID);
    #endif
    
    /*send the data to the card, the expected status word is 0x91 0x00*/
    if(sendRequest(abtTx, abtTx_size, abtRx, &abtRx_size, &status_word, 0) != 0) {return -1;}
    
    if(status_word != 0x9100)
    {
        fprintf(stderr, "Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
        return -1;
    }
    
    return 0;
}

/**
 * this func
tion deletes an application
 *
 * @param AID, the application identifier to delete, it must be a value between 0x000001 and 0xffffff
 * @return the status word, or -1 if an error has occured
 */
int deleteApplication(unsigned int AID)
{
    uint8_t abtRx[MAX_FRAME_LEN]; /*output buffer         */
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size, abtRx_size;
    unsigned int status_word;
    
    /*check the AID*/
    if(AID > 0xffffff || AID < 0x000001)
    {
        fprintf(stderr, "Invalid AID, expected a value between 0x000001 and 0xffffff, got 0x%06x\n",AID);
        return -1;
    }
    
    /*prepare the data*/
    abtTx_size = 11;
    memcpy(abtTx,deleteApplication_apdu,abtTx_size);
    abtTx[7] = (AID >> 16) & 0xff; /*data 0*/
    abtTx[6] = (AID >> 8 ) & 0xff; /*data 1*/
    abtTx[5] = AID & 0xff;         /*data 2*/
    
    #ifdef DEBUG
    /*debug message*/
    printf("Delete Application 0x%06x\n",AID);
    #endif
    
    /*send the data to the card, the expected status word is 0x91 0x00*/
    if(sendRequest(abtTx, abtTx_size, abtRx, &abtRx_size, &status_word, 0) != 0) {return -1;}
    
    if(status_word != 0x9100)
    {
        fprintf(stderr, "Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
        return -1;
    }
    
    return 0;
}

/**
 * this function lists all the applications
 *
 * @param outputList, a pointer to a list of integer to fill, the list must have at least 28 element
 * @parem outputCount, a pointer to an integer, this integer will contain the number of application
 * @return the status word, or -1 if an error has occured
 */
int listApplication(unsigned int *outputList, int *outputCount)
{
    uint8_t abtRx[MAX_FRAME_LEN]; /*output buffer         */
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size,abtRx_size;
    unsigned int status_word;
    int iterator;
    
    /*prepare the data*/
    abtTx_size = 5;
    memcpy(abtTx,listApp_apdu,abtTx_size);

    #ifdef DEBUG
    /*debug message*/
    printf("Delete Application 0x%06x\n (pass 1)",AID);
    #endif
    
    *outputCount = 0;
    status_word = 0x91AF;
    while(status_word == 0x91AF)
    {
        if(sendRequest(abtTx, abtTx_size, abtRx,&abtRx_size, &status_word, 0) != 0) {return -1;}
        memcpy(abtTx,getMoreData_apdu,abtTx_size);
        if(status_word != 0x9100 && status_word != 0x91AF)
        {
            fprintf(stderr, "Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
            return -1;
        }        
        
        if(abtRx_size%3)
        {
            fprintf(stderr, "Invalid rx size, expected a multiple of 3, got %u\n",abtRx_size);
            return -1;
        }
        
        for(iterator = 0; iterator+2 < abtRx_size; iterator += 3, *outputCount +=1)
        {
            outputList[*outputCount] = ((abtRx[iterator+2]&0xff) << 16) + ((abtRx[iterator+1]&0xff) << 8) + (abtRx[iterator]&0xff);
        }
    }
    
    return 0;
}

/**
 * this function creates a new file
 *
 * @param FID, the file identifier to create, it must be a value between 0x00 and 0xff
 * @return the status word, or -1 if an error has occured
 */
int createFile(unsigned int FID, unsigned int Size)
{
    uint8_t abtRx[MAX_FRAME_LEN]; /*output buffer         */
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size,abtRx_size;
    unsigned int status_word;
    
    /*check the AID*/
    if(FID > 0xff )/*|| FID < 0x00) the integer is unsigned, its value can not be below 0*/
    {
        fprintf(stderr, "Invalid FID, expected a value between 0x00 and 0xff, got 0x%02x\n",FID);
        return -1;
    }
    
    /*check the size*/
    if(FID > 0xffffff || FID < 0x01 )/*|| FID < 0x00) the integer is unsigned, its value can not be below 0*/
    {
        fprintf(stderr, "Invalid size, expected a value between 0x000001 and 0xffffff, got 0x%06x\n",FID);
        return -1;
    }
    
    /*prepare the data*/
    abtTx_size = 13;
    memcpy(abtTx,createFile_apdu,abtTx_size);
    
    abtTx[5] = FID & 0xff;         /*file descriptor*/
    
    abtTx[11] = (Size >> 16) & 0xff; /*data 0*/
    abtTx[10] = (Size >> 8 ) & 0xff; /*data 1*/
    abtTx[9] = Size & 0xff;         /*data 2*/
    
    #ifdef DEBUG
    /*debug message*/
    printf("Create File 0x%02x\n",FID);
    #endif
    
    /*send the data to the card, the expected status word is 0x91 0x00*/
    if(sendRequest(abtTx, abtTx_size, abtRx,&abtRx_size, &status_word, 0) != 0) {return -1;}
    
    if(status_word != 0x9100)
    {
        fprintf(stderr, "Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
        return -1;
    }
    
    return 0;
}

/**
 * this function deletes an file
 *
 * @param FID, the file identifier to delete, it must be a value between 0x00 and 0xff
 * @return the status word, or -1 if an error has occured
 */
int deleteFile(unsigned int FID)
{
    uint8_t abtRx[MAX_FRAME_LEN]; /*output buffer         */
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size,abtRx_size;
    unsigned int status_word;
    
    /*check the AID*/
    if(FID > 0xff )/*|| FID < 0x00) the integer is unsigned, its value can not be below 0*/
    {
        fprintf(stderr, "Invalid FID, expected a value between 0x00 and 0xff, got 0x%06x\n",FID);
        return -1;
    }
    
    /*prepare the data*/
    abtTx_size = 7;
    memcpy(abtTx,deleteFile_apdu,abtTx_size);
    abtTx[5] = FID & 0xff;         /*file descriptor*/
    
    #ifdef DEBUG
    /*debug message*/
    printf("Delete File 0x%02x\n",FID);
    #endif
    
    /*send the data to the card, the expected status word is 0x91 0x00*/
    if(sendRequest(abtTx, abtTx_size, abtRx,&abtRx_size, &status_word, 0) != 0) {return -1;}
    
    if(status_word != 0x9100)
    {
        fprintf(stderr, "Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
        return -1;
    }
    
    return 0;
}

/**
 * this function lists all the files
 *
 * @param outputList, a pointer to a list of integer to fill, the list must have at least 16 element
 * @parem outputCount, a pointer to an integer, this integer will contain the number of file
 * @return the status word, or -1 if an error has occured
 */
int listFile(unsigned int *outputList, int *outputCount)
{
    uint8_t abtRx[MAX_FRAME_LEN]; /*output buffer         */
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size,abtRx_size;
    unsigned int status_word;
    int iterator;
    
    *outputCount = 0;
    
    /*prepare the data*/
    abtTx_size = 5;
    memcpy(abtTx,listFile_apdu,abtTx_size);
    
    #ifdef DEBUG
    /*debug message*/
    printf("List Files 0x%06x\n",AID);
    #endif
    
    /*send the data to the card, the expected status word is 0x91 0x00 or 0x91 AF*/
    *outputCount = 0;
    if(sendRequest(abtTx, abtTx_size, abtRx,&abtRx_size, &status_word, 0) != 0) {return -1;}
    
    if(status_word != 0x9100)
    {
        fprintf(stderr, "Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
        return -1;
    }
    
    for(iterator = 0; iterator < abtRx_size; iterator += 1, *outputCount +=1)
    {
        outputList[*outputCount] = (abtRx[iterator]&0xff);
    }

    return 0;
}

/**
 * this function read a file
 *
 * @param FID, the file identifier to read, it must be a value between 0x00 and 0xff
 * @param buf,a list to store the data read 
 * @param nbyte,the number of bytes to read
 * @return the status word, or -1 if an error has occured
 */
/*int readFile(unsigned int  FID, uint8_t *buf, int nbyte) 
{
    uint8_t abtRx[MAX_FRAME_LEN];output buffer         
    uint8_t abtTx[MAX_FRAME_LEN];           */
    /*size_t abtTx_size,abtRx_size;
    unsigned int status_word;
    int iterator;
    
    /*prepare the data*/
    /*abtTx_size = 13;
    memcpy(abtTx,readData_apdu,abtTx_size);

    abtTx[5] = FID&0xFF;
    
    abtTx[6] = FID&0xFF; /*TODO*/
    /*abtTx[7] = FID&0xFF;
    abtTx[8] = FID&0xFF;

    abtTx[9]  = FID&0xFF;/*TODO*/
    /*abtTx[10] = FID&0xFF;
    abtTx[11] = FID&0xFF;

    #ifdef DEBUG
    /*debug message*/
    /*printf("Delete Application 0x%06x\n (pass 1)",AID);
    #endif
    
    *outputCount = 0;
    status_word = 0x91AF;
    while(status_word == 0x91AF)
    {
        if(sendRequest(abtTx, abtTx_size, abtRx,&abtRx_size, &status_word, 0) != 0) {return -1;}
        memcpy(abtTx,getMoreData_apdu,abtTx_size);
        if(status_word != 0x9100 && status_word != 0x91AF)
        {
            fprintf(stderr, "Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
            return -1;
        }        
        
        if(abtRx_size%3)
        {
            fprintf(stderr, "Invalid rx size, expected a multiple of 3, got %u\n",abtRx_size);
            return -1;
        }
        
        for(iterator = 0; iterator+2 < abtRx_size; iterator += 3, *outputCount +=1)
        {
            outputList[*outputCount] = ((abtRx[iterator+2]&0xff) << 16) + ((abtRx[iterator+1]&0xff) << 8) + (abtRx[iterator]&0xff);
        }
    }
    
    return 0;
}*/

/**
 * this function write a file
 *
 * @param FID, the file identifier to read, it must be a value between 0x00 and 0xff
 * @param buf,a list of bytes to write
 * @param nbyte,the number of bytes to write
 * @return the status word, or -1 if an error has occured
 */
/*int writeFile(unsigned int  FID, uint8_t *buf, int nbyte)
{
    
    return 0;
}*/

/**
 * this function reset a desfire tag
 *
 * @return the status word, or -1 if an error has occured
 */
int resetDesfire()
{
    uint8_t abtRx[MAX_FRAME_LEN]; /*output buffer         */
    /*uint8_t abtTx[MAX_FRAME_LEN]; input buffer          */
    size_t abtTx_size,abtRx_size;
    unsigned int status_word;
    
    /*prepare the data*/
    abtTx_size = 5;
    /*memcpy(abtTx,resetTag_apdu,abtTx_size);*/

    #ifdef DEBUG
    /*debug message*/
    printf("Reset tag\n");
    #endif
    
    /*send the data to the card, the expected status word is 0x91 0x00*/
    if(sendRequest(resetTag_apdu, abtTx_size, abtRx,&abtRx_size, &status_word, 0) != 0) {return -1;}
    
    if(status_word != 0x9100)
    {
        fprintf(stderr, "Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
        return -1;
    }
    
    return 0;
}

/**
 * This method selects an application and returns the status word of the operation
 * Exit is called if there is an error with libnfc
 *
 * @param AID, the application identifier to select, it must be a value between 0x000000 and 0xffffff
 * @return the status word, or -1 if there is not enought data to build the status word
 */
int selectApplication(unsigned int AID)
{
    uint8_t abtRx[MAX_FRAME_LEN]; /*output buffer         */
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size,abtRx_size;
    unsigned int status_word;
    
    /*check the AID*/
    if(AID > 0xffffff)
    {
        fprintf(stderr, "Invalid AID, expected a value between 0x000000 and 0xffffff, got 0x%06x\n",AID);
        return -1;
    }
    
    /*prepare the data*/
    abtTx_size = 9;
    memcpy(abtTx,selectApplication_apdu,abtTx_size);
    abtTx[7] = (AID >> 16) & 0xff; /*data 0*/
    abtTx[6] = (AID >> 8 ) & 0xff; /*data 1*/
    abtTx[5] = AID & 0xff;         /*data 2*/
    
    #ifdef DEBUG
    /*debug message*/
    printf("Select Application 0x%06x\n",AID);
    #endif
    
    /*send the data to the card, the expected status word is 0x91 0x00*/
    if(sendRequest(abtTx, abtTx_size, abtRx,&abtRx_size, &status_word, 0) != 0) {return -1;}
    
    if(status_word != 0x9100)
    {
        fprintf(stderr, "Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
        return -1;
    }
    
    return 0;
}

/**
 * this function makes an authentication with the desfire tag
 *
 * @param key_index, the key index on which the authentication must occur
 * @param key1, the first 8-bytes of the 16-bytes key
 * @param key2, the second 8-bytes of the 16-bytes key, if the key has 8-bytes, the key2 must be the same as key1
 * @param challenge, a 8-bytes array, it is the reader challenge to send to the desfire
 * @return 0 if the authentication is successfull, -1 otherwise
 *
 * WARNING, if the authentication key is incorrect, the error message will be the following : 
 *     "Invalid status word on authentication pass 2, expected 0x9100 got 0x91ae"
 *
 */
int authentification(uint8_t key_index,  uint8_t * key1, uint8_t * key2, uint8_t * challenge)
{
    int res;

    uint8_t abtRx[MAX_FRAME_LEN];  /*output buffer         */
    uint8_t abtTx[MAX_FRAME_LEN];  /*input buffer          */
    size_t abtTx_size,abtRx_size;
    unsigned int status_word;

    uint8_t output[8], output2[8]; /*temporary buffer      */
    
    /*check the args*/
    if(key_index > 0xD)
    {
        fprintf(stderr, "Invalid key index, expected a value between 0x0 and 0xd, got 0x%01x\n",key_index);
        return -1;
    }

    /*prepare the data of the pass 1*/
    abtTx_size = 7;
    memcpy(abtTx,auth_pass1,abtTx_size);
    abtTx[5] = key_index & 0xff; /*data 0*/
    
    #ifdef DEBUG
    printf("Authentication on key 0x%02x, pass 1\n",key_index);
    #endif
    
    /*send the request to the card*/
        /*the status word 0x91AF is expected, it means "ADDITIONAL FRAME".  The desfire tag is waiting the second pass of the authentication*/
        /*8-bytes are expected, it is the tag challenge*/
    if(sendRequest(abtTx, abtTx_size, abtRx,&abtRx_size, &status_word, 8) != 0) {return -1;}
    
    if(status_word != 0x91AF)
    {
        fprintf(stderr, "Invalid status word on request sending, expected 0x91AF got 0x%04x\n",status_word);
        return -1;
    }
    
    /*a) get the challenge plain text*/
    encrypt(abtRx, output, key1,key2);
    #ifdef DEBUG
    printf("\nnt: ");print_hex(output,8);
    #endif
    uint8_t output3[8];
    memcpy(output3, output,8);
    /*transform the tag challenge into a prim challenge*/
        /*the first byte juste go at the end of the array*/
    buildPrim(output);
    #ifdef DEBUG
    printf("nt': ");print_hex(output,8);
    #endif
    
    /*b) encrypt the reader challenge*/
    encrypt(challenge, output2, key1,key2);
    
    #ifdef DEBUG
    printf("nr: ");print_hex(challenge,8);
    printf("D1: ");print_hex(output2,8);
    #endif
    
    /*c) xor the cyphered challenge of the reader with the prim challenge of the tag*/
    xor(output2,output, output);
    #ifdef DEBUG
    printf("Buffer: ");print_hex(output,8);
    #endif
    
    /*d) cypher the result of the step c)*/
    encrypt(output, output, key1,key2);
    #ifdef DEBUG
    printf("D2: ");print_hex(output,8);printf("\n");
    #endif
    
    /*e) prepare the data of the pass 2*/
    abtTx_size = 22;
    memcpy(abtTx,auth_pass2,abtTx_size);
    memcpy(&(abtTx[5]), output2, 8);
    memcpy(&(abtTx[13]), output, 8);

    #ifdef DEBUG
    printf("Authentication on key 0x%02x, pass 2\n",key_index);
    #endif
    
    /*send the authentication pass 2*/
    if(sendRequest(abtTx, abtTx_size, abtRx,&abtRx_size, &status_word, 8) != 0) {return -1;}
    
    if(status_word != 0x9100)
    {
        fprintf(stderr, "Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
        return -1;
    }
    
    /*get the plain text of the tag response*/
    encrypt(abtRx, output, key1,key2);
    #ifdef DEBUG
    printf("\nnr': ");print_hex(output,8);
    #endif
    if(!isValidPrim(challenge, output)){ 
	memcpy(session_key, datatest, 4);
	memcpy(session_key+4, output3, 4);
	memcpy(session_key+8, datatest+4, 4);
	memcpy(session_key+12, output3+4, 4);
	
}
    /*check the tag answer*/
    return isValidPrim(challenge, output);
}

/**
 * this function sends a command to a desfire tag, check the status word and the size of the output data
 *
 * @param abtTx, the command to send to the tag
 * @param abtTx_size, the size of the command abtTx
 * @param abtRx, the buffer to store the answer of the tag
 * @param abtRx_size, the size of the output abtRx
 * @param expected_status_word, the expected status word
 * @param expected_data_length, the expected data length, if zero, any size is allowed
 * @return -1 if an error occurs, 0 otherwise
 *
 * WARNING, this function exit the program if there is a communication error with the reader or with the desfire tag
 *
 */
int sendRequest(uint8_t * abtTx, size_t abtTx_size, uint8_t * abtRx, size_t * abtRx_size,unsigned int * expected_status_word, int expected_data_length)
{
    int res, status_word;
    *abtRx_size = 0;
    
    #ifdef DEBUG
    printf("tx: ");
    print_hex(abtTx,abtTx_size);
    #endif
    
    /*send the request*/
    res = nfc_initiator_transceive_bytes(pnd, abtTx, abtTx_size, abtRx, MAX_FRAME_LEN, 0);
    if(res < 0)
    {
        nfc_perror(pnd, "nfc_initiator_transceive_bytes");
        exit(EXIT_FAILURE);
    }

    #ifdef DEBUG
    printf("rx: ");
    print_hex(abtRx,res);
    #endif
    
    /*check the status word*/    
    if(res > 1) 
    {
        /*the status word is build with the two last bytes of the output*/
        status_word = abtRx[res-2];
        status_word = (status_word<<8) + abtRx[res-1];
        
        *expected_status_word = status_word;
    }
    else
    {
        fprintf(stderr, "Invalid response length on request sending, expected at least 2 bytes got %d\n",res);
        return -1;
    }
    
    /*check the data length*/
    if(expected_data_length > 0 && (res-2) != expected_data_length) /*check the data length*/
    {
        fprintf(stderr, "Invalid length of the response data on request sending, expected %d bytes got %d\n", expected_data_length,res-2);
        return -1;
    }
    
    *abtRx_size = res-2;
    
    return 0;
}

/**
 * This function compares two 8-bytes array to check if second array is a Prim version of the first array
 *
 * @param noPrim, the no prim version of the 8-bytes array
 * @param Prim, the prim version of the 8-bytes array
 * @return 0 if Prim is the prim version of noPrim, -1 otherwise
 *
 * Example: [2,3,4,5,6,7,8,1] is the prim version of the following array [1,2,3,4,5,6,7,8]
 *
 */
int isValidPrim(uint8_t * noPrim, uint8_t * Prim)
{
    int iterator;
    
    for(iterator = 0; iterator <8;iterator+=1)
    {
        if(noPrim[ (iterator+1)%8] != Prim[ iterator ])
            return -1;
    }
    
    return 0;
}

/**
 * this procedure xor two 8-bytes arrays and put the result in a third array
 *
 * @param input1, it is the first 8-bytes array to xor
 * @param input2, it is the second 8-bytes array to xor
 * @param output, it is an 8-bytes array to put the result
 *
 */
void xor(uint8_t * input1, uint8_t * input2, uint8_t * output)
{
    int iterator;
    
    for(iterator = 0; iterator <8;iterator+=1)
    {
        output[iterator] = input1[iterator] ^ input2[iterator];
    }
}

/**
 * this procedure convert a 8-bytes array into its Prim image
 *
 * @param data, the 8-bytes array to convert
 *
 */
void buildPrim(uint8_t * data)
{
    uint8_t tmp;
    int iterator;
    
    tmp = data[0];
    
    for(iterator = 1; iterator <8;iterator+=1)
    {
        data[iterator-1] = data[iterator];
    }
    
    data[7] = tmp;
}

/**
 * This procedure decypher the input data.  The data is not cyphered because the desfire is only able to cypher the data.
 * So, to send protected data to the desfire tag, it must be decyphered.
 * the desfire use 3DES ECB EDE with two 8-bytes keys
 *
 * @param input, the 8-bytes array to decypher
 * @param output, the 8-bytes array to put the result
 * @param key1, the first DES key
 * @param key2, the second DES key
 *
 */
void encrypt(uint8_t * input, uint8_t * output, uint8_t *key1, uint8_t *key2)
{
    DES_key_schedule ks1, ks2;
    
    /*set keys*/
    DES_set_key_unchecked((DES_cblock*)key1,&ks1);
    DES_set_key_unchecked((DES_cblock*)key2,&ks2);
    
    /*encrypt*/
    DES_ecb2_encrypt((DES_cblock*)input, (DES_cblock*)output,&ks1,&ks2, DES_DECRYPT);
}

/**
 * this procedure initialize the lib libnfc and poll a card
 */
void init(void)
{
    nfc_target nt;                  /*target value           */    
    /*const nfc_modulation nmMifare = 
    {
        .nmt = NMT_ISO14443A, 
        .nbr = NBR_106,       
    };*/
    
    nfc_modulation nmMifare;/*communication settings */
    nmMifare.nmt = NMT_ISO14443A;/*communication standard       */ /*other value : NMT_ISO14443A, NMT_JEWEL, NMT_ISO14443B, NMT_ISO14443BI, NMT_ISO14443B2SR, NMT_ISO14443B2CT, NMT_FELICA, NMT_DEP*/
    nmMifare.nbr = NBR_106;/*communication speed 106kb/s  */ /*other value : NBR_UNDEFINED, NBR_106, NBR_212, NBR_424, NBR_847*/
    
    /*define the atexit procedure*/
    if (atexit(onExit) != 0) 
    {
       fprintf(stderr, "cannot set exit function\n");
       exit(EXIT_FAILURE);
    }
    
    /*context establishment*/
    nfc_init(&context);
    if (context == NULL) 
    {
        fprintf(stderr,"Unable to init libnfc (malloc)\n");
        exit(EXIT_FAILURE);
    }
    
    /*print the lib version*/
    printf("libnfc %s\n", nfc_version());

    /*open the first device available*/
    if ((pnd = nfc_open(context, NULL)) == NULL) 
    {
        fprintf(stderr, "%s", "Unable to open NFC device. (don't forget to be root)\n");
        exit(EXIT_FAILURE);
    }

    printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));
    
    /*configure the device in reader mode*/
    if (nfc_initiator_init(pnd) < 0) 
    {
        nfc_perror(pnd, "nfc_initiator_init");
        exit(EXIT_FAILURE);
    }
    printf("initiator mode: ENABLE\n");
    
    /*select target, poll a tag and print the information*/
    if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) > 0) 
    {
        printf("The following (NFC) ISO14443A tag was found:\n");
        
        printf("    ATQA (SENS_RES): ");
        print_hex(nt.nti.nai.abtAtqa, 2);
        
        printf("       UID (NFCID%c): ", (nt.nti.nai.abtUid[0] == 0x08 ? '3' : '1'));
        print_hex(nt.nti.nai.abtUid, nt.nti.nai.szUidLen);
        
        printf("      SAK (SEL_RES): ");
        print_hex(&nt.nti.nai.btSak, 1);
        
        if (nt.nti.nai.szAtsLen) 
        {
            printf("          ATS (ATR): ");
            print_hex(nt.nti.nai.abtAts, nt.nti.nai.szAtsLen);
        }
    }
}

/**
 * this procedure convert an array of bytes in string and print it on the standard output
 *
 * @param pbtData, the array of bytes to print
 * @param pbtData, the size of the array of bytes
 *
 */
static void print_hex(const uint8_t *pbtData, const size_t szBytes)
{
  size_t  szPos;

  for (szPos = 0; szPos < szBytes; szPos++) 
  {
      printf("%02x  ", pbtData[szPos]);
  }
  printf("\n");
}

/**
 * this procedure release the LibNFC ressources on the exit event
 */
void onExit(void)
{
    /*device disconnection*/
    if(pnd != NULL){nfc_close(pnd);}

    /*context destruction*/ 
    if(context != NULL){nfc_exit(context);}
}
