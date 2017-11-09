#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <nfc/nfc.h>
#include <openssl/des.h>
#include <string.h>
#include <time.h>

#define MAX_FRAME_LEN 264
#define DEBUG

/*APDU Declaration*/
uint8_t createApplication_apdu[11] = {0x90,0xCA,0x00,0x00,0x05,0x00,0x00,0x00,0x0f,0x01,0x00};
uint8_t deleteApplication_apdu[9] = {0x90,0xDA,0x00,0x00,0x03,0x00,0x00,0x00,0x00};
uint8_t listApplication_apdu[5] = {0x90,0x6A,0x00,0x00,0x00};
uint8_t listMoreApplication_apdu[5] = {0x90,0xAF,0x00,0x00,0x00};
uint8_t getKeySettings_apdu[5] = {0x90,0x45,0x00,0x00,0x00};
uint8_t authenticate1_apdu[7] = {0x90,0x0A,0x00,0x00,0x01,0x00,0x00};
uint8_t authenticate2_apdu[5] = {0x90,0xAF,0x00,0x00,0x10};

/*LibNFC global variable*/
nfc_context *context = NULL;    /*context pointer          */
nfc_device  *pnd     = NULL;    /*device pointer           */

/*utils command prototypes*/
void onExit          (void);
static void print_hex(const uint8_t *pbtData, const size_t szBytes);
void init            (void);


int createApplication(unsigned int AID);
int deleteApplication(unsigned int AID);
int listApplication(unsigned int *outputList, int *outputCount);
int getkeySettings();
int authenticate();
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
    /*libnfc initialization + tag polling*/
    init();
    if(getkeySettings() != 0)
    {
        printf("get key settings Failure\n");
        return EXIT_FAILURE;
    }

	time(NULL);
	if(authenticate() != 0)
    {
        printf("Authentication Failure\n");
        return EXIT_FAILURE;
    }
    unsigned int i = 0;
    for(i=0x01; i < 0x16; i++)
     {
    	if(createApplication(i) != 0)
    	{
        	printf("Creation Failure\n");
        	return EXIT_FAILURE;
    	}
     }
   unsigned int outputList [28 * 3];
    unsigned int outputCount = 0;
    if(listApplication(outputList,&outputCount) != 0)
    {
        printf("List  Failure \n");
        return EXIT_FAILURE;
    }
   
   #ifdef DEBUG
   printf("\nAID List : 0x");
   for(i=0; i < outputCount * 3;i++)
	{
		printf("%02x ",outputList[i]);
	}
   printf("\nNbr Applis: %u\n",outputCount);
   #endif

   if(deleteApplication(0x01) != 0)
    {
        printf("Deletion Failure\n");
        return EXIT_FAILURE;
    }
   printf("Success\n");

   return EXIT_SUCCESS;
}

int getkeySettings()
{
    uint8_t abtRx[MAX_FRAME_LEN]; /*output buffer         */
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size;
    abtTx_size = 5;
    memcpy(abtTx,getKeySettings_apdu,abtTx_size);
    if(sendRequest(abtTx, abtTx_size, abtRx, 0x9100, 0) != 0) {return -1;}
    
    return 0;
}
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
    size_t abtTx_size;
    
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
    if(sendRequest(abtTx, abtTx_size, abtRx, 0x9100, 0) != 0) {return -1;}
    
    return 0;
}

int authenticate()
{
                            
    uint8_t abtRx[MAX_FRAME_LEN];
    uint8_t abtTx[MAX_FRAME_LEN];
    uint8_t defaultkey[8]  = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t ivec[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t ivec1[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t output1[8];
    uint8_t randB[8];
    uint8_t randA[8];
    uint8_t output2[8];
    uint8_t input[8];
    //uint8_t input1[16];
    uint8_t output[16];
    DES_key_schedule ks1, ks2;
   
    size_t abtTx_size;
    abtTx_size = 7;
    memcpy(abtTx,authenticate1_apdu,abtTx_size);
    unsigned int response_size = 0;
    int status_word_O = 0;
    unsigned int k = 0;
    unsigned int cmp = 0;
    int result = sendRequest_Desfire(abtTx, abtTx_size, abtRx,&response_size,&status_word_O);
    if(status_word_O == 0x91AF && result == 0) 
	{
		/*set keys*/
    		DES_set_key_unchecked((DES_cblock*)defaultkey,&ks1);
    		DES_set_key_unchecked((DES_cblock*)defaultkey,&ks2);
		
		
		DES_ncbc_encrypt(abtRx, randB, 8,&ks1,(DES_cblock*)ivec, DES_DECRYPT);
		memcpy(ivec, randB,8);
		
		uint8_t a = randB[0];
		for(k=1; k < 8; k++)
			{
				randB[k-1] = randB[k];
			}
		randB[7] = a;
                
		for(k= 0; k < 8; k++)
		{
			randA[k] = rand()%255;
			
		}
		
		print_hex(randA,8);
		
		DES_ecb_encrypt( (DES_cblock*)randA , (DES_cblock*)output1, &ks1, DES_DECRYPT);
		for(k= 0; k < 8; k++)
		{
			input[k] = output1[k] ^ randB[k];
			
		}
		
		DES_ecb_encrypt( (DES_cblock*)input, (DES_cblock*)output2, &ks1,DES_DECRYPT);
		memcpy(output,output1,8);
		memcpy(output+8,output2,8);
		print_hex(output,16);
		memcpy(abtTx,authenticate2_apdu,5);
		memcpy(abtTx+5,output,16);
		abtTx[21] = 0x00;
		abtTx_size = 22;
		result = sendRequest_Desfire(abtTx, abtTx_size, abtRx,&response_size,&status_word_O);
		if( result == 0 && status_word_O == 0x9100)
		{
			DES_ncbc_encrypt( abtRx, output1, 8,&ks1, (DES_cblock*)ivec1, DES_DECRYPT);
			print_hex(output1,8);
			for(k=0; k< 8; k++)
			{
			        if(k <7)
				{if(output1[k] != randA[k+1]){cmp=-1;}}
				if(k==7)
				{{if(output1[k] != randA[0]){cmp=-1;}}}	
			}
		}
	}
return cmp;
}

/**
 * this function deletes an application
 *
 * @param AID, the application identifier to delete, it must be a value between 0x000001 and 0xffffff
 * @return the status word, or -1 if an error has occured
 */
int deleteApplication(unsigned int AID)
{
  
    uint8_t abtRx[MAX_FRAME_LEN];
    uint8_t abtTx[MAX_FRAME_LEN];
    size_t abtTx_size;
    
    /*check the AID*/
    if(AID > 0xffffff || AID < 0x000001)
    {
        fprintf(stderr, "Invalid AID, expected a value between 0x000001 and 0xffffff, got 0x%06x\n",AID);
        return -1;
    }
    
    /*prepare the data*/
    abtTx_size = 9;
    memcpy(abtTx,deleteApplication_apdu,abtTx_size);
    abtTx[5] = (AID >> 16) & 0xff; /*data 0*/
    abtTx[6] = (AID >> 8 ) & 0xff; /*data 1*/
    abtTx[7] = AID & 0xff;         /*data 2*/

    #ifdef DEBUG
    /*debug message*/
    printf("Delete Application 0x%06x\n",AID);
    #endif
    
    /*send the data to the card, the expected status word is 0x91 0x00*/
    if(sendRequest(abtTx, abtTx_size, abtRx, 0x9100, 0) != 0) {return -1;}
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
    uint8_t abtRx[MAX_FRAME_LEN];
    uint8_t abtTx[MAX_FRAME_LEN];
    size_t abtTx_size;
     /*prepare the data*/
    abtTx_size = 5;
    memcpy(abtTx,listApplication_apdu,abtTx_size);
    unsigned int k = 0;
    unsigned int j = 0;
    unsigned int response_size = 0;
    int status_word_O = 0;
    int result = sendRequest_Desfire(abtTx, abtTx_size, abtRx,&response_size,&status_word_O);
    if(status_word_O == 0x9100 && result == 0) 
	{	
          *outputCount = ((response_size) / 3) ;
	  for(k=0 ; k < response_size ; k++)
		{
			outputList[k] = abtRx[k];	
		}
	}
	
    else if(status_word_O ==0x91AF && result == 0) 
	{
	   //copier abtRx dans outputList et compter le nombre d'appli
          *outputCount = (response_size) / 3;
	  for( k = 0; k < response_size; k++)
		{
			outputList[k] = abtRx[k];
		}

	    memcpy(abtTx,listMoreApplication_apdu,abtTx_size); 
	    result = sendRequest_Desfire(abtTx, abtTx_size, abtRx,&response_size,&status_word_O);
	    if(status_word_O != 0x9100 || result !=0) {return -1;}
	   // copier la suite des applis dans outputList et mettre à jour le compteur des applis
	  for( k= (*outputCount * 3) ; j < response_size; k++,j++)
		{
			outputList[k] = abtRx[j];
			
		}
	*outputCount += (response_size ) / 3;
	}
        
      else {return -1;}
	
    return 0;
}


/**
 * this function sends a command to a desfire tag, check the status word and the size of the output data
 *
 * @param abtTx, the command to send to the tag
 * @param abtTx_size, the size of the command
 * @param abtRx, the buffer to store the answer of the tag
 * @param expected_status_word, the expected status word
 * @param expected_data_length, the expected data length
 * @return -1 if an error occurs, 0 otherwise
 *
 * WARNING, this function exit the program if there is a communication error with the reader or with the desfire tag
 *
 */
int sendRequest(uint8_t * abtTx, size_t abtTx_size, uint8_t * abtRx, int expected_status_word, int expected_data_length)
{
    int res, status_word;

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
        if(status_word != expected_status_word)
        {
            fprintf(stderr, "Invalid status word on request sending, expected 0x%04x got 0x%04x\n",expected_status_word,status_word);
            return -1;
        }
    }
    else
    {
        fprintf(stderr, "Invalid response length on request sending, expected 10 bytes got %d\n",res);
        return -1;
    }
    
    /*check the data length*/
    if((res-2) != expected_data_length) /*check the data length*/
    {
        fprintf(stderr, "Invalid length of the response data on request sending, expected %d bytes got %d\n", expected_data_length,res-2);
        return -1;
    }
    
    return 0;
}

/**
 * this function sends a command to a desfire tag, check the status word and the size of the output data
 *
 * @param abtTx, the command to send to the tag
 * @param abtTx_size, the size of the command
 * @param abtRx, the buffer to store the answer of the tag
 * @param expected_status_word, the expected status word
 * @param expected_data_length, the expected data length
 * @return -1 if an error occurs, 0 otherwise
 *
 * WARNING, this function exit the program if there is a communication error with the reader or with the desfire tag
 *
 */
int sendRequest_Desfire(uint8_t * abtTx, size_t abtTx_size, uint8_t * abtRx, int *data_length, int *status_word_O)
{
    int res, status_word;

    #ifdef DEBUG
    printf("tx: ");
    print_hex(abtTx,abtTx_size);
    #endif
    
    /*send the request*/
    res = nfc_initiator_transceive_bytes(pnd, abtTx, abtTx_size, abtRx, MAX_FRAME_LEN, 0);
    *data_length = res - 2;
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
	*status_word_O = status_word;
	/*if(status_word == 0x91AF && expected_status_word == 0x9100)
	{
		return 0;
	}
        else if(status_word != expected_status_word)
        {
            fprintf(stderr, "Invalid status word on request sending, expected 0x%04x got 0x%04x\n",expected_status_word,status_word);
            return -1;
        }*/
    }
    else
    {
        fprintf(stderr, "Invalid response length on request sending, expected 10 bytes got %d\n",res);
        return -1;
    }
    
    return 0;
}

/**
 * this procedure initialize the lib libnfc and poll a card
 */
void init(void)
{
    nfc_target nt;                  /*target value           */    
    const nfc_modulation nmMifare = /*communication settings */
    {
        .nmt = NMT_ISO14443A, /*communication standard       */ /*other value : NMT_ISO14443A, NMT_JEWEL, NMT_ISO14443B, NMT_ISO14443BI, NMT_ISO14443B2SR, NMT_ISO14443B2CT, NMT_FELICA, NMT_DEP*/
        .nbr = NBR_106,       /*communication speed 106kb/s  */ /*other value : NBR_UNDEFINED, NBR_106, NBR_212, NBR_424, NBR_847*/
    };
    
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
