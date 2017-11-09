/*
 * main.c
 *
 *  Created on: 6 mai 2015
 *      Author: root
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/des.h>
#include <nfc/nfc.h>
#include "nfc-utils.h"

#define PLAIN 0X01
#define MACING 0x02
#define ENCRYPTION 0x03

#define MAX_FRAME_LEN 264
#define CASCADE_BIT 0x04

static uint8_t abtRx[MAX_FRAME_LEN];
static size_t szRx = sizeof(abtRx);
static int status_word;
static nfc_device *pnd;
bool    quiet_output = false;
bool    timed = false;
size_t timeout = -1;


uint8_t selectApplication_apdu[9] = {0x90,0x5A,0x00,0x00,0x03,0x00,0x00,0x00,0x00};

uint8_t createApplication_apdu[11] = {0x90,0xCA,0x00,0x00,0x05,0x00,0x00,0x00,0x0f,0x04,0x00};
uint8_t listApplication_apdu[5] = {0x90,0x6A,0x00,0x00,0x00};
uint8_t listMoreApplication_apdu[5] = {0x90,0xAF,0x00,0x00,0x00};

uint8_t createFile_apdu_1[13] = {0x90,0xCD,0x00,0x00,0x07,0x00,0x00,0xEE,0xEE,0x04,0x00,0x00,0x00};
uint8_t createFile_apdu_2[13] = {0x90,0xCD,0x00,0x00,0x07,0x00,0x01,0x33,0x33,0x04,0x00,0x00,0x00};
uint8_t createFile_apdu_3[13] = {0x90,0xCD,0x00,0x00,0x07,0x00,0x03,0x33,0x33,0x04,0x00,0x00,0x00};

uint8_t listFile_apdu[5]          = {0x90,0x6f,0x00,0x00,0x00};

int selectApplication(unsigned int AID);
int createApplication(unsigned int AID);
int listApplication(uint8_t *outputList, unsigned int *outputCount);
int listFile (uint8_t *outputList, unsigned int *outputCount);
int createFile(unsigned int FID, unsigned int commmunicationMode);

static void
print_usage(char *argv[])
{
  printf("Usage: %s [OPTIONS]\n", argv[0]);
  printf("Options:\n");
  printf("\t-h\tHelp. Print this message.\n");
  printf("\t-q\tQuiet mode. Suppress output of READER and EMULATOR data (improves timing).\n");
  printf("\t-f\tForce RATS.\n");
  printf("\t-t\tMeasure response time (in cycles).\n");
  printf("\t-m\tModify the timeout value.\n");
  printf("\t-sw\tSize of the data to write in decimal.\n");
  printf("\t-sr\tSize of the data to read in decimal, put 0 if you want read all the file.\n");
}

static  bool
transmit_bytes(const uint8_t *pbtTx, const size_t szTx)
{
  uint32_t cycles = 65535 * 21;
  // Show transmitted command
  if (!quiet_output) {
    printf("Sent bytes:     ");
    print_hex(pbtTx, szTx);
  }
  int res;
  // Transmit the command bytes
  if (timed) {
	  printf("************************\n");
    if ((res = nfc_initiator_transceive_bytes_timed(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), &cycles)) < 0)
      return false;
    if ((!quiet_output) && (res > 0)) {
      printf("Response after %u cycles\n", cycles);
    }
  } else {
    if ((res = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, sizeof(abtRx),timeout)) < 0)
      return false;
  }
  szRx = res;
  status_word = abtRx[res-2];
  status_word = (status_word<<8) + abtRx[res-1];
  // Show received answer
  if (!quiet_output) {
    printf("Received bytes: ");
    print_hex(abtRx, szRx);
  }
  // Succesful transfer
  return true;
}

int
main(int argc, char *argv[])
{
  int arg;
  // Get commandline options
  for (arg = 1; arg < argc; arg++) {
    if (0 == strcmp(argv[arg], "-h")) {
      print_usage(argv);
      exit(EXIT_SUCCESS);
    } else if (0 == strcmp(argv[arg], "-q")) {
      quiet_output = true;
    } else if (0 == strcmp(argv[arg], "-t")) {
      timed = true;
    } else if (0 == strcmp(argv[arg], "-m")) {
        timeout = atoi(argv[arg+1]);
        if(!quiet_output)
        {
        	printf("the value of timeout is %u\n",timeout);
        }
        arg++;
     } else {
      ERR("%s is not supported option.", argv[arg]);
      print_usage(argv);
      exit(EXIT_FAILURE);
    }
  }

  nfc_context *context;
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

  // Try to open the NFC reader
  pnd = nfc_open(context, NULL);

  if (pnd == NULL) {
    ERR("Error opening NFC reader");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Initialise NFC device as "initiator"
  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

    nfc_modulation nm = {
            .nmt = NMT_ISO14443A,
            .nbr = NBR_106,
          };


      // Attacker's tag
      nfc_target ntTarget;
     if (nfc_initiator_select_passive_target(pnd, nm, NULL, 0, &ntTarget) <= 0) {
           printf("Error: no tag was found\n");
           nfc_close(pnd);
           nfc_exit(context);
           exit(EXIT_FAILURE);
         }

     // iso14443a_crc_append(abtRats, 2);
      //transmit_bytes(abtRats, 4);

      printf("Found tag:\n");
      print_nfc_target(&ntTarget, false);

      //pn53x_wrap_frame()
      //pn53x_target_send_bytes()
  uint8_t settings;
  int res = 0;
  uint8_t outputList [28 * 3];
  unsigned int outputCount = 0;
  uint8_t outputFileList [16];
  // pour le test le AID = 0
  unsigned int AID = 0x00;
  //pour le test l'application qu'on va supprimer et ensuite on va créer a l'aid 2
  unsigned int aid = 0x02;

  // ce if ne sert à rien
  if(!quiet_output)
  {
	  printf("******************Select Root Application*******************\n");
  }

  res = selectApplication(AID) ;
  if(res != 0)
   {
	  nfc_close(pnd);
 	  nfc_exit(context);
 	  return EXIT_FAILURE;
   }
  if(!quiet_output)
  {
  	printf("******************Create Applications*******************\n");
  }
  for(unsigned int k=1; k <28;k++)
  {
	  res = createApplication(k);
	  if(res != 0)
	    {
	    	nfc_close(pnd);
	     	nfc_exit(context);
	     	return EXIT_FAILURE;
	   }
  }
  if(!quiet_output)
    {
    	printf("******************List Applications*******************\n");
    }
  res = listApplication(outputList,&outputCount);
  		  if(res != 0)
  		  {
  			nfc_close(pnd);
  			  nfc_exit(context);
  			  return EXIT_FAILURE;
  		  }
  		  else{
  			  if (!quiet_output) {
  				 printf("%d application(s): ",outputCount);
  				 for(int i=0; i < outputCount * 3;i++)
  					{
  						printf("%02x ",outputList[i]);
  						if((i+1)%3==0)
  						{
  							printf("***");
  						}
  					}
  				 printf("\n");
  			   }
  		  }
  if(!quiet_output)
    {
  	  printf("******************Select Application 2*******************\n");
    }

   res = selectApplication(aid) ;
   if(!quiet_output)
      {
    	  printf("******************Create Files*******************\n");
      }
   for(unsigned int k=0; k< 16;k++)
   {
	   res = createFile(k,ENCRYPTION);
	   	  if(res != 0)
	   	    {
	   	    	nfc_close(pnd);
	   	     	nfc_exit(context);
	   	     	return EXIT_FAILURE;
	   	   }
   }

   if(!quiet_output)
       {
       	printf("******************List Files*******************\n");
       }
   outputCount = 0;
   res = listFile(outputFileList,&outputCount);
   		if(res!=0)
   		{
   			if(!quiet_output)
   				{
   						 printf("List Files failure\n");
   				}
   			return EXIT_FAILURE;
   		}
   		if(!quiet_output)
   		{
   			printf("%d Files :",outputCount);
   			for(int i = 0; i < outputCount; i++)
   				{
   					printf("%02x  ",outputFileList[i]);
   				}
   			printf("\n");
   		}

}
int createFile(unsigned int FID, unsigned int communictionMode)
{
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size;
    int res;

    if(FID > 0xff )
    {
    	if(!quiet_output)
    	    	{
    	    		printf("Invalid FID, expected a value between 0x00 and 0xff, got 0x%06x\n",FID);
    	    	}

    	return EXIT_FAILURE;
    }

    /*prepare the data*/
    abtTx_size = 13;
    if(communictionMode == PLAIN)
    {
    	memcpy(abtTx,createFile_apdu_1,abtTx_size);
    }

    else if(communictionMode == MACING)
    {
    	memcpy(abtTx,createFile_apdu_2,abtTx_size);
    }
    else if(communictionMode == ENCRYPTION)
    {
    	memcpy(abtTx,createFile_apdu_3,abtTx_size);
    }

    abtTx[5] = FID & 0xff;         /*file descriptor*/


    /*send the data to the card, the expected status word is 0x91 0x00*/
    res = transmit_bytes(abtTx,abtTx_size);

    if(!res || status_word != 0x9100)
    {
       if(!quiet_output)
       {
    	    nfc_perror(pnd, "CREATE FILE");
        	//printf("create File :Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
       }

       return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
int listFile(uint8_t *outputList, unsigned int *outputCount)
{
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size;
    int iterator;
    int res;

    /*prepare the data*/
    abtTx_size = 5;
    memcpy(abtTx,listFile_apdu,abtTx_size);

    /*send the data to the card, the expected status word is 0x91 0x00 or 0x91 AF*/
    res = transmit_bytes(abtTx,abtTx_size);
    if(!res || status_word != 0x9100)
    {
    	nfc_perror(pnd, "LIST FILES");
    	return EXIT_FAILURE;
    }
    for(iterator = 0; iterator < (szRx - 2); iterator += 1, *outputCount +=1)
        {
            outputList[*outputCount] = (abtRx[iterator]&0xff);
        }

    return EXIT_SUCCESS;
}

int listApplication(uint8_t *outputList,unsigned  int *outputCount)
{

    uint8_t abtTx[MAX_FRAME_LEN];
    size_t abtTx_size;
    int res;
    unsigned int j;
     /*prepare the data*/
    abtTx_size = 5;
    memcpy(abtTx,listApplication_apdu,abtTx_size);

    res = transmit_bytes(abtTx, abtTx_size);
    if((status_word == 0x9100) && res  )
	{
          *outputCount = ((szRx - 2) / 3) ;
          for( int k=0 ; k < szRx - 2 ; k++)
          {
			outputList[k] = abtRx[k];
          }
	}

    else if(status_word ==0x91AF && res)
	{
    	   //copier abtRx dans outputList et compter le nombre d'appli
          *outputCount = (szRx -2) / 3;
          for(int k = 0; k < szRx - 2; k++)
          {
			outputList[k] = abtRx[k];
          }

	    memcpy(abtTx,listMoreApplication_apdu,abtTx_size);
	    res = transmit_bytes(abtTx, abtTx_size);
	    if(status_word != 0x9100 || !res)
	    {
	    	return EXIT_FAILURE;
	    }
	   // copier la suite des applis dans outputList et mettre à jour le compteur des applis
	    for(int k= (*outputCount * 3) ; j < szRx - 2; k++,j++)
		{
			outputList[k] = abtRx[j];

		}
	    *outputCount += (szRx - 2) / 3;
	}

    else {
    	  nfc_perror(pnd, "LIST APPLICATIONS");
    	  return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int createApplication(unsigned int AID)
{
	    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
	    size_t abtTx_size;

	    /*check the AID*/
	    if(AID > 0xffffff || AID < 0x000001)
	    {
	    	if(!quiet_output)
	    	{
	    		printf("AID is not valid\n");
	    	}
	        return EXIT_FAILURE;
	    }

	    /*prepare the data*/
	    abtTx_size = 11;
	    memcpy(abtTx,createApplication_apdu,abtTx_size);
	    abtTx[7] = (AID >> 16) & 0xff; /*data 0*/
	    abtTx[6] = (AID >> 8 ) & 0xff; /*data 1*/
	    abtTx[5] = AID & 0xff;         /*data 2*/

	    if(!transmit_bytes(abtTx,abtTx_size) || (status_word != 0x9100))
	    {
	    	    nfc_perror(pnd, "CREATE APPLICATION");
	        	return EXIT_FAILURE;
	    }

	   return EXIT_SUCCESS;
}
int selectApplication(unsigned int AID)
{

    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size;

    if(AID > 0xffffff || AID < 0x000000)
    {
    	  if(!quiet_output)
    	   {
    	    printf("AID is not valid\n");
    	   }
    	 return EXIT_FAILURE;
    }
    /*prepare the data*/
    abtTx_size = 9;
    memcpy(abtTx,selectApplication_apdu,abtTx_size);
    abtTx[7] = (AID >> 16) & 0xff; /*data 0*/
    abtTx[6] = (AID >> 8 ) & 0xff; /*data 1*/
    abtTx[5] = AID & 0xff;         /*data 2*/

    if(!transmit_bytes(abtTx,abtTx_size) || (status_word != 0x9100))
    {
    	nfc_perror(pnd, "SELECT APPLICATION");
    	return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}



