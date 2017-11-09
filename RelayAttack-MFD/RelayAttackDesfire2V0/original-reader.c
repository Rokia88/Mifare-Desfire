/*
 * measure-time-response-desfire.c
 *
 *  Created on: 15 avr. 2015
 *      Author: rokia
 */


/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1) Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *  2 )Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Note that this license only applies on the examples, NFC library itself is under LGPL
 *
 */

/**
 * @file nfc-anticol.c
 * @brief Generates one ISO14443-A anti-collision process "by-hand"
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/des.h>
#include <nfc/nfc.h>

#include "nfc-utils.h"
#include "pn53x.h"

#define SAK_FLAG_ATS_SUPPORTED 0x20
#define PLAIN 0X01
#define MACING 0x02
#define ENCRYPTION 0x03

#define MAX_FRAME_LEN 264
#define CASCADE_BIT 0x04

static uint8_t abtRx[MAX_FRAME_LEN];
static size_t szRx = sizeof(abtRx);
static int status_word;
static nfc_device *pnd;

uint8_t key1[8] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
uint8_t key2[8] = {0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
/*PCD challenge*/
uint8_t datatest[8]          = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
//default key
uint8_t defaultkey[8]        = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};



uint8_t session_key[16] ;
uint8_t MAC[4] ;
bool    quiet_output = false;
bool    timed = false;
bool    iso_ats_supported = false;
size_t timeout = -1;
uint32_t size_data_w;
uint32_t size_data_r;
uint16_t file_s = 1024;


uint8_t selectApplication_apdu[9] = {0x90,0x5A,0x00,0x00,0x03,0x00,0x00,0x00,0x00};
uint8_t createApplication_apdu[11] = {0x90,0xCA,0x00,0x00,0x05,0x00,0x00,0x00,0x0f,0x0E,0x00};
uint8_t deleteApplication_apdu[9] = {0x90,0xDA,0x00,0x00,0x03,0x00,0x00,0x00,0x00};
uint8_t listApplication_apdu[5] = {0x90,0x6A,0x00,0x00,0x00};
uint8_t listMoreApplication_apdu[5] = {0x90,0xAF,0x00,0x00,0x00};
uint8_t createFile_apdu_1[13] = {0x90,0xCD,0x00,0x00,0x07,0x00,0x00,0xEE,0xEE,0x40,0x00,0x00,0x00};
uint8_t createFile_apdu_2[13] = {0x90,0xCD,0x00,0x00,0x07,0x00,0x01,0x55,0x55,0x40,0x00,0x00,0x00};
uint8_t createFile_apdu_3[13] = {0x90,0xCD,0x00,0x00,0x07,0x00,0x03,0x55,0x55,0x40,0x00,0x00,0x00};
uint8_t deleteFile_apdu[7]        = {0x90,0xDF,0x00,0x00,0x01,0x00,0x00};
uint8_t listFile_apdu[5]          = {0x90,0x6f,0x00,0x00,0x00};
uint8_t resetTag_apdu[5]          = {0x90,0xFC,0x00,0x00,0x00};
uint8_t changeKey_apdu[5] = {0x90, 0xC4, 0x00,0x00,0x19};
uint8_t writeFile1_apdu[4] = {0x90,0x3D,0x00,0x00};
uint8_t writeFile2_apdu[4] = {0x90,0xAF,0x00,0x00};
uint8_t readFile1_apdu[5] = {0x90,0xBD,0x00,0x00,0x07};
uint8_t readFile2_apdu[5] = {0x90,0xAF,0x00,0x00,0x00};

//uint8_t  abtDeselect[4] = {0x44,0x00, 0x00, 0x00};
uint8_t  abtHalt[4] = {0x50, 0x00, 0x00, 0x00 };
uint8_t  abtReqa[1] = { 0x26 };
uint8_t  abtSelectAll[2] = { 0x93, 0x20 };
uint8_t  abtSelectTag[9] = { 0x93, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t  abtRats[4] = { 0xe0, 0x50, 0x00, 0x00 };

uint8_t getKeySettings_apdu[5] = {0x90,0x45,0x00,0x00,0x00};
uint8_t getKeySettings_response[2] = {0x0F,0x01};

uint8_t auth_pass1[7]             = {0x90,0x0A,0x00,0x00,0x01,0x00,0x00};
uint8_t auth_pass2[22]            = {0x90,0xAF,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

int selectApplication(unsigned int AID);
int createApplication(unsigned int AID);
int deleteApplication(unsigned int AID);
int listApplication(uint8_t *outputList, unsigned int *outputCount);
int getkeySettings(uint8_t *keysettings);
void quit();
int authenticate(uint8_t key_index,  uint8_t * key1, uint8_t * key2, uint8_t * challenge);
int  isValidPrim     (uint8_t * noPrim, uint8_t * Prim);
void xor             (uint8_t * input1, uint8_t * input2, uint8_t * output);
void buildPrim       (uint8_t * data);
void encrypt         (uint8_t * input, uint8_t * output, uint8_t *key1, uint8_t *key2);
bool isEqual(uint8_t *array1,uint8_t *array2,unsigned int taille);
bool inList(unsigned int AID,uint8_t *array, unsigned int taille);
int resetDesfire();
int fileManagment(unsigned int AID);
int listFile (uint8_t *outputList, unsigned int *outputCount);
bool fileInList(unsigned int FID,uint8_t *array, unsigned int taille);
int createFile(unsigned int FID, unsigned int commmunicationMode);
int changeKey(uint8_t keyNo);
void cypher3DES(uint8_t *output, uint8_t *input, unsigned int nbrIter);
void cypher2MAC(uint8_t *output, uint8_t *input, unsigned int nbrIter);
void cypher3(uint8_t *output, uint8_t *input, unsigned int nbrIter);
int writeData_Mac(uint8_t  FID, uint8_t *buf, unsigned int nbyte);
int writeData_Encryption(uint8_t  FID, uint8_t *buf1, unsigned int nbyte);
int writeData_Plain(uint8_t  FID, uint8_t *buf, unsigned int nbyte);
int readData_PlainAndMac(unsigned int  FID, uint8_t *buf, int nbyte);
int deleteFile(unsigned int FID);

int readData_Encryption(unsigned int  FID, uint8_t *buf, int nbyte);
unsigned short crc_16(unsigned char *data, unsigned int len);



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
     } else if (0 == strcmp(argv[arg], "-sw")) {
         size_data_w = atoi(argv[arg+1]);
         if(!quiet_output)
         {
         	printf("the size of data to write is %d\n",size_data_w);
         }
         arg++;
      }else if (0 == strcmp(argv[arg], "-sr")) {
          size_data_r = atoi(argv[arg+1]);
          if(!quiet_output)
          {
          	printf("the size of data to read is %d\n",size_data_r);
          }
          arg++;
       }else {
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



 /*if (nfc_device_set_property_int(pnd, NP_TIMEOUT_COM, 0) < 0) {
      nfc_perror(pnd, "nfc_device_set_property_bool");
      nfc_close(pnd);
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }*/

 /*if (nfc_device_set_property_int(pnd, NP_TIMEOUT_COMMAND, 0) < 0) {
       nfc_perror(pnd, "nfc_device_set_property_bool");
       nfc_close(pnd);
       nfc_exit(context);
       exit(EXIT_FAILURE);
     }*/

    // Use raw send/receive methods

    nfc_modulation nm = {
            .nmt = NMT_ISO14443A,
            .nbr = NBR_106,
          };

      /*if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
          nfc_perror(pnd, "nfc_device_set_property_bool");
          nfc_close(pnd);
          nfc_exit(context);
          exit(EXIT_FAILURE);
        }*/

  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
          nfc_perror(pnd, "nfc_device_set_property_bool");
          nfc_close(pnd);
          nfc_exit(context);
          exit(EXIT_FAILURE);
  }

   /* if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
                     nfc_perror(pnd, "nfc_device_set_property_bool");
                     nfc_close(pnd);
                     nfc_exit(context);
                     exit(EXIT_FAILURE);
               }*/

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
  // pour le test le AID = 0
  unsigned int AID = 0x00;
  //pour le test l'application qu'on va supprimer et ensuite on va créer a l'aid 2
  unsigned int aid = 0x02;

  // ce if ne sert à rien
  if(res == 0)
  {
	  if(!quiet_output)
	  {
		  printf("******************Select Root Application*******************\n");
	  }
	  res = selectApplication(AID) ;

	  if(res != 0)
	  {
		   quit();
		   nfc_exit(context);
		   return EXIT_FAILURE;
	  }
	  else{
		  if(!quiet_output)
		   {
			  printf("******************List Applications*******************\n");
		   }
		  res = listApplication(outputList,&outputCount);
		  if(res != 0)
		  {
			  quit();
			  nfc_exit(context);
			  return EXIT_FAILURE;
		  }
		  else{
			  if (!quiet_output) {
				 printf("%d application(s): ",outputCount);
				 for(int i=0; i < outputCount * 3;i++)
					{
						printf("%02x ",outputList[i]);
						if(i%3==0 && i!=0)
						{
							printf("***");
						}
					}
				 printf("\n");
			   }
			  if(inList(aid, outputList,outputCount))
			  {
				  if(!quiet_output)
				   {
					  printf("******************Get PICC Master key settings*******************\n");
				   }
				  res = getkeySettings(&settings);
				  // vérifier que key settings est 0x0F 0x01
				  if(res != 0 || !isEqual(abtRx,getKeySettings_response,2))
				  {
					  if(!quiet_output)
					  {
						  printf("to authenticate with the PICC master key, you have to change the settings\n");
					  }
					  quit();
					  nfc_exit(context);
					  return EXIT_FAILURE;
				  }
				  else{
				  // s'authentifier pour pouvoir supprimer l'application
				  if(!quiet_output)
					  {
						printf("******************Authentication with PICC master key *******************\n");
					  }
				  res = authenticate(0, defaultkey,defaultkey,datatest);
				  if( res != 0)
				  {
					  if(!quiet_output)
					  {
						printf("Authentication failure\n");
					  }
					  quit();
					  nfc_exit(context);
					  return EXIT_FAILURE;
				  }
				  else{
					  if(!quiet_output)
						{
							printf("******************Delete Application*******************\n");
						}
					  res = deleteApplication(aid);

					  if( res != 0)
					  {
						  if(!quiet_output)
						  {
							  printf("Deletion failure\n");
						  }
						  quit();
						  nfc_exit(context);
						  return EXIT_FAILURE;
					  }
					}
				 }
			  }
			  if(!quiet_output)
			  	{
				  printf("******************Create Application*******************\n");
			  	}
			  res = createApplication(aid);
			  if(res != 0)
			  {
				  if(!quiet_output)
					 {
						printf("Creation failure\n");
					 }
					  quit();
					  nfc_exit(context);
					  return EXIT_FAILURE;
			  }
			  else{
				  // create, delete files, write data
				 res = fileManagment(aid);
				 // remettre la carte à son état d'origine
				 if(!quiet_output)
				 {
						 printf("*****************RESET CARD*******************\n");
				 }
				 if(!selectApplication(AID) && !authenticate(0, defaultkey,defaultkey,datatest))
				 {
					if(!resetDesfire() && !quiet_output)
						{
							printf("*************************BYE*******************************\n");
						}
				 }
				 if(res != 0)
				 {

					 quit();
					 nfc_exit(context);
					 return EXIT_FAILURE;
				 }
				 else{
					 quit();
					 nfc_exit(context);
					 return EXIT_SUCCESS;
				 }
			}

		  }
	  }
 }

}

bool isEqual(uint8_t *array1,uint8_t *array2,unsigned int taille)
{
	for(int i = 0; i < taille ;i++)
	{
		if(array1[i] != array2[i])
		{
			return false;
		}
	}
	return true;
}
bool inList(unsigned int AID,uint8_t *array, unsigned int taille)
{
	uint8_t AID_a[3];
	AID_a[2] = (AID >> 16) & 0xff;
	AID_a[1] = (AID >> 8) & 0xff;
	AID_a[0] = (AID) & 0xff;

	for(int i =0;i < taille; i+=3)
	{
		if(isEqual(AID_a,array+i,3))
		{
			return true;
		}
	}

	return false;
}

bool fileInList(unsigned int FID,uint8_t *array, unsigned int taille)
{


	for(int i =0;i < taille; i+=1)
	{
		if(array[i] == FID)
		{
			return true;
		}
	}

	return false;
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

int deleteApplication(unsigned int AID)
{
	    uint8_t abtTx[MAX_FRAME_LEN];
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
	    abtTx_size = 9;
	    memcpy(abtTx,deleteApplication_apdu,abtTx_size);
	    abtTx[7] = (AID >> 16) & 0xff; /*data 0*/
	    abtTx[6] = (AID >> 8 ) & 0xff; /*data 1*/
	    abtTx[5] = AID & 0xff;         /*data 2*/


	    if(!transmit_bytes(abtTx,abtTx_size) || (status_word != 0x9100))
	   	{
	    			nfc_perror(pnd, "DELETE APPLICATION");
	   	        	return EXIT_FAILURE;
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

int getkeySettings(uint8_t *keysettings)
{
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size;
    int res;
    abtTx_size = 5;
    memcpy(abtTx,getKeySettings_apdu,abtTx_size);
    res = transmit_bytes(abtTx, abtTx_size);

    if(!res || status_word != 0x9100)
    {
    	nfc_perror(pnd, "GET KEY SETTINGS");
    	return EXIT_FAILURE;
    }
    *keysettings = abtRx[0];
    return EXIT_SUCCESS;
}

int authenticate(uint8_t key_index,  uint8_t * key1, uint8_t * key2, uint8_t * challenge)
{
	    uint8_t abtTx[MAX_FRAME_LEN];  /*input buffer          */
	    size_t abtTx_size;
	    int res;
	    uint8_t output[8], output2[8]; /*temporary buffer      */

	    /*check the args*/
	    if(key_index > 0xD)
	    {
	    	if(!quiet_output)
	    		 {
	    		    printf("Key index is not valid\n");
	    		 }
	    	return EXIT_FAILURE;
	    }

	    /*prepare the data of the pass 1*/
	    abtTx_size = 7;
	    memcpy(abtTx,auth_pass1,abtTx_size);
	    abtTx[5] = key_index & 0xff; /*data 0*/

	    /*send the request to the card*/
	    /*the status word 0x91AF is expected, it means "ADDITIONAL FRAME".  The desfire tag is waiting the second pass of the authentication*/
	    /*8-bytes are expected, it is the tag challenge*/
	    //if(sendRequest(abtTx, abtTx_size, abtRx,&abtRx_size, &status_word, 8) != 0) {return -1;}

	    res = transmit_bytes(abtTx, abtTx_size);

	    if(!res || status_word != 0x91AF)
	    {
	    	if(!quiet_output)
	    	{
	    		nfc_perror(pnd, "AUTHENTICATION");
	    		//printf("Invalid status word on request sending, expected 0x91AF got 0x%04x\n",status_word);
	    	}

	        return EXIT_FAILURE;
	    }

	    /*a) get the challenge plain text*/
	    encrypt(abtRx, output, key1,key2);

	    uint8_t output3[8];
	    memcpy(output3, output,8);

	    /*transform the tag challenge into a prim challenge*/
	    /*the first byte juste go at the end of the array*/
	    buildPrim(output);

	    /*b) encrypt the reader challenge*/
	    encrypt(challenge, output2, key1,key2);

	    /*c) xor the cyphered challenge of the reader with the prim challenge of the tag*/
	    xor(output2,output, output);

	    /*d) cypher the result of the step c)*/
	    encrypt(output, output, key1,key2);


	    /*e) prepare the data of the pass 2*/
	    abtTx_size = 22;
	    memcpy(abtTx,auth_pass2,abtTx_size);
	    memcpy(&(abtTx[5]), output2, 8);
	    memcpy(&(abtTx[13]), output, 8);

	    /*send the authentication pass 2*/
	    res = transmit_bytes(abtTx,abtTx_size);

	    if(!res || status_word != 0x9100)
	    {
	    	if(!quiet_output)
	    	{
	    		nfc_perror(pnd, "AUTHENTICATION");
	    		 //printf("Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
	    	}

	        return EXIT_FAILURE;
	    }

	    /*get the plain text of the tag response*/
	    encrypt(abtRx, output, key1,key2);

	    int valid = isValidPrim(challenge, output);
	    if(!valid){

	    	memcpy(session_key, datatest, 4);
	    	memcpy(session_key+4, output3, 4);
	    	memcpy(session_key+8, datatest+4, 4);
	    	memcpy(session_key+12, output3+4, 4);

	    }
	    /*check the tag answer*/
	    return valid;
}

void encrypt(uint8_t * input, uint8_t * output, uint8_t *key1, uint8_t *key2)
{
    DES_key_schedule ks1, ks2;

    /*set keys*/
    DES_set_key_unchecked((DES_cblock*)key1,&ks1);
    DES_set_key_unchecked((DES_cblock*)key2,&ks2);

    /*encrypt*/
    DES_ecb2_encrypt((DES_cblock*)input, (DES_cblock*)output,&ks1,&ks2, DES_DECRYPT);
}

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

void xor(uint8_t * input1, uint8_t * input2, uint8_t * output)
{
    int iterator;

    for(iterator = 0; iterator <8;iterator+=1)
    {
        output[iterator] = input1[iterator] ^ input2[iterator];
    }
}

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

void quit()
{
	//iso14443a_crc_append(abtDeselect, 2);
	//transmit_bytes(abtDeselect,2);
	//nfc_initiator_deselect_target(pnd);
	//iso14443a_crc_append(abtHalt, 2);
	//transmit_bytes(abtHalt, 4);
	nfc_close(pnd);

}

int resetDesfire()
{
    size_t abtTx_size;
    /*prepare the data*/
    abtTx_size = 5;

    /*send the data to the card, the expected status word is 0x91 0x00*/
    transmit_bytes(resetTag_apdu,abtTx_size);
    if(status_word != 0x9100)
    {
    	nfc_perror(pnd, "RESET");
    	return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int fileManagment(unsigned int aid)
{
	if(selectApplication(aid) == 0)
	{
		//lister les fichiers qui sont dans l'appli
		//voir si les 2 fichiers qu'on veut créer est dans la liste
		//si il est dans la liste, le supprimer et recréer un autre
		//écrire des données dedans
		//lire les données qu'on a écrit
		int res;
		uint8_t outputFileList [16];
		unsigned int outputCount = 0;
		uint8_t fid_1 = 0x04;
		uint8_t fid_2 = 0x05;
		uint8_t fid_3 = 0x09;
		uint8_t keyToAccessFiles = 0x05;
		uint8_t buf[size_data_w];
		for(int i = 0; i< size_data_w; i++)
		{
			buf[i] = 0x66;
		}
		uint8_t buf_I[59]; //59 is the maximum number of bytes we can read

		{
			if(!quiet_output)
				{
					printf("******************Create File 1*******************\n");
				}
			res = createFile(fid_1,PLAIN);
			if(res != 0)
				{
					return EXIT_FAILURE;
				}

			if(!quiet_output)
				{
					printf("******************Create File 2*******************\n");
				}
			res = createFile(fid_2,MACING);
			if(res != 0)
				{
					return EXIT_FAILURE;
				}

			if(!quiet_output)
				{
					printf("******************Create File 3*******************\n");
				}
			res = createFile(fid_3,ENCRYPTION);
			if(res != 0)
				{
					return EXIT_FAILURE;
				}
			//change key N° keyToAccessFiles
			if(!quiet_output)
			{
				printf("******************Change key*******************\n");
			}
			res = changeKey(keyToAccessFiles);

			if(res !=0)
			{
				return EXIT_FAILURE;
			}
			else
			{
				if(!quiet_output)
				{
					printf("******************Authentication using  access files key*******************\n");
				}
				res = authenticate(keyToAccessFiles,key1,key2,datatest);
				if(res != 0 && !quiet_output)
				{
					printf("Authentication with %d key fails\n",keyToAccessFiles);
					return EXIT_FAILURE;
				}
				else
				{
					//write data into files
					if(!quiet_output)
					{
						printf("******************write data in plain mode*******************\n");
					}
					res = writeData_Plain(fid_1,buf, size_data_w);
					if(res != 0)
					{
						return EXIT_FAILURE;
					}
					if(!quiet_output)
					{
						printf("******************write data in Macing mode*******************\n");
					}
					res = writeData_Mac(fid_2, buf,size_data_w);
					if(res != 0)
					{
						return EXIT_FAILURE;
					}
					if(!quiet_output)
					{
						printf("******************write data in (3)DES encryption mode*******************\n");
					}
					res = writeData_Encryption(fid_3,buf,size_data_w);
					if(res != 0)
					{
						return EXIT_FAILURE;
					}
					//read data from files
					if(!quiet_output)
					{
						printf("******************read all data in plain mode*******************\n");
					}
					res = readData_PlainAndMac(fid_1,buf_I, size_data_r);
					if(res != 0)
					{
						return EXIT_FAILURE;
					}
					if(!quiet_output)
					{
						printf("******************read data in Macing mode*******************\n");
					}
					res = readData_PlainAndMac(fid_2, buf_I,size_data_r);
					if(res != 0)
					{
						return EXIT_FAILURE;
					}
					if(!quiet_output)
					{
						printf("******************read data in (3)DES encryption mode*******************\n");
					}
					res = readData_Encryption(fid_3,buf_I,size_data_r);
					if(res != 0)
					{
						return EXIT_FAILURE;
					}
				}
			}
		}

		//lister et supprimer les fichiers crées ici, car sinon, en exécutant le programme une deuxième fois sur le même programme, on risque d'avoir un pb de mémoire insuffisante, car on supprime l'application
		//qui contient ces fichiers avant d'arriver à cette fonction de gestion de fichiers,
		if(!quiet_output)
		{
			printf("******************List Files in the current application*******************\n");
		}
		//sleep(5);
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
		if(fileInList(fid_1,outputFileList,outputCount))
			{
				if(!quiet_output)
					{
						printf("******************Delete File 1*******************\n");
					}
				res = deleteFile(fid_1);
				if(res != 0)
					{
						return EXIT_FAILURE;
					}
			}
		if(fileInList(fid_2,outputFileList,outputCount))
			{
				if(!quiet_output)
					{
						printf("******************Delete File 2*******************\n");
					}
				res = deleteFile(fid_2);
				if(res != 0)
					{
						return EXIT_FAILURE;
					}
			}

		if(fileInList(fid_3,outputFileList,outputCount))
			{
				if(!quiet_output)
					{
						printf("******************Delete File 3*******************\n");
					}
				res = deleteFile(fid_3);
				if(res != 0)
					{
						return EXIT_FAILURE;
					}
			}
	}

	return EXIT_SUCCESS;
}

int readData_Encryption(unsigned int  FID, uint8_t *buf, int nbyte)
{

	   uint8_t abtTx[MAX_FRAME_LEN];
	   uint8_t response[file_s];
	   uint8_t buffer_o[file_s];
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

	   unsigned int index = 0;
	   int result = transmit_bytes(abtTx, abtTx_size);
	   /*buf = malloc ( response_size);*/
	   if( result && status_word== 0x9100)
		{
			memcpy(buf,abtRx,szRx -2);
		}

	  while( result && status_word == 0x91AF)
		{
			memcpy(buf,abtRx,szRx -2);
			memcpy(response + index, abtRx,szRx -2);
			index += (szRx -2);
			abtTx_size =5;
	   		memcpy(abtTx,readFile2_apdu,abtTx_size);
			result = transmit_bytes(abtTx, abtTx_size);
		}

		if(result && status_word == 0x9100)
		{
			memcpy(response + index, abtRx,szRx -2);
			index += (szRx -2);
			if(!quiet_output)
			{
				printf("*************Encrypted Data******************\n");
				for(int i= 0; i< index; i++)
				{
					printf("%02x", response[i]);
				}
				printf("\n");
			}
			//déchiffrer les données lues
			cypher3(buffer_o,response,index/8);
			if(!quiet_output)
			{
				printf("*************Decrypted Data******************\n");
				print_hex(buffer_o,index);
				printf("\n");
			}
			return EXIT_SUCCESS;
		}
		else
		{
			if(!quiet_output)
			{
				printf("ERROR while reading Data in (3)DES encryption mode\n");
			}
		}

	    return EXIT_FAILURE;
}

void cypher3(uint8_t *output, uint8_t *input, unsigned int nbrIter)
{
	uint8_t k1[8];
	uint8_t k2[8];
	memcpy(k1, session_key, 8);
	memcpy(k2, session_key+8,8);
	//print_hex(session_key,16);
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

int readData_PlainAndMac(unsigned int  FID, uint8_t *buf, int nbyte)
{
	   uint8_t abtTx[MAX_FRAME_LEN];
	   uint8_t response[file_s];
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
	   unsigned int index = 0;
	   int result = transmit_bytes(abtTx, abtTx_size);
	   /*buf = malloc ( response_size);*/
	   if( result && status_word == 0x9100)
		{
			memcpy(buf,abtRx,szRx -2);
		}

	  while( result && status_word == 0x91AF)
		{
			memcpy(buf,abtRx,szRx -2);
			memcpy(response + index, abtRx,szRx -2);
			index += (szRx -2);
			abtTx_size =5;
	   		memcpy(abtTx,readFile2_apdu,abtTx_size);
			result = transmit_bytes(abtTx, abtTx_size);

		}

		if(result && status_word== 0x9100)
		{

			memcpy(response + index, abtRx,szRx -2);
			index += (szRx -2);
			if(!quiet_output)
			{
				printf("*************Received Data******************\n");
				for(int i= 0; i< index; i++)
				{
					printf("%02x", response[i]);
				}
				printf("\n");
			}

			return EXIT_SUCCESS;
		}
		else{
			if(!quiet_output)
			{
				  nfc_perror(pnd, "READ DATA");
				//printf("ERROR while reading Data in plain or Mac modes\n");
			}
		}


	    return EXIT_FAILURE;
}

int writeData_Plain(uint8_t  FID, uint8_t *buf, unsigned int nbyte)
{

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
	    abtTx[9] = nbyte & 0xff;
	    unsigned int i = 0;
	    int result ;
	    for(i=0; i < nbyte && i < 52; i ++)
		{
		  abtTx[12+i] =buf[i];
		}
	    abtTx[12+i] = 0x00;
	    abtTx[4] = 7+i;
	    abtTx_size = 12+i+1;
	    result =  transmit_bytes(abtTx, abtTx_size);
	    if(nbyte > 52){
		nbyte = nbyte - 52;
		off = 52;
	   }
	    while(result && status_word==0x91AF)
		{
			abtTx_size = 4;
			memcpy(abtTx,writeFile2_apdu,abtTx_size);
			for(i=0; i < nbyte && i < 0x3B; i ++)
			{
		 		 abtTx[5+i] =buf[i+off];
			}
			abtTx[5+i] = 0x00;
			abtTx[4] = i;
	        abtTx_size = 5+i+1;
		  	result =  transmit_bytes(abtTx, abtTx_size);

			if(nbyte > 0x3B) {
				nbyte = nbyte -59;
				off += 59;
			}
		}

	    if(!result ||  status_word!= 0x9100)
		{
			if(!quiet_output)
			{
				nfc_perror(pnd, "WRITE DATA IN PLAIN MODE");
				//printf("ERROR while wrting data in plain mode %d \n",result);
			}
			return EXIT_FAILURE;
		}
	    return EXIT_SUCCESS;

}

int writeData_Encryption(uint8_t  FID, uint8_t *buf1, unsigned int nbyte)
{
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
	    //print_hex(buf, nbyte+padding+2);

	    abtTx[11] = (nbyte >> 16) & 0xff;
	    abtTx[10] = (nbyte >> 8) & 0xff;
	    abtTx[9] = (nbyte) & 0xff;
	    unsigned int i = 0;
	    int result ;

	    uint8_t ciphered[nbyte+padding+2];
	    cypher3DES(ciphered, buf, (nbyte + padding +2)/8);
		//print_hex(ciphered,nbyte+padding+2);
	    nbyte += (padding+2);
	    for(i=0; i < nbyte && i < 52; i ++)
		{
		  abtTx[12+i] =ciphered[i];
		}
	    abtTx[12+i] = 0x00;
	    abtTx[4] = 7+i;
	    abtTx_size = 12+i+1;
	    result = transmit_bytes(abtTx, abtTx_size);
	    if(nbyte > 52){
		nbyte = nbyte - 52;
		off = 52;
	   }
	    while(result && status_word==0x91AF)
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
		  	result = transmit_bytes(abtTx, abtTx_size);

			if(nbyte > 0x3B) {
				nbyte = nbyte -59;
				off += 59;
			}
		}

	    if(!result ||  status_word != 0x9100)
		{
			if(!quiet_output)
			{
				nfc_perror(pnd, "WRITE DATA IN (3)DES ENCRYPTION MODE");
				//printf("ERROR while writing Data in (3)DES encryption mode\n");
			}
			return EXIT_FAILURE;
		}
	    return EXIT_SUCCESS;
}

int writeData_Mac(uint8_t  FID, uint8_t *buf, unsigned int nbyte)
{
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
	    unsigned int i = 0;
	    int result;
	    uint8_t input[nbyte+1];
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
	    else if(nbyte%8==0)
	    {
	    	nbrIter = (nbyte/8);
	    }
	    uint8_t o_buffer[nbyte+padding];
		cypher2MAC(o_buffer,input,nbrIter);
		if(nbyte > 52 || i + 4 > 52){
		    abtTx[12+i] = 0x00;
		    abtTx[4] = 7+i;
		    abtTx_size = 12+i+1;
		    result = transmit_bytes(abtTx, abtTx_size);
		    if(nbyte > 52){
		    nbyte = nbyte - 52;
	        off = 52;
		    }
	  	}
		else if(i + 4 <= 52)
		{
				memcpy(abtTx+12+i, MAC, 4);
				abtTx[12+i+4] = 0x00;
		    	abtTx[4] = 7+i+4;
		    	abtTx_size = 12+i+1+4;
		    	result = transmit_bytes(abtTx, abtTx_size);
		}

		while(result && status_word==0x91AF)
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
		  		result = transmit_bytes(abtTx, abtTx_size);
				nbyte = nbyte -59;
				off += 59;
			}
			else if(i +4 <= 59)
			{
				memcpy(abtTx+5+i, MAC, 4);
				abtTx[5+i+4] = 0x00;
				abtTx[4] = i+4;
	         	abtTx_size = 5+i+1+4;
		  		result = transmit_bytes(abtTx, abtTx_size);
			}
		}

	    if(!result ||  status_word != 0x9100)
		{
	    		if(!quiet_output)
	    		{
	    			nfc_perror(pnd, "WRITE DATA IN MACING MODE");
	    			//printf("ERROR while writing Data in Macing mode\n");
	    		}
				return EXIT_FAILURE;
		}

	return EXIT_SUCCESS;
}

void cypher3DES(uint8_t *output, uint8_t *input, unsigned int nbrIter)
{
	uint8_t k1[8];
	uint8_t k2[8];
	// on utilise toute la session key pour faire du triple DES à deux clés
	memcpy(k1, session_key, 8);
	memcpy(k2, session_key+8,8);
	//print_hex(session_key,16);
	uint8_t output1[8];
	uint8_t input1[8];
	memcpy(input1, input,8);
	//print_hex(input1,8);
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


void cypherSimpleDES(uint8_t *output, uint8_t *input, unsigned int nbrIter)
{
	uint8_t k1[8];
	uint8_t k2[8];
	// pour chiffrer, on utilise la première moitié de la session key
	memcpy(k1, session_key, 8);
	memcpy(k2, session_key,8);
	//print_hex(session_key,16);
	uint8_t output1[8];
	uint8_t input1[8];
	memcpy(input1, input,8);
	//print_hex(input1,8);
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

unsigned short crc_16(unsigned char *data, unsigned int len)
{
        unsigned int i;
        unsigned short crc= 0x6363;

        for(i= 0; i < len ; ++i)
                crc=  update_crc16(crc, data[i]);
        return crc;
}

void cypher2MAC(uint8_t *output, uint8_t *input, unsigned int nbrIter)
{
	uint8_t k1[8];
	uint8_t k2[8];
	memcpy(k1, session_key, 8);
	memcpy(k2, session_key+8,8);
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
		DES_ecb2_encrypt((DES_cblock*)input1, (DES_cblock*)output1,&ks1,&ks2, DES_ENCRYPT);
		memcpy(output+(8 * (i+1)) , output1, 8);
	}
	memcpy(MAC, output1, 4);
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

int deleteFile(unsigned int FID)
{
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size;
    int res;

    /*check the AID*/
    if(FID > 0xff )
    {
    	if(!quiet_output)
    	{
    		printf("Invalid FID, expected a value between 0x00 and 0xff, got 0x%06x\n",FID);
    	}

        return EXIT_FAILURE;
    }

    /*prepare the data*/
    abtTx_size = 7;
    memcpy(abtTx,deleteFile_apdu,abtTx_size);
    abtTx[5] = FID & 0xff;

    /*send the data to the card, the expected status word is 0x91 0x00*/
    res = transmit_bytes(abtTx,abtTx_size);

    if(!res  || status_word != 0x9100)
    {
    	if(!quiet_output)
    	{
    		nfc_perror(pnd, "DELETE FILE");
    		//printf("delete File :Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
    	}

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
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

int changeKey(uint8_t keyNo)
{
    uint8_t abtTx[MAX_FRAME_LEN]; /*input buffer          */
    size_t abtTx_size;
    abtTx_size = 5;

    memcpy(abtTx,changeKey_apdu,abtTx_size);
	abtTx[5] = keyNo;
	uint8_t keysettings;
	uint8_t changekey;
	int res;
	uint8_t cmd_data [24];
	unsigned short crc;
	//unsigned short crc_new_key;

	if(getkeySettings(&keysettings) !=0)
		{
			printf("getKeySettings Failure !\n");
		}
	else
		{
			changekey = (keysettings >> 4);
			//printf(" the change key is  %02x\n", changekey);
			if(changekey == 0x0E || changekey == keyNo || keyNo == 0x00)
			{
				/*authentifier avec le numero de clef keyNo --> procedure 2 de changeKey cmd*/
				if(authenticate(keyNo, defaultkey, defaultkey, datatest) == 0)
				{
					memcpy(cmd_data, key1,8); /*je dois faire un xor avant et calculer le crc sur new_key seulement, mais ca revient au meme pour ce test car defaultkey =0*/
					memcpy(cmd_data+8,key2,8);
					crc = crc_16(cmd_data, 16);
					cmd_data[16] = (uint8_t) crc;
					cmd_data[17] = (uint8_t) (crc >> 8);
					uint8_t init[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
					memcpy(cmd_data+18, init, 6);
					//print_hex(cmd_data,24);
					cypher3DES(abtTx+6,cmd_data,3);
				}


			}
			else if(changekey == 0x0F)
			{
				if(!quiet_output)
				{
					printf("change basic key is not allowed\n");
				}

				return EXIT_FAILURE;
			}

			else
			{

				/*authentifier avec la changeKey --> procedure 1 de changekey cmd*/
				if(authenticate(changekey, defaultkey, defaultkey,datatest)==0)
				{
					xor(defaultkey, key1, cmd_data);
					xor(defaultkey, key2, cmd_data+8);
					crc = crc_16(cmd_data, 16);
					cmd_data[16] = (uint8_t) crc ;
					cmd_data[17 ]  =  (uint8_t) (crc >> 8);
					/* dans ces deux octets il faut mettre le crc de la new key */
					cmd_data[18] = (uint8_t) crc;
					cmd_data[19] = (uint8_t) (crc >> 8);
					uint8_t init[4] = {0x00,0x00,0x00,0x00};
					memcpy(cmd_data+20, init, 4);
					cypherSimpleDES(abtTx+6,cmd_data,3);
				}

			}
		}
	abtTx[30]= 0x00;
	abtTx_size = 31;

	res = transmit_bytes(abtTx,abtTx_size);

	if(!res || status_word != 0x9100)
	  {
	     if(!quiet_output)
	       {
	    	    nfc_perror(pnd, "CHANGE KEY");
	        	//printf("Change Key :Invalid status word on request sending, expected 0x9100 got 0x%04x\n",status_word);
	       }
	     return EXIT_FAILURE;
	  }

	return EXIT_SUCCESS;
}







