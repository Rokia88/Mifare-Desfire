/*
 * main.c
 *
 *  Created on: 2 juin 2015
 *      Author: root
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
 * @file nfc-relay-picc.c
 * @brief Relay example using two PN532 devices.
 */

// Notes & differences with nfc-relay:
// - This example only works with PN532 because it relies on
//   its internal handling of ISO14443-4 specificities.
// - Thanks to this internal handling & injection of WTX frames,
//   this example works on readers very strict on timing

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>

#include "nfc/nfc.h"

#include "nfc-utils.h"

#define MAX_FRAME_LEN 264
#define MAX_DEVICE_COUNT 3

#define MYPORT 3480
#define MYIP "127.0.0.1"
//il faut savoir s'il faut mettre l'adresse IP du SCL ou de Asus
#define DEST_IP  "127.0.0.1"
#define DEST_PORT 3490

static uint8_t abtCapdu[MAX_FRAME_LEN];
//uint8_t authentciate[12] = {0x60,0x08,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00};

static uint8_t abtCapdu[MAX_FRAME_LEN];
static size_t szCapduLen;
static uint8_t abtRapdu[MAX_FRAME_LEN];
static size_t szRapduLen;
static nfc_device *pndInitiator;
static nfc_device *pndTarget;
static bool quitting = false;
static bool quiet_output = false;
static bool initiator_only_mode = false;
static bool target_only_mode = false;
static bool swap_devices = false;
static unsigned int waiting_time = 0;
static unsigned int waiting_time2 = 0;
static bool microsecondes = false;
static bool secondes = false;
nfc_target ntEmulatedTarget;
FILE *fd3;
FILE *fd4;

pthread_t ta;

struct in_addr {
        unsigned long s_addr;
    };

struct sockaddr_in {
        short int          sin_family;  /* Famille d'adresse               */
        unsigned short int sin_port;    /* Numéro de Port                  */
        struct in_addr     sin_addr;    /* Adresse Internet                */
        unsigned char      sin_zero[8]; /* Même taille que struct sockaddr */
    };

int sockfd;
struct sockaddr_in dest_addr;   /* Contiendra l'adresse de destination */
struct sockaddr_in my_addr;

static void
intr_hdlr(int sig)
{
  (void) sig;
  printf("\nQuitting...\n");
  printf("Please send a last command to the emulator to quit properly.\n");
  quitting = true;
  return;
}
static int print_hex_fd4(const uint8_t *pbtData, const size_t szBytes, const char *pchPrefix)
{
  size_t  szPos;
  if (szBytes > MAX_FRAME_LEN) {
    return -1;
  }
  if (fprintf(fd4, "#%s %04" PRIxPTR ": ", pchPrefix, szBytes) < 0) {
    return -1;
  }

  for (szPos = 0; szPos < szBytes; szPos++) {
    if (fprintf(fd4, "%02x ", pbtData[szPos]) < 0) {
      return -1;
    }
  }
  if (fprintf(fd4, "\n") < 0) {
    return -1;
  }
  fflush(fd4);
  return 0;
}

static int scan_hex_fd3(uint8_t *pbtData, size_t *pszBytes, const char *pchPrefix)
{
  size_t  szPos;
  unsigned int uiBytes;
  unsigned int uiData;
  char pchScan[256];
  int c;
  // Look for our next sync marker
  while ((c = fgetc(fd3)) != '#') {
    if (c == EOF) {
      return -1;
    }
  }
  strncpy(pchScan, pchPrefix, 250);
  pchScan[sizeof(pchScan) - 1] = '\0';
  strcat(pchScan, " %04x:");
  if (fscanf(fd3, pchScan, &uiBytes) < 1) {
    return -1;
  }
  *pszBytes = uiBytes;
  if (*pszBytes > MAX_FRAME_LEN) {
    return -1;
  }
  for (szPos = 0; szPos < *pszBytes; szPos++) {
    if (fscanf(fd3, "%02x", &uiData) < 1) {
      return -1;
    }
    pbtData[szPos] = uiData;
  }
  return 0;
}

static void *task_a (void *p_data)
{
   //int result = 0;
   //time_t *sleeptime = (time_t *)p_data;
   //unsigned int counter = (unsigned int) p_data;
   uint8_t R[2] = {0xF2, 0x01};
   //time_t startTime = time(NULL);
   unsigned int i = 0;
   do
   {
	   if (nfc_target_send_bytes(pndTarget, R, sizeof(R), 0) < 0) {
	         nfc_perror(pndTarget, "nfc_target_send_bytes");
	         if (!target_only_mode) {
	         		 nfc_close(pndInitiator);
	       }
	         if (!initiator_only_mode) {
	        nfc_close(pndTarget);
	      }
	         printf("noSend\n");
	   //result = -1;
	   break;
	 }
	  i++;
	  printf("WTX:");
	  print_hex(R,sizeof(R));
	  //sleep(1);
   }while(1);//while(i != counter); //
   //printf("ouuttttt");
   //while(((time(NULL) - startTime) < (*sleeptime)) && ((time(NULL) -startTime )>= fwt_minus_one));
   return NULL;
}

static void
print_usage(char *argv[])
{
  printf("Usage: %s [OPTIONS]\n", argv[0]);
  printf("Options:\n");
  printf("\t-h\tHelp. Print this message.\n");
  printf("\t-q\tQuiet mode. Suppress printing of relayed data (improves timing).\n");
  printf("\t-t\tTarget mode only (the one on reader side). Data expected from FD3 to FD4.\n");
  printf("\t-i\tInitiator mode only (the one on tag side). Data expected from FD3 to FD4.\n");
  printf("\t-n N\tAdds a waiting time of N seconds (integer) in the relay to mimic long distance.\n");
  printf("\t-m m\tAdds a waiting time of m micro-secondes in the relay to mimic long distance (par exemple pour un délai de 0.5s, il faut écrire 500000) .\n");
}

static int  lenght(const uint8_t *abtx)
{
	int len = 0;
	while(abtx[len] != 0)
	{
		len ++;
	}
	return len;
}

void flush(int size)
{
	int i =0;
	for(i=0; i < size; i++)
	{
		abtRapdu[i] = 0;
	}

}


int
main(int argc, char *argv[])
{
	  int     arg;
	  const char *acLibnfcVersion = nfc_version();
	  nfc_target ntRealTarget;

	  // Get commandline options
	  for (arg = 1; arg < argc; arg++) {
	    if (0 == strcmp(argv[arg], "-h")) {
	      print_usage(argv);
	      exit(EXIT_SUCCESS);
	    } else if (0 == strcmp(argv[arg], "-q")) {
	      quiet_output = true;
	    } else if (0 == strcmp(argv[arg], "-t")) {
	      printf("INFO: %s\n", "Target mode only.");
	      initiator_only_mode = false;
	      target_only_mode = true;
	    } else if (0 == strcmp(argv[arg], "-i")) {
	      printf("INFO: %s\n", "Initiator mode only.");
	      initiator_only_mode = true;
	      target_only_mode = false;
	    } else if (0 == strcmp(argv[arg], "-s")) {
	      printf("INFO: %s\n", "Swapping devices.");
	      swap_devices = true;
	    } else if (0 == strcmp(argv[arg], "-n")) {
	      if (++arg == argc || (sscanf(argv[arg], "%10u", &waiting_time) < 1)) {
	        ERR("Missing or wrong waiting time value: %s.", argv[arg]);
	        print_usage(argv);
	        exit(EXIT_FAILURE);
	      }
	      printf("Waiting time: %u secs.\n", waiting_time);
	    } else if (0 == strcmp(argv[arg], "-m")) {
	        if (++arg == argc || (sscanf(argv[arg], "%10u", &waiting_time2) < 1)) {
	          ERR("Missing or wrong waiting time value: %s.", argv[arg]);
	          print_usage(argv);
	          exit(EXIT_FAILURE);
	      }
	      microsecondes = true;
	      printf("Waiting time: %d μs.\n", waiting_time2);
	    }else {
	      ERR("%s is not supported option.", argv[arg]);
	      print_usage(argv);
	      exit(EXIT_FAILURE);
	    }
	  }

	  // Display libnfc version
	  printf("%s uses libnfc %s\n", argv[0], acLibnfcVersion);

	#ifdef WIN32
	  signal(SIGINT, (void (__cdecl *)(int)) intr_hdlr);
	#else
	  signal(SIGINT, intr_hdlr);
	#endif

	  nfc_context *context;
	  nfc_init(&context);
	  if (context == NULL) {
	    ERR("Unable to init libnfc (malloc)");
	    exit(EXIT_FAILURE);
	  }

	  nfc_connstring connstrings[MAX_DEVICE_COUNT];
	  // List available devices
	  size_t szFound = nfc_list_devices(context, connstrings, MAX_DEVICE_COUNT);

	  if (szFound < 1) {
	      ERR("No device found");
	      nfc_exit(context);
	      exit(EXIT_FAILURE);
	    }

	    // Try to find a ISO 14443-4A tag
	    nfc_modulation nm = {
	      .nmt = NMT_ISO14443A,
	      .nbr = NBR_UNDEFINED,
	    };

	  if (!initiator_only_mode) {
	    ntEmulatedTarget.nm.nmt = NMT_ISO14443A;
	    ntEmulatedTarget.nm.nbr = NBR_106;
	    ntEmulatedTarget.nti.nai.abtAtqa[0] = 0x00;
	    ntEmulatedTarget.nti.nai.abtAtqa[1] = 0x04;

	    uint8_t uid[] = {0x08,0xd3, 0x63,0x29};
	    ntEmulatedTarget.nti.nai.abtUid[0] = uid[0];
	    ntEmulatedTarget.nti.nai.abtUid[1] = uid[1];
	    ntEmulatedTarget.nti.nai.abtUid[2] = uid[2];
	    ntEmulatedTarget.nti.nai.abtUid[3] = uid[3];
	    // We can only emulate a short UID, so fix length & ATQA bit:
	    ntEmulatedTarget.nti.nai.szUidLen = 4;
	    //ntEmulatedTarget.nti.nai.abtAtqa[1] &= (0xFF - 0x40);
	    // First byte of UID is always automatically replaced by 0x08 in this mode anyway
	    //ntEmulatedTarget.nti.nai.abtUid[0] = 0x08;

	    // ATS is always automatically replaced by PN532, we've no control on it:
	    // ATS = (05) 75 33 92 03
	    //       (TL) T0 TA TB TC
	    //             |  |  |  +-- CID supported, NAD supported
	    //             |  |  +----- FWI=9 SFGI=2 => FWT=154ms, SFGT=1.21ms
	    //             |  +-------- DR=2,4 DS=2,4 => supports 106, 212 & 424bps in both directions
	    //             +----------- TA,TB,TC, FSCI=5 => FSC=64
	    // It seems hazardous to tell we support NAD if the tag doesn't support NAD but I don't know how to disable it
	    // PC/SC pseudo-ATR = 3B 80 80 01 01 if there is no historical bytes

	    // Creates ATS and copy max 48 bytes of Tk:
	    //ntEmulatedTarget.nti = ntRealTarget.nti;
	    uint8_t *pbtTk;
	    size_t szTk;
	    pbtTk = iso14443a_locate_historical_bytes(ntEmulatedTarget.nti.nai.abtAts, ntEmulatedTarget.nti.nai.szAtsLen, &szTk);
	    szTk = (szTk > 48) ? 48 : szTk;
	    uint8_t pbtTkt[48];
	    memcpy(pbtTkt, pbtTk, szTk);
	    ntEmulatedTarget.nti.nai.abtAts[0] = 0x75;
	    ntEmulatedTarget.nti.nai.abtAts[1] = 0x33;
	    ntEmulatedTarget.nti.nai.abtAts[2] = 0xE2;
	    ntEmulatedTarget.nti.nai.abtAts[3] = 0x03;
	    ntEmulatedTarget.nti.nai.szAtsLen = 4 + szTk;
	    memcpy(&(ntEmulatedTarget.nti.nai.abtAts[4]), pbtTkt, szTk);
	    ntEmulatedTarget.nti.nai.btSak = 0x20;

	    printf("We will emulate:\n");
	    print_nfc_target(&ntEmulatedTarget, false);

	    // Try to open the NFC emulator device
	   /* if (swap_devices) {
	      pndTarget = nfc_open(context, connstrings[1]);
	    } else {*/
	      pndTarget = nfc_open(context, connstrings[0]);
	    //}
	    if (pndTarget == NULL) {
	      printf("Error opening NFC emulator device\n");
	      if (!target_only_mode) {
	        nfc_close(pndInitiator);
	      }
	      nfc_exit(context);
	      exit(EXIT_FAILURE);
	    }

	    printf("NFC emulator device: %s opened\n", nfc_device_get_name(pndTarget));

	    sockfd = socket(AF_INET, SOCK_STREAM, 0); /* Vérification d'erreurs! */

	        dest_addr.sin_family = AF_INET;        /* host byte order */
	        dest_addr.sin_port = htons(DEST_PORT); /* short, network byte order */
	        dest_addr.sin_addr.s_addr = inet_addr(DEST_IP);
	        bzero(&(dest_addr.sin_zero), 8);       /* zéro pour le reste de la struct */

	       /* ne pas oublier les tests d'erreur pour connect()! */
	    if(connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr)) < 0)
	       {
	    	   printf("connect error..\n");
	    	   exit(-1);
	       }

    printf("NFC emulator device: %s opened\n", nfc_device_get_name(pndTarget));
    if (nfc_target_init(pndTarget, &ntEmulatedTarget, abtCapdu, sizeof(abtCapdu), 0) < 0) {
      ERR("%s", "Initialization of NFC emulator failed");
      if (!target_only_mode) {
        nfc_close(pndInitiator);
      }
      nfc_close(pndTarget);
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }
    printf("%s\n", "Done, relaying frames now!");
    //nfc_device_set_property_bool(pndTarget,NP_AUTO_ISO14443_4 ,true);

  }

  if(nfc_device_set_property_bool(pndTarget,NP_EASY_FRAMING ,false) < 0)
      {
      	nfc_perror(pndTarget, "nfc_device_set_property_bool");
      	nfc_close(pndTarget);
      	nfc_exit(context);
      	exit(EXIT_FAILURE);
      }

  while (!quitting) {
      bool ret;
      int res = 0;
      int i = 0;
      bool chainning = false;
      //uint8_t T[MAX_FRAME_LEN];
      uint8_t TChainning[MAX_FRAME_LEN];
      uint8_t R[MAX_FRAME_LEN];
      if (!initiator_only_mode) {
      // Receive external reader command through target
  label:
        if ((res = nfc_target_receive_bytes(pndTarget, abtCapdu, sizeof(abtCapdu), 0)) < 0) {
          nfc_perror(pndTarget, "nfc_target_receive_bytes");
          printf("%d ",res);
          if (!target_only_mode) {
            nfc_close(pndInitiator);
          }
          nfc_close(pndTarget);
          nfc_exit(context);
          exit(EXIT_FAILURE);
        }
        szCapduLen = (size_t) res;
        if (!quiet_output) {
              printf("Forwarding C-APDU: ");
              print_hex(abtCapdu, szCapduLen);
            }

        if(abtCapdu[0] == 0xE0)
        {
        	uint8_t ATS[ntEmulatedTarget.nti.nai.szAtsLen+1];
        	ATS[0] = ntEmulatedTarget.nti.nai.szAtsLen+1;
        	memcpy(ATS+1,ntEmulatedTarget.nti.nai.abtAts,ntEmulatedTarget.nti.nai.szAtsLen);
        	 if (nfc_target_send_bytes(pndTarget, ATS,ntEmulatedTarget.nti.nai.szAtsLen+1, 0) < 0) {
        	      		          nfc_perror(pndTarget, "nfc_target_send_bytes");
        	      		          if (!target_only_mode) {
        	      		            nfc_close(pndInitiator);
        	      		          }
        	      		          if (!initiator_only_mode) {
        	      		            nfc_close(pndTarget);
        	      		          }
        	      		          nfc_exit(context);
        	      		          exit(EXIT_FAILURE);
        	  }

        	 printf("ATS:");
        	 print_hex(ATS,ntEmulatedTarget.nti.nai.szAtsLen+1);

        	 goto label;
        }


        if(((abtCapdu[0] >> 6) | 0x00) == 0)
        {
      	  //I-Block with chainning
      	  if(((abtCapdu[0] >> 4) | 0x00) == 0x01)
      	  {
      		  chainning = true;
      		  szCapduLen -=1;
      		  memcpy(TChainning+i,abtCapdu+1,szCapduLen);
      		  uint8_t ack[] = {0xA0 | (abtCapdu[0] & 0x0F)};
      		  printf("ack:");
      		  print_hex(ack,1);
      		  if (nfc_target_send_bytes(pndTarget, ack, 1, 0) < 0) {
      		          nfc_perror(pndTarget, "nfc_target_send_bytes");
      		          if (!target_only_mode) {
      		            nfc_close(pndInitiator);
      		          }
      		          if (!initiator_only_mode) {
      		            nfc_close(pndTarget);
      		          }
      		          nfc_exit(context);
      		          exit(EXIT_FAILURE);
      		  }

      		  //szCapduLen -= 1;
      		  i+=szCapduLen;
      		  goto label;
      	  }
      	  //I-Block without chainning
      	  else{
      		  szCapduLen -=1;
      		  memcpy(TChainning+i,abtCapdu+1,szCapduLen);
      		  if(chainning)
      		  {
      			  szCapduLen += i;
      		  }
      	  }

        }
        //R-Block
        else if(((abtCapdu[0] >> 6) | 0x00) == 0x02)
        {
           //R(Nack)
      	  if(((abtCapdu[0] >> 4) == 0x0b) && ((abtCapdu[0] & R[0]) == R[0]))
      	  {
      		  if (nfc_target_send_bytes(pndTarget, R, szRapduLen, 0) < 0) {
      		      		          nfc_perror(pndTarget, "nfc_target_send_bytes");
      		      		          if (!target_only_mode) {
      		      		            nfc_close(pndInitiator);
      		      		          }
      		      		          if (!initiator_only_mode) {
      		      		            nfc_close(pndTarget);
      		      		          }
      		      		          nfc_exit(context);
      		      		          exit(EXIT_FAILURE);
      		      		  }
      		  printf("Retransmission of RAPDU:");
      		  print_hex(R,szRapduLen);
      		  goto label;
      	  }
      	  else if(((abtCapdu[0] >> 4) == 0x0b) && ((abtCapdu[0] & R[0]) != R[0]))
      	  {
      		  uint8_t ack[] = {0xA0 | (abtCapdu[0] & 0x0F)};
      		  printf("ack:");
      		  print_hex(ack,1);
      		  if (nfc_target_send_bytes(pndTarget, ack, 1, 0) < 0) {
      		      		nfc_perror(pndTarget, "nfc_target_send_bytes");
      		      		if (!target_only_mode) {
      		      		    nfc_close(pndInitiator);
      		      		}
      		      		if (!initiator_only_mode) {
      		      		    nfc_close(pndTarget);
      		      		}
      		      		 nfc_exit(context);
      		      		 exit(EXIT_FAILURE);
      		     }
      		  printf("Send R(ack):");
      		  print_hex(ack,1);
      		  goto label;
      	  }
           //memcpy(TChainning,abtCapdu,szCapduLen);
        }
        //S-Block
        else if(((abtCapdu[0] >> 6) | 0x00 )== 0x03)
        {
      	  //Deselect
      	  memcpy(TChainning,abtCapdu,szCapduLen);
      	  printf("Deselect Response:");
      	  print_hex(TChainning,szCapduLen);
      	  goto label1;
        }
      }
      // Show transmitted response
      if (!quiet_output) {
      	printf("Forwarding C-APDU: ");
      	print_hex(TChainning, szCapduLen);
      }

      //if (ret) {
        // Redirect the answer back to the external reader

    	  // send TCP/IP
    	   int len =  send(sockfd, abtCapdu, szCapduLen, 0);
    	   if(len != szCapduLen || len < 0 )
    	   	   {
    	  		 quitting = true;
    	  		 continue;
    	  	 }
    	   pthread_create (&ta, NULL, task_a, NULL);
    	      //receive TCP/IP
    	  	 if((len= recv(sockfd , abtRapdu, sizeof(abtRapdu), 0)) < 0)
    	  	 {
    	  	 	quitting = true;
    	  	 	continue;
    	  	 }
    	  	//sleep(2);
    	  	pthread_cancel(ta);
    	  	 //szRapduLen = lenght(abtRapdu);
    	  	 szRapduLen = (size_t) len;
    	  	 if(szRapduLen==0)
    	  	 {
    	  		 szRapduLen = 1;
    	  	 }

        // Show transmitted response
        if (!quiet_output) {
          printf("Forwarding R-APDU: ");
          print_hex(abtRapdu, szRapduLen);
        }
        if (!initiator_only_mode) {

      	  if(((abtCapdu[0] >> 6) | 0x00) == 0)
      	  {
      		  //I-Block
      		  R[0] = abtCapdu[0];
      		  memcpy(R+1,abtRapdu,szRapduLen);
      		  szRapduLen +=1;
      	  }
      	  else if(((abtCapdu[0] >> 6) | 0x00) == 0x02)
      	  {
      		  //R-Block
      		  memcpy(R,abtRapdu,szRapduLen);
      	  }

      	  else if(((abtCapdu[0] >> 6) | 0x00 )== 0x03)
      	  {
      		  //S-Block
      		  // le cas de deselect est géré à la réception de la commande plus haut
      	  }
      	  if (!quiet_output) {
      	          printf("Forwarding R-APDU: ");
      	          print_hex(R, szRapduLen);
      	 }

          // Transmit the response bytes
  label1:
          if (nfc_target_send_bytes(pndTarget, R, szRapduLen, 0) < 0) {
            nfc_perror(pndTarget, "nfc_target_send_bytes");
            if (!target_only_mode) {
              nfc_close(pndInitiator);
            }
            if (!initiator_only_mode) {
              nfc_close(pndTarget);
            }
            nfc_exit(context);
            exit(EXIT_FAILURE);
          }
        }
      }
    //}

  if (!target_only_mode) {
    nfc_close(pndInitiator);
  }
  if (!initiator_only_mode) {
    nfc_close(pndTarget);
  }
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}




