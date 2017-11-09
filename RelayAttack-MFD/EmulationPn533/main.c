/*
 * main.c
 *
 *  Created on: 24 mai 2015
 *      Author: root
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <math.h>
#include <nfc/nfc.h>

#include "nfc-utils.h"

#define MAX_FRAME_LEN 264
#define MAX_DEVICE_COUNT 2
#define CST 10
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
pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

intr_hdlr(int sig)
{
  (void) sig;
  printf("\nQuitting...\n");
  printf("Please send a last command to the emulator to quit properly.\n");
  quitting = true;
  return;
}

unsigned dix_puissance_n(unsigned n)
{
    unsigned i, res = 1;

    for(i = 0; i < n; i++)
        res *= 10;

    return res;
}

double arrondi(const double x, unsigned n)
{
    unsigned N = dix_puissance_n(n);
    return floor(x * N + 0.5) / N;
}

/*static void *task_a (void *p_data)
{
	double fwt_minus_one = 4;
	fwt_minus_one = arrondi(fwt_minus_one,2);
	//unsigned int nbrSWTX = (unsigned int) ((waiting_time/fwt_minus_one) +1);
	long clk_tck = CLOCKS_PER_SEC;
	clock_t stop = 0;
	unsigned int i;
	clock_t start = 0;
	unsigned int counter = 0;
	double duration = 0;
	do{
    start = clock();
    stop = 0;
	do{
		 for(i=0; i <= 1000;i++)
		  {
		        	//printf("*****%u\n",i);
		   }
		  stop += clock();
		  duration = (double) (stop - start)/(double) clk_tck;
		  duration = arrondi(duration,2);
		  printf("duration %lf\n",duration);
	}while(duration < fwt_minus_one);
    uint8_t R[2] = {0xF2, 0x01};
    if (nfc_target_send_bytes(pndTarget, R, sizeof(R), 0) < 0) {
  	         nfc_perror(pndTarget, "nfc_target_send_bytes");
  	         if (!target_only_mode) {
  	         		 nfc_close(pndInitiator);
  	       }
  	         if (!initiator_only_mode) {
  	        nfc_close(pndTarget);
  	      }
  	         printf("noSend\n");
    }
    printf("WTX:");
    print_hex(R,sizeof(R));
    counter ++;
    //sleep(1);
	}while(counter < 10);
   //return NULL;
}*/

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
      secondes = true;
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

  if (initiator_only_mode || target_only_mode) {
    if (szFound < 1) {
      ERR("No device found");
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }
    if ((fd3 = fdopen(3, "r")) == NULL) {
      ERR("Could not open file descriptor 3");
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }
    if ((fd4 = fdopen(4, "r")) == NULL) {
      ERR("Could not open file descriptor 4");
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }
  } else {
    if (szFound < 2) {
      ERR("%" PRIdPTR " device found but two opened devices are needed to relay NFC.", szFound);
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }
  }

  if (!target_only_mode) {
    // Try to open the NFC reader used as initiator
    // Little hack to allow using initiator no matter if
    // there is already a target used locally or not on the same machine:
    // if there is more than one readers opened we open the second reader
    // (we hope they're always detected in the same order)
    if ((szFound == 1) || swap_devices) {
      pndInitiator = nfc_open(context, connstrings[0]);
    } else {
      pndInitiator = nfc_open(context, connstrings[0]);
    }

    if (pndInitiator == NULL) {
      printf("Error opening NFC reader\n");
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }

    printf("NFC reader device: %s opened\n", nfc_device_get_name(pndInitiator));

    if (nfc_initiator_init(pndInitiator) < 0) {
      printf("Error: fail initializing initiator\n");
      nfc_close(pndInitiator);
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }

    // Try to find a ISO 14443-4A tag
    nfc_modulation nm = {
      .nmt = NMT_ISO14443A,
      .nbr = NBR_106,
    };
    if (nfc_initiator_select_passive_target(pndInitiator, nm, NULL, 0, &ntRealTarget) <= 0) {
      printf("Error: no tag was found\n");
      nfc_close(pndInitiator);
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }

    printf("Found tag:\n");
    print_nfc_target(&ntRealTarget, false);
    if (initiator_only_mode) {
      if (print_hex_fd4(ntRealTarget.nti.nai.abtUid, ntRealTarget.nti.nai.szUidLen, "UID") < 0) {
        fprintf(stderr, "Error while printing UID to FD4\n");
        nfc_close(pndInitiator);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
      if (print_hex_fd4(ntRealTarget.nti.nai.abtAtqa, 2, "ATQA") < 0) {
        fprintf(stderr, "Error while printing ATQA to FD4\n");
        nfc_close(pndInitiator);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
      if (print_hex_fd4(&(ntRealTarget.nti.nai.btSak), 1, "SAK") < 0) {
        fprintf(stderr, "Error while printing SAK to FD4\n");
        nfc_close(pndInitiator);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
      if (print_hex_fd4(ntRealTarget.nti.nai.abtAts, ntRealTarget.nti.nai.szAtsLen, "ATS") < 0) {
        fprintf(stderr, "Error while printing ATS to FD4\n");
        nfc_close(pndInitiator);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
    }
  }
  if (initiator_only_mode) {
    printf("Hint: tag <---> *INITIATOR* (relay) <-FD3/FD4-> target (relay) <---> original reader\n\n");
  } else if (target_only_mode) {
    printf("Hint: tag <---> initiator (relay) <-FD3/FD4-> *TARGET* (relay) <---> original reader\n\n");
  } else {
    printf("Hint: tag <---> initiator (relay) <---> target (relay) <---> original reader\n\n");
  }
  if (!initiator_only_mode) {
    ntEmulatedTarget.nm .nmt = NMT_ISO14443A;
    ntEmulatedTarget.nm.nbr = NBR_106;

    if (target_only_mode) {
      size_t foo;
      if (scan_hex_fd3(ntEmulatedTarget.nti.nai.abtUid, &(ntEmulatedTarget.nti.nai.szUidLen), "UID") < 0) {
        fprintf(stderr, "Error while scanning UID from FD3\n");
        nfc_close(pndInitiator);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
      if (scan_hex_fd3(ntEmulatedTarget.nti.nai.abtAtqa, &foo, "ATQA") < 0) {
        fprintf(stderr, "Error while scanning ATQA from FD3\n");
        nfc_close(pndInitiator);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
      if (scan_hex_fd3(&(ntEmulatedTarget.nti.nai.btSak), &foo, "SAK") < 0) {
        fprintf(stderr, "Error while scanning SAK from FD3\n");
        nfc_close(pndInitiator);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
      if (scan_hex_fd3(ntEmulatedTarget.nti.nai.abtAts, &(ntEmulatedTarget.nti.nai.szAtsLen), "ATS") < 0) {
        fprintf(stderr, "Error while scanning ATS from FD3\n");
        nfc_close(pndInitiator);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
    } else {
      ntEmulatedTarget.nti = ntRealTarget.nti;
    }
    // We can only emulate a short UID, so fix length & ATQA bit:
    ntEmulatedTarget.nti.nai.szUidLen = 4;
    ntEmulatedTarget.nti.nai.abtAtqa[1] &= (0xFF - 0x40);
    // First byte of UID is always automatically replaced by 0x08 in this mode anyway
    ntEmulatedTarget.nti.nai.abtUid[0] = 0x08;
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

    printf("We will emulate:\n");
    print_nfc_target(&ntEmulatedTarget, false);

    // Try to open the NFC emulator device
    if (swap_devices) {
      pndTarget = nfc_open(context, connstrings[1]);
    } else {
      pndTarget = nfc_open(context, connstrings[1]);
    }
    if (pndTarget == NULL) {
      printf("Error opening NFC emulator device\n");
      if (!target_only_mode) {
        nfc_close(pndInitiator);
      }
      nfc_exit(context);
      exit(EXIT_FAILURE);
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


      if (!target_only_mode) {
        // Forward the frame to the original tag
        if ((res = nfc_initiator_transceive_bytes(pndInitiator, TChainning, szCapduLen , abtRapdu, sizeof(abtRapdu), -1)) < 0) {
          ret = false;
        } else {
          szRapduLen = (size_t) res;
          ret = true;
        }
      }

      if (ret) {
        // Redirect the answer back to the external reader
        if (waiting_time != 0 || waiting_time2 !=0) {
          if (!quiet_output) {
          	if(microsecondes)
          	{
          		printf("Waiting %uμs to simulate longer relay...\n", waiting_time2);
          	}
          	if(secondes){
          		printf("Waiting %us to simulate longer relay...\n", waiting_time);
          	}

          }
          if(microsecondes)
          {
        	//pthread_create (&ta, NULL, task_a,(time_t) (waiting_time2*1000000));
        	/*if(*r == -1)
        	{
        		nfc_exit(context);
        		exit(EXIT_FAILURE);
        	}*/
          	usleep(waiting_time2);
          	//pthread_cancel(ta);
          	//pthread_join (ta, NULL);
          }
          if(secondes){

        	  unsigned int i = 0;
        	  //on a besoin d'envoyer des S(WTX) que quand le délai est supérieur ou égale à 15s car, sinon pour des délais inférieurs, la valeur de la FWT et les 3 R(NAK) sont suffisants.
        	  if(waiting_time >15){
        	  for(i=0; i < waiting_time;i++)
        	  {
        		  uint8_t S[2] = {0xF2, 0x01};
        		     if (nfc_target_send_bytes(pndTarget, S, sizeof(S), 0) < 0) {
        		   	         nfc_perror(pndTarget, "nfc_target_send_bytes");
        		   	         if (!target_only_mode) {
        		   	         		 nfc_close(pndInitiator);
        		   	       }
        		   	         if (!initiator_only_mode) {
        		   	        nfc_close(pndTarget);
        		   	      }
        		   	         printf("noSend\n");
        		     }
        		     sleep(1);
        	  }
        	  }
        	 else{
        		  sleep(waiting_time);
        	 }

        	//unsigned int nbrSWTX = (unsigned int) (waiting_time/fwt_minus_one);
        	//pthread_create (&ta, NULL, task_a, NULL);
        	/*pthread_mutex_lock(&mutex);
        	pthread_cond_wait(&condition,&mutex);
        	pthread_mutex_unlock(&mutex);*/
        	//pthread_join(ta, NULL);
        	//pthread_create (&tb, NULL, task_b, (unsigned int) (waiting_time));
        	/**/
        	//pthread_cancel(ta);
          	//sleep(waiting_time);
          }

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
    }

  if (!target_only_mode) {
    nfc_close(pndInitiator);
  }
  if (!initiator_only_mode) {
    nfc_close(pndTarget);
  }
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
