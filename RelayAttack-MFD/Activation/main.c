/*
 * main.c
 *
 *  Created on: 26 avr. 2015
 *      Author: rokia
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <string.h>
#include <ctype.h>

#include <nfc/nfc.h>


#include "nfc-utils.h"

#define MAX_DEVICE_COUNT 2

static nfc_context *context;
static nfc_device *pnd;
static nfc_device *pnd;
static nfc_target nt;

static const nfc_modulation nmMifare = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};


int main(int argc, char *argv[])
{

	nfc_init(&context);
		    if (context == NULL) {
		      ERR("Unable to init libnfc (malloc)");
		      exit(EXIT_FAILURE);
		   }
		    nfc_connstring connstrings[MAX_DEVICE_COUNT];
		     size_t szFound = nfc_list_devices(context, connstrings, MAX_DEVICE_COUNT);
		     printf("**************%u \n",szFound);

		  uint8_t *pbtUID;
		  // Try to open the NFC reader
		  pnd = nfc_open(context, connstrings[0]);
		  if (pnd == NULL) {
		    ERR("Error opening NFC reader");
		    nfc_exit(context);
		    exit(EXIT_FAILURE);
		  }

		  if (nfc_initiator_init(pnd) < 0) {
		    nfc_perror(pnd, "nfc_initiator_init");
		    nfc_close(pnd);
		    nfc_exit(context);
		    exit(EXIT_FAILURE);
		  };

		  printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

		  	   // Try to find a MIFARE Classic tag
		  	  if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
		  	    printf("Error: no tag was found\n");
		  	    nfc_close(pnd);
		  	    nfc_exit(context);
		  	    exit(EXIT_FAILURE);
		  }

		  	print_nfc_target(&nt, false);
		  	sleep(30);

}
