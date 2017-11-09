/*
 * main.c
 *
 *  Created on: 2 juin 2015
 *      Author: root
 */
/*
 * insa_faux_reader.c
 *
 *  Created on: 25 avr. 2015
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
#include "config.h"
#endif // HAVE_CONFIG_H

#define MAX_DEVICE_COUNT 1

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>

#include <nfc/nfc.h>

#include "nfc-utils.h"

#define MYPORT 3490
#define MYIP "127.0.0.1"
//il faut savoir s'il faut mettre l'adresse IP du SCL ou de Asus
#define DEST_IP  "127.0.0.1"
#define DEST_PORT 3480
#define BACKLOG 1

#define MAX_FRAME_LEN 264

static uint8_t abtCapdu[MAX_FRAME_LEN];
static size_t szCapduLen;
static uint8_t abtRapdu[MAX_FRAME_LEN];
static size_t szRapduLen;
static int status_word;
static nfc_device *pnd;

struct in_addr {
        unsigned long s_addr;
    };

struct sockaddr_in {
        short int          sin_family;  /* Famille d'adresse               */
        unsigned short int sin_port;    /* Numéro de Port                  */
        struct in_addr     sin_addr;    /* Adresse Internet                */
        unsigned char      sin_zero[8]; /* Même taille que struct sockaddr */
    };

int sockfd, new_fd,sin_size,len;
struct sockaddr_in faux_reader_addr;
struct sockaddr_in faux_tag_addr;



bool    iso_ats_supported = false;
size_t timeout = -1;
static bool quitting = false;

static void
intr_hdlr(int sig)
{
  (void) sig;
  printf("\nQuitting...\n");
  printf("Please send a last command to the emulator to quit properly.\n");
  quitting = true;
  return;
}

static  bool transmit_bytes(const uint8_t *pbtTx, const size_t szTx)
{
	int res;
    if ((res = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRapdu, sizeof(abtRapdu),timeout)) < 0)
    {
       return false;
    }
    szRapduLen = (size_t) res;
    status_word = abtRapdu[res-2];
    status_word = (status_word<<8) + abtRapdu[res-1];

    // Succesful transfer
    return true;
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
		abtCapdu[i] = 0;
	}

}

int main()
{

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
	 size_t szFound = nfc_list_devices(context, connstrings, MAX_DEVICE_COUNT);
	// Try to open the NFC reader
	pnd = nfc_open(context, connstrings[0]);

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

	 nfc_target ntTarget;
	 if (nfc_initiator_select_passive_target(pnd, nm, NULL, 0, &ntTarget) <= 0) {
	       printf("Error: no tag was found\n");
	       nfc_close(pnd);
	       nfc_exit(context);
	       exit(EXIT_FAILURE);
	}

	 printf("Found tag:\n");
	 print_nfc_target(&ntTarget, false);




	 sockfd = socket(AF_INET, SOCK_STREAM, 0);

	 if(sockfd == -1)
	 {
		 exit(-1);
	 }

	 int yes = 1;
	 if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
		     perror("setsockopt");
		     exit(1);
		 }

	 faux_reader_addr.sin_family = AF_INET;
	 faux_reader_addr.sin_port = htons(MYPORT);
	 //faux_reader_addr.sin_port = 0;
	 faux_reader_addr.sin_addr.s_addr = htonl(MYIP);
	 //faux_reader_addr.sin_addr.s_addr =
	 bzero(&(faux_reader_addr.sin_zero), 8);

	 faux_tag_addr.sin_family = AF_INET;
	 faux_tag_addr.sin_port = htons(DEST_PORT);
	 faux_tag_addr.sin_addr.s_addr = htonl(DEST_IP);
	 bzero(&(faux_tag_addr.sin_zero), 8);
	 int res;

	 res = bind(sockfd, (struct sockaddr *)&faux_reader_addr, sizeof(struct sockaddr_in));
	 if( res < 0)
	 {
		 perror("bind");
		 close(sockfd);
		 exit(-1);
	 }

	 if( listen(sockfd, BACKLOG) < 0)
	 {
		 printf("listen error..\n");
		 close(sockfd);
		 exit(-1);
	 }

	 sin_size = sizeof(struct sockaddr_in);
	 new_fd = accept(sockfd, &faux_tag_addr, &sin_size);
	 if(new_fd == -1)
	 {
		 printf("accept error..\n");
		 exit(-1);
	 }

	 do
	 {
		 if((res =recv(new_fd , abtCapdu, sizeof(abtCapdu), 0)) < 0)
		 {
			 quitting = true;
			 continue;
		 }

		 //szCapduLen = lenght(abtCapdu);
		 szCapduLen = (size_t) res;
		 printf("Forwarding C-APDU: ");
		 print_hex(abtCapdu+1,szCapduLen-1);

		 if(!transmit_bytes(abtCapdu+1, szCapduLen))
		 {
			 quitting = true;
			 continue;
		 }

		 printf("Forwarding R-APDU: ");
		 if(szRapduLen == 0)
		 {
			 szRapduLen = 1;
		 }
		 sleep(5);
		 len = send(new_fd, abtRapdu, szRapduLen, 0);
		 if(len != szRapduLen || len < 0 )
		 {
			 quitting = true;
			 continue;
		 }
		 print_hex(abtRapdu,szRapduLen);

		 flush(szCapduLen);

	 }while(!quitting);

	 close(sockfd);
	 nfc_close(pnd);
	 nfc_exit(context);
	 return 0;
}



