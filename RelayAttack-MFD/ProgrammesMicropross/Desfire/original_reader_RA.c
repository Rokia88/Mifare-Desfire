/*Ce fichier implÈmente de diffÈrentes commandes spÈcifiques ‡ la Mifare Desfire*/
/*il peut etre utilisÈ dans le cas classique o˘ TCL2 interroge une Mifare Desfire ou bien dans le cadre d'une attaque par relai*/

#define WINDOWS_DBG	
#include "MP300.h"
#include "MP300TCL2.h"	// includes defines and prototypes
#define REQA 0
#define AntiColl 1
#define SelectApp_root 2
#define ListApps1 3
#define ListApps2 4
#define getKeySettings_Delete 5
#define authPass1_Delete 6
#define authPass2_Delete 7
#define deleteApp 8
#define CreateApp 9
#define selectApp_aid2 10
#define CreateFilePlain 11
#define CreateFileMac 12
#define CreateFileEncr 13
#define getkeySettings_CK 14
#define authPass1_CK 15
#define authPass2_CK 16
#define ChangeKey 17
#define authPass1_WR 18
#define authPass2_WR 19
#define writePlain1 20
#define writePlain2 21
#define writeEncry1 22
#define writeEncry2 23
#define writeMac1 24
#define writeMac2 25
#define readPlain1 26
#define readPlain2 27
#define readMac1 28
#define readMac2 29
#define readEncr1 30
#define readEncr2 31
#define listFiles 32
#define deleteFile1 33
#define deleteFile2 34
#define deleteFile3 35
#define selectApp_reset 36
#define authPass1_reset 37
#define authPass2_reset 38
#define resetDesfire 39

#define TotalCmds 40


#define file_s 1024
#define size_data_w 0x60
#define size_data_r 0x60
#define xTimes 1024


#define PLAIN 0X01
#define MACING 0x02
#define ENCRYPTION 0x03

char *Cmds[TotalCmds] = { "REQA", "AntiColl", "SelectApp_root", "ListApps1", "ListApps2", "getKeySettings_Delete", "authPass1_Delete", "authPass2_Delete", "deleteApp", "CreateApp",
"selectApp_aid2", "CreateFilePlain", "CreateFileMac", "CreateFileEncr", "getkeySettings_CK", "authPass1_CK", "authPass2_CK", "ChangeKey", "authPass1_WR", "authPass2_WR", "writePlain1", "writePlain2", "writeEncry1", "writeEncry2", "writeMac1", "writeMac2", "readPlain1", "readPlain2", "readMac1", "readMac2", "readEncr1", "readEncr2", "listFiles", "deleteFile1", "deleteFile2", "deleteFile3", "selectApp_reset", "authPass1_reset", "authPass2_reset", "reset" };
BYTE bufout[80];
BYTE bufin[MAX_RECEIVED_FRAME_SIZE];
BYTE UID[20];
BYTE MAC[4];
BYTE ats[80];
DWORD time;
DWORD Timeout = 1000000;
DWORD response_times[TotalCmds];
DWORD32 cmd_size[TotalCmds];
DWORD32 resp_size[TotalCmds];

DWORD response_times_write[xTimes];
DWORD32 cmd_size_write[xTimes];
DWORD32 resp_size_write[xTimes];

DWORD response_times_write2[xTimes];
DWORD32 cmd_size_write2[xTimes];
DWORD32 resp_size_write2[xTimes];

DWORD response_times_write3[xTimes];
DWORD32 cmd_size_write3[xTimes];
DWORD32 resp_size_write3[xTimes];

DWORD response_times_read1[xTimes];
DWORD32 cmd_size_read1[xTimes];
DWORD32 resp_size_read1[xTimes];

DWORD response_times_read2[xTimes];
DWORD32 cmd_size_read2[xTimes];
DWORD32 resp_size_read2[xTimes];

DWORD response_times_read3[xTimes];
DWORD32 cmd_size_read3[xTimes];
DWORD32 resp_size_read3[xTimes];

BYTE session_key[16];
BYTE key1[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
BYTE key2[8] = { 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
/*PCD challenge*/
BYTE datatest[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
//default key
BYTE defaultkey[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static DWORD lgrep;
static WORD sw1sw2;
static WORD err;

int CALL TranslateMPCLog2(char * SourceFile, char *DestinationFile, int rfu1, DWORD rfu2, DWORD rfu3, int rfu4);

DWORD32 selectApplication(DWORD32 AID, BYTE select, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	Lc = 0x03;
	Le = 0x00;
	apdu_header = 0x905A0000;
	if (AID > 0xffffff || AID < 0x000000)
	{
		printf("AID is not valid\n");
		return EXIT_FAILURE;
	}
	bufout[2] = (AID >> 16) & 0xff; /*data 0*/
	bufout[1] = (AID >> 8) & 0xff; /*data 1*/
	bufout[0] = AID & 0xff;         /*data 2*/
	err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("Select Timeout");
		exit(EXIT_FAILURE);
	}
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (select == 1)
	{
		response_times[SelectApp_root] = time;
		cmd_size[SelectApp_root] = 4 + 2 + Lc;
		resp_size[SelectApp_root] = lgrep + 2;
	}

	if (select == 2)
	{
		response_times[selectApp_aid2] = time;
		cmd_size[selectApp_aid2] = 4 + 2 + Lc;
		resp_size[selectApp_aid2] = lgrep + 2;
	}

	if (select == 3)
	{
		response_times[selectApp_reset] = time;
		cmd_size[selectApp_reset] = 4 + 2 + Lc;
		resp_size[selectApp_reset] = lgrep + 2;
	}

	if (err != RET_OK || sw1sw2 != 0x9100)
	{
		//error handling
		//printf("Select Application Error\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

DWORD32 listApplications(BYTE *outputList, DWORD32 *outputCount, BYTE CplNum)
{
	BYTE Lc = 0;
	BYTE Le;
	DWORD apdu_header;

	DWORD32 j = 0;
	Le = 0x00;
	apdu_header = 0x906A0000;

	err = MPC_SendAPDU(CplNum, apdu_header, NO_LC, 0L, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("list application Timeout");
		exit(EXIT_FAILURE);
	}
	response_times[ListApps1] = time;
	cmd_size[ListApps1] = 5;
	resp_size[ListApps1] = lgrep + 2;
	if ((sw1sw2 == 0x9100) && !err)
	{
		*outputCount = ((lgrep) / 3);
		for (DWORD32 k = 0; k < lgrep; k++)
		{
			outputList[k] = bufin[k];
		}

	}

	else if ((sw1sw2 == 0x91AF) && !err)
	{
		//copier abtRx dans outputList et compter le nombre d'appli
		*outputCount = (lgrep) / 3;
		for (DWORD32 k = 0; k < lgrep; k++)
		{
			outputList[k] = bufin[k];
		}
		apdu_header = 0x90AF0000;
		Lc = 0x00;
		Le = 0x00;
		err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
		MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
		response_times[ListApps2] = time;
		cmd_size[ListApps2] = 5;
		resp_size[ListApps2] = lgrep + 2;
		if (sw1sw2 != 0x9100 || !err)
		{
			return EXIT_FAILURE;
		}
		// copier la suite des applis dans outputList et mettre ‡ jour le compteur des applis
		for (DWORD32 k = (*outputCount * 3); j < lgrep; k++, j++)
		{
			outputList[k] = bufin[j];
		}
		*outputCount += (lgrep) / 3;
	}

	else {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

DWORD32 getkeySettings(WORD *settings, BYTE GKS, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	Lc = 0x00;
	Le = 0x00;
	apdu_header = 0x90450000;

	err = MPC_SendAPDU(CplNum, apdu_header, NO_LC, 0L, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("get key settings Timeout");
		exit(EXIT_FAILURE);
	}
	if (GKS == 1)
	{
		response_times[getKeySettings_Delete] = time;
		cmd_size[getKeySettings_Delete] = 5;
		resp_size[getKeySettings_Delete] = lgrep + 2;
	}

	if (GKS == 2)
	{
		response_times[getkeySettings_CK] = time;
		cmd_size[getkeySettings_CK] = 5;
		resp_size[getkeySettings_CK] = lgrep + 2;
	}

	if (err || sw1sw2 != 0x9100 || lgrep != 2)
	{
		//printf("GET KEY SETTINGS ERROR\n");
		return EXIT_FAILURE;
	}
	(*settings) = (((WORD)bufin[0]) << 8) + ((WORD)bufin[1]);
	return EXIT_SUCCESS;
}

boolean isEqual(BYTE *array1, BYTE *array2, DWORD32 taille)
{
	for (int i = 0; i < taille; i++)
	{
		if (array1[i] != array2[i])
		{
			return FALSE;
		}
	}
	return TRUE;
}

void encrypt(BYTE * input, BYTE * output, BYTE *key1, BYTE *key2, BYTE CplNum)
{
	if (!isEqual(key1, key2, 8))
	{
		MPS_InitTripleDES(CplNum, key1, key2, key1, 1);
		MPS_ComputeTripleDES(CplNum, input, output);
	}

	else if (isEqual(key1, key2, 8))
	{
		MPS_InitDES(CplNum, key1, 1);
		MPS_ComputeDES(CplNum, input, output);
	}
}

void buildPrim(BYTE * data)
{
	BYTE tmp;
	int iterator;

	tmp = data[0];

	for (iterator = 1; iterator <8; iterator += 1)
	{
		data[iterator - 1] = data[iterator];
	}

	data[7] = tmp;
}

void xor(BYTE * input1, BYTE * input2, BYTE * output)
{
	int iterator;

	for (iterator = 0; iterator <8; iterator += 1)
	{
		output[iterator] = input1[iterator] ^ input2[iterator];
	}
}

int isValidPrim(BYTE * noPrim, BYTE * Prim)
{
	int iterator;

	for (iterator = 0; iterator <8; iterator += 1)
	{
		if (noPrim[(iterator + 1) % 8] != Prim[iterator])
			return -1;
	}

	return 0;
}

DWORD32 authenticate(BYTE key_index, BYTE * key1, BYTE * key2, BYTE * challenge, BYTE auth, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	BYTE output[8], output2[8]; /*temporary buffer      */

	/*check the args*/
	if (key_index > 0xD)
	{
		//printf("Key index is not valid\n");
		return EXIT_FAILURE;
	}

	/*prepare the data of the pass 1*/
	Lc = 0x01;
	Le = 0x00;
	apdu_header = 0x900A0000;
	bufout[0] = key_index & 0xff;

	/*send the request to the card*/
	/*the status word 0x91AF is expected, it means "ADDITIONAL FRAME".  The desfire tag is waiting the second pass of the authentication*/
	/*8-bytes are expected, it is the tag challenge*/
	//if(sendRequest(abtTx, abtTx_size, abtRx,&abtRx_size, &status_word, 8) != 0) {return -1;}

	err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("authentication1 Timeout");
		exit(EXIT_FAILURE);
	}
	if (auth == 1)
	{
		response_times[authPass1_Delete] = time;
		cmd_size[authPass1_Delete] = 4 + 2 + Lc;
		resp_size[authPass1_Delete] = lgrep + 2;
	}
	if (auth == 2)
	{
		response_times[authPass1_CK] = time;
		cmd_size[authPass1_CK] = 4 + 2 + Lc;
		resp_size[authPass1_CK] = lgrep + 2;
	}

	if (auth == 3)
	{
		response_times[authPass1_WR] = time;
		cmd_size[authPass1_WR] = 4 + 2 + Lc;
		resp_size[authPass1_WR] = lgrep + 2;
	}

	if (auth == 4)
	{
		response_times[authPass1_reset] = time;
		cmd_size[authPass1_reset] = 4 + 2 + Lc;
		resp_size[authPass1_reset] = lgrep + 2;
	}

	if (err || sw1sw2 != 0x91AF)
	{
		return EXIT_FAILURE;
	}

	/*a) get the challenge plain text*/
	encrypt(bufin, output, key1, key2, CplNum);

	BYTE output3[8];
	memcpy(output3, output, 8);

	/*transform the tag challenge into a prim challenge*/
	/*the first byte juste go at the end of the array*/
	buildPrim(output);

	/*b) encrypt the reader challenge*/
	encrypt(challenge, output2, key1, key2, CplNum);

	/*c) xor the cyphered challenge of the reader with the prim challenge of the tag*/
	xor(output2, output, output);

	/*d) cypher the result of the step c)*/
	encrypt(output, output, key1, key2, CplNum);


	/*e) prepare the data of the pass 2*/
	Lc = 0x10;
	Le = 0x00;
	apdu_header = 0x90AF0000;
	memcpy(bufout, output2, 8);
	memcpy(&(bufout[8]), output, 8);

	/*send the authentication pass 2*/
	err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("authentication2 Timeout");
		exit(EXIT_FAILURE);
	}
	if (auth == 1)
	{
		response_times[authPass2_Delete] = time;
		cmd_size[authPass2_Delete] = 4 + 2 + Lc;
		resp_size[authPass2_Delete] = lgrep + 2;
	}
	if (auth == 2)
	{
		response_times[authPass2_CK] = time;
		cmd_size[authPass2_CK] = 4 + 2 + Lc;
		resp_size[authPass2_CK] = lgrep + 2;
	}
	if (auth == 3)
	{
		response_times[authPass2_WR] = time;
		cmd_size[authPass2_WR] = 4 + 2 + Lc;
		resp_size[authPass2_WR] = lgrep + 2;
	}
	if (auth == 4)
	{
		response_times[authPass2_reset] = time;
		cmd_size[authPass2_reset] = 4 + 2 + Lc;
		resp_size[authPass2_reset] = lgrep + 2;
	}

	if (err || sw1sw2 != 0x9100)
	{
		return EXIT_FAILURE;
	}

	/*get the plain text of the tag response*/
	encrypt(bufin, output, key1, key2, CplNum);

	int valid = isValidPrim(challenge, output);
	if (!valid){

		memcpy(session_key, datatest, 4);
		memcpy(session_key + 4, output3, 4);
		memcpy(session_key + 8, datatest + 4, 4);
		memcpy(session_key + 12, output3 + 4, 4);

	}
	/*check the tag answer*/
	return valid;
}


boolean inList(DWORD32 AID, BYTE *array, DWORD32 taille)
{
	BYTE AID_a[3];
	AID_a[2] = (AID >> 16) & 0xff;
	AID_a[1] = (AID >> 8) & 0xff;
	AID_a[0] = (AID)& 0xff;

	for (int i = 0; i < taille; i += 3)
	{
		if (isEqual(AID_a, array + i, 3))
		{
			return TRUE;
		}
	}

	return FALSE;
}

DWORD32 deleteApplication(DWORD32 AID, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	/*check the AID*/
	if (AID > 0xffffff || AID < 0x000001)
	{
		return EXIT_FAILURE;
	}

	Lc = 0x03;
	Le = 0x00;
	apdu_header = 0x90DA0000;
	/*prepare the data*/;
	bufout[2] = (AID >> 16) & 0xff; /*data 0*/
	bufout[1] = (AID >> 8) & 0xff; /*data 1*/
	bufout[0] = AID & 0xff;         /*data 2*/

	err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("delete application Timeout");
		exit(EXIT_FAILURE);
	}
	response_times[deleteApp] = time;
	cmd_size[deleteApp] = 4 + 2 + Lc;
	resp_size[deleteApp] = lgrep + 2;
	if (err || (sw1sw2 != 0x9100))
	{
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

DWORD32 createApplication(DWORD32 AID, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	/*check the AID*/
	if (AID > 0xffffff || AID < 0x000001)
	{
		return EXIT_FAILURE;
	}

	/*prepare the data*/
	bufout[2] = (AID >> 16) & 0xff; /*data 0*/
	bufout[1] = (AID >> 8) & 0xff; /*data 1*/
	bufout[0] = AID & 0xff;         /*data 2*/

	bufout[3] = 0x0F & 0xff;
	bufout[4] = 0x0E & 0xff;

	Lc = 0x05;
	Le = 0x00;

	apdu_header = 0x90CA0000;

	err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("create application Timeout");
		exit(EXIT_FAILURE);
	}
	response_times[CreateApp] = time;
	cmd_size[CreateApp] = 4 + 2 + Lc;
	resp_size[CreateApp] = lgrep + 2;

	if (err || (sw1sw2 != 0x9100))
	{
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

DWORD32 createFile(DWORD32 FID, DWORD32 communictionMode, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	if (FID > 0xff)
	{
		return EXIT_FAILURE;
	}
	apdu_header = 0x90CD0000;
	Lc = 0x07;
	Le = 0x00;
	/*prepare the data*/
	if (communictionMode == PLAIN)
	{
		bufout[0] = FID & 0xff;
		bufout[1] = 0x00;
		bufout[2] = 0xEE;
		bufout[3] = 0xEE;
		bufout[4] = 0x00;
		bufout[5] = 0x04;
		bufout[6] = 0x00;
		err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
		MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
		if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
		{
			perror("create file(plain) Timeout");
			exit(EXIT_FAILURE);
		}
		response_times[CreateFilePlain] = time;
		cmd_size[CreateFilePlain] = 4 + 2 + Lc;
		resp_size[CreateFilePlain] = lgrep + 2;
	}

	else if (communictionMode == MACING)
	{
		bufout[0] = FID & 0xff;
		bufout[1] = 0x01;
		bufout[2] = 0x55;
		bufout[3] = 0x55;
		bufout[4] = 0x00;
		bufout[5] = 0x04;
		bufout[6] = 0x00;
		err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
		MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
		if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
		{
			perror("create file(Mac) Timeout");
			exit(EXIT_FAILURE);
		}
		response_times[CreateFileMac] = time;
		cmd_size[CreateFileMac] = 4 + 2 + Lc;
		resp_size[CreateFileMac] = lgrep + 2;
	}
	else if (communictionMode == ENCRYPTION)
	{
		bufout[0] = FID & 0xff;
		bufout[1] = 0x03;
		bufout[2] = 0x55;
		bufout[3] = 0x55;
		bufout[4] = 0x00;
		bufout[5] = 0x04;
		bufout[6] = 0x00;
		err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
		MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
		if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
		{
			perror("create file(encryption) Timeout");
			exit(EXIT_FAILURE);
		}
		response_times[CreateFileEncr] = time;
		cmd_size[CreateFileEncr] = 4 + 2 + Lc;
		resp_size[CreateFileEncr] = lgrep + 2;
	}
	if (err || sw1sw2 != 0x9100)
	{
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void cypher3DES(BYTE *output, BYTE *input, DWORD32 nbrIter, BYTE CplNum)
{
	BYTE k1[8];
	BYTE k2[8];
	// on utilise toute la session key pour faire du triple DES √† deux cl√©s
	memcpy(k1, session_key, 8);
	memcpy(k2, session_key + 8, 8);
	//print_hex(session_key,16);
	BYTE output1[8];
	BYTE input1[8];
	memcpy(input1, input, 8);
	//print_hex(input1,8);
	encrypt(input1, output1, k1, k2, CplNum);
	memcpy(output, output1, 8);
	unsigned int i;
	for (i = 0; i < nbrIter - 1; i++)
	{
		xor(output1, input + (8 * (i + 1)), input1);
		encrypt(input1, output1, k1, k2, CplNum);
		memcpy(output + (8 * (i + 1)), output1, 8);
	}
}
void cypherSimpleDES(BYTE *output, BYTE *input, unsigned int nbrIter, BYTE CplNum)
{
	BYTE k1[8];
	BYTE k2[8];
	// pour chiffrer, on utilise la premi√®re moiti√© de la session key
	memcpy(k1, session_key, 8);
	memcpy(k2, session_key, 8);
	//print_hex(session_key,16);
	BYTE output1[8];
	BYTE input1[8];
	memcpy(input1, input, 8);
	//print_hex(input1,8);
	encrypt(input1, output1, k1, k2, CplNum);
	memcpy(output, output1, 8);
	unsigned int i;
	for (i = 0; i < nbrIter - 1; i++)
	{
		xor(output1, input + (8 * (i + 1)), input1);
		encrypt(input1, output1, k1, k2, CplNum);
		memcpy(output + (8 * (i + 1)), output1, 8);
	}

}

void cypher2MAC(BYTE *output, BYTE *input, unsigned int nbrIter, BYTE CplNum)
{
	BYTE k1[8];
	BYTE k2[8];
	memcpy(k1, session_key, 8);
	memcpy(k2, session_key + 8, 8);
	BYTE output1[8];
	BYTE input1[8];
	memcpy(input1, input, 8);
	MPS_InitTripleDES(CplNum, k1, k2, k1, 0);
	MPS_ComputeTripleDES(CplNum, input1, output1);
	//DES_ecb2_encrypt((DES_cblock*)input1, (DES_cblock*)output1, &ks1, &ks2, DES_ENCRYPT);
	memcpy(output, output1, 8);
	unsigned int i;
	for (i = 0; i < nbrIter - 1; i++)
	{
		xor(output1, input + (8 * (i + 1)), input1);
		MPS_ComputeTripleDES(CplNum, input1, output1);
		//DES_ecb2_encrypt((DES_cblock*)input1, (DES_cblock*)output1, &ks1, &ks2, DES_ENCRYPT);
		memcpy(output + (8 * (i + 1)), output1, 8);
	}
	memcpy(MAC, output1, 4);
}

unsigned short update_crc16(unsigned short crc, unsigned char c)
{
	unsigned short i, v, tcrc = 0;

	v = (crc ^ c) & 0xff;
	for (i = 0; i < 8; i++)
	{
		tcrc = ((tcrc ^ v) & 1) ? (tcrc >> 1) ^ 0x8408 : tcrc >> 1;
		v >>= 1;
	}
	return ((crc >> 8) ^ tcrc) & 0xffff;
}

unsigned short crc_16(unsigned char *data, unsigned int len)
{
	unsigned int i;
	unsigned short crc = 0x6363;

	for (i = 0; i < len; ++i)
		crc = update_crc16(crc, data[i]);
	return crc;
}


DWORD32 changeKey(BYTE keyNo, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	apdu_header = 0x90C40000;
	Lc = 0x19;
	Le = 0x00;

	WORD keysettings;
	BYTE changekey;
	BYTE cmd_data[24];
	unsigned short crc;
	//unsigned short crc_new_key;

	if (getkeySettings(&keysettings, 2, CplNum) != 0)
	{
		printf("getKeySettings Failure !\n");
	}
	else
	{
		changekey = ((BYTE)(keysettings >> 8) >> 4);
		//printf(" the change key is  %02x\n", changekey);
		if (changekey == 0x0E || changekey == keyNo || keyNo == 0x00)
		{
			/*authentifier avec le numero de clef keyNo --> procedure 2 de changeKey cmd*/
			if (authenticate(keyNo, defaultkey, defaultkey, datatest, 2, CplNum) == 0)
			{
				memcpy(cmd_data, key1, 8); /*je dois faire un xor avant et calculer le crc sur new_key seulement, mais ca revient au meme pour ce test car defaultkey =0*/
				memcpy(cmd_data + 8, key2, 8);
				crc = crc_16(cmd_data, 16);
				cmd_data[16] = (BYTE)crc;
				cmd_data[17] = (BYTE)(crc >> 8);
				BYTE init[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				memcpy(cmd_data + 18, init, 6);
				//print_hex(cmd_data,24);
				cypher3DES(bufout + 1, cmd_data, 3, CplNum);
			}


		}
		else if (changekey == 0x0F)
		{
			//printf("change basic key is not allowed\n");
			return EXIT_FAILURE;
		}

		else
		{

			/*authentifier avec la changeKey --> procedure 1 de changekey cmd*/
			if (authenticate(changekey, defaultkey, defaultkey, datatest, 2, CplNum) == 0)
			{
				xor(defaultkey, key1, cmd_data);
				xor(defaultkey, key2, cmd_data + 8);
				crc = crc_16(cmd_data, 16);
				cmd_data[16] = (BYTE)crc;
				cmd_data[17] = (BYTE)(crc >> 8);
				/* dans ces deux octets il faut mettre le crc de la new key */
				cmd_data[18] = (BYTE)crc;
				cmd_data[19] = (BYTE)(crc >> 8);
				BYTE init[4] = { 0x00, 0x00, 0x00, 0x00 };
				memcpy(cmd_data + 20, init, 4);
				cypherSimpleDES(bufout + 1, cmd_data, 3, CplNum);
			}

		}
	}
	bufout[0] = keyNo & 0xff;
	err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("change key Timeout");
		exit(EXIT_FAILURE);
	}
	response_times[ChangeKey] = time;
	cmd_size[ChangeKey] = 4 + 2 + Lc;
	resp_size[ChangeKey] = lgrep + 2;

	if (err || sw1sw2 != 0x9100)
	{
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int writeData_Plain(BYTE  FID, BYTE *buf, DWORD32 nbyte, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	apdu_header = 0x903D0000;
	Le = 0x00;
	unsigned int off;
	bufout[0] = FID;
	bufout[1] = 0x00;
	bufout[2] = 0x00;
	bufout[3] = 0x00;
	bufout[6] = (nbyte >> 16) & 0xff;
	bufout[5] = (nbyte >> 8) & 0xff;
	bufout[4] = nbyte & 0xff;
	unsigned int i = 0;
	unsigned int k = 0;
	for (i = 0; i < nbyte && i < 52; i++)
	{
		bufout[7 + i] = buf[i];
	}
	Lc = 7 + i;
	err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("write data1 (Plain) Timeout");
		exit(EXIT_FAILURE);
	}
	response_times[writePlain1] = time;
	cmd_size[writePlain1] = 4 + 2 + Lc;
	resp_size[writePlain1] = lgrep + 2;

	if (nbyte > 52){
		nbyte = nbyte - 52;
		off = 52;
	}
	while (!err && sw1sw2 == 0x91AF)
	{
		apdu_header = 0x90AF0000;
		Le = 0x00;
		for (i = 0; i < nbyte && i < 0x3B; i++)
		{
			bufout[i] = buf[i + off];
		}

		Lc = i;
		err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
		MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
		if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
		{
			perror("write data2 (Plain) Timeout");
			exit(EXIT_FAILURE);
		}
		response_times_write[k] = time;
		cmd_size_write[k] = 4 + 2 + Lc;
		resp_size_write[k] = lgrep + 2;
		k++;

		if (nbyte > 0x3B) {
			nbyte = nbyte - 59;
			off += 59;
		}
	}

	if (err || sw1sw2 != 0x9100)
	{
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int writeData_Encryption(BYTE  FID, BYTE *buf1, DWORD32 nbyte, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	apdu_header = 0x903D0000;
	Le = 0x00;
	unsigned int off;
	bufout[0] = FID;
	bufout[1] = 0x00;
	bufout[2] = 0x00;
	bufout[3] = 0x00;

	unsigned int padding = 0;
	if ((nbyte + 2) % 8 != 0){ padding = ((((nbyte + 2) / 8) + 1) * 8) - (nbyte + 2); }
	BYTE *buf = malloc(nbyte + padding + 2);
	memcpy(buf, buf1, nbyte);
	unsigned short crc = crc_16(buf, nbyte);
	buf[nbyte] = (BYTE)crc;
	buf[nbyte + 1] = (BYTE)(crc >> 8);
	memset(buf + nbyte + 2, 0, padding);
	//print_hex(buf, nbyte+padding+2);

	bufout[6] = (nbyte >> 16) & 0xff;
	bufout[5] = (nbyte >> 8) & 0xff;
	bufout[4] = (nbyte)& 0xff;
	unsigned int i = 0;
	unsigned int k = 0;
	int result;

	BYTE *ciphered = malloc(nbyte + padding + 2);
	cypher3DES(ciphered, buf, (nbyte + padding + 2) / 8, CplNum);
	//print_hex(ciphered,nbyte+padding+2);
	nbyte += (padding + 2);
	for (i = 0; i < nbyte && i < 52; i++)
	{
		bufout[7 + i] = ciphered[i];
	}
	Lc = 7 + i;
	err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("write data1 (encryption) Timeout");
		exit(EXIT_FAILURE);
	}
	response_times[writeEncry1] = time;
	cmd_size[writeEncry1] = 4 + 2 + Lc;
	resp_size[writeEncry1] = lgrep + 2;

	if (nbyte > 52){
		nbyte = nbyte - 52;
		off = 52;
	}
	while (!err && sw1sw2 == 0x91AF)
	{
		apdu_header = 0x90AF0000;
		Le = 0x00;
		for (i = 0; i < nbyte && i < 0x3B; i++)
		{
			bufout[i] = ciphered[i + off];
		}
		Lc = i;
		err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
		MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
		if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
		{
			perror("write data2 (encryption) Timeout");
			exit(EXIT_FAILURE);
		}
		response_times_write2[k] = time;
		cmd_size_write2[k] = 4 + 2 + Lc;
		resp_size_write2[k] = lgrep + 2;
		k++;
		if (nbyte > 0x3B) {
			nbyte = nbyte - 59;
			off += 59;
		}
	}

	if (err || sw1sw2 != 0x9100)
	{
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int writeData_Mac(BYTE  FID, BYTE *buf, DWORD32 nbyte, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	apdu_header = 0x903D0000;
	Le = 0x00;
	unsigned int off;
	bufout[0] = FID;
	bufout[1] = 0x00;
	bufout[2] = 0x00;
	bufout[3] = 0x00;
	bufout[6] = (nbyte >> 16) & 0xff;
	bufout[5] = (nbyte >> 8) & 0xff;
	bufout[4] = nbyte & 0xff;
	unsigned int i = 0;
	unsigned int k = 0;
	BYTE *input = malloc(nbyte + 1);
	memcpy(input, buf, nbyte);
	for (i = 0; i < nbyte && i < 52; i++)
	{
		bufout[7 + i] = buf[i];
	}
	unsigned int padding = 0;
	unsigned int nbrIter = 0;
	if (nbyte % 8 != 0)
	{
		padding = ((nbyte / 8) + 1) * 8 - nbyte;
		memset(input + nbyte, 0, padding);
		nbrIter = (nbyte / 8) + 1;
	}
	else if (nbyte % 8 == 0)
	{
		nbrIter = (nbyte / 8);
	}
	BYTE *o_buffer = malloc(nbyte + padding);
	cypher2MAC(o_buffer, input, nbrIter, CplNum);
	if (nbyte > 52 || i + 4 > 52){
		Lc = 7 + i;
		err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
		MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
		if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
		{
			perror("write data1 (mac) Timeout");
			exit(EXIT_FAILURE);
		}
		response_times[writeMac1] = time;
		cmd_size[writeMac1] = 4 + 2 + Lc;
		resp_size[writeMac1] = lgrep + 2;
		if (nbyte > 52){
			nbyte = nbyte - 52;
			off = 52;
		}
	}
	else if (i + 4 <= 52)
	{
		memcpy(bufout + 7 + i, MAC, 4);
		Lc = 7 + i + 4;
		err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
		MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
		if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
		{
			perror("write data2( mac) Timeout");
			exit(EXIT_FAILURE);
		}
		response_times[writeMac1] = time;
		cmd_size[writeMac1] = 4 + 2 + Lc;
		resp_size[writeMac1] = lgrep + 2;
	}

	while (!err && sw1sw2 == 0x91AF)
	{
		apdu_header = 0x90AF0000;
		Le = 0x00;

		for (i = 0; i < nbyte && i < 59; i++)
		{
			bufout[i] = buf[i + off];

		}

		if (nbyte > 59 || i + 4 > 59)
		{
			Lc = i;
			err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
			MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
			response_times_write3[k] = time;
			cmd_size_write3[k] = 4 + 2 + Lc;
			resp_size_write3[k] = lgrep + 2;
			k++;
			nbyte = nbyte - 59;
			off += 59;
		}
		else if (i + 4 <= 59)
		{
			memcpy(bufout + i, MAC, 4);
			Lc = i + 4;
			err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
			MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
			response_times_write3[k] = time;
			cmd_size_write3[k] = 4 + 2 + Lc;
			resp_size_write3[k] = lgrep + 2;
			k++;
		}
	}

	if (err || sw1sw2 != 0x9100)
	{
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int readData_PlainAndMac(DWORD32  FID, BYTE *buf, DWORD32 nbyte, BYTE PlainOrMac, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;
	unsigned int k = 0;
	BYTE response[file_s + 4];
	DWORD32 index = 0;
	apdu_header = 0x90BD0000;
	Le = 0x00;
	bufout[0] = FID;
	bufout[1] = 0x00;
	bufout[2] = 0x00;
	bufout[3] = 0x00;
	bufout[6] = (nbyte >> 16) & 0xff;
	bufout[5] = (nbyte >> 8) & 0xff;
	bufout[4] = nbyte & 0xff;
	Lc = 7;
	err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("read data1 (plain or mac) Timeout");
		exit(EXIT_FAILURE);
	}
	if (PlainOrMac == 1)
	{
		response_times[readPlain1] = time;
		cmd_size[readPlain1] = 4 + 2 + Lc;
		resp_size[readPlain1] = lgrep + 2;
	}
	if (PlainOrMac == 2)
	{
		response_times[readMac1] = time;
		cmd_size[readMac1] = 4 + 2 + Lc;
		resp_size[readMac1] = lgrep + 2;
	}

	/*buf = malloc ( response_size);*/
	if (!err && sw1sw2 == 0x9100)
	{
		memcpy(buf, bufin, lgrep);
	}

	while (!err && sw1sw2 == 0x91AF)
	{
		memcpy(buf, bufin, lgrep);
		memcpy(response + index, bufin, lgrep);
		index += lgrep;
		apdu_header = 0x90AF0000;
		Lc = 0x00;
		err = MPC_SendAPDU(CplNum, apdu_header, NO_LC, 0L, Le, bufin, &lgrep, &sw1sw2);
		MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
		if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
		{
			perror("read data1 (plain or mac) Timeout");
			exit(EXIT_FAILURE);
		}
		if (PlainOrMac == 1)
		{
			response_times_read2[k] = time;
			cmd_size_read2[k] = 4 + 2 + Lc;
			resp_size_read2[k] = lgrep + 2;
			k++;
		}
		if (PlainOrMac == 2)
		{
			response_times_read3[k] = time;
			cmd_size_read3[k] = 4 + 2 + Lc;
			resp_size_read3[k] = lgrep + 2;
			k++;
		}
	}

	if (!err && sw1sw2 == 0x9100)
	{

		memcpy(response + index, bufin, lgrep);
		index += lgrep;
		printf("*************Received Data******************\n");
		for (int i = 0; i< index; i++)
		{
			printf("%02x", response[i]);
		}
		printf("\n");
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

void cypher3(BYTE *output, BYTE *input, unsigned int nbrIter, BYTE CplNum)
{
	BYTE k1[8];
	BYTE k2[8];
	memcpy(k1, session_key, 8);
	memcpy(k2, session_key + 8, 8);
	//print_hex(session_key,16);
	BYTE output1[8];
	BYTE input1[8];
	memcpy(input1, input, 8);
	encrypt(input1, output1, k1, k2, CplNum);
	memcpy(output, output1, 8);
	unsigned int i;
	for (i = 0; i < nbrIter - 1; i++)
	{
		encrypt(input + (8 * (i + 1)), output1, k1, k2, CplNum);
		xor(input + (8 * i), output1, input1);
		memcpy(output + (8 * (i + 1)), input1, 8);
	}
}

int readData_Encryption(DWORD32  FID, BYTE *buf, DWORD32 nbyte, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;
	unsigned int k = 0;
	BYTE response[file_s * 2];
	BYTE buffer_o[file_s * 2];
	size_t abtTx_size;
	apdu_header = 0x90BD0000;
	Le = 0x00;
	bufout[0] = FID;
	bufout[1] = 0x00;
	bufout[2] = 0x00;
	bufout[3] = 0x00;
	bufout[6] = (nbyte >> 16) & 0xff;
	bufout[5] = (nbyte >> 8) & 0xff;
	bufout[4] = nbyte & 0xff;
	Lc = 7;
	err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("read data1 (encryption) Timeout");
		exit(EXIT_FAILURE);
	}
	response_times[readEncr1] = time;
	cmd_size[readEncr1] = 4 + 2 + Lc;
	resp_size[readEncr1] = lgrep + 2;

	unsigned int index = 0;

	if (!err && sw1sw2 == 0x9100)
	{
		memcpy(buf, bufin, lgrep);
	}

	while (!err && sw1sw2 == 0x91AF)
	{
		memcpy(buf, bufin, lgrep);
		memcpy(response + index, bufin, lgrep);
		index += lgrep;
		apdu_header = 0x90AF0000;
		Lc = 0x00;
		err = MPC_SendAPDU(CplNum, apdu_header, NO_LC, 0L, Le, bufin, &lgrep, &sw1sw2);
		MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
		if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
		{
			perror("read data2 (encryption) Timeout");
			exit(EXIT_FAILURE);
		}
		response_times_read1[k] = time;
		cmd_size_read1[k] = 4 + 2 + Lc;
		resp_size_read1[k] = lgrep + 2;
		k++;
	}

	if (!err && sw1sw2 == 0x9100)
	{
		memcpy(response + index, bufin, lgrep);
		index += (lgrep);
		printf("*************Encrypted Data******************\n");
		for (int i = 0; i< index; i++)
		{
			printf("%02x", response[i]);
		}
		printf("\n");

		//d√©chiffrer les donn√©es lues
		cypher3(buffer_o, response, index / 8, CplNum);
		printf("*************Decrypted Data******************\n");
		for (int i = 0; i< index; i++)
		{
			printf("%02x", buffer_o[i]);
		}
		printf("\n");
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

int listFile(BYTE *outputList, unsigned int *outputCount, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	apdu_header = 0x906F0000;
	Le = 0x00;
	int iterator;
	int res;

	err = MPC_SendAPDU(CplNum, apdu_header, NO_LC, 0L, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("list files Timeout");
		exit(EXIT_FAILURE);
	}
	response_times[listFiles] = time;
	cmd_size[listFiles] = 5;
	resp_size[listFiles] = lgrep + 2;

	if (err || sw1sw2 != 0x9100)
	{
		return EXIT_FAILURE;
	}
	for (iterator = 0; iterator < (lgrep); iterator += 1, *outputCount += 1)
	{
		outputList[*outputCount] = (bufin[iterator] & 0xff);
	}

	return EXIT_SUCCESS;
}

int deleteFile(DWORD32 FID, BYTE delete, BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	/*check the AID*/
	if (FID > 0xff)
	{
		return EXIT_FAILURE;
	}


	apdu_header = 0x90DF0000;
	Le = 0x00;
	Lc = 0x01;
	bufout[0] = FID & 0xff;
	err = MPC_SendAPDU(CplNum, apdu_header, Lc, bufout, Le, bufin, &lgrep, &sw1sw2);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	if (err == ERR_PROTOCOL_STOP_TIMEOUT_DETECTED)
	{
		perror("delete file Timeout");
		exit(EXIT_FAILURE);
	}
	if (delete == 1)
	{
		response_times[deleteFile1] = time;
		cmd_size[deleteFile1] = 6;
		resp_size[deleteFile1] = lgrep + 2;
	}
	if (delete == 2)
	{
		response_times[deleteFile2] = time;
		cmd_size[deleteFile2] = 6;
		resp_size[deleteFile2] = lgrep + 2;
	}
	if (delete == 3)
	{
		response_times[deleteFile3] = time;
		cmd_size[deleteFile3] = 6;
		resp_size[deleteFile3] = lgrep + 2;
	}


	if (err || sw1sw2 != 0x9100)
	{
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

boolean fileInList(unsigned int FID, BYTE *array, unsigned int taille)
{
	for (int i = 0; i < taille; i += 1)
	{
		if (array[i] == FID)
		{
			return TRUE;
		}
	}

	return FALSE;
}



DWORD32 fileManagment(DWORD32 aid, BYTE CplNum)
{
	if (selectApplication(aid, 2, CplNum) == 0)
	{
		BYTE outputFileList[16];
		unsigned int outputCount = 0;
		BYTE fid_1 = 0x04;
		BYTE fid_2 = 0x05;
		BYTE fid_3 = 0x09;
		BYTE keyToAccessFiles = 0x05;
		BYTE buf[size_data_w];
		for (int i = 0; i< size_data_w; i++)
		{
			buf[i] = 0x66;
		}
		BYTE buf_I[59]; //59 is the maximum number of bytes we can read

		{
			printf("******************Create File 1*******************\n");

			err = createFile(fid_1, PLAIN, CplNum);
			if (err != 0)
			{
				return EXIT_FAILURE;
			}

			printf("******************Create File 2*******************\n");

			err = createFile(fid_2, MACING, CplNum);
			if (err != 0)
			{
				return EXIT_FAILURE;
			}

			printf("******************Create File 3*******************\n");

			err = createFile(fid_3, ENCRYPTION, CplNum);
			if (err != 0)
			{
				return EXIT_FAILURE;
			}

			printf("******************Change key*******************\n");

			err = changeKey(keyToAccessFiles, CplNum);

			if (err != 0)
			{
				return EXIT_FAILURE;
			}
			else
			{
				printf("******************Authentication using  access files key*******************\n");
				err = authenticate(keyToAccessFiles, key1, key2, datatest, 3, CplNum);
				if (err != 0)
				{
					return EXIT_FAILURE;
				}
				else
				{
					//write data into files
					printf("******************write data in plain mode*******************\n");
					err = writeData_Plain(fid_1, buf, size_data_w, CplNum);
					if (err != 0)
					{
						return EXIT_FAILURE;
					}
					printf("******************write data in Macing mode*******************\n");

					err = writeData_Mac(fid_2, buf, size_data_w, CplNum);
					if (err != 0)
					{
						return EXIT_FAILURE;
					}

					printf("******************write data in (3)DES encryption mode*******************\n");

					err = writeData_Encryption(fid_3, buf, size_data_w, CplNum);
					if (err != 0)
					{
						return EXIT_FAILURE;
					}
					//read data from files

					printf("******************read all data in plain mode*******************\n");

					err = readData_PlainAndMac(fid_1, buf_I, size_data_r, 1, CplNum);
					if (err != 0)
					{
						return EXIT_FAILURE;
					}

					printf("******************read data in Macing mode*******************\n");

					err = readData_PlainAndMac(fid_2, buf_I, size_data_r, 2, CplNum);
					if (err != 0)
					{
						return EXIT_FAILURE;
					}

					printf("******************read data in (3)DES encryption mode*******************\n");

					err = readData_Encryption(fid_3, buf_I, size_data_r, CplNum);
					if (err != 0)
					{
						return EXIT_FAILURE;
					}
				}
			}
		}

		//lister et supprimer les fichiers cr√©es ici, car sinon, en ex√©cutant le programme une deuxi√®me fois sur le m√™me programme, on risque d'avoir un pb de m√©moire insuffisante, car on supprime l'application
		//qui contient ces fichiers avant d'arriver √† cette fonction de gestion de fichiers,
		printf("******************List Files in the current application*******************\n");

		//sleep(5);
		err = listFile(outputFileList, &outputCount, CplNum);
		if (err != 0)
		{
			return EXIT_FAILURE;
		}
		/*if (!quiet_output)
		{*/
		printf("%d Files :", outputCount);
		for (int i = 0; i < outputCount; i++)
		{
			printf("%02x  ", outputFileList[i]);
		}
		printf("\n");
		//}
		if (fileInList(fid_1, outputFileList, outputCount))
		{
			printf("******************Delete File 1*******************\n");
			err = deleteFile(fid_1, 1, CplNum);
			if (err != 0)
			{
				return EXIT_FAILURE;
			}
		}
		if (fileInList(fid_2, outputFileList, outputCount))
		{
			printf("******************Delete File 2*******************\n");
			err = deleteFile(fid_2, 2, CplNum);
			if (err != 0)
			{
				return EXIT_FAILURE;
			}
		}

		if (fileInList(fid_3, outputFileList, outputCount))
		{
			printf("******************Delete File 3*******************\n");
			err = deleteFile(fid_3, 3, CplNum);
			if (err != 0)
			{
				return EXIT_FAILURE;
			}
		}
	}

	return EXIT_SUCCESS;

}

int reset(BYTE CplNum)
{
	BYTE Lc;
	BYTE Le;
	DWORD apdu_header;

	apdu_header = 0x90FC0000;
	Le = 0x00;
	if (selectApplication(0, 3, CplNum) == EXIT_SUCCESS)
	{
		if (authenticate(0, defaultkey, defaultkey, datatest, 4, CplNum) == EXIT_SUCCESS)
		{
			err = MPC_SendAPDU(CplNum, apdu_header, NO_LC, 0L, Le, bufin, &lgrep, &sw1sw2);
			MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
			response_times[resetDesfire] = time;
			cmd_size[resetDesfire] = 5;
			resp_size[resetDesfire] = lgrep + 2;
		}
	}
	if (err || sw1sw2 != 0x9100)
	{
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}



void Desfire(BYTE CplNum)
{
	WORD lng;
	WORD ATQA, lngats;
	BYTE SAK;
	DWORD32 result;
	DWORD32 AID = 0x00;
	DWORD32 aid = 0x02;
	WORD settings;
	BYTE outputList[28 * 3];
	DWORD32 outputCount = 0;
	DWORD enableProtocolManagment = 0;
	DWORD enableNAD = 0;
	DWORD enableCID = 0;
	DWORD param = 0;
	err = MPC_SelectType(CplNum, TYPE_A);		// select card type
	
	//err = MPC_ChangeProtocolParameters(CPL1, CPP_PROTOCOL_ERROR_MANAGEMENT, &enableProtocolManagment, 4);
	err = MPC_SelectFieldStrength(CplNum, UNIT_PER_CENT, 80);		// field strength = 80%
	MPC_PiccResponseTime(CplNum, PRT_ENABLE, TOU_MICRO, &time);
	//MPC_ChangeProtocolParameters(CplNum, CPP_PROTOCOL_ERROR_MANAGEMENT, &param, 4);
	//envoyer REQA
	err = MPC_RequestA(CplNum, &ATQA);
	MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
	response_times[REQA] = time;
	if (!err)
	{
		err = MPC_AnticollA(CplNum, &UID[0], &lng, &SAK); // send anticol command
		MPC_PiccResponseTime(CplNum, PRT_GET, TOU_MICRO, &time);
		response_times[AntiColl] = time;
	}
	if (!err)
	{
		if (SAK & 0x20) 	// 14443-4 supported ?
		{
			err = MPC_SendRATS(CplNum, &ats[0], &lngats);  // send RATS command
			//commenter ces lignes sur le tag ÈmulÈ n'est pas un SCL3711(pn533)
			if (err != 0)
			{
				err = MPC_SendRATS(CplNum, &ats[0], &lngats);
			}
			if (!err)
			{
				//commenter ces lignes quand vous communiquez avec une vrai desfire
				//dÈcommenter quand vous communiquez avec un tag emulated
				err = MPC_ChangeProtocolParameters(CPL1, CPP_NAD, &enableNAD, 4);
				err = MPC_ChangeProtocolParameters(CPL1, CPP_CID, &enableCID, 4);
				//err = MPC_ChangeProtocolParameters(CPL1, CPP_PROTOCOL_STOP_TIMEOUT, &Timeout, 4);
				// can now exchange APDU with API MPC_SendAPDU 
				result = selectApplication(AID, 1, CplNum);
				if (!result)
				{
					result = listApplications(outputList, &outputCount, CplNum);
					if (!result)
					{
						printf("%d applications: ", outputCount);
						for (int i = 0; i < outputCount * 3; i++)
						{
							printf("%02x ", outputList[i]);
							if ((i + 1) % 3 == 0)
							{
								printf("***");
							}
						}
						printf("\n");
						if (inList(aid, outputList, outputCount))
						{
							result = getkeySettings(&settings, 1, CplNum);
							if (!result && settings == 0x0F01)
							{
								result = authenticate(0, defaultkey, defaultkey, datatest, 1, CplNum);
								if (!result)
								{
									result = deleteApplication(aid, CplNum);
									if (result)
									{
										printf("delete application error\n");
										return;
									}
								}
								else{
									printf("authentication error\n");
									return;
								}
							}
						}
						result = createApplication(aid, CplNum);
						if (!result)
						{
							result = fileManagment(aid, CplNum);
							if (!result)
							{
								result = reset(CplNum);
								if (!result)
								{
									MPC_PiccResponseTime(CplNum, PRT_DISABLE, TOU_MICRO, &time);
									for (int i = 0; i < TotalCmds; i++)
									{
										if (i == writePlain2)
										{
											for (int j = 0; j < sizeof(cmd_size_write) && cmd_size_write[j] != 0; j++)
											{
												printf("Response to %s (Cmd_S:%u,Resp_S:%u) received after %lu us\n", Cmds[i], cmd_size_write[j], resp_size_write[j], response_times_write[j]);
											}
											continue;
										}
										if (i == writeEncry2)
										{
											for (int j = 0; j < sizeof(cmd_size_write2) && cmd_size_write2[j] != 0; j++)
											{
												printf("Response to %s (Cmd_S:%u,Resp_S:%u) received after %lu us\n", Cmds[i], cmd_size_write2[j], resp_size_write2[j], response_times_write2[j]);
											}
											continue;
										}

										if (i == writeMac2)
										{
											for (int j = 0; j < sizeof(cmd_size_write3) && cmd_size_write3[j] != 0; j++)
											{
												printf("Response to %s (Cmd_S:%u,Resp_S:%u) received after %lu us\n", Cmds[i], cmd_size_write3[j], resp_size_write3[j], response_times_write3[j]);
											}
											continue;
										}

										if (i == readEncr2)
										{
											for (int j = 0; j < sizeof(cmd_size_read1) && cmd_size_read1[j] != 0; j++)
											{
												printf("Response to %s (Cmd_S:%u,Resp_S:%u) received after %lu us\n", Cmds[i], cmd_size_read1[j], resp_size_read1[j], response_times_read1[j]);
											}
											continue;
										}
										if (i == readPlain2)
										{
											for (int j = 0; j < sizeof(cmd_size_read2) && cmd_size_read2[j] != 0; j++)
											{
												printf("Response to %s (Cmd_S:%u,Resp_S:%u) received after %lu us\n", Cmds[i], cmd_size_read2[j], resp_size_read2[j], response_times_read2[j]);
											}
											continue;
										}
										if (i == readMac2)
										{
											for (int j = 0; j < sizeof(cmd_size_read3) && cmd_size_read3[j] != 0; j++)
											{
												printf("Response to %s (Cmd_S:%u,Resp_S:%u) received after %lu us\n", Cmds[i], cmd_size_read3[j], resp_size_read3[j], response_times_read3[j]);
											}
											continue;
										}
										printf("Response to %s (Cmd_S:%u,Resp_S:%u) received after %lu us\n", Cmds[i], cmd_size[i], resp_size[i], response_times[i]);

									}
								}
								else
								{
									printf("Reset Error \n");
									return;
								}
							}
							else{
								printf("File managment Error \n");
								return;
							}
						}
						else{
							printf("create application error\n");
							return;
						}
					}

				}
				else{
					printf("Select Application Error \n");
					return;
				}
			}
		}
	}

	err = MPC_SelectFieldStrength(CplNum, UNIT_PER_CENT, 0);		// example to set RF field off
}


// Main entry point
void main(void)
{
int a;
WORD err;
BYTE CplNum = 1;	// position of the module TCL2

// The connection must be established before 5 seconds.
SetDLLTimeOutValue(10);
SetDLLParameter(TCP_TIMEOUT, 30000);
//a = OpenCommunication("USB");	//  using ETHERNET connection
a = OpenCommunication((LPSTR)"10779:131.254.15.164");
//	a = OpenCommunication((LPSTR)"COM1:115200,N,8,2");	// or using COM1 connection
if (!a)
{
//Resource Allocation (mandatory in order to use fonctions dedicated to the TCL2 coupler)
err = MPOS_OpenResource(TCL2, CplNum,OVERRIDE);
if (!err)	// if the resource is allocated
{
	//err = MPS_CloseLog(CplNum);
	err = StartDownloadTo(CplNum, "C:\\Users\\Rokia\\Documents\\Spy1024.log");
	err = MPS_OpenLog(CplNum, MASK_ALL_CL_EVENTS, 0);
	Desfire(CplNum);
	err = MPS_CloseLog(CplNum);
	err = MPS_EndDownload(CplNum);
	if (err == 0)  {
		int errint = TranslateMPCLog2("C:\\Users\\Rokia\\Documents\\Spy1024.log", "C:\\Users\\Rokia\\Documents\\SpyRokRok14.mplog", 0, 0, 0, 0);
	}
	Sleep(10000);
//Resource Desallocation
MPOS_CloseResource(TCL2, CplNum);
}
CloseCommunication();
}
}
