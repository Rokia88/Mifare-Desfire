#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/des.h>

uint8_t defaultkey[8]  = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
uint8_t datatest1[8]   = {0x6e,0x75,0x77,0x94,0x4a,0xdf,0xfc,0x0c};
uint8_t datatest2[8]   = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
uint8_t datatest3[8]   = {0xad,0x6c,0xc1,0x60,0x25,0xcc,0xfb,0x7b};

int isValidPrim(uint8_t * noPrim, uint8_t * Prim);
void xor(uint8_t * input1, uint8_t * input2, uint8_t * output);
void buildPrim(uint8_t * data);
void encrypt(uint8_t * input, uint8_t * output, uint8_t *key1, uint8_t *key2);
static void print_hex(const uint8_t *pbtData, const size_t szBytes);

int main(int argc, char *argv[])
{
    uint8_t output[8], output2[8];
    
    /*get data from card*/
        /*TO datatest1*/
    
    /*a*/
    encrypt(datatest1, output, defaultkey, defaultkey);
    printf("nt: ");print_hex(output,8);
    buildPrim(output);
    printf("nt': ");print_hex(output,8);
    
    /*b*/
    encrypt(datatest2, output2, defaultkey, defaultkey);
    printf("nr: ");print_hex(datatest2,8);
    printf("D1: ");print_hex(output2,8);
    
    /*c*/
    xor(output2,output, output);
    printf("Buffer: ");print_hex(output,8);
    
    /*d*/
    encrypt(output, output, defaultkey, defaultkey);
    printf("D2: ");print_hex(output,8);
    
    /*e*/
        /*send data to card*/
            /*store the answer in datatest3*/
    
    encrypt(datatest3, output, defaultkey, defaultkey);
    printf("nr': ");print_hex(output,8);
    
    /*print output*/
    if(isValidPrim(datatest2, output) == 0)
    {
        printf("Authentication success\n");
    }
    else
    {
        printf("Authentication failed\n");
    }
    
    return 0;
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

void xor(uint8_t * input1, uint8_t * input2, uint8_t * output)
{
    int iterator;
    
    for(iterator = 0; iterator <8;iterator+=1)
    {
        output[iterator] = input1[iterator] ^ input2[iterator];
    }
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

void encrypt(uint8_t * input, uint8_t * output, uint8_t *key1, uint8_t *key2)
{
    DES_key_schedule ks1, ks2;
    
    /*set keys*/
    DES_set_key_unchecked((DES_cblock*)key1,&ks1);
    DES_set_key_unchecked((DES_cblock*)key2,&ks2);
    
    /*encrypt*/
    DES_ecb2_encrypt((DES_cblock*)input, (DES_cblock*)output,&ks1,&ks2, DES_ENCRYPT);
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
