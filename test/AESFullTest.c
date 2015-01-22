/*
   This file is part of JustGarble.

   JustGarble is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   JustGarble is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with JustGarble.  If not, see <http://www.gnu.org/licenses/>.

*/
#include <gnutls/gnutls.h>      
#include <gnutls/x509.h>      
#include <gnutls/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "../include/justGarble.h"

#include "../include/garble.h"
#include "../include/common.h"
#include "../include/circuits.h"
#include "../include/gates.h"
#include "../include/util.h"
#include "../include/dkcipher.h"
#include "../include/aes.h"
#include "../include/justGarble.h"

#include "../include/tinyaes.h"

int *final;

#define AES_CIRCUIT_FILE_NAME "./aesCircuit"
block* oldOutputMapTest;



#define BIGENDHEYO
void make_uint_array_from_blob(int* dest, unsigned char* blob, uint32_t bloblen)
{
  memset(dest, 0, bloblen * 8);
  int x;
  for (x = 0; x < bloblen; x++)
  {
    unsigned char thisblob = blob[x];
#ifdef BIGENDHEYO
    dest[x * 8] = (0x80 & thisblob) == 0x80 ? 1 : 0; 
    dest[x * 8 + 1] = (0x40 & thisblob) == 0x40 ? 1 : 0; 
    dest[x * 8 + 2] = (0x20 & thisblob) == 0x20 ? 1 : 0; 
    dest[x * 8 + 3] = (0x10 & thisblob) == 0x10 ? 1 : 0; 
    dest[x * 8 + 4] = (0x08 & thisblob) == 0x08 ? 1 : 0; 
    dest[x * 8 + 5] = (0x04 & thisblob) == 0x04 ? 1 : 0; 
    dest[x * 8 + 6] = (0x02 & thisblob) == 0x02 ? 1 : 0; 
    dest[x * 8 + 7] = (0x01 & thisblob) == 0x01 ? 1 : 0; 
#else
    dest[x * 8 + 7] = (0x80 & thisblob) == 0x80 ? 1 : 0; 
    dest[x * 8 + 6] = (0x40 & thisblob) == 0x40 ? 1 : 0; 
    dest[x * 8 + 5] = (0x20 & thisblob) == 0x20 ? 1 : 0; 
    dest[x * 8 + 4] = (0x10 & thisblob) == 0x10 ? 1 : 0; 
    dest[x * 8 + 3] = (0x08 & thisblob) == 0x08 ? 1 : 0; 
    dest[x * 8 + 2] = (0x04 & thisblob) == 0x04 ? 1 : 0; 
    dest[x * 8 + 1] = (0x02 & thisblob) == 0x02 ? 1 : 0; 
    dest[x * 8] = (0x01 & thisblob) == 0x01 ? 1 : 0; 

#endif
  
  }
}

void buildAESCircuit() {
  srand(time(NULL));
  GarbledCircuit garbledCircuit;
  GarblingContext garblingContext;

  int roundLimit = 10;
  int n = 128 + 128 * (roundLimit + 1); //XOR the key 11 times
  int m = 128;
  int q = 50000; //Just an upper bound
  int r = 50000;
  int inp[n];
  countToN(inp, n);
  int addKeyInputs[n * (roundLimit + 1)];
  int addKeyOutputs[n];
  int subBytesOutputs[n];
  int shiftRowsOutputs[n];
  int mixColumnOutputs[n];
  int round;
  block labels[2 * n];
  oldOutputMapTest = (block*) malloc(sizeof(block) * 2 * m);
  OutputMap outputMap = oldOutputMapTest;
  InputLabels inputLabels = labels;
  int i;

  createInputLabels(labels, n);
  createEmptyGarbledCircuit(&garbledCircuit, n, m, q, r, inputLabels);
  startBuilding(&garbledCircuit, &garblingContext);

  countToN(addKeyInputs, n * 2);

  AddRoundKey(&garbledCircuit, &garblingContext, addKeyInputs, addKeyOutputs);

  memset(mixColumnOutputs, 0, sizeof(int) * 128);
    for (i = 0; i < 4; i++) {
        JustineMixColumns(&garbledCircuit, &garblingContext,
            addKeyOutputs + i * 32, mixColumnOutputs + 32 * i);
    }
 

final = mixColumnOutputs;
  /* 
  for (round = 1; round < 2; round++) {

    for (i = 0; i < 16; i++) {
      SubBytes(&garbledCircuit, &garblingContext, addKeyOutputs + 8 * i,
          subBytesOutputs + 8 * i);
    }

    ShiftRows(&garbledCircuit, &garblingContext, subBytesOutputs,
        shiftRowsOutputs);

    for (i = 0; i < 4; i++) {
      if (round != roundLimit - 1)
        MixColumns(&garbledCircuit, &garblingContext,
            shiftRowsOutputs + i * 32, mixColumnOutputs + 32 * i);
    }
    for (i = 0; i < 128; i++) {
      addKeyInputs[i] = shiftRowsOutputs[i];
      addKeyInputs[i + 128] = (round + 1) * 128 + i;
    }

    AddRoundKey(&garbledCircuit, &garblingContext, addKeyInputs,addKeyOutputs);
  }
  for (i = 0; i < 16; i++) {
    SubBytes(&garbledCircuit, &garblingContext, addKeyOutputs + 8 * i,
        subBytesOutputs + 8 * i);
  }

  ShiftRows(&garbledCircuit, &garblingContext, subBytesOutputs,
      shiftRowsOutputs);

  for (i = 0; i < 128; i++) {
    addKeyInputs[i] = shiftRowsOutputs[i];
    addKeyInputs[i + 128] = (12) * 128 + i;
  }

  AddRoundKey(&garbledCircuit, &garblingContext, addKeyInputs,addKeyOutputs) ;
  final = addKeyOutputs;*/
  finishBuilding(&garbledCircuit, &garblingContext, outputMap, final);



  garbleCircuit(&garbledCircuit, inputLabels, outputMap);

  //JMS: Replace timing with check for correctness
  block finalOutput[m];
  block extractedLabels[n];

  __m128i mykey =  randomBlock();
  unsigned char* t = (unsigned char*) &(mykey);
  AES_KEY key;
  memset(&key, 0, sizeof(key));
  AES_set_encrypt_key((unsigned char*) &mykey, 128, &key);

  int x = 0;
  int inputs[n];
  for(x = 0; x < 128; x++) inputs[x] = 1; 
  unsigned char* blob = &key.rd_key;

  printf("(%u) Input key...", key.rounds);
  make_uint_array_from_blob(inputs + 128, blob, n/8 - 16);
  for(x = 0; x < n; x++) printf("%u", inputs[x]);
  printf("\n\n");

  extractLabels(extractedLabels, inputLabels, inputs, n);
  evaluate(&garbledCircuit, extractedLabels, finalOutput);

  int outputVals[m];
  memset(outputVals, 0, sizeof(int) * m);
  mapOutputs(outputMap, finalOutput, outputVals, m);

  unsigned char input_aes[16];
  memset(input_aes, 0xff, 16);
  unsigned char output_aes[16];

  printf("THEIR CODE:\n");
  AES_encrypt(input_aes, output_aes, &key);
  int aes_output_int[128];
  make_uint_array_from_blob(aes_output_int, output_aes, 16); 
  for(x = 0; x < 128; x++) printf("%u", aes_output_int[x]);
  printf("\n\n"); 

  printf("GNUTLS:\n");
  gnutls_global_init();
  gnutls_cipher_hd_t aes_handle;
  gnutls_cipher_algorithm_t cipher = gnutls_cipher_get_id("AES-128-CBC");
  gnutls_datum_t gtlskey;
  gtlskey.data = (unsigned char*) &mykey;
  //gtlskey.size = 0;
  gtlskey.size = sizeof(__m128i);
  gnutls_datum_t* iv = NULL;
  int res = gnutls_cipher_init(&aes_handle, cipher, &gtlskey, iv); 
  
  
  unsigned char output_gnutls[128];
  memset(output_gnutls, 0, 128);
  int success = gnutls_cipher_encrypt2(aes_handle, input_aes, 16, output_gnutls, 16);
  int gnutls_output_int[128];
  make_uint_array_from_blob(gnutls_output_int, output_gnutls, 16);
  for(x = 0; x < 128; x++) printf("%u", gnutls_output_int[x]);
  printf("\n\n");


  printf("TINY AES:\n");
  unsigned char output_tinyaes[16];
  int tinyaes_output_int[128];
  unsigned char IV[16];
  memset(IV, 0, 16);
  AES128_CBC_encrypt_buffer(output_tinyaes, input_aes, 16, (const uint8_t*) &mykey, IV);
  make_uint_array_from_blob(tinyaes_output_int, output_tinyaes, 16);
  for(x = 0; x < 128; x++) printf("%u", tinyaes_output_int[x]);
  printf("\n\n");


  //Should be 1's and 0's.
  printf("Final output of circuit: \n");
  for(x = 0; x < 128; x++){
    printf("%u", outputVals[x]);
  }
  printf("\n");

  //writeCircuitToFile(&garbledCircuit, AES_CIRCUIT_FILE_NAME);
}

int main() {
  int rounds = 10;
  int n = 128 + (128 * rounds);
  int m = 128;

  GarbledCircuit aesCircuit;
  block inputLabels[2 * n];
  block outputMap[2 * m]; //JMS: Change from m to 2 * m
  int i, j;
  buildAESCircuit();
  exit(5);
  readCircuitFromFile(&aesCircuit, AES_CIRCUIT_FILE_NAME);

  int timeGarble[TIMES];
  int timeEval[TIMES];
  double timeGarbleMedians[TIMES];
  double timeEvalMedians[TIMES];

  for (j = 0; j < 1; j++) {
    for (i = 0; i < 1; i++) {
      timeGarble[i] = garbleCircuit(&aesCircuit, inputLabels, outputMap);

      //JMS: Replace timing with check for correctness
      block finalOutput[m];
      block extractedLabels[n];

      int inputs[n];
      for (j = 0; j < n; j++) {
        inputs[j] = rand() % 2;
      }
      extractLabels(extractedLabels, inputLabels, inputs, n);

      evaluate(&aesCircuit, extractedLabels, finalOutput);

      int outputVals[m];
      memset(outputVals, 0, sizeof(int) * m);
      mapOutputs(outputMap, finalOutput, outputVals, m);

      //Should be 1's and 0's.
      int x;
      printf("Final output of circuit: ");
      for(x = 0; x < m; x++){
        printf("%u", outputVals[x]);
      }
      printf("\n");
      //timeEval[i] = timedEval(&aesCircuit, inputLabels);
    }
    //timeGarbleMedians[j] = ((double) median(timeGarble, TIMES))
    //		/ aesCircuit.q;
    //timeEvalMedians[j] = ((double) median(timeEval, TIMES)) / aesCircuit.q;
  }
  //double garblingTime = doubleMean(timeGarbleMedians, TIMES);
  //double evalTime = doubleMean(timeEvalMedians, TIMES);
  //printf("%lf %lf\n", garblingTime, evalTime);
  return 0;
}

