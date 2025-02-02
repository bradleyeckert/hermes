/* Platform-specific support functions for tcsecure.c.
*/
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tchostHW.h"

#define MAXKEYS 3

/*
This data is private keys that must be in a privileged memory space.
On an MCU, they would be in a dedicated sector of internal Flash.
IRL, keys should be hashed or hidden by ECDSA.
*/
static uint8_t tcKeyArray[16*MAXKEYS] = {
  // --------________--------________--------________
    "The quick brown fox jumped over the lazy dog."
  // KE..............................KH..............
};

/*
Point to a 128-bit key in a set of keys. Keys may concatenate to 256-bit.
*/
const uint8_t * tchKeyN(unsigned int n) {
	if (n >= MAXKEYS) return NULL;
	return &tcKeyArray[n * 16];
}

/*
Generate a run of random bytes
Returns 0 if the random number is random
*/
int tchRNGfunction(uint8_t *dest, unsigned int size) {
	if (size > 32) size = 32;
	while (size--) {				// pseudo-random numbers for testing
		*dest++ = rand() & 0xFF;	// DO NOT USE in a real application
	}								// You want true random numbers IRL.
	return 0;                       // return TC_ERROR_BAD_RNG if broken
}


