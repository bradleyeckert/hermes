/* Platform-specific support functions for hermes
*/
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "hermesHW.h"

/*
Generate a random byte
*/
int getc_TRNG(void) {
	return rand() & 0xFF;	// DO NOT USE in a real application
}                           // Use a TRNG instead

/*
Also, note that TRNGs (random numbers from hardware noise) are very slow.
To get real random numbers for the IV, continuously fill an array from the TRNG
and get the current hash of the array when you need a new 32-byte random number.
The hash will change to a new unpredictable hash with each new TRNG byte.
*/


