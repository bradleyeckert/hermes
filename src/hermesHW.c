/* Platform-specific support functions for hermes
*/
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
//#include <stdio.h>
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

//                            |---------- encryption ---------|---signature---|---key_HMAC---|
//                            0000000000000000111111111111111122222222222222223333333333333333
// encryption256, hash128 =   0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
static uint8_t my_keys[64] = "Do not use this encryption key! Or this one...";

/*
Write the key and return the address of the key (it may have changed)
Return NULL if key cannot be updated
*/
uint8_t * UpdateHermesKeySet(uint8_t* keyset) {
    memcpy(my_keys, keyset, 64);
	return my_keys;
}
/*
Return the keys, NULL if missing. 48 bytes are used.
*/
uint8_t * HermesKeySet(void) {
	return my_keys;
}
