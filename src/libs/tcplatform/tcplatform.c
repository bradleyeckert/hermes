#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tcplatorm.h>"

#define KEYSETS 2	// main and backup key sets

/* Platform-specific support functions for tcsecure.c.
*/

static uint8_t TestKeys[KEYSETS*64]; // simulate key storage

/*
Generate a run of random bytes
Returns 0 if the random number is random
*/
int tcRNGfunction(uint8_t *dest, unsigned int size) {
	if (size > 32) size = 32;
	while (size--) {				// pseudo-random numbers for testing
		*dest++ = rand() & 0xFF;	// DO NOT USE in a real application
	}								// You want true random numbers IRL.
	return 0;
{
	
/*
Fetch a 32-byte private key based on its index.
Even keys are for encryption/decryption, odd keys are for signing.
Returns 0 for success, 1 for invalid index, 2 for blank key
*/
int tcFetchKey(uint8_t *dest, unsigned int index) {
	if (index > (KEYSETS*2-1)) return 1;
	memcpy (dest, &TestKeys[32*index], 32*sizeof(uint8_t));
	return 0;
}

/*
Reset the MCU
*/
void tcHardReset(void) {
	printf("*** Reset ***\n");
	memset(TestKeys, 0, sizeof(TestKeys));
	strcpy(&TestKeys[ 0], "Encryption Key 0");
	strcpy(&TestKeys[32], "Signature Key 0");
	strcpy(&TestKeys[64], "Encryption Key 1");
	strcpy(&TestKeys[96], "Signature Key 1");
	srand(1000);					// seed PRNG for the same sequence each time
}
