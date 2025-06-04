#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "../xchacha.h"
#include "../blake2s.h"
#include "../mole.h"
#include "../moleconfig.h"

#define MaximumKeys 32

int moleTRNG(uint8_t *dest, int length) {
	while (length--) *dest++ = rand() & 0xFF;   // DO NOT USE 'rand' in a real application
	return 0;                                   // Use a TRNG instead
}

static const uint8_t KHK[] = KDF_PASS;

blake2s_state hCtx; // HMAC context
char *keyname[MaximumKeys];

int main(int argc, char *argv[]) {
    keyname[0] = "MY_KEY";
    int keys = 1;
    if (argc > 1) {
        keys = argc - 1;
        if (keys >= MaximumKeys) {
            printf("Too many keys ");
            return 1;
        }
        for (int i = 0; i < keys; i++) {
            keyname[i] = argv[i + 1];
        }
    }
    srand(time(0)); // seed with time
    for (int i = 0; i < keys; i++) {
        uint8_t k[MOLE_PASSCODE_LENGTH];
        moleTRNG(k, MOLE_PASSCODE_LENGTH);
        b2s_hmac_init(&hCtx, KHK, 16, 0);
        for (int i=0; i < (MOLE_PASSCODE_HMAC); i++) {
            b2s_hmac_putc(&hCtx, k[i]);
        }
        b2s_hmac_final(&hCtx, &k[MOLE_PASSCODE_HMAC]);
        printf("#define %s { ", keyname[i]);
        for (uint8_t i = 0; i < MOLE_PASSCODE_LENGTH; i++) {
            if ((i % 16) == 0) printf("\\\n  ");
            printf("0x%02X", k[i]);
            if (i != (MOLE_PASSCODE_LENGTH-1)) printf(", ");
        }
        printf("}\n\n");
    }
}
