#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "../xchacha/src/xchacha.h"
#include "../blake2s/src/blake2s.h"
#include "../mole.h"

#define MaximumKeys 32

static uint8_t getc_RNG(void) {
    rand();
    return rand() & 0xFF;
}

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
        uint8_t k[MOLE_KEYSET_LENGTH];
        for (int i=0; i < MOLE_KEYSET_LENGTH; i++) k[i] = getc_RNG();
        b2s_hmac_init(&hCtx, &k[32], 16, MOLE_KEY_HASH_KEY);
        for (int i=0; i < (MOLE_KEYSET_HMAC); i++) {
            b2s_hmac_putc(&hCtx, k[i]);
        }
        b2s_hmac_final(&hCtx, &k[MOLE_KEYSET_HMAC]);
        printf("#define %s { ", keyname[i]);
        for (uint8_t i = 0; i < MOLE_KEYSET_LENGTH; i++) {
            if ((i % 16) == 0) printf("\\ \n  ");
            printf("0x%02X", k[i]);
            if (i != (MOLE_KEYSET_LENGTH-1)) printf(", ");
        }
        printf("}\n\n");
    }
}
