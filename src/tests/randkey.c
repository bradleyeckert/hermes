#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "../xchacha/src/xchacha.h"
#include "../blake2s/src/blake2s.h"
#include "../mole.h"

//    ctx->hInitFn((void *)&*ctx->rhCtx, &key[32], 16, MOLE_KEY_HASH_KEY);
//    for (int i=0; i < 48; i++) ctx->hputcFn((void *)&*ctx->rhCtx, key[i]);
//    ctx->hFinalFn((void *)&*ctx->rhCtx, ctx->hmac);

static uint8_t getc_RNG(void) {
    rand();
    return rand() & 0xFF;
}

blake2s_state hCtx; // HMAC context

int main(int argc, char *argv[]) {
    char *keyname = "MY_KEY";
    char *filename = NULL;
    if (argc > 1) {
        keyname = argv[1];
    }
    if (argc > 2) {
        filename = argv[2];
    }
    FILE * file = fopen(filename, "w");
    if (file == NULL) file = stdout;
    srand(time(0)); // seed with time
    uint8_t k[MOLE_KEYSET_LENGTH];
    for (int i=0; i < MOLE_KEYSET_LENGTH; i++) k[i] = getc_RNG();
    b2s_hmac_init(&hCtx, &k[32], 16, MOLE_KEY_HASH_KEY);
    for (int i=0; i < (MOLE_KEYSET_HMAC); i++) {
        b2s_hmac_putc(&hCtx, k[i]);
    }
    b2s_hmac_final(&hCtx, &k[MOLE_KEYSET_HMAC]);
    fprintf(file, "#define %s { ", keyname);
    for (uint8_t i = 0; i < MOLE_KEYSET_LENGTH; i++) {
        if ((i % 16) == 0) fprintf(file, "\\ \n  ");
        fprintf(file, "0x%02X", k[i]);
        if (i != (MOLE_KEYSET_LENGTH-1)) fprintf(file, ", ");
    }
    fprintf(file, "};\n");
    fclose(file);
}
