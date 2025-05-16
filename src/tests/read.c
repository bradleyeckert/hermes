#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../xchacha/src/xchacha.h"
#include "../blake2s/src/blake2s.h"
#include "../moleconfig.h"

static const uint8_t keyset[] = TESTPASS_2;
static const uint8_t KDFpasscode[] = KDF_PASS;

#define FILENAME "demofile.bin"

xChaCha_ctx   cCtx; // encryption context
blake2s_state hCtx; // HMAC context
uint8_t cryptokey[32];
uint8_t hmackey[32];

// KDF adapted from mole.c:

static void KDF (uint8_t *dest, const uint8_t *src,
                int length, int iterations, int reverse) {
    uint8_t KDFbuffer[32];
    for (int i = 0; i < length; i++) {
        if (reverse) KDFbuffer[i] = src[length + (~i)];
        else         KDFbuffer[i] = src[i];
    }
    while (iterations--) {
        b2s_hmac_init(&hCtx, KDFpasscode, length, 0);
        for (int i = 0; i < length; i++) {
            b2s_hmac_putc(&hCtx, KDFbuffer[i]);
        }
        b2s_hmac_final(&hCtx, KDFbuffer);
    }
    memcpy(dest, KDFbuffer, length);
}

static void moleNewKeys(const uint8_t *key) {
    KDF(hmackey,   key, 32, 55, 0);
    KDF(cryptokey, key, 32, 55, 1);
}


// Decode a file created by moletest.c

uint64_t hctr;      // HMAC counter
FILE* file;         // input file
uint8_t HMAC[16];   // captured HMAC

int NextChar(void) {
    int c = fgetc(file);
    if (c < 0) return c;                        // EOF
    if (c == 0x0B) {
        c = fgetc(file);
        if (c > 1) switch(c) {
        case 2:
            b2s_hmac_final(&hCtx, HMAC);
            hctr++;
            return 0x100;
        default:
            printf("\nUnknown 10 ??");
        } else c += 0x0A;
    }
    b2s_hmac_putc(&hCtx, c);
    return c;
}

int NextBlock(uint8_t *dest) {                  // return bytes read before HMAC
    for (int i = 0; i < 16; i++) {
        int c = NextChar();
        if (c == EOF) return c;
        if (c & 0x100) return i;                // HMAC tag
        *dest++ = c;
    }
    return 16;
}

int TestHMAC(uint8_t *src) {
    for (int i = 0; i < 16; i++) if (src[i] != HMAC[i]) return 1;
    return 0;
}

void dump(const uint8_t *src, uint8_t len) {
    for (uint8_t i = 0; i < len; i++) {
        if ((i % 16) == 0) printf("\n___");
        printf("%02X ", src[i]);
    }
    printf("<- ");
}

void SkipEndTag(void) {
    int c;
    do {
        c = fgetc(file);                        // .. .. .. 0A .. ..
        if (c == EOF) return;                   //             ^-- file pointer
    } while (c != 0x0A);
}

int main(int argc, char *argv[]) {
    char *filename;
    if (argc > 1) {
        filename = argv[1];
    } else {
        filename = FILENAME;
    }
    uint8_t IV[17];
    printf("\nReading %s ", filename);
    file = fopen(filename, "rb");
    if (file == NULL) {
        printf("\nError opening file!");
        return 1;
    }
    moleNewKeys(keyset);
    SkipEndTag();                               // skip boilerplate
//    SkipEndTag();
    printf("\nBegin CHALLENGE message at 0x%X ", (unsigned int)ftell(file));
    hctr = 0;
    b2s_hmac_init(&hCtx, hmackey, 16, hctr);
    if (NextChar() != 0x18) {
        printf("\nError: Couldn't find challenge tag");
        goto end;
    }
    NextBlock(IV);
    dump(IV, 16); printf("mIV (visible, but used once to encrypt cIV)");
    xc_crypt_init(&cCtx, cryptokey, IV);// set up to decrypt cIV
    NextBlock(IV);
    NextChar();                                 // ignore 'avail' field
    NextChar();
    xc_crypt_block(&cCtx, IV, IV, 1);           // mIV --> cIV
    memcpy(&hctr, IV, 8);                       // initial IV and hctr
    xc_crypt_init(&cCtx, cryptokey, IV);
    dump(IV, 16); printf("cIV (private)");
    dump((uint8_t*)&hctr, 8); printf("Initial 64-bit HMAC counter");
    if (NextBlock(IV)) {
        printf("\nError: Expected 10 04 HMAC trigger");
        goto end;
    }
    NextBlock(IV);                              // expected HMAC
    if (NextChar() != 0x0A) {
        printf("\nError: Expected END tag");
        goto end;
    }
    if (TestHMAC(IV)) {
        printf("\nError: Bad HMAC");
        dump(IV, 16); printf("expected");
        dump(HMAC, 16); printf("actual");
        goto end;
    }
    SkipEndTag();
    printf("\nDecryption stream has been initialized, fp=0x%X ", (unsigned int)ftell(file));
// Begin RAW PACKET messages
    while(1) {
        b2s_hmac_init(&hCtx, hmackey, 16, hctr);
        int c = NextChar();
        if (c < 0) {
            printf("\nFINISHED!");
            goto end;
        }
        if (c != 0x1F) {
            printf("\nError: Expected RAW PACKET tag");
            goto end;
        }
        if (NextChar() != 0x01) {
            printf("\nError: Expected format 0x80 (unknown length)");
            goto end;
        }
        while (1) {
            int n = NextBlock(IV);
            if (n < 0) {
                printf("\nError: Early EOF %d", n);
                goto end;
            }
            if (n < 16) break;
            xc_crypt_block(&cCtx, IV, IV, 1);
            IV[16] = 0;
            dump(IV, n); printf("%s", IV);
        }
        NextBlock(IV);                          // expected HMAC
        if (TestHMAC(IV)) {
            printf("\nError: Bad HMAC");
            dump(IV, 16); printf("expected");
            dump(HMAC, 16); printf("actual");
            goto end;
        }
        SkipEndTag();
        SkipEndTag();                           // skip padding
    }
end:
    fclose(file);
}
