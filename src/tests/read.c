#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../xchacha/src/xchacha.h"
#include "../siphash/src/siphash.h"

const uint8_t my_encryption_key[] = {
  0xB0,0x95,0x57,0xF5,0xDF,0x80,0x6C,0x6D,0x8D,0x74,0xD9,0x8B,0x43,0x65,0x11,0x08,
  0xA5,0xF6,0x79,0xBD,0xF7,0xEB,0x15,0xB8,0xE0,0xE1,0x60,0x8F,0x6E,0x3C,0x7B,0xF4,
  0x5B,0x62,0x8A,0x8A,0x8F,0x27,0x5C,0xF7,0xE5,0x87,0x4A,0x3B,0x32,0x9B,0x61,0x40,
  0xF8,0xF8,0x79,0x10,0x83,0x97,0x66,0xD3,0x46,0xCC,0x08,0x8E,0x65,0xF1,0x65,0x3F};

#define my_signature_key  (&my_encryption_key[32])

#define FILENAME "C:/Users/Brad/Documents/GitHub/hermes_CodeBlocks/HERMES/bin/Release/demofile.bin"

// Decode a file

xChaCha_ctx cCtx;   // encryption context
siphash_ctx hCtx;   // HMAC context
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
            sip_hmac_final(&hCtx, HMAC);
            hctr++;
            return 0x100;
        default:
            printf("\nUnknown 10 ??");
        } else c += 0x0A;
    }
    sip_hmac_putc(&hCtx, c);
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
        c = fgetc(file);                        // .. .. .. 12 .. ..
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
    SkipEndTag();                               // skip boilerplate
    SkipEndTag();
    printf("\nBegin CHALLENGE message at 0x%X ", (unsigned int)ftell(file));
    hctr = 0;
    sip_hmac_init(&hCtx, my_signature_key, 16, hctr);
    if (NextChar() != 0x18) {
        printf("\nError: Couldn't find challenge tag");
        goto end;
    }
    NextBlock(IV);
    dump(IV, 16); printf("mIV (visible, but used once to encrypt cIV)");
    xc_crypt_init(&cCtx, my_encryption_key, IV);// set up to decrypt cIV
    NextBlock(IV);
    NextChar();                                 // ignore 'avail' field
    NextChar();
    xc_crypt_block(&cCtx, IV, IV, 1);           // mIV --> cIV
    memcpy(&hctr, IV, 8);                       // initial IV and hctr
    xc_crypt_init(&cCtx, my_encryption_key, IV);
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
        sip_hmac_init(&hCtx, my_signature_key, 16, hctr);
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
