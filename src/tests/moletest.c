#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../mole.h"

// -----------------------------------------------------------------------------
// Some default values for testing

port_ctx Alice;
port_ctx Bob;
int snoopy;

#define MY_PROTOCOL 0

// Connect Alice to Bob via a virtual null-modem cable

int error_pacing = 720;
int errorpos = 0;                       // inject error every error_pacing byte

static uint8_t snoop(uint8_t c, char t) {
    if (!(++errorpos % error_pacing)) {
        c++;
        printf("\n<><><><><><> Error injected <><><><><><> ");
    }
    if (!snoopy) return c;
    printf("%02X", c);
    if (c == 0x12) printf("\n");
    else           printf("%c", t);
    return c;
}

static char* errorCode(int e) {
    switch(e) {
    case MOLE_ERROR_INVALID_STATE:   return "Invalid state (should never happen)";
    case MOLE_ERROR_UNKNOWN_CMD:     return "Unknown Command";
    case MOLE_ERROR_TRNG_FAILURE:    return "TRNG failure - need to re-initialize";
    case MOLE_ERROR_MISSING_KEY:     return "Missing key - maybe has NULL value";
    case MOLE_ERROR_BAD_HMAC:        return "Invalid HMAC";
    case MOLE_ERROR_INVALID_LENGTH:  return "Invalid packet length";
    case MOLE_ERROR_LONG_BOILERPLT:  return "Boilerplate is too long";
    case MOLE_ERROR_MSG_TRUNCATED:   return "Message was truncated";
    case MOLE_ERROR_OUT_OF_MEMORY:   return "Insufficient MOLE_ALLOC_MEM_UINT32S";
    case MOLE_ERROR_REKEYED:         return "Keys were changed";
    case MOLE_ERROR_BUF_TOO_SMALL:   return "Buffer blocks must be at least 2";
    default: return "unknown";
    }
}

static void AliceCiphertextOutput(uint8_t c) {
    c = snoop(c, '-');
    int r = molePutc(&Bob, c);
    if (r) printf("\n*** Bob returned %d: %s, ", r, errorCode(r));
}

static void BobCiphertextOutput(uint8_t c) {
    c = snoop(c, '~');
    int r = molePutc(&Alice, c);
    if (r) printf("\n*** Alice returned %d: %s, ", r, errorCode(r));
}

/*
Received-plaintest functions
*/
static void PlaintextHandler(const uint8_t *src, int length) {
    printf("\nPlaintext {");
    for (int i = 0; i < length; i++) {
        putc(src[i], stdout);
        //printf("%02x/", src[i]);
    }
    printf("} ");
}

static void BoilerHandlerA(const uint8_t *src) {
    printf("\nAlice received %d-byte boilerplate {%s}", src[0], &src[1]);
}

static void BoilerHandlerB(const uint8_t *src) {
    printf("\n  Bob received %d-byte boilerplate {%s}", src[0], &src[1]);
}

const uint8_t AliceBoiler[] =   {"\x13noyb<Alice's_UUID>0"};
const uint8_t BobBoiler[] =     {"\x13noyb<Bob's_UUID__>0"};


const uint8_t AliceMessages[][128] = {
" 1. Alice had got so much into the way of expecting nothing but out-of-the-way things to happen,",
" 2. that it seemed quite dull and stupid for life to go on in the common way.",
" 3. I almost wish I hadn't gone down that rabbit-hole-and yet-and yet-it's rather curious, you know, this sort of life!",
" 4. Sometimes, I've believed as many as six impossible things before breakfast.",
" 5. Well, I never heard it before, but it sounds uncommon nonsense.",
" 6. A dream is not reality but who's to say which is which?",
" 7. How puzzling all these changes are! I'm never sure what I'm going to be,",
" 8. from one minute to another.",
" 9. We're all mad here.",
"10. If you drink much from a bottle marked 'poison' it is certain to disagree with you sooner or later.",
"11. 'If you knew Time as well as I do,' said the Hatter, 'you wouldn't talk about wasting it.'",
"12. It would be so nice if something made sense for a change."
};

const uint8_t BobMessages[][128] = {
" 1. Bob: Now, Bart, any last requests?",
" 2. Bart: Well, there was one, but... Naah, forget it.",
" 3. Bob: No, go on.",
" 4. Bart: It's just that you have such a beautiful voice...",
" 5. Bob: Guilty as charged.",
" 6. Bart: Uh huh. Anyway, I was wondering if you could sing the entire score of the \"H.M.S. Pinafore\".",
" 7. Bob: Very well, Bart. I shall send you to Heaven before I send you to hell. And a 1 and a 2 and",
" 8. [singing]",
" 9. Bob: \"We sail the ocean blue, and our saucy ship's a beauty. We are sober men and true, and attentive to our duty...",
"10. [later]",
"11. Bob: \"I'm called Little Buttercup, poor Little Buttercup, though I could never tell why...\"",
"12. [later]",
"13. Bob: ...\"What never?\" \"No never.\" \"What never?\" \"Hardly ever!\"",
"14. [with Bart]",
"15. Bob, Bart: \"he's hardly ever sick at sea...\"",
"16. [later]",
"17. Bob: \"... For he himself has said it, and it's clearly to his credit, that he is an Englishman.\"",
"18.      \"He remai-hains ah-han Eh-heh-heh-heh-heh-hengLISHman!\""};

int SendAlice(int msgID) {
    int elements = sizeof(AliceMessages) / sizeof(AliceMessages[0]);
    if (msgID >= elements) msgID = elements - 1;
    const uint8_t* s = AliceMessages[msgID];
    if (!moleAvail(&Alice)) {
        molePair(&Alice);
    }
    int ior = moleSend(&Alice, s, strlen((char*)s));
    if (ior) printf("\n<<<moleSend>>> returned error code %d ", ior);
    return elements;
}

int SendBob(int msgID) {
    int elements = sizeof(BobMessages) / sizeof(BobMessages[0]);
    if (msgID >= elements) msgID = elements - 1;
    const uint8_t* s = BobMessages[msgID];
    if (!moleAvail(&Bob)) {
        printf("\nRe-authenticating the connection");
        molePair(&Bob);
    }
    int ior = moleSend(&Bob, s, strlen((char*)s));
    if (ior) printf("\n<<<moleSend>>> returned error code %d ", ior);
    return elements;
}

void PairAlice(void) {
    printf("\nAlice is pairing with keys ");
    for (int i=0; i<64; i++) printf("%02x", Alice.key[i]);
    molePair(&Alice);
    if (Alice.hctrTx != Bob.hctrRx) printf("\nERROR: Alice cannot send to Bob");
    if (Bob.hctrTx != Alice.hctrRx) printf("\nERROR: Bob cannot send to Alice");
    printf("\nAvailability: Alice=%d, Bob=%d",
           moleAvail(&Alice), moleAvail(&Bob));
}

// File encryption

FILE *file;
int tally;

void CharToFile(uint8_t c) {
    fputc(c, file);
    tally++;
}

// 32-byte encryption key, 32-byte MAC key, 16-byte admin password, 16-byte hash
uint8_t my_keys[96] = {
  0xF6,0x22,0x91,0x9D,0xE1,0x8B,0x1F,0xDA,0xB0,0xCA,0x99,0x02,0xB9,0x72,0x9D,0x49,
  0x2C,0x80,0x7E,0xC5,0x99,0xD5,0xE9,0x80,0xB2,0xEA,0xC9,0xCC,0x53,0xBF,0x67,0xD6,
  0xBF,0x14,0xD6,0x7E,0x2D,0xDC,0x8E,0x66,0x83,0xEF,0x57,0x49,0x61,0xFF,0x69,0x8F,
  0x61,0xCD,0xD1,0x1E,0x9D,0x9C,0x16,0x72,0x72,0xE6,0x1D,0xF0,0x84,0x4F,0x4A,0x77,
  0x02,0xD7,0xE8,0x39,0x2C,0x53,0xCB,0xC9,0x12,0x1E,0x33,0x74,0x9E,0x0C,0xF4,0xD5,
  0xD9,0x40,0x7E,0xB1,0xEB,0x54,0x61,0xE8,0x88,0xDD,0xB3,0xCF,0x12,0x51,0x64,0xCF};

const uint8_t new_keys[96] = {
  0x48,0xD3,0x8F,0x75,0xE6,0xD9,0x1D,0x2A,0xE5,0xC0,0xF7,0x2B,0x78,0x81,0x87,0x44,
  0x0E,0x5F,0x50,0x00,0xD4,0x61,0x8D,0xBE,0x7B,0x05,0x15,0x07,0x3B,0x33,0x82,0x1F,
  0x18,0x70,0x92,0xDA,0x64,0x54,0xCE,0xB1,0x85,0x3E,0x69,0x15,0xF8,0x46,0x6A,0x04,
  0x96,0x73,0x0E,0xD9,0x16,0x2F,0x67,0x68,0xD4,0xF7,0x4A,0x4A,0xD0,0x57,0x68,0x76,
  0xFA,0x16,0xBB,0x11,0xAD,0xAE,0x24,0x88,0x79,0xFE,0x52,0xDB,0x25,0x43,0xE5,0x3C,
  0x8D,0xD6,0x41,0x17,0x60,0x9B,0xD9,0x95,0xF6,0xF7,0xC9,0xE7,0x8D,0x10,0xF1,0x50};

/*
Write the key and return the address of the key (it may have changed)
Return NULL if key cannot be updated
*/

uint8_t * UpdateKeySet(uint8_t* keyset) {
    memcpy(my_keys, keyset, MOLE_KEYSET_LENGTH);
	return my_keys;
}

int getc_RNG(void) {
	return rand() & 0xFF;	// DO NOT USE in a real application
}                           // Use a TRNG instead

//    ctx->hInitFn((void *)&*ctx->rhCtx, &key[32], 16, MOLE_KEY_HASH_KEY);
//    for (int i=0; i < 48; i++) ctx->hputcFn((void *)&*ctx->rhCtx, key[i]);
//    ctx->hFinalFn((void *)&*ctx->rhCtx, ctx->hmac);

void makeKey(void) {        // printf a random key set, with HMAC
    uint8_t k[MOLE_KEYSET_LENGTH];
    for (int i=0; i < MOLE_KEYSET_LENGTH; i++) k[i] = getc_RNG();
    Alice.hInitFn((void*)Alice.rhCtx, &k[32], 16, MOLE_KEY_HASH_KEY);
    for (int i=0; i < (MOLE_KEYSET_LENGTH - MOLE_HMAC_LENGTH); i++) {
        Alice.hputcFn((void*)Alice.rhCtx, k[i]);
    }
    Alice.hFinalFn((void*)Alice.rhCtx, &k[MOLE_KEYSET_LENGTH - MOLE_HMAC_LENGTH]);
    printf("uint8_t my_keys[%d] = {", MOLE_KEYSET_LENGTH);
    for (uint8_t i = 0; i < MOLE_KEYSET_LENGTH; i++) {
        if ((i % 16) == 0) printf("\n  ");
        printf("0x%02X", k[i]);
        if (i != (MOLE_KEYSET_LENGTH-1)) printf(",");
    }
    printf("};\n");
}

int main() {
    int tests = 0x1FF;      // enable these tests...
//    snoopy = 1;             // display the wire traffic
    moleNoPorts();
    int ior = moleAddPort(&Alice, AliceBoiler, MY_PROTOCOL, "ALICE", 2, getc_RNG,
                  BoilerHandlerA, PlaintextHandler, AliceCiphertextOutput, my_keys, UpdateKeySet);
    if (!ior) ior = moleAddPort(&Bob, BobBoiler, MY_PROTOCOL, "BOB", 2, getc_RNG,
                  BoilerHandlerB, PlaintextHandler, BobCiphertextOutput, my_keys, UpdateKeySet);
//    for (int i=0; i<5; i++) makeKey();
    if (ior) {
        printf("\nError %d: %s, ", ior, errorCode(ior));
        printf("too small by %d ", -moleRAMunused()/4);
        printf("or the key has a bad HMAC");
        return ior;
    }
    printf("Static context RAM usage: %d bytes per port\n", moleRAMused(2)/2);
    printf("context_memory has %d unused bytes (%d unused longs)\n",
           moleRAMunused(), moleRAMunused()/4);
    Alice.hctrTx = 0x3412; // ensure that re-pair resets these
    Alice.hctrRx = 0x341200;
    Bob.hctrTx = 0x785600;
    Bob.hctrRx = 0x7856;
    if (tests & 0x01) moleBoilerReq(&Alice);
    if (tests & 0x02) moleBoilerReq(&Bob);
    if (tests & 0x04) PairAlice();
    int i, j;
    if (tests & 0x08) {
        printf("\n\nAlice =================================");
        moleSend(&Alice, (uint8_t*)"*", 1);
        moleSend(&Alice, (uint8_t*)"*", 0);
    }
    if (tests & 0x10) {
        i = 0;
        do {j = SendAlice(i++);} while (i != j);
    }
    if (tests & 0x20) {
        printf("\n\nBob ===================================");
        i = 0;
        do {j = SendBob(i++);} while (i != j);
    }
    error_pacing = 1000000; // turn off error injection
    if (tests & 0x40) {
        printf("\nEnable admin mode =======================");
        printf("\nBefore = %x", Bob.admin);
        moleAdmin(&Alice);
        printf("\nAfter = 0x%x", Bob.admin);
    }
    if (tests & 0x80) {
        printf("\n\nRe-keying ===============================");
        i = moleReKey(&Alice, new_keys);
        if (i) printf("\nError %d: %s, ", i, errorCode(i));
        PairAlice();
    }
    printf("\nAlice sent %d bytes", Alice.counter);
    printf("\nBob sent %d bytes", Bob.counter);
    if (tests & 0x100) {
        printf("\n\nTest write to demofile.bin ");
        Alice.ciphrFn = CharToFile;
        file = fopen("demofile.bin", "wb");
        if (file == NULL) {
            printf("\nError creating file!");
            return 1;
        }
        moleFileNew(&Alice);
        for (int i = 0; i < 100; i++) {
            moleFileOut(&Alice, (uint8_t*)"ABCDEFGHIJKLMNOP", 16);
        }
        moleFileFinal(&Alice, 0);
        fclose(file);
    }
    return 0;
}
