#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../hermes.h"

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
    case HERMES_ERROR_INVALID_STATE:   return "Invalid state (should never happen)";
    case HERMES_ERROR_UNKNOWN_CMD:     return "Unknown Command";
    case HERMES_ERROR_TRNG_FAILURE:    return "TRNG failure - need to re-initialize";
    case HERMES_ERROR_MISSING_KEY:     return "Missing key - maybe has NULL value";
    case HERMES_ERROR_BAD_HMAC:        return "Invalid HMAC";
    case HERMES_ERROR_INVALID_LENGTH:  return "Invalid packet length";
    case HERMES_ERROR_LONG_BOILERPLT:  return "Boilerplate is too long";
    case HERMES_ERROR_MSG_TRUNCATED:   return "Message was truncated";
    case HERMES_ERROR_OUT_OF_MEMORY:   return "Insufficient HERMES_ALLOC_MEM_UINT32S";
    case HERMES_ERROR_REKEYED:         return "Keys were changed";
    case HERMES_ERROR_BUF_TOO_SMALL:   return "Buffer blocks must be at least 2";
    default: return "unknown";
    }
}

static void AliceCiphertextOutput(uint8_t c) {
    c = snoop(c, '-');
    int r = hermesPutc(&Bob, c);
    if (r) printf("\n*** Bob returned %d: %s, ", r, errorCode(r));
}

static void BobCiphertextOutput(uint8_t c) {
    c = snoop(c, '~');
    int r = hermesPutc(&Alice, c);
    if (r) printf("\n*** Alice returned %d: %s, ", r, errorCode(r));
}

/*
Received-plaintest functions
PlaintextHandler takes a u16-counted src string
The u16-counted ack string has been set to default empty.
As many as maxack bytes can be returned.
*/
static void PlaintextHandler(const uint8_t *src, uint8_t *ack, uint16_t maxack) {
    uint16_t length;
    memcpy (&length, src, 2);  // little-endian msg length
    printf("\nPlaintext {");
    for (int i = 0; i < length; i++) {
        putc(src[i + sizeof(uint16_t)], stdout);
    }
    printf("} ");
    /*
    if (ack) { // a return message can be sent
        ack[0] = 5;
        ack[1] = 0;
        memcpy(&ack[2], "Hello", 5);
    }
    */
}

static void BoilerHandlerA(const uint8_t *src) {
    printf("\nAlice received %d-byte boilerplate {%s}", src[0], &src[1]);
}

static void BoilerHandlerB(const uint8_t *src) {
    printf("\n  Bob received %d-byte boilerplate {%s}", src[0], &src[1]);
}

const uint8_t AliceBoiler[] =   {"\x12nyb<Alice's_UUID>0"};
const uint8_t BobBoiler[] =     {"\x12nyb<Bob's_UUID__>0"};


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
    if (!hermesAvail(&Alice)) {
        hermesPutc(&Alice, HERMES_CMD_RESET);
    }
    int ior = hermesSend(&Alice, s, strlen((char*)s));
    if (ior) printf("\n<<<hermesSend>>> returned error code %d ", ior);
    return elements;
}

int StreamAlice(int msgID) {
    int elements = sizeof(AliceMessages) / sizeof(AliceMessages[0]);
    if (msgID >= elements) msgID = elements - 1;
    const uint8_t* s = AliceMessages[msgID];
    if (!hermesAvail(&Alice)) {
        hermesPutc(&Alice, HERMES_CMD_RESET);
    }
    int ior = hermesStreamOut(&Alice, s, strlen((char*)s));
    if (ior) printf("\n<<<hermesStreamOut>>> returned error code %d ", ior);
    return elements;
}

int SendBob(int msgID) {
    int elements = sizeof(BobMessages) / sizeof(BobMessages[0]);
    if (msgID >= elements) msgID = elements - 1;
    const uint8_t* s = BobMessages[msgID];
    if (!hermesAvail(&Bob)) {
        printf("\nRe-authenticating the connection");
        hermesPutc(&Bob, HERMES_CMD_RESET);
    }
    int ior = hermesSend(&Bob, s, strlen((char*)s));
    if (ior) printf("\n<<<hermesSend>>> returned error code %d ", ior);
    return elements;
}

void PairAlice(void) {
    printf("\nAlice is pairing with keys ");
    for (int i=0; i<64; i++) printf("%02x", Alice.key[i]);
    hermesPutc(&Alice, HERMES_CMD_RESET);
    if (Alice.hctrTx != Bob.hctrRx) printf("\nERROR: Alice cannot send to Bob");
    if (Bob.hctrTx != Alice.hctrRx) printf("\nERROR: Bob cannot send to Alice");
    printf("\nAvailability: Alice=%d, Bob=%d",
           hermesAvail(&Alice), hermesAvail(&Bob));
}

// File encryption

FILE *file;
int tally;

void CharToFile(uint8_t c) {
    fputc(c, file);
    tally++;
}

uint8_t my_keys[64] = {
  0x18,0x70,0x92,0xDA,0x64,0x54,0xCE,0xB1,0x85,0x3E,0x69,0x15,0xF8,0x46,0x6A,0x04,
  0x96,0x73,0x0E,0xD9,0x16,0x2F,0x67,0x68,0xD4,0xF7,0x4A,0x4A,0xD0,0x57,0x68,0x76,
  0xFA,0x16,0xBB,0x11,0xAD,0xAE,0x24,0x88,0x79,0xFE,0x52,0xDB,0x25,0x43,0xE5,0x3C,
  0xC1,0xC3,0x22,0x5B,0x7B,0x39,0x18,0x06,0x4F,0xCB,0x50,0x69,0x24,0x07,0x2F,0x12};

const uint8_t new_keys[64] = {
  0x65,0x38,0x2A,0x46,0x89,0xA9,0x82,0x79,0x7A,0x76,0x78,0xC2,0x63,0xB1,0x26,0xDF,
  0xDA,0x29,0x6D,0x3E,0x62,0xE0,0x96,0x12,0x34,0xBF,0x39,0xA6,0x3F,0x89,0x5E,0xF1,
  0x6D,0x0E,0xE3,0x6C,0x28,0xA1,0x1E,0x20,0x1D,0xCB,0xC2,0x03,0x3F,0x41,0x07,0x84,
  0x14,0x13,0x34,0xB5,0x11,0x23,0x73,0xE7,0xE5,0x98,0xA1,0x2F,0xCF,0xE5,0x16,0x7C};

/*
Write the key and return the address of the key (it may have changed)
Return NULL if key cannot be updated
*/
uint8_t * UpdateKeySet(uint8_t* keyset) {
    memcpy(my_keys, keyset, 64);
	return my_keys;
}

int getc_RNG(void) {
	return rand() & 0xFF;	// DO NOT USE in a real application
}                           // Use a TRNG instead

void makeKey(void) {        // printf a random key set, with HMAC
    uint8_t k[64];
    for (int i=0; i < 48; i++) k[i] = getc_RNG();
    Alice.hInitFn((void*)Alice.rhCtx, &k[32], 16, HERMES_KEY_HASH_KEY);
    for (int i=0; i < 48; i++) Alice.hputcFn((void*)Alice.rhCtx, k[i]);
    Alice.hFinalFn((void*)Alice.rhCtx, &k[48]);
    printf("uint8_t key[64] = {");
    for (uint8_t i = 0; i < 64; i++) {
        if ((i % 16) == 0) printf("\n  ");
        printf("0x%02X", k[i]);
        if (i != 63) printf(",");
    }
    printf("};\n");
}

int main() {
    int tests = 0x1FF;      // enable these tests...
//    snoopy = 1;             // display the wire traffic
    hermesNoPorts();
    int ior = hermesAddPort(&Alice, AliceBoiler, MY_PROTOCOL, "ALICE", 2, 2, getc_RNG,
                  BoilerHandlerA, PlaintextHandler, AliceCiphertextOutput, my_keys, UpdateKeySet);
    if (!ior) ior = hermesAddPort(&Bob, BobBoiler, MY_PROTOCOL, "BOB", 2, 2, getc_RNG,
                  BoilerHandlerB, PlaintextHandler, BobCiphertextOutput, my_keys, UpdateKeySet);
    if (ior) {
        printf("\nError %d: %s, ", ior, errorCode(ior));
        printf("too small by %d ", -hermesRAMunused()/4);
        printf("or the key has a bad HMAC");
        return ior;
    }
    printf("Static context RAM usage: %d bytes per port\n", hermesRAMused(2)/2);
    printf("context_memory has %d unused bytes (%d unused longs)\n",
           hermesRAMunused(), hermesRAMunused()/4);
    Alice.hctrTx = 0x3412; // ensure that re-pair resets these
    Alice.hctrRx = 0x341200;
    Bob.hctrTx = 0x785600;
    Bob.hctrRx = 0x7856;
    if (tests & 0x01) hermesPutc(&Alice, HERMES_TAG_GET_BOILER);
    if (tests & 0x02) hermesPutc(&Bob, HERMES_TAG_GET_BOILER);
    if (tests & 0x04) PairAlice();
    int i, j;
    if (tests & 0x08) {
        printf("\n\nAlice ================================");
        hermesSend(&Alice, (uint8_t*)"*", 1);
        hermesSend(&Alice, (uint8_t*)"*", 0);
    }
    if (tests & 0x10) {
        i = 0;
        do {j = SendAlice(i++);} while (i != j);
    }
    if (tests & 0x20) {
        printf("\n\nBob ==================================");
        i = 0;
        do {j = SendBob(i++);} while (i != j);
    }
    if (tests & 0x40) {
        printf("\n\nAlice-to-Bob, no ACK, no error injection...");
        error_pacing = 1000000;
        i = 0;
        hermesStreamInit(&Alice);
        do {j = StreamAlice(i++);} while (i != j);
    }
    if (tests & 0x80) {
        printf("\n\nRe-keying =============================");
        i = hermesReKey(&Alice, new_keys);
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
        hermesFileNew(&Alice);
        for (int i = 0; i < 100; i++) {
            hermesFileOut(&Alice, (uint8_t*)"ABCDEFGHIJKLMNOP", 16);
        }
        hermesFileFinal(&Alice, 0);
        fclose(file);
    }
    return 0;
}
