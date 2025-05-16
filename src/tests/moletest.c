#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../mole.h"
#include "../moleconfig.h"

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
    case MOLE_ERROR_KDFBUF_TOO_SMALL:return "KDFbuffer is too small";
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
    printf("\nAlice is pairing with key ");
    for (int i=0; i<32; i++) printf("%02x", Alice.cryptokey[i]);
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

// 32-byte encryption key, 32-byte MAC key, 16-byte admin password, 32-byte spare keys, 16-byte hash
uint8_t my_keys[] = TESTPASS_1;
const uint8_t new_keys[] = TESTPASS_2;

/*
Write the key and return the address of the key (it may have changed)
Return NULL if key cannot be updated
*/

uint8_t * UpdateKeySet(uint8_t* keyset) {
    memcpy(my_keys, keyset, MOLE_PASSCODE_LENGTH);
	return my_keys;
}

int getc_RNG(void) {
	return rand() & 0xFF;	// DO NOT USE in a real application
}                           // Use a TRNG instead

int main() {
    int tests = 0x1FF;      // enable these tests...
//    snoopy = 1;             // display the wire traffic
    moleNoPorts();
    int ior = moleAddPort(&Alice, AliceBoiler, MY_PROTOCOL, "ALICE", 2, getc_RNG,
                  BoilerHandlerA, PlaintextHandler, AliceCiphertextOutput, my_keys, UpdateKeySet);
    if (!ior) ior = moleAddPort(&Bob, BobBoiler, MY_PROTOCOL, "BOB", 2, getc_RNG,
                  BoilerHandlerB, PlaintextHandler, BobCiphertextOutput, my_keys, UpdateKeySet);
    if (ior) {
        printf("\nError %d: %s, ", ior, errorCode(ior));
        if (ior == MOLE_ERROR_OUT_OF_MEMORY) printf("too small by %d ", -moleRAMunused()/4);
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
