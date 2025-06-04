#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../mole.h"
#include "../moleconfig.h"

// ---------------------------------------------------------------------------
// Some default values for testing

port_ctx Alice;
port_ctx Bob;
int snoopy;

#define MY_PROTOCOL 0

// Connect Alice to Bob via a virtual null-modem cable

int error_pacing = 720;
int errorpos = 0;                      // inject error every error_pacing byte

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
    case MOLE_ERROR_INVALID_STATE:
        return "Invalid state (should never happen)";
    case MOLE_ERROR_TRNG_FAILURE:
        return "TRNG failure - need to re-initialize";
    case MOLE_ERROR_BAD_HMAC:
        return "Invalid HMAC";
    case MOLE_ERROR_INVALID_LENGTH:
        return "Invalid packet length";
    case MOLE_ERROR_LONG_BOILERPLT:
        return "Boilerplate is too long";
    case MOLE_ERROR_OUT_OF_MEMORY:
        return "Insufficient MOLE_ALLOC_MEM_UINT32S";
    case MOLE_ERROR_REKEYED:
        return "Keys were changed";
    case MOLE_ERROR_MSG_NOT_SENT:
        return "Message not sent";
    case MOLE_ERROR_BUF_TOO_SMALL:
        return "Buffer blocks must be at least 2";
    case MOLE_ERROR_KDFBUF_TOO_SMALL:
        return "KDFbuffer is too small";
    case MOLE_ERROR_MISSING_HMAC:
        return "Stream is missing the HMAC tag ";
    case MOLE_ERROR_MISSING_IV:
        return "Stream is missing the IV ";
    case MOLE_ERROR_STREAM_ENDED:
        return "Stream ended prematurely ";
    case MOLE_ERROR_BAD_END_RUN:
        return "Unexpected plaintext in data run ";
    case MOLE_ERROR_NO_RAWPACKET:
        return "Stream is missing RAW_PACKET tag ";
    case MOLE_ERROR_NO_ANYLENGTH:
        return "Stream is missing ANYLENGTH tag ";
    case MOLE_ERROR_BAD_BIST:
        return "Built-in Self Test failed ";
    case MOLE_ERROR_UNKNOWN_MSG:
        return "Unknown message ";
    default: return "unknown";
    }
}
#define MOLE_ERROR_INVALID_STATE       1 /* FSM reached an invalid state */
#define MOLE_ERROR_TRNG_FAILURE        2 /* Bad RNG value */
#define MOLE_ERROR_BAD_HMAC            3
#define MOLE_ERROR_INVALID_LENGTH      4
#define MOLE_ERROR_LONG_BOILERPLT      5
#define MOLE_ERROR_OUT_OF_MEMORY       6
#define MOLE_ERROR_REKEYED             7
#define MOLE_ERROR_MSG_NOT_SENT        8
#define MOLE_ERROR_BUF_TOO_SMALL       9
#define MOLE_ERROR_KDFBUF_TOO_SMALL   10
#define MOLE_ERROR_MISSING_HMAC       11
#define MOLE_ERROR_MISSING_IV         12
#define MOLE_ERROR_STREAM_ENDED       13
#define MOLE_ERROR_NO_RAWPACKET       14
#define MOLE_ERROR_NO_ANYLENGTH       15
#define MOLE_ERROR_BAD_END_RUN        16
#define MOLE_ERROR_BAD_BIST           17
#define MOLE_ERROR_UNKNOWN_MSG        18

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

static char LastReceived[4096];

static void PlaintextHandler(const uint8_t *src, int length) {
    printf("\nPlaintext {");
    for (int i = 0; i < length; i++) {
        putc(src[i], stdout);
        //printf("%02x/", src[i]);
    }
    printf("} ");
    memcpy(LastReceived, src, length);
    LastReceived[length] = 0;
}

static int TestLast(const char* expected) {
    return strcmp(LastReceived, expected);
}

static void BoilerHandlerA(const uint8_t *src) {
    printf("\nAlice received %d-byte boilerplate {%s}", src[0], &src[1]);
}

static void BoilerHandlerB(const uint8_t *src) {
    printf("\n  Bob received %d-byte boilerplate {%s}", src[0], &src[1]);
}

const uint8_t AliceBoiler[] =   {"\x13mole0<Alice's_UUID>"};
const uint8_t BobBoiler[] =     {"\x13mole0<Bob's_UUID__>"};


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

int PairAlice(void) {
    printf("\nAlice is pairing with key ");
    for (int i=0; i<32; i++) printf("%02x", Alice.cryptokey[i]);
    molePair(&Alice);
    if (Alice.hashCounterTX != Bob.hashCounterRX) {
        printf("\nERROR: Alice cannot send to Bob");
    }
    if (Bob.hashCounterTX != Alice.hashCounterRX) {
        printf("\nERROR: Bob cannot send to Alice");
    }
    printf("\nAvailability: Alice=%d, Bob=%d",
        moleAvail(&Alice), moleAvail(&Bob));
    return (moleAvail(&Alice)) && (moleAvail(&Bob));
}

// File encryption

FILE *file;
int tally;

void CharToFile(uint8_t c) {
    tally++;
    fputc(c, file);
}

int CharFromFile(void) {
    tally++;
    return fgetc(file);
}

void CharEmit(uint8_t c) {
    fputc(c, stdout);
}


// 32-byte token, 16-byte adminOK password, 16-byte hash
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

int moleTRNG(uint8_t *dest, int length) {
	while (length--) *dest++ = rand() & 0xFF;   // DO NOT USE 'rand' in a real application
	return 0;                                   // Use a TRNG instead
}

int main() {
    int tests = 0x3FF;          // enable these tests...
//    tests = 0x307;
//    snoopy = 1;               // display the wire traffic
    error_pacing = 100000000;   // no error injection
    moleNoPorts();
    int ior = moleAddPort(&Alice, AliceBoiler, MY_PROTOCOL, "ALICE", 3,
        BoilerHandlerA, PlaintextHandler, AliceCiphertextOutput, UpdateKeySet);
    if (!ior) ior = moleAddPort(&Bob, BobBoiler, MY_PROTOCOL, "BOB", 3,
        BoilerHandlerB, PlaintextHandler, BobCiphertextOutput, UpdateKeySet);
    if (ior) {
        printf("\nError %d: %s, ", ior, errorCode(ior));
        if (ior == MOLE_ERROR_OUT_OF_MEMORY) {
            printf("too small by %d ", -moleRAMunused()/4);
        }
        return ior;
    }
    printf("Static context RAM usage: %d bytes per port\n", moleRAMused(2)/2);
    printf("context_memory has %d unused bytes (%d unused longs)",
        moleRAMunused(), moleRAMunused()/4);
    printf(", see MOLE_ALLOC_MEM_UINT32S\n");
    moleNewKeys(&Alice, my_keys);
    moleNewKeys(&Bob, my_keys);
    Alice.hashCounterTX = 0x3412; // ensure that re-pair resets these
    Alice.hashCounterRX = 0x341200;
    Bob.hashCounterTX = 0x785600;
    Bob.hashCounterRX = 0x7856;
    if (tests & 0x01) moleBoilerReq(&Alice);
    if (tests & 0x02) moleBoilerReq(&Bob);
    if (tests & 0x04) if (0 == PairAlice()) return 0x1004;
    int i, j;
    if (tests & 0x08) {
        printf("\n\nAlice ===================================");
        moleSend(&Alice, (uint8_t*)"*", 1);
        if (TestLast("*")) return 0x1008;
        moleSend(&Alice, (uint8_t*)"Hello World", 11);
        if (TestLast("Hello World")) return 0x1008;
        for (int i = 0; i < 33; i++) {
            moleSend(&Alice, (uint8_t*)"0123456789ABCDEFGHIJLKMNOPQRSTUV", i);
        }
    }
    if (tests & 0x10) {
        i = 0;
        do {j = SendAlice(i++);} while (i != j);
    }
    if (tests & 0x20) {
        printf("\n\nBob =====================================");
        i = 0;
        do {j = SendBob(i++);} while (i != j);
    }
    error_pacing = 100000000; // turn off error injection
    if (tests & 0x40) {
        printf("\nEnable adminOK mode =======================");
        printf("\nBefore = %x", Bob.adminOK);
        moleAdmin(&Alice);
        printf("\nAfter = 0x%x", Bob.adminOK);
        if (Bob.adminOK != MOLE_ADMIN_ACTIVE) {
            printf("\nAdmin passcode was not accepted");
            return 0x1040;
        }
    }
    if (tests & 0x80) {
        printf("\n\nRe-keying ===============================");
        i = moleReKey(&Alice, new_keys);
        if (i) printf("\nError %d: %s, ", i, errorCode(i));
        if (0 == PairAlice()) return 0x1080;
    }
    printf("\nAlice sent %d bytes", Alice.counter);
    printf("\nBob sent %d bytes", Bob.counter);
    if (tests & 0x100) {
        printf("\n\nTest write to bootfile.bin, ");
        Alice.ciphrFn = CharToFile;
        file = fopen("bootfile.bin", "wb");
        if (file == NULL) {
            printf("\nError creating file!");
            return 0x1101;
        }
        tally = 0;
        i = moleFileNew(&Alice);
        if (i) {
            printf("\nError %d: %s, ", i, errorCode(i));
            return 0x1102;
        }
        // Encrypt 1600 (0x640) bytes of plaintext as input
        for (int i = 0; i < 100; i++) {
            moleFileOut(&Alice, (uint8_t*)"ABCDEFGHIJKLMNOP", 16);
        }
        moleFileFinal(&Alice);
        fclose(file);
        printf("0x%x bytes written\n", tally);
    }
    if (tests & 0x200) {
        printf("\nTest read from bootfile.bin: ");
        file = fopen("bootfile.bin", "rb");
        if (file == NULL) {
            printf("\nError opening file!");
            return 0x1202;
        }
        tally = 0;
        int ior = moleFileIn(&Bob, CharFromFile, CharEmit);
        fclose(file);      // ^-- change to Bob
        printf("\n0x%x bytes read, ior=%d\n", tally, ior);
        if (ior) return 0x1200;
    }
    return 0;
}
