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

// Inverse of the probability of a bit error
#define CONNECTION_QUALITY 0

// Connect Alice to Bob via a virtual null-modem cable

#define ERROR_PACING 720
int errorpos = 0;    // inject error here

static uint8_t snoop(uint8_t c, char t) {
    if (!(++errorpos % ERROR_PACING)) {
        c++;
        printf("\n<><><><><><> Error injected <><><><><><> ");
    }
    if (!snoopy) return c;
    printf("%02X", c);
    if (c == 0x12) printf("\n");
    else           printf("%c", t);
    return c;
}

static void AliceCiphertextOutput(uint8_t c) {
    c = snoop(c, '-');
    int r = hermesPutc(&Bob, c);
    if (r) printf("\n*** Bob saw return code %d ", r);
}

static void BobCiphertextOutput(uint8_t c) {
    c = snoop(c, '~');
    int r = hermesPutc(&Alice, c);
    if (r) printf("\n*** Alice saw return code %d ", r);
}

// Received-plaintest functions

static void PlaintextHandler(const uint8_t *src, uint32_t length) {
    printf("\nPlaintext {");
    while (length--) putc(*src++, stdout);
    printf("} ");
}

static void BoilerHandlerA(const uint8_t *src, uint32_t length) {
    printf("\nAlice received boilerplate {%s}", src);
}

static void BoilerHandlerB(const uint8_t *src, uint32_t length) {
    printf("\n  Bob received boilerplate {%s}", src);
}
//                                0123456789abcdef0123456789abcdef
uint8_t my_encryption_key[32] = {"Do not use this encryption key!"};
uint8_t my_signature_key[16] =  {"Or this key..."};
const uint8_t AliceBoiler[] =   {"\x12nyb<Alice's_UUID>0"};
const uint8_t BobBoiler[] =     {"\x12nyb<Bob's_UUID__>0"};

#define MY_PROTOCOL 0

//int errors = 0;
//uint8_t text[MAX_TX_LENGTH];                    // random text for testing
//  for (int i = 0; i < MAX_TX_LENGTH; i++) text[i] = getc_TRNG();

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
"11. 'If you knew Time as well @as I do,' said the Hatter, 'you wouldn't talk about wasting it.'",
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
"17. Bob: \"... For he himself has said it, and it's clearly to his credit, that he is an Englishman.",
"         He remai-hains ah-han Eh-heh-heh-heh-heh-hengLISHman!"};

int SendAlice(int msgID) {
    int elements = sizeof(AliceMessages) / sizeof(AliceMessages[0]);
    if (msgID >= elements) msgID = elements - 1;
    const uint8_t* s = AliceMessages[msgID];
    if (!hermesAvail(&Alice)) hermesPair(&Alice);
    int ior = hermesSend(&Alice, s, strlen((char*)s));
    if (ior) printf("\n<<<hermesSend>>> returned error code %d ", ior);
    return elements;
}

int SendBob(int msgID) {
    int elements = sizeof(BobMessages) / sizeof(BobMessages[0]);
    if (msgID >= elements) msgID = elements - 1;
    const uint8_t* s = BobMessages[msgID];
    if (!hermesAvail(&Bob)) hermesPair(&Bob);
    int ior = hermesSend(&Bob, s, strlen((char*)s));
    if (ior) printf("\n<<<hermesSend>>> returned error code %d ", ior);
    return elements;
}

int main() {
    int tests = 0x1F;   // enable these tests...
//    snoopy = 1;         // display the wire traffic
    hermesNoPorts();
    hermesAddPort(&Alice, AliceBoiler, MY_PROTOCOL, "ALICE",
                  BoilerHandlerA, PlaintextHandler, AliceCiphertextOutput,
                  my_encryption_key, my_signature_key);
    hermesAddPort(&Bob, BobBoiler, MY_PROTOCOL, "BOB",
                  BoilerHandlerB, PlaintextHandler, BobCiphertextOutput,
                  my_encryption_key, my_signature_key);
    printf("%d RAM bytes are used for 2 ports (Alice and Bob)\n", hermesRAMused(2));
    printf("context_memory has %d unused bytes\n", hermesRAMunused());
    Alice.hctrTx = 1234; // ensure that re-pair resets these
    Alice.hctrRx = 4321;
    if (tests & 0x01) hermesBoiler(&Alice);
    if (tests & 0x02) hermesBoiler(&Bob);
    if (tests & 0x04) hermesPair(&Alice);
    printf("\nAvailability: Alice=%d, Bob=%d", hermesAvail(&Alice), hermesAvail(&Bob));
    int i, j;
    if (tests & 0x08) {
        printf("\n\nAlice ================================");
        hermesSend(&Alice, (uint8_t*)"*", 1);
        hermesSend(&Alice, (uint8_t*)"*", 0);
        i = 0;
        do {j = SendAlice(i++);} while (i != j);
    }
    if (tests & 0x10) {
        printf("\n\nBob ==================================");
        i = 0;
        do {j = SendBob(i++);} while (i != j);
    }
    return 0;
}

