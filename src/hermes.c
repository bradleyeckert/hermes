/*
Original project: https://github.com/bradleyeckert/hermes
AEAD-secured ports (for UARTs, etc.)
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "xchacha/src/xchacha.h"
#include "siphash/src/siphash.h"
#include "hermes.h"
#include "hermesHW.h"

#define ALLOC_HEADROOM (ALLOC_MEM_UINT32S - allocated_uint32s)
#ifndef ALLOC_MEM_UINT32S
#define ALLOC_MEM_UINT32S 256
#endif

#define TRACE 2

void DUMP(const uint8_t *src, uint8_t len) {
    if (TRACE > 1) {
        for (uint8_t i = 0; i < len; i++) {
            if ((i % 33) == 0) printf("\n___");
            printf("%02X ", src[i]);
        }
        printf("<- ");
    }
}

#define PRINTF  if (TRACE > 1) printf
#define PRINTf  if (TRACE) printf

/*
#define ERRORF(fmt, ...) \
        do { if (TRACE>1) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)
*/

static uint32_t context_memory[ALLOC_MEM_UINT32S];
static int allocated_uint32s;

static void * Allocate(int bytes) {
	void * r = (void *)&context_memory[allocated_uint32s];
	allocated_uint32s += ((bytes + 3) >> 2);
	return r;
}

// Send: c[1]
static void SendByte(port_ctx *ctx, uint8_t c) {
    if ((c & 0xFC) == 0x10) {                   // special 10h to 13h byte?
        ctx->tcFn(0x10);
        ctx->tcFn(c & 3);
    } else {
        ctx->tcFn(c);
    }
    ctx->hPutcFn((void *)&*ctx->thCtx, c);      // add to HMAC
}

#define HDRlength (HERMES_LENGTH_LENGTH+2)      /* Header length (tag+len+~LSB) */
#define ivADlength  1                           /* Associated data length */

//TO DO: Put ctx->hctrTx into hInitFn

// Send: Tag[1], Length[2], ~Length[2], format[1]
static void SendHeader(port_ctx *ctx, int tag, uint32_t msglen) {
    DUMP((uint8_t*)&ctx->hctrTx, 8); printf("Begin HMAC hctrTx, port %p, ", (void*)ctx);
    ctx->hInitFn((void *)&*ctx->thCtx, ctx->hkey, HERMES_HMAC_LENGTH, ctx->hctrTx);
    SendByte(ctx, tag);                         // Header consists of a TAG byte,
    msglen += HDRlength;
    uint8_t c = (uint8_t)msglen;
    for (int i = HERMES_LENGTH_LENGTH; i > 0; --i) {
        SendByte(ctx, (uint8_t)(msglen));
        msglen >>= 8;                           // a little-endian length,
    }
    SendByte(ctx, ~c);                          // and low-byte redundancy.
}

// Send: HMAC[]
static void SendTxHash(port_ctx *ctx){
    uint8_t hash[HERMES_HMAC_LENGTH];
    ctx->hFinalFn((void *)&*ctx->thCtx, hash);
    for (int i = 0; i < HERMES_HMAC_LENGTH; i++) {
        SendByte(ctx, hash[i]);
    }
    ctx->tcFn(HERMES_TAG_END);
}

// Send: Tag[1], Length[2], ~Length[2], format[1], mIV[], cIV[],
// RXbufsize[1], HMAC[]
static int SendIV(port_ctx *ctx, int tag) {
    PRINTF("\nSending IV, tag=%d, port=%p; ", tag, (void*)ctx);
    SendHeader(ctx, tag,
               HERMES_IV_LENGTH * 2 + HERMES_HMAC_LENGTH + ivADlength);
    uint8_t mIV[HERMES_IV_LENGTH];
    uint8_t cIV[HERMES_IV_LENGTH];
    int r = 0;
    int c;
    for (int i = 0; i < HERMES_IV_LENGTH ; i++) {
        c = getc_TRNG();  r |= c;  mIV[i] = (uint8_t)c;
        SendByte(ctx, (uint8_t)c);
        c = getc_TRNG();  r |= c;  cIV[i] = (uint8_t)c;
        if (r & 0x100) {
            return HERMES_ERROR_TRNG_FAILURE;
        }
    }
    memcpy(&ctx->hctrTx, cIV, 8);
    DUMP((uint8_t*)&ctx->hctrTx, 8); PRINTF("New HMAC hctrTx, ");
    ctx->cInitFn ((void *)&*ctx->tcCtx, ctx->ckey, mIV);
    ctx->cBlockFn((void *)&*ctx->tcCtx, cIV, mIV, 0);
    for (int i = 0; i < HERMES_IV_LENGTH ; i++) {
        SendByte(ctx, mIV[i]);
    }
    SendByte(ctx, HERMES_RXBUF_LENGTH >> 6) ;
    SendTxHash(ctx);
    ctx->cInitFn((void *)&*ctx->tcCtx, ctx->ckey, cIV);
    ctx->tReady = 1;
    ctx->tAck = 0;
    return 0;
}

// Encrypt and send an ACK or NACK with a 1-byte message
static int SendACK (port_ctx *ctx, int tag, uint8_t c) {
    uint8_t m[16];
    m[0] = c;
    ctx->cBlockFn((void *)&*ctx->tcCtx, m, m, 0);
    SendHeader(ctx, tag, 16 + HERMES_HMAC_LENGTH);
    for (int i = 0; i < 16; i++) SendByte(ctx, m[i]);
    SendTxHash(ctx);
    return 0;
}

#define PREAMBLE_SIZE 3
#define MAX_TX_LENGTH (HERMES_TXBUF_LENGTH - PREAMBLE_SIZE)

// Encrypt and send a message
static int ResendMessage (port_ctx *ctx) {
    uint8_t m[16];
    uint16_t bytes;
    memcpy(&bytes, ctx->txbuf, 2);
    bytes += PREAMBLE_SIZE;             // include preamble in the message
    PRINTF("\nSending MESSAGE[%d/%d], port=%p, tAck=%d, rAck=%d; ",
        bytes, ((bytes + 15) & ~0x0F), (void*)ctx, ctx->tAck, ctx->rAck);
    bytes = (bytes + 15) & ~0x0F;       // send whole blocks
    SendHeader(ctx, HERMES_TAG_MESSAGE, bytes + HERMES_HMAC_LENGTH);
    for (int i = 0; i < bytes; i += 16) {   // encrypt in blocks
        ctx->cBlockFn((void *)&*ctx->tcCtx, &ctx->txbuf[i], m, 0);
        for (int j = 0; j < 16; j++) SendByte(ctx, m[j]);
    }
    SendTxHash(ctx);
    return 0;
}

// -----------------------------------------------------------------------------
// Public functions

// Call this before setting up any hermes ports
void hermesNoPorts(void) {
	memset(context_memory, 0, sizeof(context_memory));
	allocated_uint32s = 0;
}

// Add a secure port
void hermesAddPort(port_ctx *ctx, const uint8_t *boilerplate, int protocol,
                   hermes_plainFn boiler, hermes_plainFn plain, hermes_ciphrFn ciphr,
                   const uint8_t *enc_key, const uint8_t *hmac_key) {
    memset(ctx, 0, sizeof(port_ctx));
    ctx->tmFn = plain;
    ctx->tcFn = ciphr;
    ctx->boilFn = boiler;
    ctx->ckey = enc_key;
    ctx->hkey = hmac_key;
    ctx->boil = boilerplate;
    switch (protocol) {
    default: // 0
        ctx->rcCtx = Allocate(sizeof(xChaCha_ctx));
        ctx->tcCtx = Allocate(sizeof(xChaCha_ctx));
        ctx->rhCtx = Allocate(sizeof(siphash_ctx));
        ctx->thCtx = Allocate(sizeof(siphash_ctx));
        ctx->hInitFn  = sip_hmac_init_g;
        ctx->hPutcFn  = sip_hmac_putc_g;
        ctx->hFinalFn = sip_hmac_final_g;
        ctx->cInitFn  = xc_crypt_init_g;
        ctx->cBlockFn = xc_crypt_block_g;
    }
}

void hermesPair(port_ctx *ctx) {
    PRINTF("\nSending Pairing request, port=%p; ", (void*)ctx);
    ctx->hctrTx = 0;
    SendHeader(ctx, HERMES_TAG_RESET, 0);
    ctx->tcFn(HERMES_TAG_END);
}

void hermesBoiler(port_ctx *ctx) {
    PRINTF("\nSending Boilerplate request, port=%p; ", (void*)ctx);
    SendHeader(ctx, HERMES_TAG_GET_BOILER, 0);
    ctx->tcFn(HERMES_TAG_END);
}

// Size of message available to accept
uint32_t hermesAvail(port_ctx *ctx){
    if (!ctx->rReady) return 0;
    if (!ctx->tReady) return 0;
    if (ctx->tAck == ctx->rAck) return 0;
    uint32_t rxAvail = (ctx->avail << 6) - (HERMES_HMAC_LENGTH + PREAMBLE_SIZE);
    if      (rxAvail > MAX_TX_LENGTH) rxAvail = MAX_TX_LENGTH;
    return rxAvail;
}

// Encrypt and send a message
int hermesSend(port_ctx *ctx, const uint8_t *m, uint32_t bytes){
    int r = 0;
    uint32_t len = bytes;
    if (len > hermesAvail(ctx)) {
        r = HERMES_ERROR_MSG_TRUNCATED;
        len = hermesAvail(ctx);
        PRINTF("\nTruncating message to %d bytes, ", len);
    }
    ctx->tAck = ctx->rAck;              // tag as unacknowledged
    memcpy(ctx->txbuf, &len, 2);        // save the length
    ctx->txbuf[2] = ctx->tAck;          // and the message counter
    memcpy(&ctx->txbuf[PREAMBLE_SIZE], m, len); // and the input
    return ResendMessage(ctx) | r;
}

// -----------------------------------------------------------------------------
// Receive char or command from input stream
int hermesPutc(port_ctx *ctx, int c){
    int r = 0;
    int temp, i;
    uint8_t cIV[HERMES_IV_LENGTH];
    if (c & 0xFF00) {
        switch (c) {
        case HERMES_CMD_RESET:
reset:      hermesPair(ctx);
            ctx->state = 0;
            break;
        default:
            r = HERMES_ERROR_UNKNOWN_CMD;
        }
        return r;
    } // -----------------------------------------------------------------------
    if (ctx->escaped) {
        ctx->escaped = 0;
        if (c > 3) goto reset;
        c = (c & 3) + 0x10;                     // 10h 00h -> 10h
    }
    else if (c == 0x10) {
        ctx->escaped = 1;
        return 0;
    } // -----------------------------------------------------------------------
    ctx->hPutcFn((void *)&*ctx->rhCtx, c);      // add to hash
    switch (ctx->state) {
    case 0: // valid tags are 0x18 to 0x1F
        if ((c & 0xF8) != 0x18) break;
        if (c == HERMES_TAG_CHALLENGE) ctx->hctrRx = 0;
        DUMP((uint8_t*)&ctx->hctrRx, 8); PRINTF("Begin HMAC hctrRx, port %p, ", (void*)ctx);
        ctx->hInitFn((void *)&*ctx->rhCtx, ctx->hkey, HERMES_HMAC_LENGTH, ctx->hctrRx);
        ctx->hPutcFn((void *)&*ctx->rhCtx, c);
        ctx->tag = c;
next_header_char:
        ctx->state++;
        break;
    case 1: // lower length byte
        ctx->length = c;
        goto next_header_char;
    case 2: // middle length byte
        ctx->length |= (uint32_t)c << 8;
#if HERMES_LENGTH_LENGTH == 2
        ctx->state = 5; // truncate length to 2-byte
        break;
#else
        goto next_header_char;
// state 3 is reserved for an optional extended length
    case 3: // upper length byte
        ctx->length |= (uint32_t)c << 16;
#if HERMES_LENGTH_LENGTH == 3
        ctx->state = 5; // truncate length to 2-byte
        break;
#else
        goto next_header_char;
#endif // HERMES_LENGTH_LENGTH
    case 4: // upper length byte
        ctx->length |= (uint32_t)c << 24;
        goto next_header_char;
#endif // HERMES_LENGTH_LENGTH
    case 5: // lower ~length
        if ((ctx->length & 0xFF) == (c ^ 0xFF)) goto next_header_char;
        ctx->state = 9;
        r = HERMES_ERROR_INVALID_LENGTH;
        break;
    case 6: // message data begins here
        ctx->rxbuf[0] = c;
        ctx->i = 1;
        ctx->state++;
        switch (ctx->tag) {
        case HERMES_TAG_GET_BOILER:
            temp = ctx->boil[0];
            SendHeader(ctx, HERMES_TAG_BOILERPLATE, temp);
            for (i=1; i <= temp; i++) {
                ctx->tcFn(ctx->boil[i]);
            }
            ctx->tcFn(HERMES_TAG_END);
            ctx->state = 0;
            break;
        case HERMES_TAG_RESET:
            ctx->hctrRx = 0;
            ctx->state = 0;
            r = SendIV(ctx, HERMES_TAG_CHALLENGE);
            break;
        }
        break;
    case 7: // get payload
        ctx->rxbuf[ctx->i++] = c;
        temp = ctx->length - HDRlength;
        i = ctx->i;
        if (i == (temp - HERMES_HMAC_LENGTH)) {
            ctx->hFinalFn((void *)&*ctx->rhCtx, ctx->hmac);
        }
        if ((i == temp) || (i == HERMES_RXBUF_LENGTH)) {
            if (ctx->tag == HERMES_TAG_BOILERPLATE) {
                if (i > 63) {
                    r = HERMES_ERROR_LONG_BOILERPLT;
                    temp = 64;
                }
                ctx->boilFn(ctx->rxbuf, temp);
                ctx->state = 0;
            } else {
                ctx->state++;
            }
        }
        break;
    case 8: // test HMAC, then process the payload
        temp = ctx->length - (HDRlength + HERMES_HMAC_LENGTH);
        for (i = 0; i < HERMES_HMAC_LENGTH; i++) {
            if (ctx->hmac[i] != ctx->rxbuf[i+temp]) {
                ctx->state = 0;
                r = HERMES_ERROR_BAD_HMAC;
                if (ctx->tag == HERMES_TAG_MESSAGE) {
                    PRINTf("\n>>> Sending NACK, port=%p; ", (void*)ctx);
                    SendACK(ctx, HERMES_TAG_NACK, ctx->rAck);
                    ctx->retries++;
                    // to do: If too many retries, re-pair
                    // make challenge an exported function
                }
                goto endcase;
            }
        }
        PRINTF("\nAuthenticated packet of length %d, tag %d received on port=%p; ",
               temp, ctx->tag, (void*)ctx);
        switch (ctx->tag) {
        case HERMES_TAG_CHALLENGE:
        case HERMES_TAG_RESPONSE:
            if (temp != (2 * HERMES_IV_LENGTH + ivADlength)) {
                r = HERMES_ERROR_INVALID_LENGTH;
                break;
            }
            ctx->cInitFn ((void *)&*ctx->rcCtx, ctx->ckey, ctx->rxbuf); // decrypt with mIV
            ctx->cBlockFn((void *)&*ctx->rcCtx, &ctx->rxbuf[HERMES_IV_LENGTH], cIV, 1);
            ctx->cInitFn ((void *)&*ctx->rcCtx, ctx->ckey, cIV);
            memcpy(&ctx->hctrRx, cIV, 8);
            ctx->avail = ctx->rxbuf[2*HERMES_IV_LENGTH];
            ctx->rReady = 1;
            ctx->rAck = 1;
            PRINTF("\nReceived IV, tag=%d; ", ctx->tag);
            DUMP((uint8_t*)&ctx->hctrRx, 8); PRINTF("Received HMAC hctrRx, ");
            if (ctx->tag == HERMES_TAG_CHALLENGE) {
                r = SendIV(ctx, HERMES_TAG_RESPONSE);
            }
            break;
        case HERMES_TAG_MESSAGE:
            PRINTF("\nDecrypting MESSAGE; ");
            for (i = 0; i < temp; i += 16) {
                ctx->cBlockFn((void *)&*ctx->rcCtx, &ctx->rxbuf[i], &ctx->rxbuf[i], 1);
            }
            memcpy (&temp, ctx->rxbuf, 2); // little-endian length
            if (temp > 110) {
                printf("\nMessage length = %d, QUIT", temp);
                exit(-1);
            }
            ctx->rAck = ctx->rxbuf[2];
            ctx->tmFn(&ctx->rxbuf[PREAMBLE_SIZE], temp);
            SendACK(ctx, HERMES_TAG_ACK, ctx->rAck + 1);
            ctx->hctrTx++;
            break;
        case HERMES_TAG_ACK:
            ctx->cBlockFn((void *)&*ctx->rcCtx, ctx->rxbuf, ctx->rxbuf, 1);
            PRINTF("\nReceived ACK=%d; ", ctx->rxbuf[0]);
            ctx->rAck = ctx->rxbuf[0];
            ctx->hctrRx++;
            ctx->retries = 0;
            break;
        case HERMES_TAG_NACK:
            ctx->cBlockFn((void *)&*ctx->rcCtx, ctx->rxbuf, ctx->rxbuf, 1);
            PRINTf("\n<<< Received NACK=%d; ", ctx->rxbuf[0]);
            ResendMessage(ctx);
            break;
        default: break;
        }
        ctx->state = 0;
        break;
    case 9: // wait for the end tag
        if (c == HERMES_TAG_END) {
            ctx->state = 0;
            hermesPair(ctx);
        }
        break;
    default:
        ctx->state = 0;
        r = HERMES_ERROR_INVALID_STATE;
    }
endcase:
    return r;
}

// -----------------------------------------------------------------------------
// Some default values for testing

port_ctx Alice;
port_ctx Bob;
int snoopy;

// Inverse of the probability of a bit error
#define CONNECTION_QUALITY 1000

// Connect Alice to Bob via a virtual null-modem cable

static uint8_t snoop(uint8_t c, char t) {
    if (CONNECTION_QUALITY) {
        uint32_t rnd = getc_TRNG() + (getc_TRNG()<<8)
               + (getc_TRNG()<<16) + (getc_TRNG()<<24);
        if ((rnd % (CONNECTION_QUALITY + 1)) == 0){
            PRINTF("\nBit error inserted ");
            uint8_t b = getc_TRNG() & 7;
            c ^= 1 << b;
        }
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
    if (snoopy) DUMP(src, length); else printf("\n");
    printf("Plaintext {");
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
" 3. I almost wish I hadn't gone down that rabbit-hole-and yet-and yet-it's rather curious,",
" 4. you know, this sort of life!",
" 5. Sometimes, I've believed as many as six impossible things before breakfast.",
" 6. Well, I never heard it before, but it sounds uncommon nonsense.",
" 7. A dream is not reality but who's to say which is which?",
" 8. How puzzling all these changes are! I'm never sure what I'm going to be,",
" 9. from one minute to another.",
"10. We're all mad here.",
"11. If you drink much from a bottle marked 'poison' it is certain to disagree with you sooner or later.",
"12. 'If you knew Time as well as I do,' said the Hatter, 'you wouldn't talk about wasting it.'",
"13. It would be so nice if something made sense for a change."
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
    int ior = hermesSend(&Alice, s, strlen((char*)s));
    if (ior) printf("\n<<<hermesSend>>> returned error code %d ", ior);
    return elements;
}

int SendBob(int msgID) {
    int elements = sizeof(BobMessages) / sizeof(BobMessages[0]);
    if (msgID >= elements) msgID = elements - 1;
    const uint8_t* s = BobMessages[msgID];
    int ior = hermesSend(&Bob, s, strlen((char*)s));
    if (ior) printf("\n<<<hermesSend>>> returned error code %d ", ior);
    return elements;
}

int main() {
    int tests = 0x1F;   // enable these tests...
    snoopy = 1;         // don't display the wire traffic
    hermesNoPorts();
    hermesAddPort(&Alice, AliceBoiler, MY_PROTOCOL,
                  BoilerHandlerA, PlaintextHandler, AliceCiphertextOutput,
                  my_encryption_key, my_signature_key);
    hermesAddPort(&Bob, BobBoiler, MY_PROTOCOL,
                  BoilerHandlerB, PlaintextHandler, BobCiphertextOutput,
                  my_encryption_key, my_signature_key);
    int bytes = 4*allocated_uint32s + 2*sizeof(port_ctx);
    printf("%d RAM bytes used for 2 ports (Alice and Bob)\n", bytes);
    printf("ALLOC_MEM_UINT32S may be reduced by %d\n", ALLOC_HEADROOM);
    PRINTF("Ports: Alice=%p, Bob=%p\n", &Alice, &Bob);
    Alice.hctrTx = 1234; // ensure that re-pair resets these
    Alice.hctrRx = 4321;
    if (tests & 0x01) hermesBoiler(&Alice);
    if (tests & 0x02) hermesBoiler(&Bob);
    if (tests & 0x04) hermesPair(&Alice);
    printf("\nAvailability: Alice=%d, Bob=%d", hermesAvail(&Alice), hermesAvail(&Bob));
    DUMP((uint8_t*)&Alice.hctrTx, 8); PRINTF("Alice.hctrTx");
    DUMP((uint8_t*)&Alice.hctrRx, 8); PRINTF("Alice.hctrRx");
    DUMP((uint8_t*)&Bob.hctrTx, 8); PRINTF("Bob.hctrTx");
    DUMP((uint8_t*)&Bob.hctrRx, 8); PRINTF("Bob.hctrRx\n");
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
