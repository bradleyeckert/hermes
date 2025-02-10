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

// use this to printf how many uint32s you have left over
#define ALLOC_HEADROOM (ALLOC_MEM_UINT32S - allocated_uint32s)
#ifndef ALLOC_MEM_UINT32S
#define ALLOC_MEM_UINT32S 256
#endif

void dump(uint8_t *src, uint8_t len) {
    if (len) {
        for (uint8_t i = 0; i < len; i++) {
            if ((i % 33) == 0) printf("\n___");
            printf("%02X ", src[i]);
        }
        printf("<- ");
    }
}


static uint32_t context_memory[ALLOC_MEM_UINT32S];
static int allocated_uint32s;

static void * Allocate(int bytes) {
	void * r = (void *)&context_memory[allocated_uint32s];
	allocated_uint32s += ((bytes + 3) >> 2);
	return r;
}

// Send: c[1]
static void SendByte(port_ctx *ctx, uint8_t c) {
    if ((c & 0xFC) == 0x10) {           // special 10h to 13h byte?
        ctx->tcFn(0x10);
        ctx->tcFn(c & 3);
    } else {
        ctx->tcFn(c);
    }
    ctx->hPutcFn((void *)&*ctx->thCtx, c); // add to hash
}

#define HDRlength 6 /* Header length (tag+len+~len) */
#define ADlength  1 /* Associated data length */

// Send: Tag[1], Length[2], ~Length[2], format[1]
static void SendHeader(port_ctx *ctx, int tag, int msglen) {
    ctx->hInitFn((void *)&*ctx->thCtx, ctx->hkey, HERMES_HMAC_LENGTH);
    SendByte(ctx, tag);                 // Header starts with a TAG byte,
    msglen += HDRlength;                // length includes the header
    for (int i = 2; i > 0; --i) {       // a 16-bit big-endian length
        SendByte(ctx, (uint8_t)(msglen));      // send twice to detect
        SendByte(ctx, (uint8_t)(msglen >> 8)); // bad length early
        msglen ^= -1;
    }
    SendByte(ctx, ctx->protocol);
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
    SendHeader(ctx, tag,
               HERMES_IV_LENGTH * 2 + HERMES_HMAC_LENGTH + ADlength);
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
    ctx->cInitFn ((void *)&*ctx->tcCtx, ctx->ckey, mIV);
    ctx->cBlockFn((void *)&*ctx->tcCtx, cIV, mIV, 0);
    for (int i = 0; i < HERMES_IV_LENGTH ; i++) {
        SendByte(ctx, mIV[i]);
    }
    SendByte(ctx, HERMES_RXBUF_LENGTH >> 6) ;
    SendTxHash(ctx);
    ctx->cInitFn((void *)&*ctx->tcCtx, ctx->ckey, cIV);
    ctx->tReady = 1;
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
    ctx->protocol = protocol;
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

// Send a pairing request
int hermesPair(port_ctx *ctx) {
    return SendIV(ctx, HERMES_TAG_HARD_RESET);
}

// Send a boilerplate request
void hermesBoiler(port_ctx *ctx) {
    SendHeader(ctx, HERMES_TAG_GET_BOILER, 0);
    ctx->tcFn(HERMES_TAG_END);
}

#define MAX_TX_LENGTH (HERMES_TXBUF_LENGTH - 2)

// Size of message available to accept
int hermesAvail(port_ctx *ctx){
    if (!ctx->rReady) return 0;
    if (!ctx->tReady) return 0;
    int rxAvail = ctx->avail << 6;
    if (rxAvail > MAX_TX_LENGTH) rxAvail = MAX_TX_LENGTH;
    return rxAvail;
}

// Encrypt and send a message
int hermesSend(port_ctx *ctx, const uint8_t *m, uint16_t bytes){
    if (bytes > hermesAvail(ctx)) return HERMES_ERROR_TXIN_TOO_LONG;
    int blocks = (2 + 15 + bytes) >> 4; // 15 bytes needs 17
    int i;
    memset(&ctx->txbuf[(bytes+1)&~15], 0, 16);  // pad the last block
    memcpy(ctx->txbuf, &bytes, 2);              // save the length
    memcpy(&ctx->txbuf[2], m, bytes);           // and the input
    bytes = blocks << 4;
    for (i = 0; i < bytes; i += 16) {
        ctx->cBlockFn((void *)&*ctx->tcCtx, &ctx->txbuf[i], &ctx->txbuf[i], 0);
//        ctx->hmacIVt += 1;
    }
    SendHeader(ctx, HERMES_TAG_MESSAGE, bytes + HERMES_HMAC_LENGTH);
    for (i = 0; i < bytes; i++) {
        SendByte(ctx, ctx->txbuf[i]);
    }
    SendTxHash(ctx);
    return 0;
}

#define WAIT_END(ior) ctx->state = 9; r = (ior); break;

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
            return HERMES_ERROR_UNKNOWN_CMD;
        }
        return 0;
    }
    if (ctx->escaped) {
        ctx->escaped = 0;
        if (c > 3) goto reset;
        c = (c & 3) + 0x10;                     // 10h 00h -> 10h
    }
    else if (c == 0x10) {
        ctx->escaped = 1;
        return 0;
    }
    ctx->hPutcFn((void *)&*ctx->rhCtx, c);      // add to hash
    switch (ctx->state) {
    case 0: // valid tags are 0x18 to 0x1F
        if ((c & 0xF8) != 0x18) break;
        ctx->hInitFn((void *)&*ctx->rhCtx, ctx->hkey, HERMES_HMAC_LENGTH);
        ctx->hPutcFn((void *)&*ctx->rhCtx, c);
        ctx->tag = c;
        goto next_header_char;
    case 1: // lower length byte
        ctx->length = c;
        goto next_header_char;
    case 2: // upper length byte
        ctx->length |= (uint16_t)c << 8;
        goto next_header_char;
    case 3: // lower ~length
        if ((ctx->length & 0xFF) != (c ^ 0xFF)) {goto badlength;}
        goto next_header_char;
    case 4: // upper ~length
        if (((ctx->length >> 8) != (c ^ 0xFF)) ||
            (ctx->length > HERMES_RXBUF_LENGTH)) {
badlength:  WAIT_END(HERMES_ERROR_INVALID_LENGTH)
        }
        goto next_header_char;
    case 5: // protocol
        if (ctx->protocol != c) {
            WAIT_END(HERMES_ERROR_WRONG_PROTOCOL)
        }
next_header_char:
        ctx->state++;
        break;
    case 6: // message data begins here
        ctx->rxbuf[0] = c;
        ctx->i = 1;
        ctx->state++;
        if (ctx->tag == HERMES_TAG_GET_BOILER) { // received a request for boilerplate
            SendHeader(ctx, HERMES_TAG_BOILERPLATE, HERMES_BOILER_LENGTH);
            for (i=0; i < HERMES_BOILER_LENGTH; i++) {
                ctx->tcFn(ctx->boil[i]);
            }
            ctx->tcFn(HERMES_TAG_END);
            ctx->state = 0;
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
                return HERMES_ERROR_BAD_HMAC;
            }
        }
// The payload has been authenticated, temp is the data length
        switch (ctx->tag) {
        case HERMES_TAG_HARD_RESET:
        case HERMES_TAG_SOFT_RESET:
            if (temp != (2 * HERMES_IV_LENGTH + ADlength)) {
                return HERMES_ERROR_INVALID_LENGTH;
            }
            ctx->cInitFn ((void *)&*ctx->rcCtx, ctx->ckey, ctx->rxbuf); // decrypt with mIV
            ctx->cBlockFn((void *)&*ctx->rcCtx, &ctx->rxbuf[HERMES_IV_LENGTH], cIV, 1);
            ctx->cInitFn ((void *)&*ctx->rcCtx, ctx->ckey, cIV);
            ctx->avail = ctx->rxbuf[2*HERMES_IV_LENGTH];
            ctx->rReady = 1;
            if (ctx->tag == HERMES_TAG_HARD_RESET) {
                r = SendIV(ctx, HERMES_TAG_SOFT_RESET);
            }
            break;
        case HERMES_TAG_MESSAGE:
            for (i = 0; i < temp; i += 16) {
                ctx->cBlockFn((void *)&*ctx->rcCtx, &ctx->rxbuf[i], &ctx->rxbuf[i], 1);
//                ctx->hmacIVr += 1;
            }
            memcpy (&temp, ctx->rxbuf, 2); // little-endian length
            ctx->tmFn(&ctx->rxbuf[2], temp);
        default: break;
        }
        ctx->state = 0;
        break;
    case 9: // wait for the end tag
        if (c == HERMES_TAG_END) {
            ctx->state = 0;
        }
        break;
    default:
        ctx->state = 0;
        return HERMES_ERROR_INVALID_STATE;
    }
    return r;
}

// -----------------------------------------------------------------------------
// Some default values for testing

port_ctx Alice;
port_ctx Bob;
int snoopy;

// Connect Alice to Bob via a virtual null-modem cable

static void snoop(uint8_t c, char t) {
    if (!snoopy) return;
    printf("%02X", c);
    if (c == 0x12) printf("\n");
    else           printf("%c", t);
}

static void AliceCiphertextOutput(uint8_t c) {
    snoop(c, '-');
    int r = hermesPutc(&Bob, c);
    if (r) printf("\nAlice saw return code %d ", r);
}

static void BobCiphertextOutput(uint8_t c) {
    snoop(c, '~');
    int r = hermesPutc(&Alice, c);
    if (r) printf("\nAlice saw return code %d ", r);
}

// Received-plaintest functions

static void PlaintextHandler(const uint8_t *src, uint32_t length) {
    if (snoopy) dump(src, length); else printf("\n");
    printf("Plaintext {");
    while (length--) putc(*src++, stdout);
    printf("} ");
}

static void BoilerHandlerA(const uint8_t *src, uint32_t length) {
    printf("\nAlice received boilerplate {%s}", src);
}

static void BoilerHandlerB(const uint8_t *src, uint32_t length) {
    printf("\nBob received boilerplate {%s}", src);
}
//                                0123456789abcdef0123456789abcdef
uint8_t my_encryption_key[32] = {"Do not use this encryption key!"};
uint8_t my_signature_key[16] =  {"Or this key..."};
const uint8_t AliceBoiler[16] = {"nyb0Alice"};
const uint8_t BobBoiler[16] =   {"nyb0Bob"};

#define MY_PROTOCOL 0

int main() {
    int tests = 0x1F;   // enable these tests...
//    snoopy = 1;         // don't display the wire traffic
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
    if (tests & 0x01) hermesBoiler(&Alice);
    if (tests & 0x02) hermesBoiler(&Bob);
    if (tests & 0x04) hermesPair(&Alice);
    if (tests & 0x08) {
        hermesSend(&Alice, "Alice says Hello", 16);
        hermesSend(&Alice, "Your code feels so tiny!", 24);
    }
    if (tests & 0x10) {
        hermesSend(&Bob,   "Bob says World", 14);
        hermesSend(&Bob,   "You should see my SipHash!", 26);
    }
    printf("\nAvailability: Alice=%d, Bob=%d", hermesAvail(&Alice), hermesAvail(&Bob));
    return 0;
}
