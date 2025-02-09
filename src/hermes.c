/* AEAD-secured ports (for UARTs, etc.)
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
#define ALLOC_MEM_UINT32S 512
#endif

static uint32_t context_memory[ALLOC_MEM_UINT32S];
static int allocated_uint32s;

// call this before setting up hermes ports to initialize the context_memory
void hermesNoPorts(void) {
	memset(context_memory, 0, sizeof(context_memory));
	allocated_uint32s = 0;
}

static void * Allocate(int bytes) {
	void * r = (void *)&context_memory[allocated_uint32s];
	allocated_uint32s += ((bytes + 3) >> 2);
	return r;
}

void hermesAddPort(port_ctx *ctx, const uint8_t *boilerplate, int protocol,
                   hermes_plainFn boiler, hermes_plainFn plain, hermes_cyphrFn ciphr,
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
        ctx->hInitFn = sip_hmac_init_g;
        ctx->hPutcFn = sip_hmac_putc_g;
        ctx->hFinalFn = sip_hmac_final_g;
    }
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

// Send: Tag[1], Length[4], format[1]
static void SendHeader(port_ctx *ctx, int tag, int msglen) {
    ctx->hInitFn((void *)&*ctx->thCtx, ctx->hkey, HERMES_HMAC_LENGTH);
    SendByte(ctx, tag);                 // Header starts with a TAG byte,
    for (int i = 2; i > 0; --i) {       // a 16-bit big-endian length
        SendByte(ctx, (uint8_t)(msglen >> 8)); // send twice to detect
        SendByte(ctx, (uint8_t)(msglen));      // bad length early
        msglen ^= -1;
    }
    SendByte(ctx, ctx->protocol);
}

// Send: HMAC[]
static void SendTxHash(port_ctx *ctx){
    ctx->hFinalFn((void *)&*ctx->thCtx, ctx->pad);
    for (int i = 0; i < HERMES_HMAC_LENGTH; i++) {
        SendByte(ctx, ctx->pad[i]);
    }
    ctx->tcFn(HERMES_TAG_END);
}

// Send: Tag[1], Length[4], format[1], mIV[16], cIV[16], HMAC[]
static int SendIV(port_ctx *ctx, int tag) {
    SendHeader(ctx, tag,
               HERMES_IV_LENGTH * 2 + HERMES_HMAC_LENGTH + 6);
    uint8_t mIV[HERMES_IV_LENGTH];
    uint8_t cIV[HERMES_IV_LENGTH];
    int r = 0;
    int c;
    for (int i = 0; i < HERMES_IV_LENGTH ; i++) {
        c = getc_TRNG();  r |= c;  mIV[i] = c;
        SendByte(ctx, (uint8_t)c);
        c = getc_TRNG();  r |= c;  cIV[i] = c;
        if (r & 0x100) {
            return HERMES_ERROR_TRNG_FAILURE;
        }
    }
    xc_crypt_init(&*ctx->tcCtx, ctx->ckey, mIV);
    xc_crypt_block(&*ctx->tcCtx, mIV, cIV, 0);
    for (int i = 0; i < HERMES_IV_LENGTH ; i++) {
        SendByte(ctx, cIV[i]);
    }
    SendTxHash(ctx);
    ctx->hmacIVt = 0;
    xc_crypt_init(&*ctx->tcCtx, ctx->ckey, cIV);
    return 0;
}

// Encrypt and send a message
int hermesSend(port_ctx *ctx, uint8_t *m, int bytes){
    SendHeader(ctx, HERMES_TAG_MESSAGE, bytes+6);
    while (bytes--) SendByte(ctx, *m++);
    SendTxHash(ctx);
    ctx->hmacIVt += 1;
    if (ctx->hmacIVt == 0) ctx->state = 0; // rolled over
    return 0;
}

// Send a pairing request
int hermesPair(port_ctx *ctx) {
    return SendIV(ctx, HERMES_TAG_HARD_RESET);
}

// Send a boilerplate request
void hermesBoiler(port_ctx *ctx) {
    SendHeader(ctx, HERMES_TAG_GET_BOILER, 6);
    ctx->tcFn(HERMES_TAG_END);
}

// Receive char or command from input stream
int hermesPutc(port_ctx *ctx, int c){
    int r = 0;
    int temp, i;
    if (c & 0xFF00) {
        switch (c) {
        case HERMES_CMD_RESET:
            hermesPair(ctx);
            ctx->state = 0;
            break;
        default: return HERMES_ERROR_UNKNOWN_CMD;
        }
        return 0;
    }
    if (ctx->escaped) {
        ctx->escaped = 0;
        c = (c & 3) + 0x10;             // 10h 00h -> 10h
    }
    else if (c == 0x10) {
        ctx->escaped = 1;
        return 0;
    }
    switch (ctx->state) {
    case 0:
        ctx->state++;
    case 1: // tag
        ctx->hInitFn((void *)&*ctx->rhCtx, ctx->hkey, HERMES_HMAC_LENGTH);
        ctx->tag = c;
        goto nextchar;
    case 2: // upper length byte
        ctx->length = c << 8;
        goto nextchar;
    case 3: // lower length byte
        ctx->length |= (uint16_t)c;
        goto nextchar;
    case 4: // upper ~length
        if ((ctx->length >> 8) != (c ^ 0xFF)) {goto badlength;}
        goto nextchar;
    case 5: // lower ~length
        if (ctx->length != (c ^ 0xFF)) {
badlength:  ctx->state = 10;
        }
        goto nextchar;
    case 6: // protocol
        if (ctx->protocol != c) {
            ctx->state = 11;
        }
nextchar: ctx->state++;
        ctx->hPutcFn((void *)&*ctx->rhCtx, c); // add to hash
        break;
    case 7: // evaluate tag; c is the first byte of a message or HERMES_TAG_END
//        printf("\nctx=%p, tag %d, length %d, ", &ctx, ctx->tag, ctx->length);
        switch (ctx->tag) {
        case HERMES_TAG_GET_BOILER: // received a request for boilerplate
            SendHeader(ctx, HERMES_TAG_BOILERPLATE, 6+HERMES_BOILER_LENGTH);
            for (int i=0; i < HERMES_BOILER_LENGTH; i++) {
                ctx->tcFn(ctx->boil[i]);
            }
            ctx->tcFn(HERMES_TAG_END);
            ctx->state = 0;
            break;
        case HERMES_TAG_BOILERPLATE: // receiving boilerplate
            ctx->rxbuf[0] = c;
            ctx->i = 1;
            ctx->state++;
            break;
        default: break;
            ctx->state = 0;
        }
        break;
    case 8: // get remaining boilerplate
        ctx->rxbuf[ctx->i++] = c;
        temp = ctx->length - 6;
        i = ctx->i;
        if ((i == temp)                         // received length
            || (i == HERMES_RXBUF_LENGTH)) {    // or maximum length
            ctx->boilFn(ctx->rxbuf, temp);
            ctx->state = 10;                    // wait for END token
        }
        break;
    case 10: // wait for the end tag
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

static void AliceCiphertextOutput(uint8_t c) {
    printf("%02X-", c);
    hermesPutc(&Bob, c);
}

static void BobCiphertextOutput(uint8_t c) {
    printf("%02X~", c);
    hermesPutc(&Alice, c);
}

static void PlaintextHandler(const uint8_t *src, uint32_t length) {
    while (length--) putc(*src++, stdout);
}

static void BoilerHandler(const uint8_t *src, uint32_t length) {
    printf("\nBoilerplate={%s}\n", src);
}
//                                      0123456789abcdef0123456789abcdef
const uint8_t my_encryption_key[32] = {"Do not use this encryption key!"};
const uint8_t my_signature_key[16] =  {"Or this key..."};
const uint8_t AliceBoiler[16] =       {"hms0Alice"};
const uint8_t BobBoiler[16] =         {"hms0Bob"};

#define MY_PROTOCOL 0

int main() {
    hermesNoPorts();
    hermesAddPort(&Alice, AliceBoiler, MY_PROTOCOL,
                  BoilerHandler, PlaintextHandler, AliceCiphertextOutput,
                  my_encryption_key, my_signature_key);
    hermesAddPort(&Bob, BobBoiler, MY_PROTOCOL,
                  BoilerHandler, PlaintextHandler, BobCiphertextOutput,
                  my_encryption_key, my_signature_key);
    hermesBoiler(&Alice);
    hermesBoiler(&Bob);
//    hermesPair(&Alice);
    return 0;
}
