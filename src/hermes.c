/*
Original project: https://github.com/bradleyeckert/hermes
AEAD-secured ports (for UARTs, etc.)
*/

#include <stdint.h>
#include <string.h>
#include "xchacha/src/xchacha.h"
#include "siphash/src/siphash.h"
#include "hermes.h"
#include "hermesHW.h"

#define ALLOC_HEADROOM (HERMES_ALLOC_MEM_UINT32S - allocated_uint32s)

#define TRACE 0

#if (TRACE)
#include <stdio.h>
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
#define PRINTf  printf
#else
void DUMP(const uint8_t *src, uint8_t len) {}
#define PRINTF(...) do { } while (0)
#define PRINTf PRINTF
#endif

// -----------------------------------------------------------------------------
// Hermes

static uint32_t context_memory[HERMES_ALLOC_MEM_UINT32S];
static int allocated_uint32s;

static void * Allocate(int bytes) {
	void * r = (void *)&context_memory[allocated_uint32s];
	allocated_uint32s += ((bytes + 3) >> 2);
	return r;
}

static void SendByteU(port_ctx *ctx, uint8_t c) {
    if ((c & 0xFC) == 0x10) {                   // special 10h to 13h byte?
        ctx->tcFn(0x10);
        ctx->tcFn(c & 3);
        ctx->counter++;
    } else {
        ctx->tcFn(c);
    }
    ctx->counter++;
}

static void SendByte(port_ctx *ctx, uint8_t c) {
    SendByteU(ctx, c);
    ctx->hPutcFn((void *)&*ctx->thCtx, c);      // add to HMAC
}

#define HDRlength 1 //(HERMES_LENGTH_LENGTH+2)      /* Header length (tag+len+~LSB) */
#define ivADlength  2                           /* Associated data length */

// Send: Tag[1]
static void SendHeader(port_ctx *ctx, int tag) {
    ctx->hInitFn((void *)&*ctx->thCtx, ctx->hkey, HERMES_HMAC_LENGTH, ctx->hctrTx);
    SendByte(ctx, tag);                         // Header consists of a TAG byte,
}

static void SendEnd(port_ctx *ctx) {            // send END tag
    ctx->tcFn(HERMES_TAG_END);
    ctx->tcFn(HERMES_TAG_END);                  // repeat for redundancy
    ctx->counter += 2;
}

static void SendBoiler(port_ctx *ctx) {         // send boilerplate packet
    uint8_t len = ctx->boil[0];
    SendHeader(ctx, HERMES_TAG_BOILERPLATE);
    for (int i = 1; i <= len; i++) ctx->tcFn(ctx->boil[i]);
    ctx->counter += len;
    SendEnd(ctx);
}

static void SendTxHash(port_ctx *ctx){          // finish authenticated packet
    uint8_t hash[HERMES_HMAC_LENGTH];
    ctx->hFinalFn((void *)&*ctx->thCtx, hash);
    ctx->hctrTx++;
    ctx->tcFn(0x10);                            // HMAC marker
    ctx->tcFn(0x04);
    ctx->counter += 2;
    for (int i = 0; i < HERMES_HMAC_LENGTH; i++) SendByteU(ctx, hash[i]);
    SendEnd(ctx);
}

// Send: Tag[1], Length[2], ~Length[1], format[1], mIV[], cIV[],
// RXbufsize[2], HMAC[]
static int SendIV(port_ctx *ctx, int tag) {
    uint8_t mIV[HERMES_IV_LENGTH];
    uint8_t cIV[HERMES_IV_LENGTH];
    int r = 0;
    int c;
    for (int i = 0; i < HERMES_IV_LENGTH ; i++) {
        c = getc_TRNG();  r |= c;  mIV[i] = (uint8_t)c;
        c = getc_TRNG();  r |= c;  cIV[i] = (uint8_t)c;
        if (r & 0x100) {
            return HERMES_ERROR_TRNG_FAILURE;
        }
    }
    memcpy(&ctx->hctrRx, cIV, 8);
    PRINTF("\n%s sending IV, tag=%d, ", ctx->name, tag);
    SendHeader(ctx, tag);
    for (int i = 0; i < HERMES_IV_LENGTH ; i++) {
        SendByte(ctx, mIV[i]);
    }
    DUMP((uint8_t*)&ctx->hctrRx, 8); PRINTF("New %s.hctrRx",ctx->name);
    DUMP((uint8_t*)&ctx->hctrTx, 8); PRINTF("Current %s.hctrTx\n",ctx->name);
    ctx->cInitFn ((void *)&*ctx->tcCtx, ctx->ckey, mIV);
    ctx->cBlockFn((void *)&*ctx->tcCtx, cIV, mIV, 0);
    for (int i = 0; i < HERMES_IV_LENGTH ; i++) {
        SendByte(ctx, mIV[i]);
    }
    SendByte(ctx, ctx->rBlocks) ;
    SendByte(ctx, ctx->rBlocks >> 8) ;
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
    PRINTF("\nEncrypting ACK/NACK, block counter = %d; ", ctx->tcCtx->blox);
    ctx->cBlockFn((void *)&*ctx->tcCtx, m, m, 0);
    SendHeader(ctx, tag);
    for (int i = 0; i < 16; i++) SendByte(ctx, m[i]);
    SendTxHash(ctx);
    return 0;
}

#define PREAMBLE_SIZE 3
#define MAX_TX_LENGTH ((ctx->tBlocks << 6) - PREAMBLE_SIZE)

// Encrypt and send a message
static int ResendMessage (port_ctx *ctx) {
    uint8_t m[16];
    uint16_t bytes;
    ctx->retries = 0;
    memcpy(&bytes, ctx->txbuf, 2);
    bytes += PREAMBLE_SIZE;             // include preamble in the message
    PRINTF("\n%s sending MESSAGE[%d/%d], tAck=%d, rAck=%d; ",
        ctx->name, bytes, ((bytes + 15) & ~0x0F), ctx->tAck, ctx->rAck);
    bytes = (bytes + 15) & ~0x0F;       // send whole blocks
    SendHeader(ctx, HERMES_TAG_MESSAGE);
    for (int i = 0; i < bytes; i += 16) {   // encrypt in blocks
        PRINTF("\nEncrypting MESSAGE, block counter = %d; ", ctx->tcCtx->blox);
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
void hermesAddPort(port_ctx *ctx, const uint8_t *boilerplate, int protocol, char* name,
                   uint16_t rxBlocks, uint16_t txBlocks,
                   hermes_plainFn boiler, hermes_plainFn plain, hermes_ciphrFn ciphr,
                   const uint8_t *enc_key, const uint8_t *hmac_key) {
    memset(ctx, 0, sizeof(port_ctx));
    ctx->tmFn = plain;      // plaintext output handler
    ctx->tcFn = ciphr;      // ciphertext output handler
    ctx->boilFn = boiler;
    ctx->ckey = enc_key;
    ctx->hkey = hmac_key;
    ctx->boil = boilerplate;
    ctx->name = name;
    ctx->rxbuf = Allocate(rxBlocks << 6);
    ctx->rBlocks = rxBlocks;
    ctx->txbuf = Allocate(txBlocks << 6);
    ctx->tBlocks = txBlocks;
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

int hermesRAMused (int ports) {
    return sizeof(uint32_t) * HERMES_ALLOC_MEM_UINT32S + ports * sizeof(port_ctx);
}

int hermesRAMunused (void) {
    return sizeof(uint32_t) * ALLOC_HEADROOM;
}

void hermesPair(port_ctx *ctx) {
    PRINTF("\n%s sending Pairing request, ", ctx->name);
    ctx->rReady = 0;
    ctx->tReady = 0;
    SendHeader(ctx, HERMES_TAG_RESET);
    SendEnd(ctx);
}

void hermesBoiler(port_ctx *ctx) {
    PRINTF("\n%s sending Boilerplate request, ", ctx->name);
    SendHeader(ctx, HERMES_TAG_GET_BOILER);
    SendEnd(ctx);
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

// Encrypt and send a message, buffering in case of transmission error.
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
int hermesPutc(port_ctx *ctx, uint16_t c){
    int r = 0;
    int temp, i, badHMAC;
    if (c & 0xFF00) {
        switch (c) {
        case HERMES_CMD_RESET:
reset:      hermesPair(ctx);
            ctx->state = IDLE;
            break;
        default:
            r = HERMES_ERROR_UNKNOWN_CMD;
        }
        return r;
    }
    // Pack escape sequence to binary ------------------------------------------
    int ended = (c == HERMES_TAG_END);          // distinguish '12' from '10 02'
    if (ctx->escaped) {
        ctx->escaped = 0;
        if (c > 3) switch(c) {
            case 4:                             // 10h 04h captures HMAC
                ctx->hFinalFn((void *)&*ctx->rhCtx, ctx->hmac); // snag before hash
                ctx->hctrRx++;
                ctx->MACed = 1;
                return 0;
            default: goto reset;
        } else {
        c += 0x10;                              // 10h 00h -> 10h
        }
    }
    else if (c == 0x10) {
        ctx->escaped = 1;
        return 0;
    }
    // FSM ---------------------------------------------------------------------
    ctx->hPutcFn((void *)&*ctx->rhCtx, c);      // add to hash
    switch (ctx->state) {
    case IDLE: // valid tags are 0x18 to 0x1F
        if (c < HERMES_TAG_GET_BOILER) break;   // limit range of valid tags
        if (c > HERMES_TAG_NACK)       break;
        if (c == HERMES_TAG_CHALLENGE) {
            ctx->hctrRx = 0;                    // before initializing the hash
            ctx->rReady = 0;
            ctx->tReady = 0;
        }
        ctx->hInitFn((void *)&*ctx->rhCtx, ctx->hkey, HERMES_HMAC_LENGTH, ctx->hctrRx);
        ctx->hPutcFn((void *)&*ctx->rhCtx, c);
        ctx->tag = c;
        ctx->MACed = 0;
        ctx->state = DISPATCH;
        break;
    case DISPATCH: // message data begins here
        PRINTF("\n%s incoming packet, tag=%d\n", ctx->name, ctx->tag);
        ctx->rxbuf[0] = c;
        ctx->ridx = 1;
        ctx->bidx = 0;
        ctx->state = GET_PAYLOAD;
        switch (ctx->tag) {
        case HERMES_TAG_GET_BOILER:
            SendBoiler(ctx);
            ctx->state = IDLE;
            break;
        case HERMES_TAG_RESET:
            ctx->hctrTx = 0;
            ctx->state = IDLE;
            r = SendIV(ctx, HERMES_TAG_CHALLENGE);
            break;
        case HERMES_TAG_BOILERPLATE:
            ctx->state = GET_BOILER;
            break;
        case HERMES_TAG_CHALLENGE:
        case HERMES_TAG_RESPONSE:
            ctx->state = GET_IV;
            break;
        }
        break;
    case GET_IV:
        ctx->rxbuf[ctx->ridx++] = c;
        if (ctx->ridx == HERMES_IV_LENGTH) {
            PRINTF("\nSet temporary IV for decrypting the secret IV ");
            ctx->cInitFn ((void *)&*ctx->rcCtx, ctx->ckey, ctx->rxbuf);
            ctx->state = GET_PAYLOAD;
        }
        break;
    case GET_BOILER:
        if (ctx->ridx == 64) {
            r = HERMES_ERROR_LONG_BOILERPLT;
            ended = 1;
        }
        if (ended) {
            ctx->boilFn(ctx->rxbuf, ctx->ridx);
            ctx->state = IDLE;
        } else {
            ctx->rxbuf[ctx->ridx++] = c;
        }
        break;
    case GET_PAYLOAD:
        if (!ended) {
            ctx->rxbuf[ctx->ridx++] = c;
            if (ctx->ridx == (ctx->rBlocks << 6)) {
                ctx->state = AUTHENTICATE;
            }
            temp = ctx->ridx;
            if (!ctx->MACed && !(temp & 15)) {
                temp -= 16; // -> beginning of block
                PRINTF("\n%s decrypting payload rxbuf[%d]; ", ctx->name, temp);
                ctx->cBlockFn((void *)&*ctx->rcCtx, &ctx->rxbuf[temp], &ctx->rxbuf[temp], 1);
            }
            break;
        }
    case AUTHENTICATE:
        ctx->state = IDLE;
        temp = ctx->ridx - HERMES_HMAC_LENGTH;
        badHMAC = 0;
        for (i = 0; i < HERMES_HMAC_LENGTH; i++) {
            if (ctx->hmac[i] != ctx->rxbuf[i+temp]) {
                r = HERMES_ERROR_BAD_HMAC;
                badHMAC = 1;
            }
        }
        PRINTF("\n%s received authentic packet of length %d, tag %d; ",
               ctx->name, temp, ctx->tag);
        if (badHMAC) PRINTf("\n**** Bad HMAC ****");
        switch (ctx->tag) {
        case HERMES_TAG_CHALLENGE:
            ctx->tReady = 0;
            ctx->hctrTx = 0;
        case HERMES_TAG_RESPONSE:
            ctx->rReady = 0;
            if (badHMAC) break;
            if (temp != (2 * HERMES_IV_LENGTH + ivADlength)) {
                r = HERMES_ERROR_INVALID_LENGTH;
                break;
            }
            ctx->cInitFn ((void *)&*ctx->rcCtx, ctx->ckey, &ctx->rxbuf[HERMES_IV_LENGTH]);
            memcpy(&ctx->hctrTx, &ctx->rxbuf[HERMES_IV_LENGTH], 8);
            memcpy(&ctx->avail, &ctx->rxbuf[2*HERMES_IV_LENGTH], 2);
            ctx->rReady = 1;
            ctx->rAck = 1;
            PRINTF("\nReceived IV, tag=%d; ", ctx->tag);
            DUMP((uint8_t*)&ctx->hctrRx, 8); PRINTF("Received HMAC hctrRx, ");
            if (ctx->tag == HERMES_TAG_CHALLENGE) {
                r = SendIV(ctx, HERMES_TAG_RESPONSE);
            }
            break;
        case HERMES_TAG_MESSAGE:
            if (badHMAC) {
                PRINTf("\n%s is sending NACK, ", ctx->name);
                ctx->retries++;
                if (ctx->retries > 3) {
                    hermesPair(ctx);
                }
                SendACK(ctx, HERMES_TAG_NACK, ctx->rAck);
                r = 0; // override "bad HMAC", sender gets a second chance
            } else {
                memcpy (&temp, ctx->rxbuf, 2);  // little-endian msg length
                c = ctx->rxbuf[2];
                if (c & 0x80) break;            // no ACK for this message
                ctx->rAck = c;
                ctx->tmFn(&ctx->rxbuf[PREAMBLE_SIZE], temp);
                SendACK(ctx, HERMES_TAG_ACK, (c + 1) & 0x7F);
            }
            break;
        case HERMES_TAG_ACK:
            if (badHMAC) {
                PRINTF("DROPPED ACK, ");
                break;
            }
            PRINTF("\nReceived ACK=%d; ", ctx->rxbuf[0]);
            ctx->rAck = ctx->rxbuf[0];
            ctx->retries = 0;
            break;
        case HERMES_TAG_NACK:
            if (badHMAC) {
                PRINTF("DROPPED NACK, ");
                break;
            }
            PRINTf("\n<<< Received NACK=%d; ", ctx->rxbuf[0]);
            ResendMessage(ctx);
            break;
        default: break;
        }
        break;
    default:
        ctx->state = IDLE;
        r = HERMES_ERROR_INVALID_STATE;
    }
    return r;
}

// -----------------------------------------------------------------------------
// File output: Init to start a packet, Out to append blocks, Final to finish.

void hermesFileInit (port_ctx *ctx) {
    SendHeader(ctx, HERMES_TAG_RAWTX);
}

int hermesFileNew(port_ctx *ctx) {
    ctx->rReady = 0;
    ctx->tReady = 0;
    SendBoiler(ctx);
    int r = SendIV(ctx, HERMES_TAG_CHALLENGE);
    hermesFileInit(ctx);
    return r;
}

void hermesFileFinal (port_ctx *ctx) {
    SendTxHash(ctx);
}
void hermesFileOut (port_ctx *ctx, const uint8_t *src, int len) {
    while (len > 0) {
        int siz = len;
        if (siz > 15) {siz = 16;}
        else {memset(ctx->txbuf, 0, 16);}
        memcpy(ctx->txbuf, &src, siz);
        ctx->cBlockFn((void *)&*ctx->tcCtx, ctx->txbuf, ctx->txbuf, 0);
        for (int i = 0; i < 16; i++) {
            SendByte(ctx, ctx->txbuf[i]);
        }
        src += 16;
        len -= 16;
    }
    if (ctx->counter > HERMES_FILE_MESSAGE_SIZE) {
        ctx->counter = 0;
        hermesFileFinal(ctx);
        hermesFileInit(ctx);
    }
}
