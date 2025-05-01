/*
Original project: https://github.com/bradleyeckert/mole
AEAD-secured ports (for UARTs, etc.)
*/

#include <stdint.h>
#include <string.h>
#include "xchacha/src/xchacha.h"
#include "blake2s/src/blake2s.h"
#include "mole.h"

#define ALLOC_HEADROOM (MOLE_ALLOC_MEM_UINT32S - allocated_uint32s)

#define TRACE 0

#if (TRACE)
#include <stdio.h>
static void DUMP(const uint8_t *src, uint8_t len) {
    if (TRACE > 1) {
        for (uint8_t i = 0; i < len; i++) {
            if ((i % 32) == 0) printf("\n___");
            printf("%02X ", src[i]);
        }
        printf("<- ");
    }
}
#define PRINTF  if (TRACE > 1) printf
#define PRINTf  printf
#else
static void DUMP(const uint8_t *src, uint8_t len) {}
#define PRINTF(...) do { } while (0)
#define PRINTf PRINTF
#endif

#define BLOCK_SHIFT 6

// Note: txbuf is bigger than needed, it should be 16 bytes

// -----------------------------------------------------------------------------
// Mole

static uint32_t context_memory[MOLE_ALLOC_MEM_UINT32S];
static int allocated_uint32s;

static void * Allocate(int bytes) {
	void * r = (void *)&context_memory[allocated_uint32s];
	allocated_uint32s += ((bytes + 3) >> 2);
	return r;
}

static int testHMAC(port_ctx *ctx, const uint8_t *buf) {
    if (memcmp(ctx->hmac, buf, 16)) return MOLE_ERROR_BAD_HMAC;
    return 0;
}

static int testKey(port_ctx *ctx, const uint8_t *key) {
    DUMP(&key[0], MOLE_KEYSET_HMAC);    PRINTF("keyset data\n");
    ctx->hInitFn((void *)&*ctx->rhCtx, &key[32], 16, MOLE_KEY_HASH_KEY);
    for (int i=0; i < MOLE_KEYSET_HMAC; i++) {
        ctx->hputcFn((void *)&*ctx->rhCtx, key[i]);
    }
    ctx->hFinalFn((void *)&*ctx->rhCtx, ctx->hmac);
    DUMP(ctx->hmac, 16);  PRINTF("expected key hmac");
    DUMP(&key[MOLE_KEYSET_HMAC], 16);   PRINTF("actual key hmac\n");
    return testHMAC(ctx, &key[MOLE_KEYSET_HMAC]);
}

static void SendByteU(port_ctx *ctx, uint8_t c) {
    if ((c & 0xFE) == MOLE_TAG_END) {         // MOLE_TAG_END or MOLE_ESCAPE
        ctx->ciphrFn(MOLE_ESCAPE);
        ctx->ciphrFn(c & 1);
        ctx->counter++;
    } else {
        ctx->ciphrFn(c);
    }
    ctx->counter++;
}

static void SendByte(port_ctx *ctx, uint8_t c) {
    SendByteU(ctx, c);
    ctx->hputcFn((void *)&*ctx->thCtx, c);      // add to HMAC
}

static void SendN(port_ctx *ctx, const uint8_t *src, int length) {
    for (int i = 0; i < length; i++) {
        SendByte(ctx, src[i]);
    }
}

static void Send2(port_ctx *ctx, int x) {
    SendByte(ctx, x) ;               // RX buffer size[2]
    SendByte(ctx, x >> 8) ;
}

static void Send16(port_ctx *ctx, const uint8_t *src) {
    SendN(ctx, src, 16);
}

static void SendTxBuf(port_ctx *ctx) {
    ctx->cBlockFn((void *)&*ctx->tcCtx, ctx->txbuf, ctx->txbuf, 0);
    Send16(ctx, ctx->txbuf);
}

#define ivADlength  2                           /* Associated data length */

// Send: Tag[1]
static void SendHeader(port_ctx *ctx, int tag) {
    ctx->hInitFn((void *)&*ctx->thCtx, &ctx->key[32], MOLE_HMAC_LENGTH, ctx->hctrTx);
    SendByte(ctx, tag);                         // Header consists of a TAG byte,
}

static void SendEnd(port_ctx *ctx) {            // send END tag
    ctx->counter++;
    ctx->ciphrFn(MOLE_TAG_END);
}

static void SendBoiler(port_ctx *ctx) {         // send boilerplate packet
    uint8_t len = ctx->boil[0];
    SendHeader(ctx, MOLE_TAG_BOILERPLATE);
    for (int i = 0; i <= len; i++) SendByteU(ctx, ctx->boil[i]);
    SendByteU(ctx, 0);                          // zero-terminate to stringify
    SendEnd(ctx);
}

static void SendTxHash(port_ctx *ctx, int pad){ // finish authenticated packet
    DUMP((uint8_t*)&ctx->hctrTx, 8); PRINTF("%s is sending HMAC with hctrTx, ", ctx->name);
    uint8_t hash[MOLE_HMAC_LENGTH];
    ctx->hFinalFn((void *)&*ctx->thCtx, hash);
    ctx->hctrTx++;
    ctx->ciphrFn(MOLE_ESCAPE);                   // HMAC marker
    ctx->ciphrFn(MOLE_HMAC_TRIGGER);
    for (int i = 0; i < MOLE_HMAC_LENGTH; i++) SendByteU(ctx, hash[i]);
    ctx->ciphrFn(MOLE_TAG_END);
    ctx->counter += 3;
    while (pad && (ctx->counter & 0x1F)) {      // pad until next 32-byte boundary
        ctx->counter++;
        ctx->ciphrFn(0);
    }
    ctx->counter++;
    ctx->ciphrFn(MOLE_TAG_END);
}

// Send: Tag[1], mIV[], cIV[], RXbufsize[2], HMAC[]
static int SendIV(port_ctx *ctx, int tag) {     // send random IV with random IV
    uint8_t mIV[MOLE_IV_LENGTH];              // using these instead of txbuf
    uint8_t cIV[MOLE_IV_LENGTH];              // to allow for re-transmission
    int r = 0;
    int c;
    for (int i = 0; i < MOLE_IV_LENGTH ; i++) {
        c = ctx->rngFn();  r |= c;  mIV[i] = (uint8_t)c;
        c = ctx->rngFn();  r |= c;  cIV[i] = (uint8_t)c;
        if (r & 0x100) {
            return MOLE_ERROR_TRNG_FAILURE;
        }
    }
    memcpy(&ctx->hctrRx, cIV, 8);
    PRINTF("\n%s sending IV, tag=%d, ", ctx->name, tag);
    SendHeader(ctx, tag);                       // TAG (also resets HMAC)
#if (MOLE_IV_LENGTH == 16)
    Send16(ctx, mIV);
#else
    SendN(ctx, mIV, MOLE_IV_LENGTH);
#endif
    DUMP((uint8_t*)&ctx->hctrRx, 8); PRINTF("New %s.hctrRx",ctx->name);
    DUMP((uint8_t*)&ctx->hctrTx, 8); PRINTF("Current %s.hctrTx",ctx->name);
    DUMP((uint8_t*)mIV, MOLE_IV_LENGTH); PRINTF("used by %s to encrypt cIV\n",ctx->name);
    ctx->cInitFn ((void *)&*ctx->tcCtx, ctx->key, mIV);
    ctx->cBlockFn((void *)&*ctx->tcCtx, cIV, mIV, 0);
#if (MOLE_IV_LENGTH == 16)
    Send16(ctx, mIV);
#else
    SendN(ctx, mIV, MOLE_IV_LENGTH);
#endif
    Send2(ctx, ctx->rBlocks);                   // RX buffer size[2]
    SendTxHash(ctx, MOLE_END_UNPADDED);       // HMAC
    ctx->cInitFn((void *)&*ctx->tcCtx, ctx->key, cIV);
    ctx->tReady = 1;
    return 0;
}

#define PREAMBLE_SIZE 2
#define MAX_RX_LENGTH ((ctx->rBlocks << BLOCK_SHIFT) - (MOLE_HMAC_LENGTH + PREAMBLE_SIZE))


// -----------------------------------------------------------------------------
// Public functions

// Call this before setting up any mole ports and when closing app.
void moleNoPorts(void) {
	memset(context_memory, 0, sizeof(context_memory));
	allocated_uint32s = 0;
}

// Add a secure port
int moleAddPort(port_ctx *ctx, const uint8_t *boilerplate, int protocol, char* name,
                   uint16_t rxBlocks, mole_rngFn rngFn,
                   mole_boilrFn boiler, mole_plainFn plain, mole_ciphrFn ciphr,
                   const uint8_t *key, mole_WrKeyFn WrKeyFn) {
    memset(ctx, 0, sizeof(port_ctx));
    ctx->plainFn = plain;                       // plaintext output handler
    ctx->ciphrFn = ciphr;                       // ciphertext output handler
    ctx->boilrFn = boiler;                      // boilerplate output handler
    ctx->key = key;
    ctx->WrKeyFn = WrKeyFn;
    ctx->rngFn = rngFn;
    ctx->boil = boilerplate;                    // counted string
    ctx->name = name;                           // Zstring name for debugging
    ctx->rxbuf = Allocate(rxBlocks << BLOCK_SHIFT);
    ctx->rBlocks = rxBlocks;                    // block size (1<<BLOCK_SHIFT) bytes
    if (rxBlocks < 2) return MOLE_ERROR_BUF_TOO_SMALL;
    switch (protocol) {
    default: // 0
        ctx->rcCtx = Allocate(sizeof(xChaCha_ctx));
        ctx->tcCtx = Allocate(sizeof(xChaCha_ctx));
        ctx->rhCtx = Allocate(sizeof(blake2s_state));
        ctx->thCtx = Allocate(sizeof(blake2s_state));
        ctx->hInitFn  = b2s_hmac_init_g;
        ctx->hputcFn  = b2s_hmac_putc_g;
        ctx->hFinalFn = b2s_hmac_final_g;
        ctx->cInitFn  = xc_crypt_init_g;
        ctx->cBlockFn = xc_crypt_block_g;
    }
    if (ALLOC_HEADROOM < 0) return MOLE_ERROR_OUT_OF_MEMORY;
    return testKey(ctx, key);
}

int moleRAMused (int ports) {
    return sizeof(uint32_t) * allocated_uint32s + ports * sizeof(port_ctx);
}

int moleRAMunused (void) {
    return sizeof(uint32_t) * ALLOC_HEADROOM;
}

void molePair(port_ctx *ctx) {
    PRINTF("\n%s sending Pairing request, ", ctx->name);
    ctx->rReady = 0;
    ctx->tReady = 0;
    SendHeader(ctx, MOLE_TAG_RESET);
    SendEnd(ctx);
}

void moleBoilerReq(port_ctx *ctx) {
    PRINTF("\n%s sending Boilerplate request, ", ctx->name);
    SendHeader(ctx, MOLE_TAG_GET_BOILER);
    SendEnd(ctx);
}

// Send: Tag[1], password[16], HMAC[]
void moleAdmin(port_ctx *ctx) {
    uint8_t m[16];
    PRINTF("\n%s sending Admin password, ", ctx->name);
    SendHeader(ctx, MOLE_TAG_ADMIN);
    ctx->cBlockFn((void *)&*ctx->tcCtx, &ctx->key[64], m, 0);
    Send16(ctx, m);
    SendTxHash(ctx, MOLE_END_UNPADDED);
}

// Size of message available to accept
uint32_t moleAvail(port_ctx *ctx){
    if (!ctx->rReady) return 0;
    if (!ctx->tReady) return 0;
    return (ctx->avail << BLOCK_SHIFT) - (MOLE_HMAC_LENGTH + PREAMBLE_SIZE);
}

// -----------------------------------------------------------------------------
// Receive char or command from input stream
int molePutc(port_ctx *ctx, uint8_t c){
    int r = 0;
    int temp;
    uint8_t *k;
    // Pack escape sequence to binary ------------------------------------------
    int ended = (c == MOLE_TAG_END);          // distinguish '12' from '10 02'
    if (ctx->escaped) {
        ctx->escaped = 0;
        if (c > 1) switch(c) {
            case MOLE_HMAC_TRIGGER:
                DUMP((uint8_t*)&ctx->hctrRx, 8);
                PRINTF("%s receiving HMAC with hctrRx, ", ctx->name);
                ctx->hFinalFn((void *)&*ctx->rhCtx, ctx->hmac);
                ctx->hctrRx++;
                ctx->MACed = 1;
                return 0;
            default:                            // embedded reset
                ctx->state = IDLE;
                molePair(ctx);
                return 0;
        } else {
        c += MOLE_TAG_END;
        }
    }
    else if (c == MOLE_ESCAPE) {
        ctx->escaped = 1;
        return 0;
    }
    // FSM ---------------------------------------------------------------------
    ctx->hputcFn((void *)&*ctx->rhCtx, c);      // add to hash
    int i = ctx->ridx;
    switch (ctx->state) {
    case IDLE:
        if (c < MOLE_TAG_GET_BOILER) break;   // limit range of valid tags
        if (c > MOLE_TAG_ADMIN)      break;
        if (c == MOLE_TAG_IV_A) {
            ctx->hctrRx = 0;                    // before initializing the hash
            ctx->rReady = 0;
            ctx->tReady = 0;
        }
        ctx->hInitFn((void *)&*ctx->rhCtx, &ctx->key[32], MOLE_HMAC_LENGTH, ctx->hctrRx);
        ctx->hputcFn((void *)&*ctx->rhCtx, c);
        ctx->tag = c;
        ctx->MACed = 0;
        ctx->state = DISPATCH;
        break;
    case DISPATCH: // message data begins here
        PRINTF("\n%s incoming packet, tag=%d\n", ctx->name, ctx->tag);
        ctx->rxbuf[0] = c;
        ctx->ridx = 1;
        ctx->state = GET_PAYLOAD;
        switch (ctx->tag) {
        case MOLE_TAG_GET_BOILER:
            SendBoiler(ctx);
            ctx->state = IDLE;
            break;
        case MOLE_TAG_RESET:
            ctx->hctrTx = 0;
            ctx->state = IDLE;
            r = SendIV(ctx, MOLE_TAG_IV_A);
            break;
        case MOLE_TAG_BOILERPLATE:
            ctx->state = GET_BOILER;
            break;
        case MOLE_TAG_IV_A:
        case MOLE_TAG_IV_B:
            ctx->state = GET_IV;
            break;
        }
    case HANG:                                  // wait for end token
noend:  if (ended) ctx->state = IDLE;           // premature end not allowed
        break;
    case GET_IV:
        ctx->rxbuf[ctx->ridx++] = c;
        if (ctx->ridx == MOLE_IV_LENGTH) {
            PRINTF("\nSet temporary IV for decrypting the secret IV ");
            ctx->cInitFn ((void *)&*ctx->rcCtx, ctx->key, ctx->rxbuf);
            ctx->state = GET_PAYLOAD;
        }
        goto noend;
    case GET_BOILER:
        if (i == MAX_RX_LENGTH) {
            r = MOLE_ERROR_LONG_BOILERPLT;
            ended = 1;
        }
        if (ended) {
            if ((i - 2) == ctx->rxbuf[0])
            ctx->boilrFn(ctx->rxbuf);
        } else {
            ctx->rxbuf[ctx->ridx++] = c;
        }
        goto noend;
    case GET_PAYLOAD:
        if (!ended) {                           // input terminated by end token
            if (i != (ctx->rBlocks << BLOCK_SHIFT)) {
                ctx->rxbuf[ctx->ridx++] = c;
                temp = ctx->ridx;
                if (!ctx->MACed && !(temp & 15)) {
                    temp -= 16;                 // -> beginning of block
                    PRINTF("\n%s decrypting payload rxbuf[%d]; ", ctx->name, temp);
                    ctx->cBlockFn((void *)&*ctx->rcCtx, &ctx->rxbuf[temp], &ctx->rxbuf[temp], 1);
                }
            } else {
                ctx->state = HANG;
                r = MOLE_ERROR_INVALID_LENGTH;
            }
            break;
        }
        ctx->state = IDLE;
        temp = i - MOLE_HMAC_LENGTH;
        c = ctx->rxbuf[0];                      // repurpose c
        r = testHMAC(ctx, &ctx->rxbuf[temp]);   // 0 if okay, else bad HMAC
        PRINTF("\n%s received packet of length %d, tag %d, rxbuf[0]=0x%02X; ",
               ctx->name, temp, ctx->tag, c);
        if (r) {
            PRINTf("\n**** Bad HMAC ****");
        }
        switch (ctx->tag) {
        case MOLE_TAG_IV_A:
            ctx->tReady = 0;
            ctx->hctrTx = 0;
        case MOLE_TAG_IV_B:
            ctx->rReady = 0;
            if (r) break;
            if (temp != (2 * MOLE_IV_LENGTH + ivADlength)) {
                r = MOLE_ERROR_INVALID_LENGTH;
                break;
            }
            ctx->cInitFn ((void *)&*ctx->rcCtx, ctx->key, &ctx->rxbuf[MOLE_IV_LENGTH]);
            memcpy(&ctx->hctrTx, &ctx->rxbuf[MOLE_IV_LENGTH], 8);
            memcpy(&ctx->avail, &ctx->rxbuf[2*MOLE_IV_LENGTH], 2);
            ctx->rReady = 1;
            PRINTF("\nReceived IV, tag=%d; ", ctx->tag);
            DUMP((uint8_t*)&ctx->hctrRx, 8); PRINTF("Received HMAC hctrRx, ");
            DUMP((uint8_t*)&ctx->rxbuf[MOLE_IV_LENGTH], 16); PRINTF("Private cIV, ");
            if (ctx->tag == MOLE_TAG_IV_A) {
                r = SendIV(ctx, MOLE_TAG_IV_B);
            }
            break;
        case MOLE_TAG_ADMIN:
            ctx->admin = 0;
            if (r) break;
            DUMP(&ctx->key[64], 16); PRINTF("Expected Password");
            DUMP(ctx->rxbuf, 16);    PRINTF("Actual Password");
            if (memcmp(ctx->rxbuf, &ctx->key[64], 16) == 0) ctx->admin = 0x55;
            break;
        case MOLE_TAG_MESSAGE:
            if (r) {
                molePair(ctx);                // assume synchronization is lost
            } else {
                if (c == MOLE_MSG_NEW_KEY) {
                    PRINTF("\nTesting the new key");
                    temp = testKey(ctx, &ctx->rxbuf[1]);
                    if (temp) return temp;      // bad key
                    k = ctx->WrKeyFn(&ctx->rxbuf[1]);
                    c = 0;
                    if (k == NULL) return 0;    // no key
                    return MOLE_ERROR_REKEYED;
                }
                i = ctx->rxbuf[temp - 1];       // remainder
                temp = temp + i - 17;           // trim padding
                ctx->plainFn(&ctx->rxbuf[1], temp);
            }
            break;
        default: break;
        }
        break;
    default:
        ctx->state = IDLE;
        r = MOLE_ERROR_INVALID_STATE;
    }
    return r;
}

// -----------------------------------------------------------------------------
// File output: Init to start a packet, Out to append blocks, Final to finish.

void moleFileInit (port_ctx *ctx) {
    SendHeader(ctx, MOLE_TAG_RAWTX);
    SendByte(ctx, MOLE_LENGTH_UNKNOWN);
}

static int NewStream(port_ctx *ctx) {
    ctx->counter = 0;
    ctx->prevblock = 0;
    ctx->rReady = 0;
    ctx->tReady = 0;
    ctx->hctrTx = 0;
    SendBoiler(ctx);                          // include ID information for keying
    int r = SendIV(ctx, MOLE_TAG_IV_A);       // and an encrypted IV
    return r;
}

int moleFileNew(port_ctx *ctx) {              // start a new one-way message
    int r = NewStream(ctx);
    ctx->hctrTx = ctx->hctrRx + 1;
    moleFileInit(ctx);                        // get ready to write 16-byte blocks
    return r;
}

void moleFileFinal (port_ctx *ctx, int pad) { // end the one-way message
    SendTxHash(ctx, pad);
}

void moleFileOut (port_ctx *ctx, const uint8_t *src, int len) {
    while (len > 0) {
        memcpy(ctx->txbuf, src, 16);
        SendTxBuf(ctx);
        src += 16;
        len -= 16;
        uint32_t p = ctx->counter + 2 * MOLE_HMAC_LENGTH + 3;
        uint8_t block = (uint8_t)(p >> MOLE_FILE_MESSAGE_SIZE);
        if (ctx->prevblock != block) {
            ctx->prevblock = block;
            moleFileFinal(ctx, MOLE_END_PADDED);
            moleFileInit(ctx);
        }
    }
}

// Arbitrary length message streaming is similar to file output.
// Do not guarantee delivery, just send and forget. This scheme assumes a host PC
// with a large rxbuf, so it will get the data. Otherwise, the HMAC is dropped.

int moleTxInit(port_ctx *ctx) {               // use if not paired
    return NewStream(ctx);
}

void moleSendInit(port_ctx *ctx, uint8_t type) {
    SendHeader(ctx, MOLE_TAG_MESSAGE);
    ctx->txbuf[0] = type;
    ctx->txidx = 1;
}

void moleSendChar(port_ctx *ctx, uint8_t c) {
    int i = ctx->txidx;
    ctx->txbuf[i] = c;
    i = (i + 1) & 0x0F;
    ctx->txidx = i;
    if (!i) SendTxBuf(ctx);
}

void moleSendFinal(port_ctx *ctx) {
    ctx->txbuf[15] = ctx->txidx;
    SendTxBuf(ctx);
    SendTxHash(ctx, MOLE_END_UNPADDED);
}

static void moleSendMsg(port_ctx *ctx, const uint8_t *src, int len, int type) {
    moleSendInit(ctx, type);
    while (len--) moleSendChar(ctx, *src++);
    moleSendFinal(ctx);
}

int moleSend(port_ctx *ctx, const uint8_t *src, int len) {
    moleSendMsg(ctx, src, len, MOLE_MSG_MESSAGE);
//  if (ctx->counter > 1023) return moleTxInit(ctx);
    return 0;
}

// Encrypt and send a key set
int moleReKey(port_ctx *ctx, const uint8_t *key){
    if (moleAvail(ctx) < MOLE_KEYSET_LENGTH) return MOLE_ERROR_MSG_NOT_SENT;
    moleSendMsg(ctx, key, MOLE_KEYSET_LENGTH, MOLE_MSG_NEW_KEY);
    return 0;
}
