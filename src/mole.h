#ifndef __MOLE_H__
#define __MOLE_H__

#include <stdint.h>
#include "xchacha/src/xchacha.h"
#include "blake2s/src/blake2s.h"

#define MOLE_ALLOC_MEM_UINT32S   4096 /* longs for context memory */
#define MOLE_KEY_HASH_KEY        0ull /* 8-byte keyset master key */
#define MOLE_FILE_MESSAGE_SIZE      9 /* Log2 of file message block */

#define MOLE_IV_LENGTH             16 /* Bytes in IV, should be 16 */
#define MOLE_HMAC_LENGTH           16 /* Bytes in HMAC, may be 8 or 16 */
#define MOLE_KEYSET_LENGTH        160 /* ..., hmac16 */
#define MOLE_KEYSET_HMAC  (MOLE_KEYSET_LENGTH - MOLE_HMAC_LENGTH)

// Message tags
#define MOLE_TAG_END             0x0A /* signal end of message (don't change) */
#define MOLE_ESCAPE              0x0B
#define MOLE_HMAC_TRIGGER        0x02 /* 2nd char of escape sequence, triggers HMAC */
#define MOLE_TAG_GET_BOILER      0x14 /* request boilerplate */
#define MOLE_TAG_BOILERPLATE     0x15 /* boilerplate */
#define MOLE_TAG_RESET           0x16 /* trigger a 2-way IV init */
#define MOLE_TAG_MESSAGE         0x17 /* signal an encrypted message */
#define MOLE_TAG_IV_A            0x18 /* signal a 2-way IV init */
#define MOLE_TAG_IV_B            0x19 /* signal a 1-way IV init */
#define MOLE_TAG_ADMIN           0x1A /* admin password (random 128-bit number) */
#define MOLE_TAG_RAWTX           0x1F /* Raw non-repeatable AEAD message */

#define MOLE_MSG_MESSAGE         0x00
#define MOLE_MSG_NEW_KEY         0xAA
#define MOLE_LENGTH_UNKNOWN      0x01
#define MOLE_END_UNPADDED           0
#define MOLE_END_PADDED             1

// Error tags
#define MOLE_ERROR_INVALID_STATE    1 /* FSM reached an invalid state */
#define MOLE_ERROR_UNKNOWN_CMD      2 /* Command not recognized */
#define MOLE_ERROR_TRNG_FAILURE     3 /* Bad RNG value */
#define MOLE_ERROR_MISSING_KEY      4
#define MOLE_ERROR_BAD_HMAC         5
#define MOLE_ERROR_INVALID_LENGTH   6
#define MOLE_ERROR_LONG_BOILERPLT   7
#define MOLE_ERROR_MSG_TRUNCATED    8
#define MOLE_ERROR_OUT_OF_MEMORY    9
#define MOLE_ERROR_REKEYED         10
#define MOLE_ERROR_MSG_NOT_SENT    11
#define MOLE_ERROR_BUF_TOO_SMALL   12

enum States {
  IDLE = 0,
  DISPATCH,
  GET_BOILER,
  GET_IV,
  GET_PAYLOAD,
  HANG
};

/*
Stream I/O is through functions. Bytes are transmitted by an output function.
Bytes are received (as a function parameter) by processing them with an FSM.
The moleIn function returns an I/O result (0 if okay).

The FSM is not full-duplex. If the FSM has wait for the UART transmitter
(mole_ciphrFn is blocking), it may miss incoming bytes. This can be solved 3 ways:

- Operate in half-duplex mode
- Buffer the input with a FIFO
- Buffer the output with a FIFO
*/

typedef void (*mole_ciphrFn)(uint8_t c);    // output raw ciphertext byte
typedef void (*mole_plainFn)(const uint8_t *src, int length);
typedef void (*mole_boilrFn) (const uint8_t *src);
typedef int  (*mole_rngFn)  (void);
typedef uint8_t* (*mole_WrKeyFn)(uint8_t* keyset);

typedef int  (*hmac_initFn)(size_t *ctx, const uint8_t *key, int hsize, uint64_t ctr);
typedef void (*hmac_putcFn)(size_t *ctx, uint8_t c);
typedef int  (*hmac_finalFn)(size_t *ctx, uint8_t *out);
typedef void (*crypt_initFn)(size_t *ctx, const uint8_t *key, const uint8_t *iv);
typedef void (*crypt_blockFn)(size_t *ctx, const uint8_t *in, uint8_t *out, int mode);

typedef struct
{   char* name;             // port name (for debugging)
// The 4 following could be declared void*, but use actual structures for code completion
    xChaCha_ctx *rcCtx;     // receiver encryption context
	blake2s_state *rhCtx;   // receiver HMAC context
    xChaCha_ctx *tcCtx;     // transmitter encryption context
	blake2s_state *thCtx;   // transmitter HMAC context
    mole_boilrFn boilrFn;   // boilerplate handler (from molePutc)
    mole_plainFn plainFn;   // plaintext handler (from molePutc)
    mole_ciphrFn ciphrFn;   // ciphertext transmit function
    mole_WrKeyFn WrKeyFn;   // rewrite key set for this port
    mole_rngFn rngFn;       // get a reasonably random byte
    hmac_initFn hInitFn;    // HMAC initialization function
    hmac_putcFn hputcFn;    // HMAC putc function
    hmac_finalFn hFinalFn;  // HMAC finalization function
    crypt_initFn cInitFn;   // Encryption initialization function
    crypt_blockFn cBlockFn; // Encryption block function
    uint64_t hctrRx;        // HMAC counters
    uint64_t hctrTx;
    const uint8_t *boil;    // boilerplate
    const uint8_t *key;     // encryption/decryption key[32] and HMAC key[16]
    uint8_t *rxbuf;
    uint8_t txbuf[16];
    enum States state;      // of the FSM
    uint8_t hmac[MOLE_HMAC_LENGTH];
    uint32_t counter;       // TX counter
    uint16_t rBlocks;       // size of rxbuf in blocks
    uint16_t avail;         // max size of message you can send = avail*64 bytes
    uint16_t ridx;          // rxbuf index
    uint8_t MACed;          // HMAC triggered
    uint8_t tag;            // received message type
    uint8_t escaped;        // assembling a 2-byte escape sequence
    uint8_t txidx;          // byte index for char output
    uint8_t prevblock;      // previous message block (for file out)
    // Things the app needs to know...
    uint8_t rReady;         // receiver is initialized
    uint8_t tReady;         // transmitter is initialized
    uint8_t admin;          // admin password was received
} port_ctx;


/** Clear the port list. Call before moleAddPort.
 *  May be used to wipe contexts before exiting an app so sensitive data
 *  doesn't hang around in memory.
 */
void moleNoPorts(void);


/** Append to the port list.
 * @param ctx         Port identifier
 * @param boilerplate Plaintext port identification boilerplate
 * @param protocol    AEAD protocol used: 0 = xchacha20-blake2s
 * @param name        Name of port (for debugging)
 * @param rxBlocks    Size of receive buffer in 64-byte blocks
 * @param rngFn       Function to generate a random byte
 * @param boiler      Handler for received boilerplate (src, n)
 * @param plain       Handler for received data (src, n)
 * @param ciphr       Handler for char transmission (c)
 * @param key         32-byte encryption key, 16-byte HMAC key, and 16-byte HMAC of these
 * @param WrKeyFn     Function to overwrite the key
 * @return 0 if okay, otherwise MOLE_ERROR_?
 */
int moleAddPort(port_ctx *ctx, const uint8_t *boilerplate, int protocol, char* name,
                   uint16_t rxBlocks, mole_rngFn rngFn,
                   mole_boilrFn boiler, mole_plainFn plain, mole_ciphrFn ciphr,
                   const uint8_t *key, mole_WrKeyFn WrKeyFn);


/** Input raw ciphertext (or command), such as received from a UART
 * @param ctx Port identifier
 * @param c   Incoming byte
 * @return 0 if okay, otherwise MOLE_ERROR_?
 */
int molePutc(port_ctx *ctx, uint8_t c);


/** Send an IV to enable moleSend
 * @param ctx   Port identifier
 */
int moleTxInit(port_ctx *ctx);


/** Send a message
 * @param ctx   Port identifier
 * @param m     Plaintext message to send
 * @param bytes Length of message in bytes
 * @return      0 if okay, otherwise MOLE_ERROR_?
 */
int moleSend(port_ctx *ctx, const uint8_t *m, int bytes);

// Underlying char primitives for moleSend:

void moleSendInit(port_ctx *ctx, uint8_t type); // use MOLE_MSG_MESSAGE for type
void moleSendChar(port_ctx *ctx, uint8_t c);
void moleSendFinal(port_ctx *ctx);


/** Encrypt and send a re-key message, returns key
 * @param key   64-byte key set
 * @return      0 if okay, otherwise MOLE_ERROR_?
 */
int moleReKey(port_ctx *ctx, const uint8_t *key);


/** Get number of bytes allowed in a message
 * @param ctx   Port identifier
 * @return      Capacity (0 if not paired)
 */
uint32_t moleAvail(port_ctx *ctx);

/** Send a pairing request
 * @param ctx   Port identifier
 */
void molePair(port_ctx *ctx);

/** Send a boilerplate request
 * @param ctx   Port identifier
 */
void moleBoilerReq(port_ctx *ctx);

/** Send administrative password (encrypted)
 * @param ctx   Port identifier
 */
void moleAdmin(port_ctx *ctx);


int moleRAMused (int ports);
int moleRAMunused (void);

int  moleFileNew (port_ctx *ctx);
void moleFileInit (port_ctx *ctx);
void moleFileFinal (port_ctx *ctx, int pad);
void moleFileOut (port_ctx *ctx, const uint8_t *src, int len);

#endif /* __MOLE_H__ */
