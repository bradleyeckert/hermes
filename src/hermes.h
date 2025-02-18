#ifndef __TCSTREAMS_H__
#define __TCSTREAMS_H__

#include <stdint.h>
#include "xchacha/src/xchacha.h"
#include "siphash/src/siphash.h"

#define HERMES_ALLOC_MEM_UINT32S  308
#define HERMES_FILE_MESSAGE_SIZE    9   /* Log2 of file message block */

#define HERMES_IV_LENGTH           16   /* Bytes in IV, should be 16 */
#define HERMES_HMAC_LENGTH         16   /* Bytes in HMAC, may be 8 or 16 */

// Message tags
#define HERMES_TAG_END           0x12   /* signal end of message (don't change) */
#define HERMES_TAG_GET_BOILER    0x14   /* request boilerplate */
#define HERMES_TAG_BOILERPLATE   0x15   /* boilerplate */
#define HERMES_TAG_RESET         0x16   /* trigger a 2-way IV init */
#define HERMES_TAG_MESSAGE       0x17   /* signal an encrypted message */
#define HERMES_TAG_CHALLENGE     0x18   /* signal a 2-way IV init */
#define HERMES_TAG_RESPONSE      0x19   /* signal a 1-way IV init */
#define HERMES_TAG_ACK           0x1A   /* signal an ACK */
#define HERMES_TAG_NACK          0x1B   /* signal a NACK */
#define HERMES_TAG_RAWTX         0x1F

#define HERMES_MSG_NEW_KEY       0xAA
#define HERMES_MSG_NO_ACK        0xFF

// Error tags
#define HERMES_ERROR_INVALID_STATE  1   /* FSM reached an invalid state */
#define HERMES_ERROR_UNKNOWN_CMD    2   /* Command not recognized */
#define HERMES_ERROR_TRNG_FAILURE   3   /* Bad RNG value */
#define HERMES_ERROR_MISSING_KEY    4
#define HERMES_ERROR_BAD_HMAC       5
#define HERMES_ERROR_INVALID_LENGTH 6
#define HERMES_ERROR_LONG_BOILERPLT 7
#define HERMES_ERROR_MSG_TRUNCATED  8
#define HERMES_ERROR_OUT_OF_MEMORY  9
#define HERMES_ERROR_REKEYED       10
#define HERMES_ERROR_MSG_NOT_SENT  11

// Commands
#define HERMES_CMD_RESET          256   /* Reset the FSM and re-pair the connection */

enum States {
  IDLE = 0,
  DISPATCH,
  GET_BOILER,
  GET_IV,
  GET_PAYLOAD,
  AUTHENTICATE
};

/*
Stream I/O is through functions. Bytes are transmitted by an output function.
Bytes are received (as a function parameter) by processing them with an FSM.
The hermesIn function returns an I/O result (0 if okay).

The FSM is not full-duplex. If the FSM has wait for the UART transmitter
(hermes_ciphrFn is hung), it may miss incoming bytes. This can be solved 3 ways:

- Operate in half-duplex mode
- Buffer the input with a FIFO
- Buffer the output with a FIFO
*/

typedef void (*hermes_ciphrFn)(uint8_t c);   // output raw ciphertext byte
typedef void (*hermes_plainFn)(const uint8_t *src, uint32_t length);
typedef int  (*hermes_rngFn)  (uint8_t *dest, int length);

typedef int  (*hmac_initFn)(size_t *ctx, const uint8_t *key, int hsize, uint64_t ctr);
typedef void (*hmac_putcFn)(size_t *ctx, uint8_t c);
typedef int  (*hmac_finalFn)(size_t *ctx, uint8_t *out);
typedef void (*crypt_initFn)(size_t *ctx, const uint8_t *key, const uint8_t *iv);
typedef void (*crypt_blockFn)(size_t *ctx, const uint8_t *in, uint8_t *out, int mode);

typedef struct
{   char* name;             // port name (for debugging)
    xChaCha_ctx *rcCtx;     // receiver encryption context
	siphash_ctx *rhCtx;     // receiver HMAC context
    xChaCha_ctx *tcCtx;     // transmitter encryption context
	siphash_ctx *thCtx;	    // transmitter HMAC context
    hermes_plainFn boilFn;  // boilerplate handler (from hermesPutc)
    hermes_plainFn tmFn;    // plaintext handler (from hermesPutc)
    hermes_ciphrFn tcFn;    // ciphertext transmit function
    hmac_initFn hInitFn;    // HMAC initialization function
    hmac_putcFn hPutcFn;    // HMAC putc function
    hmac_finalFn hFinalFn;  // HMAC finalization function
    crypt_initFn cInitFn;   // Encryption initialization function
    crypt_blockFn cBlockFn; // Encryption block function
    uint64_t hctrRx;        // HMAC counters
    uint64_t hctrTx;
    const uint8_t *boil;    // boilerplate
    const uint8_t *key;     // encryption/decryption key[32] and HMAC key[16]
    uint8_t hmac[HERMES_HMAC_LENGTH];
    uint8_t *rxbuf;
    uint8_t *txbuf;
    enum States state;      // of the FSM
    uint32_t counter;       // TX counter
    uint16_t rBlocks;       // size of rxbuf in blocks
    uint16_t tBlocks;       // size of rxbuf in blocks
    uint16_t avail;         // max size of message you can send = avail*64 bytes
    uint16_t ridx;          // rxbuf index
    uint8_t MACed;          // HMAC triggered
    uint8_t tag;            // received message type
    uint8_t escaped;        // assembling a 2-byte escape sequence
    uint8_t retries;        // count the NACKs
    uint8_t rAck;           // receiver Ack
    uint8_t tAck;           // transmitter Ack
    uint8_t prevblock;      // previous message block
    // Things the app needs to know...
    uint8_t rReady;         // receiver is initialized
    uint8_t tReady;         // transmitter is initialized
} port_ctx;


/** Clear the port list. Call before hermesAddPort.
 *  May be used to wipe contexts before exiting an app so sensitive data
 *  doesn't hang around in memory.
 */
void hermesNoPorts(void);


/** Append to the port list.
 * @param ctx         Port identifier
 * @param boilerplate Plaintext port identification boilerplate
 * @param protocol    AEAD protocol used: 0 = xchacha20-siphash
 * @param name        Name of port (for debugging)
 * @param rxBlocks    Size of receive buffer in 64-byte blocks
 * @param txBlocks    Size of transmit buffer in 64-byte blocks
 * @param boiler      Handler for received boilerplate (src, n)
 * @param plain       Handler for received data (src, n)
 * @param ciphr       Handler for char transmission (c)
 * @param enc_key     32-byte encryption key
 * @param hmac_key    16-byte HMAC key
 * @return    0 if okay, otherwise HERMES_ERROR_?
 */
int hermesAddPort(port_ctx *ctx, const uint8_t *boilerplate, int protocol, char* name,
                   uint16_t rxBlocks, uint16_t txBlocks,
                   hermes_plainFn boiler, hermes_plainFn plain, hermes_ciphrFn ciphr,
                   const uint8_t *key);


/** Input raw ciphertext (or command), such as received from a UART
 * @param ctx Port identifier
 * @param c   Incoming byte or command (command if > 255)
 * @return    0 if okay, otherwise HERMES_ERROR_?
 */
int hermesPutc(port_ctx *ctx, uint16_t c);


/** Trigger pairing. Resets the encrypted connection.
 * @param ctx Port identifier
 */
void hermesPair(port_ctx *ctx);


/** Trigger boilerplate.
 * @param ctx Port identifier
 * The received boilerplate comes out hermesAddPort's boiler function.
 */
void hermesBoiler(port_ctx *ctx);


/** Send a message
 * @param ctx   Port identifier
 * @param m     Plaintext message to send
 * @param bytes Length of message in bytes
 * @return      0 if okay, otherwise HERMES_ERROR_?
 * Only send data if hermesAvail is not 0.
 */
int hermesSend(port_ctx *ctx, const uint8_t *m, uint32_t bytes);


/** Encrypt and send a re-key message, returns key
 * @param key   48-byte key set
 * @return      0 if okay, otherwise HERMES_ERROR_?
 */
int hermesReKey(port_ctx *ctx, const uint8_t *key);


/** Get number of bytes allowed in a message
 * @param ctx   Port identifier
 * @return      Capacity
 */
uint32_t hermesAvail(port_ctx *ctx);


int hermesRAMused (int ports);
int hermesRAMunused (void);

int hermesFileNew(port_ctx *ctx);
void hermesFileInit (port_ctx *ctx);
void hermesFileFinal (port_ctx *ctx, int pad);
void hermesFileOut (port_ctx *ctx, const uint8_t *src, int len);


#endif /* __TCSTREAMS_H__ */
