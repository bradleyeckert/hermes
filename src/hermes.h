#ifndef __TCSTREAMS_H__
#define __TCSTREAMS_H__

#include <stdint.h>
#include "xchacha/src/xchacha.h"
#include "siphash/src/siphash.h"

#define HERMES_BOILER_LENGTH       16   /* boilerplate length */
#define HERMES_IV_LENGTH           16   /* Bytes in IV */
#define HERMES_HMAC_LENGTH         16   /* Bytes in HMAC */
#define HERMES_RXBUF_LENGTH       128   /* RX buffer length, a multiple of 16 */
#define HERMES_TXBUF_LENGTH       128   /* TX buffer length, a multiple of 16 */

// Message tags
#define HERMES_TAG_END             18   /* signal end of message (don't change) */
#define HERMES_TAG_GET_BOILER      24   /* request boilerplate */
#define HERMES_TAG_BOILERPLATE     25   /* boilerplate */
#define HERMES_TAG_HARD_RESET      26   /* signal a new 2-way IV init */
#define HERMES_TAG_SOFT_RESET      27   /* signal a new 1-way IV init */
#define HERMES_TAG_MESSAGE         28   /* signal an encrypted message */

// Error tags
#define HERMES_ERROR_INVALID_STATE  1   /* FSM reached an invalid state */
#define HERMES_ERROR_UNKNOWN_CMD    2   /* Command not recognized */
#define HERMES_ERROR_TRNG_FAILURE   3   /* Bad RNG value */
#define HERMES_ERROR_MISSING_KEY    4
#define HERMES_ERROR_BAD_HMAC       5
#define HERMES_ERROR_BAD_HMAC_LEN   6
#define HERMES_ERROR_WRONG_PROTOCOL 7
#define HERMES_ERROR_INVALID_LENGTH 8
#define HERMES_ERROR_LONG_BOILERPLT 9
#define HERMES_ERROR_TXIN_TOO_LONG 10

// Commands
#define HERMES_CMD_RESET          256   /* Reset the FSM and re-pair the connection */

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
typedef int (*hermes_rngFn)  (uint8_t *dest, int length);

typedef int  (*hmac_initFn)(size_t *ctx, const uint8_t *key, uint32_t counter, int hsize);
typedef void (*hmac_putcFn)(size_t *ctx, uint8_t c);
typedef int (*hmac_finalFn)(size_t *ctx, uint8_t *out);
typedef void (*crypt_initFn)(size_t *ctx, const uint8_t *key, const uint8_t *iv);
typedef void (*crypt_blockFn)(size_t *ctx, const uint8_t *in, uint8_t *out, int mode);

typedef struct
{   xChaCha_ctx *rcCtx;     // receiver encryption context
	siphash_ctx *rhCtx;     // receiver HMAC context
    xChaCha_ctx *tcCtx;     // transmitter encryption context
	siphash_ctx *thCtx;	    // transmitter HMAC context
    uint32_t hmacIVr;       // receiver HMAC IV
    uint32_t hmacIVt;       // transmitter HMAC IV
    hermes_plainFn boilFn;  // boilerplate handler (from hermesPutc)
    hermes_plainFn tmFn;    // plaintext handler (from hermesPutc)
    hermes_ciphrFn tcFn;    // ciphertext transmit function
    hmac_initFn hInitFn;    // HMAC initialization function
    hmac_putcFn hPutcFn;    // HMAC putc function
    hmac_finalFn hFinalFn;  // HMAC finalization function
    crypt_initFn cInitFn;   // Encryption initialization function
    crypt_blockFn cBlockFn; // Encryption block function
    const uint8_t *boil;    // boilerplate
    const uint8_t *ckey;    // encryption/decryption key
    const uint8_t *hkey;    // HMAC signing key
    uint8_t hmac[HERMES_HMAC_LENGTH];
    uint8_t rxbuf[HERMES_RXBUF_LENGTH];
    uint8_t txbuf[HERMES_TXBUF_LENGTH];
    uint16_t i;
    uint16_t length;        // received message length
    uint8_t tag;            // received message type
    uint8_t protocol;       // which AEAD protocol is in use
    uint8_t state;          // of the FSM
    uint8_t escaped;        // assembling a 2-byte escape sequence
    // Things the app needs to know...
    uint8_t rReady;         // receiver is initialized
    uint8_t tReady;         // transmitter is initialized
    uint8_t avail;          // max size of message you can send = avail*64 bytes
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
 * @param boiler      Handler for received boilerplate (src, n)
 * @param plain       Handler for received data (src, n)
 * @param ciphr       Handler for char transmission (c)
 * @param enc_key     32-byte encryption key
 * @param hmac_key    32-byte HMAC key
 */
void hermesAddPort(port_ctx *ctx, const uint8_t *boilerplate, int protocol,
                   hermes_plainFn boiler, hermes_plainFn plain, hermes_ciphrFn ciphr,
                   const uint8_t *enc_key, const uint8_t *hmac_key);


/** Input raw ciphertext (or command), such as received from a UART
 * @param ctx Port identifier
 * @param c   Incoming byte or command (command if > 255)
 * @return    0 if okay, otherwise HERMES_ERROR_?
 */
int hermesPutc(port_ctx *ctx, int c);


/** Trigger pairing. Resets the encrypted connection.
 * @param ctx Port identifier
 * @return    0 if okay, otherwise HERMES_ERROR_?
 */
int hermesPair(port_ctx *ctx);


/** Trigger boilerplate.
 * @param ctx Port identifier
 * @return    0 if okay, otherwise HERMES_ERROR_?
 * The received boilerplate comes out hermesAddPort's boiler function.
 */
void hermesBoiler(port_ctx *ctx);


/** Send a message
 * @param ctx   Port identifier
 * @param m     Plaintext message to send
 * @param bytes Length of message in bytes
 * @return      0 if okay, otherwise HERMES_ERROR_?
 */
int hermesSend(port_ctx *ctx, const uint8_t *m, uint16_t bytes);


#if ((HERMES_RXBUF_LENGTH < 64) || (HERMES_RXBUF_LENGTH > 16320))
#error Invalid value for HERMES_RXBUF_LENGTH
#endif

#if ((HERMES_TXBUF_LENGTH < 64) || (HERMES_TXBUF_LENGTH > 16320))
#error Invalid value for HERMES_TXBUF_LENGTH
#endif

#endif /* __TCSTREAMS_H__ */
