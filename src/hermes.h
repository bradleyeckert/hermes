#ifndef __TCSTREAMS_H__
#define __TCSTREAMS_H__

#include <stdint.h>
#include "xchacha/src/xchacha.h"
#include "siphash/src/siphash.h"

#define HERMES_BOILER_LENGTH   16      /* boilerplate length */
#define HERMES_IV_LENGTH        8      /* Bytes in IV       */
#define HERMES_HMAC_LENGTH      8      /* Bytes in HMAC       */
#define HERMES_RXBUF_LENGTH    256      /* Buffer length */

// Message tags
#define HERMES_TAG_END          18      /* signal end of message (don't change) */
#define HERMES_TAG_GET_BOILER   20      /* request boilerplate */
#define HERMES_TAG_BOILERPLATE  21      /* boilerplate */
#define HERMES_TAG_HARD_RESET   22      /* signal a new 2-way IV init */
#define HERMES_TAG_SOFT_RESET   23      /* signal a new 1-way IV init */
#define HERMES_TAG_MESSAGE      24      /* signal an encrypted message */

// Error tags
#define HERMES_ERROR_INVALID_STATE  1   /* FSM reached an invalid state */
#define HERMES_ERROR_UNKNOWN_CMD    2   /* Command not recognized */
#define HERMES_ERROR_TRNG_FAILURE   3   /* Bad RNG value */
#define HERMES_ERROR_MISSING_KEY    4
#define HERMES_ERROR_BAD_HMAC       5
#define HERMES_ERROR_BAD_FORMAT     6

// Commands
#define HERMES_CMD_RESET  256   /* Reset the FSM and re-pair the connection */

/*
Stream I/O is through functions. Bytes are transmitted by an output function.
Bytes are received (as a function parameter) by processing them with an FSM.
The hermesIn function returns an I/O result (0 if okay).

The FSM is not full-duplex. If the FSM has wait for the UART transmitter
(hermes_cyphrFn is hung), it may miss incoming bytes. This can be solved 3 ways:

- Operate in half-duplex mode
- Buffer the input with a FIFO
- Buffer the output with a FIFO
*/

typedef void (*hermes_cyphrFn)(uint8_t c);   // output raw ciphertext byte
typedef void (*hermes_plainFn)(const uint8_t *src, uint32_t length);
typedef int (*hermes_rngFn)  (uint8_t *dest, int length);

typedef int  (*hmac_initFn)(size_t *ctx, const uint8_t *key, int hsize);
typedef void (*hmac_putcFn)(size_t *ctx, uint8_t c);
typedef int (*hmac_finalFn)(size_t *ctx, uint8_t *out);
typedef void (*crypt_initFn)(size_t *ctx, const uint8_t *key, const uint8_t *iv);
typedef void (*crypt_blockFn)(size_t *ctx, const uint8_t *in, uint8_t *out, int mode);

// about 88+HERMES_RXBUF_LENGTH bytes per port
typedef struct
{   xChaCha_ctx *rcCtx;     // receiver encryption context
	siphash_ctx *rhCtx;     // receiver HMAC context
    xChaCha_ctx *tcCtx;     // transmitter encryption context
	siphash_ctx *thCtx;	    // transmitter HMAC context
    uint32_t hmacIVr;       // receiver HMAC IV
    uint32_t hmacIVt;       // transmitter HMAC IV
    hermes_plainFn boilFn;  // boilerplate handler (from hermesPutc)
    hermes_plainFn tmFn;    // plaintext handler (from hermesPutc)
    hermes_cyphrFn tcFn;    // ciphertext transmit function
    hmac_initFn hInitFn;    // HMAC initialization function
    hmac_putcFn hPutcFn;    // HMAC putc function
    hmac_finalFn hFinalFn;  // HMAC finalization function
    crypt_initFn cInitFn;   // Encryption initialization function
    crypt_blockFn cBlockFn; // Encryption block function
    const uint8_t *boil;    // boilerplate
    const uint8_t *ckey;    // encryption/decryption key
    const uint8_t *hkey;    // HMAC signing key
    uint8_t pad[16];        // scratchpad
    uint8_t rxbuf[HERMES_RXBUF_LENGTH];
    uint16_t i;
    uint16_t length;        // received message length
    uint8_t tag;
    uint8_t protocol;       // which AEAD protocol is in use
    uint8_t state;          // of the FSM
    uint8_t escaped;        // assembling a 2-byte escape sequence
} port_ctx;

/** Input raw ciphertext (or command)
 * @param c   Incoming byte or command (command if > 255)
 * @return    0 if okay
 */
int hermesPutc(port_ctx *ctx, int c);

void hermesNoPorts(void);

int hermesPair(port_ctx *ctx);


int hermesSend(port_ctx *ctx, uint8_t *m, int bytes);


/** Initialize the context for hermesIn
 * @param c   Incoming byte or command (command if > 255)
 * @param out Output function for processing received packet
 */
void hermesAddPort(port_ctx *ctx, const uint8_t *boilerplate, int protocol,
                   hermes_plainFn boiler, hermes_plainFn plain, hermes_cyphrFn ciphr,
                   const uint8_t *enc_key, const uint8_t *hmac_key);


#endif /* __TCSTREAMS_H__ */
