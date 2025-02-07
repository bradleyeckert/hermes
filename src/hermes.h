#ifndef __TCSTREAMS_H__
#define __TCSTREAMS_H__

#include <stdint.h>
#include "xchacha/src/xchacha.h"
#include "siphash/src/siphash.h"

#define KEYS_PER_PORT 4                 /* for XChaCha20-SipHash AEAD */
#define T_NONCE_FORMAT 0                /* Xchacha20-SipHash */

// Message tags
#define HOST_TAG_NEW_TH 249		        /* New target --> host session */
#define HOST_TAG_NEW_HT 23		        /* New host --> target session */

// Error tags
#define T_ERROR_MISSING_KEY     1
#define T_ERROR_BAD_RNG         2
#define T_ERROR_BAD_HMAC        3
#define T_ERROR_BAD_FORMAT      4
#define T_ERROR_BUFFER_TEARING  5

/*
Stream I/O is through functions. Bytes are transmitted by an output function.
Bytes are received (as a function parameter) by processing them with an FSM.
The hermesIn function returns an I/O result (0 if okay).
*/


typedef int (*hermes_cyphrFn)(uint8_t c);   // output raw ciphertext byte
typedef int (*hermes_plainFn)(const uint8_t *src, uint32_t length);

// RAM usage: 400 bytes per port
typedef struct
{   xChaCha_ctx rcCtx;      // receiver encryption context
	siphash_ctx rhCtx;      // receiver HMAC context
    xChaCha_ctx tcCtx;      // transmitter encryption context
	siphash_ctx thCtx;	    // transmitter HMAC context
    hermes_plainFn tmFn;    // plaintext handler (from hermesIn)
    hermes_cyphrFn tcFn;    // ciphertext transmit function
    int state;
} port_ctx;

/** Input raw ciphertext (or command)
 * @param c   Incoming byte or command (command if > 255)
 * @return    0 if okay
 */
int hermesPutc(port_ctx *ctx, int c);

/** Initialize the context for hermesIn
 * @param c   Incoming byte or command (command if > 255)
 * @param out Output function for processing received packet
 * @return    0 if okay
 */
int hermesInit(port_ctx *ctx, hermes_plainFn plain, hermes_cyphrFn cyphr);


#endif /* __TCSTREAMS_H__ */
