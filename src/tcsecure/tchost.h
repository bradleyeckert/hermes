#ifndef __TCHOST_H__
#define __TCHOST_H__

#include <stdint.h>
#include "tcconfig.h"

/* TC_HOST_BUFSIZE = size of transmit and receive buffers on target,
 * must be a power of 2. The minimum allowable size is 128.
 */

extern tcsec_ctx tc_host_tx[HOST_PORTS];
extern tcsec_ctx tc_host_rx[HOST_PORTS];


/** Host side decrypts the tcChallengeHost challenge, generates its own random
 * number (RX nonce), encrypts it with the shared key and H>T nonce IV, and
 * sends it back to the target.
 * @param hrx Host receive context
 * @param htx Host transmit context
 * @param in The 24-byte challenge received from the host
 * @param out The 40-byte challenge to send to the target
 * @return 0 if okay, else error
 */
int tcChallengeTarget(int host_port, int target_port);


/** Encrypt a message
 * @param ctx Context to use
 * @param in Plaintext message
 * @param inlen Input message length
 * @param out Ciphertext+HMAC message
 * @return 0 if okay, else error
 */
int tchEncrypt(tcsec_ctx *ctx, uint8_t *in, int inlen, uint8_t *out);

/** Decrypt a message
 * @param ctx Context to use
 * @param in Ciphertext+HMAC message
 * @param inlen Input message length
 * @param out Plaintext message
 * @return 0 if okay, else error
 */
int tchDecrypt(tcsec_ctx *ctx, uint8_t *in, int inlen, uint8_t *out);


#endif /* __TCHOST_H__ */

