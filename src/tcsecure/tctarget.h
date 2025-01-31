#ifndef __TCTARGET_H__
#define __TCTARGET_H__

#include <stdint.h>
#include "tcconfig.h"

/* TC_BUFSIZE = size of transmit and receive buffers on target,
 * must be a power of 2. The minimum allowable size is 128.
 */

extern tcsec_ctx tc_target_tx[TARGET_PORTS];
extern tcsec_ctx tc_target_rx[TARGET_PORTS];

// There is no header file for cspihash.c so declare the function here
uint64_t siphash24(const void *src, unsigned long src_sz, const uint8_t key[16]);


/** Target side generates a challenge to send to the host.
 * @param Port this challenge is for
 * @return 0 if okay, else error
 * Output is in tc_target_tx.buf
 */
int tcChallengeHost(int port);


/** The target decrypts the host's challenge
 * @param trx Target receive context
 * @param in The 40-byte received from the target
 */
int tcValidateHost(int port);


/** Encrypt a message
 * @param ctx Context to use
 * @param in Plaintext message
 * @param inlen Input message length
 * @param out Ciphertext+HMAC message
 * @return 0 if okay, else error
 */
int tctEncrypt(int port);


/** Decrypt a message
 * @param ctx Context to use
 * @param in Ciphertext+HMAC message
 * @param inlen Input message length
 * @param out Plaintext message
 * @return 0 if okay, else error
 */
int tctDecrypt(int port);



#endif /* __TCTARGET_H__ */

