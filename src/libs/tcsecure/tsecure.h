#ifndef __TCSECURE_H__
#define __TCSECURE_H__

#include <stddef.h>

typedef struct	// copy of XChaCha_ctx from xchacha20.h
{	uint32_t input[16];
} ChaCha_ctx;

typedef struct	// copy of poly1305_context from poly1305-donna.h
{	size_t aligner;
	uint8_t opaque[136];
} poly1305_ctx;

typedef struct
{	ChaCha_ctx cha;
	poly1305_ctx poly;
	uint8_t ckey[32];				// private keys in RAM (protect this)
	uint8_t skey[32];
	uint8_t iv[24];
} authenticate_c

/** Target side generates a 24-byte challenge to send to the host.
 * Generate random number, Initialize XChaCha20(TX) and encrypt the number,
 * @param ttx Target transmit context
 * @param challenge The 24-byte iv or nonce to use
 * @return 0 if okay, else error
 */
int tcChallengeHost(authenticate_ctx *ttx, uint8_t[24] challenge);


/** Host side decrypts the tcChallengeHost challenge, generates its own random
 * number (RX nonce), encrypts it with the shared key and H>T nonce IV, and
 * sends it back to the target.
 * @param hrx Host receive context
 * @param htx Host transmit context
 * @param in The 24-byte challenge received from the host
 * @param out The 40-byte challenge to send to the target
 * @return 0 if okay, else error
 */
int tcChallengeTarget(authenticate_ctx *hrx, authenticate_ctx *htx, uint8_t[24] in, uint8_t[40] out);


/** The target decrypts the host's challenge
 * @param trx Target receive context
 * @param in The 40-byte received from the target
 */
int tcValidateHost(authenticate_ctx *htx, uint8_t[40] in);

/** Encrypt a message
 * @param ctx Context to use
 * @param in Plaintext message
 * @param inlen Input message length
 * @param out Ciphertext+HMAC message
 * @return 0 if okay, else error
 */
int tcEncrypt(authenticate_ctx *ctx, uint8_t *in, int inlen, uint8_t *out);

/** Decrypt a message
 * @param ctx Context to use
 * @param in Ciphertext+HMAC message
 * @param inlen Input message length
 * @param out Plaintext message
 * @return 0 if okay, else error
 */
int tcDecrypt(authenticate_ctx *ctx, uint8_t *in, int inlen, uint8_t *out);



#endif /* __TCSECURE_H__ */

