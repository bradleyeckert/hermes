

#include "tctarget.h"
#include "tcplatform.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../libs/xchacha20/src/xchacha20.h"
#include "../libs/poly1305-donna/poly1305-donna.h"
#include "tcconfig.h"

// The tx and rx buffers within each tcsec_ctx are accessed outside this module
// so they are global variables

tcsec_ctx tc_target_tx[TARGET_PORTS];
tcsec_ctx tc_target_rx[TARGET_PORTS];

static const uint8_t ChallengeTag[] = {
    HOST_TAG_AUTH2, 3+2*IV_LENGTH+HASH_LENGTH, TC_PROTOCOL
};

void bufClear(tcsec_ctx *s) {
    s->head = s->tail = 0;
}

void bufAppend(tcsec_ctx *s, const uint8_t *src, uint8_t len) {
    for (uint8_t i = 0; i < len; i++) {
        s->buf[s->head] = *src++;
        s->head = (s->head + 1) & (TC_BUFSIZE - 1);
    }
}

void bufAppendHash(tcsec_ctx *s, int i) {
	uint64_t t = siphash24(&s->buf[i], s->head-i, (uint8_t*)&s->key);
	memcpy(&s->buf[s->head], &t, sizeof t);
    s->key[0] += 1;
	s->head += sizeof t;
}


/** Encrypt a message
 * @param ctx Context to use
 * @param in Plaintext message
 * @param inlen Input message length
 * @param out Ciphertext+HMAC message
 * @return 0 if okay, else error
 */
//int tctEncrypt(tcsec_ctx *ctx, uint8_t *in, int inlen, uint8_t *out);


/** Decrypt a message
 * @param ctx Context to use
 * @param in Ciphertext+HMAC message
 * @param inlen Input message length
 * @param out Plaintext message
 * @return 0 if okay, else error
 */
//int tctDecrypt(tcsec_ctx *ctx, uint8_t *in, int inlen, uint8_t *out);

// The authentication 3-pass handshake negotiates IVs for XChaCha20
// initialization by tcValidateHost.

/** Target side generates a challenge to send to the host.
 * @param port Port this challenge is for
 * @return 0 if okay, else error
 * Output is to tc_target_tx.buf
 */
int tcChallengeHost(int port) {
    tcsec_ctx *s = &tc_target_tx[port];
    unsigned int keyID = 6 * port;
    bufClear(s);
    memcpy(s->key, tcKeyN(keyID+2), sizeof(s->key));    // initial HMAC key
    bufAppend(s, ChallengeTag, sizeof(ChallengeTag));   // plaintext command
    unsigned int h = s->head;
	int r = tcRNGfunction(&s->buf[h], IV_LENGTH);       // preliminary IV
	if (r) return r;                                    // RNG failure
    xchacha_keysetup((void*)s, tcKeyN(keyID), &s->buf[h]); // used locally too
    uint8_t *temp = &s->buf[TC_BUFSIZE - IV_LENGTH];
	r = tcRNGfunction(temp, IV_LENGTH);
	xchacha_encrypt_bytes((void*)s, temp, &s->buf[h+IV_LENGTH], IV_LENGTH);
	s->head = h + IV_LENGTH * 2;
    xchacha_keysetup((void*)s, tcKeyN(keyID), temp);       // final IV for tx
    bufAppendHash(s, h);
	return r;
}

/** The target decrypts the host's challenge
 * @param trx Target receive context
 * @param in The 40-byte received from the target
 */
//int tcValidateHost(tcsec_ctx *htx, uint8_t[40] in);
//	printf("generating %d rands...", size);
//	printf("ok\n");


