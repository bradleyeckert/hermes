/* Tether crypto functions common to both Host and Target
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../libs/xchacha20/src/xchacha20.h"
#include "tcconfig.h"
#include "tctarget.h"
#include "tctargetHW.h"

void dump(uint8_t *src, uint8_t len) {
    if (len) {
        for (uint8_t i = 0; i < len; i++) {
            if ((i % 24) == 0) printf("\n");
            printf("%02X ", src[i]);
        }
    }
}

void showCTX (tcsec_ctx *s) {   // dump context info
	printf("tcsec_ctx %p contents: \nhead=%d, tail=%d", s, s->head, s->tail);
	uint8_t size = s->head - s->tail;
	if (s->tail) printf(", (size=%d)", size);
	if (size) dump(&s->buf[s->tail], size);
    printf("\n");
}

/*
Functions to send and receive wrapped nonces may be used by either host or target
so the key pointer and random number generator are passed as functions.
*/

void bufClear(tcsec_ctx *s) {
    s->head = s->tail = 0;
}

void bufAddChar(tcsec_ctx *s, uint8_t c) {
    s->buf[s->head] = c;
    s->head = (s->head + 1) & (TC_BUFSIZE - 1);
}

/*
Append a tunneled IV to the buffer in s. The HMAC spans the challenge. A challenge
is a random 24-bit plaintext IV, another random 24-bit encrypted IV, and an HMAC.
*/
int tcSendIV(tcsec_ctx *s, int port, keyFn keypointer, rngFn random, int extra) {
    bufAddChar(s, 1 + 2*IV_LENGTH + HASH_LENGTH + extra);
    bufAddChar(s, TC_NONCE_FORMAT);                     // format is plaintext
    unsigned int keyID = port * KEYS_PER_PORT;
    const uint8_t *key = keypointer(keyID+2);
    if (key == NULL)
        return TC_ERROR_MISSING_KEY;
    memcpy(s->hkey, key, sizeof(s->hkey));              // initial HMAC key
    unsigned int h = s->head;
	int r = random(&s->buf[h], IV_LENGTH);              // X is fixed-length
	if (r)
        return r;                                       // RNG failure
    key = keypointer(keyID);
    if (key == NULL)
        return TC_ERROR_MISSING_KEY;
    xchacha_keysetup((void*)s, key, &s->buf[h]);        // used locally too
    int Ysize = IV_LENGTH + extra;                      // Y can have extra length
    uint8_t *temp = &s->buf[TC_BUFSIZE - Ysize];
	r = random(temp, Ysize);
	xchacha_encrypt_bytes((void*)s, temp, &s->buf[h+IV_LENGTH], Ysize);
	s->head = h + IV_LENGTH + Ysize;
    xchacha_keysetup((void*)s, key, temp);              // final IV for tx
    uint64_t t = siphash24(&s->buf[h], s->head-h, (uint8_t*)&s->hkey);
    s->hkey[0] += 1;
	memcpy(&s->buf[s->head], &t, sizeof t);
	s->head += sizeof t;
	return r;
}

/*
Receive a tunneled IV in buffer s. The HMAC spans the message.
*/
int tcReceiveIV(tcsec_ctx *s, int port, keyFn keypointer) {
    uint8_t length = s->buf[s->tail++] - (HASH_LENGTH+1);
    uint8_t format = s->buf[s->tail++];
    uint16_t tail = s->tail;
    if (format)
        return TC_ERROR_BAD_FORMAT;
    unsigned int keyID = port * KEYS_PER_PORT;
    const uint8_t *key = keypointer(keyID+2);
    if (key == NULL)
        return TC_ERROR_MISSING_KEY;
    memcpy(s->hkey, key, sizeof(s->hkey));              // initial HMAC key
    uint64_t *expected = (uint64_t *)&s->buf[tail+length];
    uint64_t actual = siphash24(&s->buf[tail], length, (uint8_t*)&s->hkey);
    s->hkey[0] += 1;
    if (actual != *expected)                            // check the HMAC
        return TC_ERROR_BAD_HMAC;
    key = keypointer(keyID);
    if (key == NULL)
        return TC_ERROR_MISSING_KEY;
    xchacha_keysetup((void*)s, key, &s->buf[tail]);
    tail += IV_LENGTH;
    length -= IV_LENGTH;
    uint8_t *newIV = &s->buf[TC_BUFSIZE - length];
    xchacha_decrypt_bytes((void*)s, &s->buf[tail], newIV, length);
    xchacha_keysetup((void*)s, key, newIV);
    s->tail = tail + length + HASH_LENGTH;
    return 0;
}
