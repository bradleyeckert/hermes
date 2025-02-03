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
            if ((i % 30) == 0) printf("\n");
            printf("%02X ", src[i]);
        }
    }
}

void showCTX (tcsec_ctx *s) {   // dump context info
	printf("tcsec_ctx %p contents: \nhead=%d, tail=%d", s, s->head, s->tail);
	dump((uint8_t *)s->hkey, 16);
	printf("<-- hkey");
	dump(s->buf, s->head);
    printf("<-- buf\n");
}

/*
Functions to send and receive wrapped nonces may be used by either host or target
so the key pointer and random number generator are passed as functions.
*/

void tcClearBuffer(tcsec_ctx *s) {
    s->head = s->tail = 0;
}

void tcPutch(tcsec_ctx *s, uint8_t c) {
    s->buf[s->head] = c;
    s->head = (s->head + 1) & (TC_BUFSIZE - 1);
    s->ready = 1;
}

uint8_t tcGetch(tcsec_ctx *s) {
	uint8_t c =  s->buf[s->tail];
    s->tail = (s->tail + 1) & (TC_BUFSIZE - 1);
    if (s->head == s->tail)
        s->ready = 0;           // input is exhausted
    return c;
}

void tcAppend(tcsec_ctx *s, uint8_t *src, uint8_t len) {
    while (len--) {
        tcPutch(s, *src++);
    }
}

void tcCryptAppend(tcsec_ctx *s, uint8_t *src, uint8_t len) {
    while (len--) {
        tcPutch(s, *src++ ^ xchacha_next((void*)s));
    }
}

static int testWrap(int len) {
    if (len > (TC_BUFSIZE - 4)) {
        return TC_ERROR_BUFFER_TEARING; }
    return 0;
}

/** Append a tunneled IV to the buffer in s. The HMAC spans the message.
 * @param s structure
 * @param port Port for key selection
 * @param keypointer Function that points to a key given its index
 * @param random Function that fills a byte array with random data
 * @param Ysize Size of the nonce (24 for Xchacha20) plus whatever else
 * @return 0 if okay, else error
 * This should be called with an empty or nearly empty buffer to prevent a
 * TC_ERROR_BUFFER_TEARING error, which happens if the tail is too high to
 * prevent walking off the end of the buffer.
*/
int tcSendIV(tcsec_ctx *s, int port, keyFn keypointer, rngFn random, int Ysize) {
    int length = 1 + IV_LENGTH + Ysize + sizeof(uint64_t);
    tcPutch(s, length);
    tcPutch(s, TC_NONCE_FORMAT);
    unsigned int h = s->head;
    int r = testWrap(h + length);
    if (r)
        return r;                                       // unsafe wrap
    unsigned int keyID = port * KEYS_PER_PORT;
    const uint8_t *key = keypointer(keyID+2);
    if (key == NULL)
        return TC_ERROR_MISSING_KEY;
    memcpy(s->hkey, key, sizeof(s->hkey));              // get s HMAC key
	r = random(&s->buf[h], IV_LENGTH);                  // X is fixed-length
	if (r)
        return r;                                       // RNG failure
    key = keypointer(keyID);
    if (key == NULL)
        return TC_ERROR_MISSING_KEY;
    xchacha_keysetup((void*)s, key, &s->buf[h]);        // used locally too
    uint8_t *temp = &s->buf[TC_BUFSIZE - Ysize];
	r = random(temp, Ysize);                            // generate tunneled IV
	s->head = h + IV_LENGTH;
	tcCryptAppend(s, temp, Ysize);
    xchacha_keysetup((void*)s, key, temp);              // final IV for tx
    uint64_t t = siphash24(&s->buf[h], s->head-h, (char*)&s->hkey);
    s->hkey[0] += 1;
    tcAppend(s, (uint8_t *)&t, sizeof t);
	return r;
}

/** Receive a tunneled IV in buffer s. The HMAC spans the message.
 * @param s structure
 * @param port Port for key selection
 * @param keypointer Function that points to a key given its index
 * @return 0 if okay, else error
 * The message should not wrap the buffer, to prevent a TC_ERROR_BUFFER_TEARING error.
*/
int tcReceiveIV(tcsec_ctx *s, int port, keyFn keypointer) {
    uint8_t length = tcGetch(s) - (sizeof(uint64_t) + 1);
    uint8_t format = tcGetch(s);
    uint16_t tail = s->tail;
    if (format)
        return TC_ERROR_BAD_FORMAT;
    int r = testWrap(tail + length + sizeof(uint64_t));
    if (r)
        return r;                                       // unsafe wrap
    unsigned int keyID = port * KEYS_PER_PORT;
    const uint8_t *key = keypointer(keyID+2);
    if (key == NULL)
        return TC_ERROR_MISSING_KEY;
    memcpy(s->hkey, key, sizeof(s->hkey));              // save HMAC key
    uint64_t *expected = (uint64_t *)&s->buf[tail+length];
    uint64_t actual = siphash24(&s->buf[tail], length, (char*)&s->hkey);
    s->hkey[0] += 1;
    if (actual != *expected)                            // check the HMAC
        return TC_ERROR_BAD_HMAC;
    key = keypointer(keyID);
    if (key == NULL)
        return TC_ERROR_MISSING_KEY;
    xchacha_keysetup((void*)s, key, &s->buf[tail]);
    tail += IV_LENGTH;									// skip to Y[length]
    length -= IV_LENGTH;
    uint8_t *newIV = &s->buf[TC_BUFSIZE - length];
    xchacha_decrypt_bytes((void*)s, &s->buf[tail], newIV, length);
    xchacha_keysetup((void*)s, key, newIV);
    s->tail = tail + length + sizeof(uint64_t);
    return 0;
}

/** Encrypt a message
 * @param s structure, destination
 * @param port Context to use
 * @param dest Plaintext
 * @param len Length of message to send
 * @return 0 if okay, else error
 */
int tcEncrypt(tcsec_ctx *s, int port, uint8_t *src, int len) {
    return 0;
}



/** Decrypt a message
 * @param s structure, source
 * @param port Context to use
 * @param dest Plaintext destination
 * @param len Length of message to send
 * @return 0 if okay, else error
 */
int tcDecrypt(tcsec_ctx *s, int port, uint8_t *dest, int *len) {
    return 0;
}
