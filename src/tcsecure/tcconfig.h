#ifndef __TCCONFIG_H__
#define __TCCONFIG_H__

#include <stdint.h>
#include "tcconfig.h"

#define TC_BUFSIZE 256			/* 128 or 256 */
#define TARGET_PORTS 1
#define HOST_PORTS 1

#define IV_LENGTH 24			/* for XChaCha20 */
#define HASH_LENGTH 8			/* for SipHash */
#define KEYS_PER_PORT 3 		/* for XChaCha20-SipHash AEAD */
#define TC_NONCE_FORMAT 0       /* Xchacha20-SipHash */

// Message tags
#define HOST_TAG_NEW_TH 249		/* New target --> host session */
#define HOST_TAG_NEW_HT 23		/* New host --> target session */

// Error tags
#define TC_ERROR_MISSING_KEY    -1
#define TC_ERROR_BAD_RNG        -2
#define TC_ERROR_BAD_HMAC       -3
#define TC_ERROR_BAD_FORMAT     -4

#if ((TC_BUFSIZE-1) & TC_BUFSIZE)
#error TC_BUFSIZE must be an exact power of 2
#endif

typedef struct
{	uint32_t input[16]; // xchacha state
    uint64_t hkey[2];   // siphash key
	uint16_t tail;
	uint16_t head;
	uint8_t buf[TC_BUFSIZE];
} tcsec_ctx;

// There is no header file for cspihash.c so declare the function here
uint64_t siphash24(const void *src, unsigned long src_sz, const uint8_t key[16]);

/** Encrypt a message
 * @param port Context to use
 * @return 0 if okay, else error
 */
int tcEncrypt(int port);


/** Decrypt a message
 * @param port Context to use
 * @return 0 if okay, else error
 */
int tcDecrypt(int port);

typedef const uint8_t * (*keyFn)(unsigned int n);
typedef int (*rngFn)(uint8_t *dest, unsigned int size);

void bufClear(tcsec_ctx *s);
void bufAddChar(tcsec_ctx *s, uint8_t c);

int tcSendIV(tcsec_ctx *s, int port, keyFn getkey, rngFn random, int extra);
int tcReceiveIV(tcsec_ctx *s, int port, keyFn getkey);


#endif /* __TCCONFIG_H__ */
