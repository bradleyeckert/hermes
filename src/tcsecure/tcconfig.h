#ifndef __TCCONFIG_H__
#define __TCCONFIG_H__

#include <stdint.h>
#include "tcconfig.h"

/* TC_BUFSIZE = size of transmit and receive buffers.
 * The minimum allowable size is 128.
 */

#define TC_BUFSIZE 256
#define TARGET_PORTS 1
#define HOST_PORTS 1

#define IV_LENGTH 24
#define HASH_LENGTH 8
#define KEYS_PER_PORT 6

// Target --> Host message tags
#define HOST_TAG_AUTH1 22
#define HOST_TAG_AUTH2 249
#define HOST_TAG_AUTH3 23
#define HOST_TAG_AUTH4 248

// Protocol 0 is Xchacha20-SipHash
#define TC_PROTOCOL 0

// Error tags
#define TC_ERROR_MISSING_KEY    -1
#define TC_ERROR_BAD_RNG        -2
#define TC_ERROR_BAD_HASH       -3


#if ((TC_BUFSIZE-1) & TC_BUFSIZE)
#error TC_BUFSIZE must be an exact power of 2
#endif

typedef struct
{	uint32_t input[16]; // xchacha state
    uint64_t hkey[2];   // siphash key
	uint8_t tail;
	uint8_t head;
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


void bufClear(tcsec_ctx *s);
void bufAppend(tcsec_ctx *s, const uint8_t *src, uint8_t len);
int tcSendIV(tcsec_ctx *s, int port);
int tcReceiveIV(tcsec_ctx *s, int port);

static const uint8_t ChallengeTag[] = {
    HOST_TAG_AUTH2, 3+2*IV_LENGTH+HASH_LENGTH, TC_PROTOCOL
};
static const uint8_t ResponseTag[] = {
    HOST_TAG_AUTH3, 3+2*IV_LENGTH+HASH_LENGTH, TC_PROTOCOL
};


#endif /* __TCCONFIG_H__ */
