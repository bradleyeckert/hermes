#ifndef __TCCONFIG_H__
#define __TCCONFIG_H__

#include <stdint.h>
#include "tcconfig.h"

#define TC_BUFSIZE 256
#define TARGET_PORTS 1
#define HOST_PORTS 1

#define IV_LENGTH 24
#define HASH_LENGTH 8

// Target --> Host message tags
#define HOST_TAG_AUTH1 22
#define HOST_TAG_AUTH2 249
#define HOST_TAG_AUTH3 23
#define HOST_TAG_AUTH4 248

// Protocol 0 is Xchacha20-SipHash
#define TC_PROTOCOL 0


#if ((TC_BUFSIZE-1) & TC_BUFSIZE)
#error TC_BUFSIZE must be an exact power of 2
#endif

typedef struct
{	uint32_t input[16]; // xchacha state
    uint64_t key[2];    // siphash key
	uint8_t tail;
	uint8_t head;
	uint8_t buf[TC_BUFSIZE];
} tcsec_ctx;


#endif /* __TCCONFIG_H__ */
