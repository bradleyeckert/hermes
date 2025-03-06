#ifndef __BCI_H__
#define __BCI_H__

#include <stdint.h>
#include "config.h"

void HermesBCI(const uint8_t * inbuf, int inlen, uint8_t * outbuf, int * outlen);
void HermesBCIinit(void);

#define BCI_INPUT_OVERFLOW      1
#define BCI_ACK               254
#define BCI_NACK              253
#define BCI_INPUT_UNDERFLOW   252

#define BCI_BYTESperCELL        4
#define BCI_BYTESperINST        2
#define BCI_BYTESperREGISTER    4

struct Status_t {       // Read Write
    uint8_t base;       // yes  yes     Numeric base
    uint8_t state;      // yes  yes     0 if interpreting, 1 if Compiling
    uint8_t crypto;     // yes  yes     0 if app is not using the cryptographic keys
    uint8_t depth;      // yes  yes     Depth of data stack
    uint8_t rdepth;     // yes  yes     Depth of return stack
    uint8_t spare;      // yes  yes
    uint8_t keying;     // yes  no      0 if key rotation is not in progress
    uint8_t unlocked;   // no   no      0 if locked (not authenticated)
    uint8_t cpuid[12];  // no   no      96-bit CPU ID
};

#endif /* __BCI_H__ */
