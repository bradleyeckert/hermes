#ifndef __BCI_H__
#define __BCI_H__

#include <stdint.h>
#include "config.h"

void BCIhandler(vm_ctx ctx, const uint8_t *src, uint8_t *ret, uint16_t maxret);
void BCIinitial(vm_ctx ctx);

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
};

#endif /* __BCI_H__ */
