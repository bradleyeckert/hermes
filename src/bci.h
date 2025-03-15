#ifndef __BCI_H__
#define __BCI_H__

#include <stdint.h>


#define BCI_INPUT_OVERFLOW      1
#define BCI_ACK               254
#define BCI_NACK              253
#define BCI_INPUT_UNDERFLOW   252

#define BCI_BYTESperCELL        4
#define BCI_BYTESperINST        2
#define BCI_BYTESperREGISTER    4



struct Status_t {
    uint8_t base;           // Numeric base
    uint8_t state;          // 0 if interpreting, 1 if Compiling
};

typedef void (*BCITXinitFn)(void);
typedef void (*BCITXputcFn)(uint8_t c);
typedef void (*BCITXfinalFn)(void);

typedef struct
{   char* name;             // node name (for debugging)
    uint32_t pc;            // program counter
    uint16_t ir;            // instruction register
    uint32_t r, a, n, t, x, y;
    BCITXinitFn InitFn;     // output initialization function
    BCITXputcFn putcFn;     // output putc function
    BCITXfinalFn FinalFn;   // output finalization function
} vm_ctx;

void BCIhandler(vm_ctx *ctx, const uint8_t *src, uint16_t length);
void BCIinitial(vm_ctx *ctx);

#endif /* __BCI_H__ */
