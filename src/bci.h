#ifndef __BCI_H__
#define __BCI_H__

#include <stdint.h>

#define BCI_IOR_INVALID_ADDRESS   -9

#define BCI_INPUT_OVERFLOW         1
#define BCI_ACK                  254
#define BCI_NACK                 253
#define BCI_INPUT_UNDERFLOW      252

#define VM_CELLBITS               20
#define VM_SIGN     (1 << (VM_CELLBITS - 1))
#define VM_MASK     ((1 << VM_CELLBITS) - 1)

#define BCIFN_BOILER   0
#define BCIFN_READ     1
#define BCIFN_WRITE    2
#define BCIFN_EXECUTE  3
#define BCIFN_CRC      4
#define BCIFN_READREG  5
#define BCIFN_WRITEREG 6

#define DATASIZE                1024
#define CODESIZE                2048
#define STACKSIZE                 16
#define BCI_EMPTY_STACK   0xAAAAAAAA
#define BCI_STATUS_SINGLE          0
#define BCI_STATUS_STOPPED         1
#define BCI_STATUS_RUNNING         2
#define BCI_ACCESS_PERIPHERALS     1
#define BCI_ACCESS_CODESPACE       2
#define BCI_DEBUG_ACCESS           3
#define BCI_CYCLE_LIMIT     10000000

typedef void (*BCITXinitFn)(void);
typedef void (*BCITXputcFn)(uint8_t c);
typedef void (*BCITXfinalFn)(void);

typedef struct
{   char* name;                 // node name (for debugging)
    uint32_t pc;                // program counter
    uint32_t ir;                // instruction register
    uint32_t r, n, t, a, b, x, y;
    uint32_t DataStack[STACKSIZE];
    uint32_t ReturnStack[STACKSIZE];
    uint32_t DataMem[DATASIZE];
    uint32_t memq;              // DataMem output bus (synchronous-read)
    uint32_t CodeMem[CODESIZE];
    uint16_t upperBus;          // upper 16 bits of 32-bit I/O data
    int16_t ior;
    uint8_t sp, rp, status, cy;
    BCITXinitFn InitFn;         // output initialization function
    BCITXputcFn putcFn;         // output putc function
    BCITXfinalFn FinalFn;       // output finalization function
} vm_ctx;

/** Step the VM
 * @param ctx VM identifier
 * @return 0 if okay, otherwise VM_ERROR_?
 */
int BCIstepVM(vm_ctx *ctx, uint32_t inst);

void BCIhandler(vm_ctx *ctx, const uint8_t *src, uint16_t length);
void BCIinitial(vm_ctx *ctx);

#endif /* __BCI_H__ */
