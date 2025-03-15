#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "bci.h"
#include "bciHW.h"

/*
BCIhandler takes input from a buffer and outputs to encrypted UART using these primitives:
void hermesSendInit(port_ctx *ctx, uint8_t tag);
void hermesSendChar(port_ctx *ctx, uint8_t c);
void hermesSendFinal(port_ctx *ctx);

Since the VM has a context structure, these are late-bound in the context to allow stand-alone testing.

There may be multiple commands in the input.
*/

void BCIhandler(vm_ctx *ctx, const uint8_t *src, uint16_t length) {
    printf("\nPlaintext {");
    for (int i = 0; i < length; i++) {
        putc(src[i + sizeof(uint16_t)], stdout);
    }
    printf("} ");
}

void BCIinitial(vm_ctx *ctx) {
    ctx->pc = 0;
}

// --------------------------------------------------------------
// some test code to move out later

void mySendInit(void) {
    printf("Init");
}

void mySendChar(uint8_t c) {
    printf("Putc");
}

void mySendFinal(void) {
    printf("Final");
}

void myInitial(vm_ctx *ctx) {
    ctx->InitFn = mySendInit;           // output initialization function
    ctx->putcFn = mySendChar;           // output putc function
    ctx->FinalFn = mySendFinal;         // output finalization function
}


vm_ctx me;

// Tests create a command string by using various functions to build the string.
// The return

int main() {
//    int tests = 1;      // enable these tests...
    myInitial(&me);
    BCIinitial(&me);
    return 0;
}
