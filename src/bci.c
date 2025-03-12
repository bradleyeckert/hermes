#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "bci.h"

/*
BCIhandler takes input from a buffer and outputs to a buffer.
Input and output are u16-counted strings.
hermesAvail indicates how long the strings may be.

There may be multiple commands in the input.
*/
void BCIhandler(vm_ctx ctx, const uint8_t *src, uint8_t *ret, uint16_t maxret) {
    uint16_t length;
    memcpy(&length, src, 2);            // little-endian msg length
    printf("\nPlaintext {");
    for (int i = 0; i < length; i++) {
        putc(src[i + sizeof(uint16_t)], stdout);
    }
    printf("} ");
    /*
    if (ret) {                          // a return message can be sent
        ret[0] = 5;
        ret[1] = 0;
        memcpy(&ret[2], "Hello", 5);
    }
    */
}

void BCIinitial(vm_ctx ctx) {
}


int main() {
    int tests = 1;      // enable these tests...
    return 0;
}
