#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include "../bci.h"

/*
Test parser format:
String = in1, in2, in3, ..., inN ==> out1, out2, out3, ...
Parameters are in the C hex format 0x... where the number of bytes is determined
by the number of digits. A parameter begins with "0x" and ends with anything
that is not a digit.
*/

uint8_t command[3][260];                // command, expected, actual
vm_ctx me;
int testID;
int errors;

uint8_t mismatch(void) {                // compare expected to actual
    uint8_t len1 = command[1][0];
    uint8_t len2 = command[2][0];
    if (len1 != len2) return 1;
    for (int i = 1; i <= len1; i++) {
        if (command[1][i] != command[2][i]) return 1;
    }
    return 0;
}

void appendByte(int i, uint8_t c) {
    uint8_t len = command[i][0];
    command[i][len + 1] = c;
    command[i][0] = len + 1;
}

// Capture the BCI output stream in command[2]

void mySendInit(void)     {command[2][0] = 0;}
void mySendChar(uint8_t c) {appendByte(2, c);}

void mySendFinal(void) {
    if (mismatch()) {
        errors++;
        printf("\nTest %d = ", testID);
        for (int i = 1; i <= command[0][0]; i++) printf("%02x", command[0][i]);
        printf("\n  Actual = ");
        for (int i = 1; i <= command[2][0]; i++) printf("%02x", command[2][i]);
        printf("\nExpected = ");
        for (int i = 1; i <= command[1][0]; i++) printf("%02x", command[1][i]);
    }
}

void myInitial(vm_ctx *ctx) {
    ctx->InitFn = mySendInit;           // output initialization function
    ctx->putcFn = mySendChar;           // output putc function
    ctx->FinalFn = mySendFinal;         // output finalization function
}

void t(int tid, const char *s) {        // test function
    uint8_t state = 0;
    uint8_t digits = 0;
    uint8_t expecting = 0;
    uint8_t done = 0;
    uint32_t x = 0;
    testID = tid;
    memset(command, 0, sizeof(command));
    do {
        uint8_t c = *s++;               // parse the hex numbers
        done = (c == 0);
        if (done) state = 3;
        switch (state) {
            case 0:
                x = 0;
                switch (c) {
                    case '0': state = 1;  break;    // 0x1234
                    case 'h': state = 2;  break;    // h1234
                    case '=': state = 4;  break;    // ==>
                }
                break;
            case 1: if ('x' == c) state++;
                break;
            case 2: c = toupper(c);
                if (((c >= '0') && (c <= '9')) ||
                    ((c >= 'A') && (c <= 'F'))) {
                    c -= '0';
                    if (c > 9) c -= 7;
                    x = (x << 4) + c;
                    digits++;
                    break;
                }
            case 3:
                digits = (digits + 1) / 2;
                while (digits--) appendByte(expecting, x >> (8*digits));
                state = 0;
                break;
            case 4: if ('>' != c) break;
                expecting = 1;
            default: state = 0;
        }
    } while (!done);
    if (expecting) {                    // call the BCI (in bci.c)
        BCIhandler(&me, &command[0][1], command[0][0]);
    }
}

// Tests illustrate the use of the BCI functions

int main() {
    myInitial(&me);
    BCIinitial(&me);
    t( 0, "0x00 ==> 0x0100FE");                                             // boilerplate
    t( 1, "0x01, 0x02, 0x00000123 ==> 0x02, 0x00000000, 0x00000000, 0xFE"); // read memory
    t( 2, "0x02, 0x02, 0x00000123, 0x01234567, 0x01765432 ==> 0xFE");       // write memory
    // run length --^  ^--address  ^--1st      ^--2nd         ^--ack
    t( 3, "0x01, 0x02, 0x00000123 ==> 0x02, 0x01234567, 0x01765432, 0xFE"); // read memory
    // run length --^  ^--address   len--^  ^--1st      ^--2nd      ^--ack
    t( 4, "0x03, 0x0000000A, 0x02, 0x01122334, 0x01776655, 0x00000000 ==> 0x02, 0x01122334, 0x01776655, 0x0000000A, 0xFE");
    // base -----^   depth------^  ^--2nd      ^--top      ^--xt      depth--^  ^--2nd      ^--top      ^--base
    t( 5, "0x04, 0x00000123, 0x00000002 ==> 0x2a922a9d, 0xFE");             // read CRC
    t( 6, "0x04, 0x00000120, 0x00000002 ==> 0x6522df69, 0xFE");
    return 0;
}
