/* AEAD-secured ports (UARTs, etc.)
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "xchacha/src/xchacha.h"
#include "siphash/src/siphash.h"
#include "hermes.h"

void dump(uint8_t *src, uint8_t len) {
    if (len) {
        for (uint8_t i = 0; i < len; i++) {
            if ((i % 30) == 0) printf("\n");
            printf("%02X ", src[i]);
        }
    }
}

static int default_cyphr(uint8_t c) {
    printf("%02X ", c); // output hex byte to stdout
    return 0;
}

static int default_plain(const uint8_t *src, uint32_t length) {
    while (length--) putc(*src++, stdout);
    return 0;
}

int hermesInit(port_ctx *ctx, hermes_plainFn plain, hermes_cyphrFn cyphr) {
    memset(ctx, 0, sizeof(port_ctx));
    ctx->tmFn = plain;
    ctx->tcFn = cyphr;
    return 0;
}

int hermesPutc(port_ctx *ctx, int c){
    ctx->tcFn(c);
    return 0;
}

/* typedef struct
{   xChaCha_ctx rcCtx;      // receiver encryption context
	siphash_ctx rhCtx;      // receiver HMAC context
    xChaCha_ctx tcCtx;      // transmitter encryption context
	siphash_ctx thCtx;	    // transmitter HMAC context
    hermes_plainFn tmFn;    // plaintext handler
    hermes_cyphrFn tcFn;    // ciphertext transmit function
    int state;
} port_ctx;
 */

int main() {
    port_ctx portA;
    hermesInit(&portA, default_plain, default_cyphr);
    hermesPutc(&portA, 0x55);
    return 0;
}
