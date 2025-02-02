/* Tether crypto functions for Host
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "inttypes.h"
#include "../libs/xchacha20/src/xchacha20.h"
#include "tchost.h"
#include "tchostHW.h"
#include "tcconfig.h"

static tcsec_ctx tx[HOST_PORTS];
static tcsec_ctx rx[HOST_PORTS];

tcsec_ctx * tc_host_tx(int port) {
    if (port >= HOST_PORTS) return &tx[HOST_PORTS-1];
    return &tx[port];
}

tcsec_ctx * tc_host_rx(int port) {
    if (port >= HOST_PORTS) return &rx[HOST_PORTS-1];
    return &rx[port];
}

// In: IV[plain]:IV[cipher]:HMAC
int tcNonceFromTarget(int host_port) {
    return tcReceiveIV(&rx[host_port], host_port, tchKeyN);
}

// Out: ResponseTag:IV[plain]:IV[cipher]:HMAC
int tcNonceToTarget(int host_port, int extra) {
    tcsec_ctx *s = &tx[host_port];
    bufClear(s);
    bufAddChar(s, HOST_TAG_NEW_HT);
    return tcSendIV(s, host_port, tchKeyN, tchRNGfunction, extra);
}

/*
void xchacha_decrypt_bytes(XChaCha_ctx* ctx, const uint8_t* ciphertext,
    uint8_t* plaintext,
    uint32_t msglen);
*/
