/* Tether crypto functions for Target
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../libs/xchacha20/src/xchacha20.h"
#include "tcconfig.h"
#include "tctarget.h"
#include "tctargetHW.h"

static tcsec_ctx tx[TARGET_PORTS];
static tcsec_ctx rx[TARGET_PORTS];

/** Point to the TX crypto structure
 * @param port Port to use
 * @return Pointer to structure selected by port
 */
tcsec_ctx * tc_target_tx(int port) {
    if (port >= HOST_PORTS) return &tx[HOST_PORTS-1];
    return &tx[port];
}

/** Point to the RX crypto structure
 * @param port Port to use
 * @return Pointer to structure selected by port
 */
tcsec_ctx * tc_target_rx(int port) {
    if (port >= HOST_PORTS) return &rx[HOST_PORTS-1];
    return &rx[port];
}

/** Target generates a wrapped nonce for the host
 * @param target_port Port this nonce is for
 * @return 0 if okay, else error
 * Output is to tx[port].buf
 */
int tcNonceToHost(int target_port, int Ysize) {
    tcsec_ctx *s = &tx[target_port];
    tcClearBuffer(s);
    tcPutch(s, HOST_TAG_NEW_TH);
    return tcSendIV(s, target_port, tctKeyN, tctRNGfunction, Ysize);
}

/** Target receives the host's nonce
 * @param target_port Port this nonce is for
 * @return 0 if okay, else error
 */
int tcNonceFromHost(int target_port) {
    return tcReceiveIV(&rx[target_port], target_port, tctKeyN);
}

/** Wipe crypto state for all ports
 * @return statically allocated bytes of RAM
 */
int tcTargetInit(void) {
    memset(tx, 0, sizeof(tx));
    memset(rx, 0, sizeof(rx));
    return sizeof(tx) + sizeof(rx);
}

