/* Tether crypto functions for Target
*/

#include "tctarget.h"
#include "tcplatform.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../libs/xchacha20/src/xchacha20.h"
#include "tcconfig.h"

// The tx and rx buffers within each tcsec_ctx are accessed outside this module
// so they are global variables

static tcsec_ctx tx[TARGET_PORTS];
static tcsec_ctx rx[TARGET_PORTS];

tcsec_ctx * tc_target_tx(int port) {
    if (port >= HOST_PORTS) return &tx[HOST_PORTS-1];
    return &tx[port];
}

tcsec_ctx * tc_target_rx(int port) {
    if (port >= HOST_PORTS) return &rx[HOST_PORTS-1];
    return &rx[port];
}

/** Target side generates a challenge to send to the host.
 * @param target_port Port this challenge is for
 * @return 0 if okay, else error
 * Output is to tx(port).buf
 */
int tcChallengeHost(int target_port) {
    tcsec_ctx *s = &tx[target_port];
    bufClear(s);
    bufAppend(s, ChallengeTag, sizeof(ChallengeTag));
    return tcSendIV(s, target_port);
}

/** The target decrypts the host's challenge
 * @param target_port Port this response is for
 * @return 0 if okay, else error
 */
int tcValidateHost(int target_port) {
    return tcReceiveIV(&rx[target_port], target_port);
}

