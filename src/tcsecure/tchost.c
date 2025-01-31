
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../libs/xchacha20/src/xchacha20.h"
#include "../libs/poly1305-donna/poly1305-donna.h"
#include "tcconfig.h"

tcsec_ctx tc_host_tx[HOST_PORTS];
tcsec_ctx tc_host_rx[HOST_PORTS];

/* To Do:
Check the hash from tail to head-9, compare to head-8 to head-1 hash
Pull in the IV as plaintext, decrypt the message, save as the RX IV.
Set up the TX the same way as tcChallengeHost

*/

int tcChallengeTarget(int host_port, int target_port) {
    return 0;
}

