#ifndef __TCHOST_H__
#define __TCHOST_H__

#include <stdint.h>
#include "tcconfig.h"

tcsec_ctx * tc_host_tx(int port);
tcsec_ctx * tc_host_rx(int port);


/** Host side decrypts the tcChallengeHost challenge, generates its own random
 * number (RX nonce), encrypts it with the shared key and H>T nonce IV, and
 * sends it back to the target.
 * @param hrx Host receive context
 * @param htx Host transmit context
 * @param in The 24-byte challenge received from the host
 * @param out The 40-byte challenge to send to the target
 * @return 0 if okay, else error
 */
int tcChallengeTarget(int host_port);


#endif /* __TCHOST_H__ */

