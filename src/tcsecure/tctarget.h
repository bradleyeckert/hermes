#ifndef __TCTARGET_H__
#define __TCTARGET_H__

#include <stdint.h>
#include "tcconfig.h"

tcsec_ctx * tc_target_tx(int port);
tcsec_ctx * tc_target_rx(int port);

/** Target side generates a challenge to send to the host.
 * @param target_port Port this challenge is for
 * @return 0 if okay, else error
 * Output is in tc_target_tx(port).buf
 */
int tcChallengeHost(int target_port);


/** The target decrypts the host's challenge
 * @param trx Target receive context
 * @param in The 40-byte received from the target
 */
int tcValidateHost(int target_port);


#endif /* __TCTARGET_H__ */

