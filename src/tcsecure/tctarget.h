#ifndef __TCTARGET_H__
#define __TCTARGET_H__

#include <stdint.h>
#include "tcconfig.h"

tcsec_ctx * tc_target_tx(int port);
tcsec_ctx * tc_target_rx(int port);
int tcNonceToHost(int target_port, int extra);
int tcNonceFromHost(int target_port);
int tcTargetInit(void);
int tcTargetWipe(void);


#endif /* __TCTARGET_H__ */

