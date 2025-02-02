#ifndef __TCHOST_H__
#define __TCHOST_H__

#include <stdint.h>
#include "tcconfig.h"

tcsec_ctx * tc_host_tx(int port);
tcsec_ctx * tc_host_rx(int port);
int tcNonceToTarget(int host_port, int extra);
int tcNonceFromTarget(int host_port);


#endif /* __TCHOST_H__ */

