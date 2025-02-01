#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../src/tcsecure/tchost.h"
#include "../../src/tcsecure/tctarget.h"

void moveSrcToDest(tcsec_ctx *src, tcsec_ctx *dest, int error) {
    memcpy(dest->buf, src->buf, src->head);
    dest->head = src->head;
    dest->tail = 0;
    if (error) dest->buf[error] ^= 1;    // inject error
}

int TestNonceExchange(int error1, int error2) {
    int r = tcNonceToHost(0);
	if (r) printf("tcNonceToHost ERROR %d\n", r);
	moveSrcToDest(tc_target_tx(0), tc_host_rx(0), error1);
	tc_host_rx(0)->tail = 3;                        // skip the message tag
	r = tcNonceFromTarget(0);
	if (r) printf("tcNonceFromTarget ERROR %d\n", r);
	r = tcNonceToTarget(0);
	if (r) printf("tcNonceToTarget ERROR %d\n", r);
	moveSrcToDest(tc_host_tx(0), tc_target_rx(0), error2);
	tc_target_rx(0)->tail = 3;     // skip the message tag
	r = tcNonceFromHost(0);
	if (r) printf("tcNonceFromHost ERROR %d\n", r);
    return 0;
}

int main() { // quickie tests:
	printf("Testing nonce exchange\n");
	tcTargetInit();
	TestNonceExchange(0, 0);
	return 0;
}
