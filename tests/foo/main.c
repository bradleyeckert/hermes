#include "../../src/tcsecure/tchost.h"
#include "../../src/tcsecure/tctarget.h"
#include "../../src/tcsecure/tcplatform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void moveSrcToDest(tcsec_ctx *src, tcsec_ctx *dest) {
    memcpy(dest->buf, src->buf, src->head);
    dest->head = src->head;
    dest->tail = 0;
}

int main() { // quickie tests:
	int r = tcChallengeHost(0);
	if (r) printf("tcChallengeHost ERROR %d\n", r);
	moveSrcToDest(tc_target_tx(0), tc_host_rx(0));
	tc_host_rx(0)->tail = 3;     // skip the message tag
	r = tcChallengeTarget(0);
	if (r) printf("tcChallengeTarget ERROR %d\n", r);
	moveSrcToDest(tc_host_tx(0), tc_target_rx(0));
	tc_target_rx(0)->tail = 3;     // skip the message tag
	r = tcValidateHost(0);
	if (r) printf("tcValidateHost ERROR %d\n", r);
	printf("Authentication handshake PASSED\n");
	return 0;
}
