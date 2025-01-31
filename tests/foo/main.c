#include "../../src/tcsecure/tchost.h"
#include "../../src/tcsecure/tctarget.h"
#include "../../src/tcsecure/tcplatform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void dump(uint8_t *src, uint8_t len) {
    if (len) {
        for (uint8_t i = 0; i < len; i++) {
            if ((i % 24) == 0) printf("\n");
            printf("%02X ", src[i]);
        }
    }
}

void showCTX (tcsec_ctx *s) {   // dump context info
	printf("tcsec_ctx %p contents: \nhead=%d, tail=%d", s, s->head, s->tail);
	uint8_t size = s->head - s->tail;
	if (s->tail) printf(", (size=%d)", size);
	if (size) dump(&s->buf[s->tail], size);
    printf("\n");
}

void HostToTarget(tcsec_ctx *src, tcsec_ctx *dest) {
    memcpy(dest->buf, src->buf, src->head);
    dest->head = src->head;
    dest->tail = 0;
}

void TargetToHost(tcsec_ctx *src, tcsec_ctx *dest) {
    memcpy(dest->buf, src->buf, src->head);
    dest->head = src->head;
    dest->tail = 0;
}

int main() { // quickie tests:
	tcChallengeHost(0);
	TargetToHost(&tc_target_tx[0], &tc_host_rx[0]);
	tc_host_rx[0].tail = 3;     // skip the message tag
	showCTX(&tc_target_tx[0]);
	showCTX(&tc_host_rx[0]);
	tcChallengeTarget(0, 0);
	return 0;
}
