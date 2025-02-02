// Test the nonce exchanges each way

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../src/tcsecure/tchost.h"
#include "../src/tcsecure/tctarget.h"

// Null-modem cable you can insert errors into
void moveSrcToDest(tcsec_ctx *src, tcsec_ctx *dest, int error) {
    memcpy(dest->buf, src->buf, src->head);
    dest->head = src->head;
    dest->tail = 0;
    int size = (dest->head) - 3;
    if (error) dest->buf[3 + error % size] ^= 1;    // inject error
}

int TestNonceExchange(int error) {
    int error1 = 0;
    int error2 = 0;
    if ((error & 0x80) == 0) error1 = error;
    if ((error & 0x80) != 0) error2 = error;
    if (!error1 && error) error1++;
    if (!error2 && error) error2++;
    int r = tcNonceToHost(0, IV_LENGTH);
	if (r) return r;
	moveSrcToDest(tc_target_tx(0), tc_host_rx(0), error1);
	tc_host_rx(0)->tail = 1;        // skip the message tag
	r = tcNonceFromTarget(0);
	if (r) return r & ~0x10;
	r = tcNonceToTarget(0, IV_LENGTH);
	if (r) return r & ~0x20;
	moveSrcToDest(tc_host_tx(0), tc_target_rx(0), error2);
	tc_target_rx(0)->tail = 1;      // skip the message tag
	r = tcNonceFromHost(0);
	if (r) return r & ~0x30;
    return 0;
}

#define TESTS 100000

int main() { // quickie tests:
	printf("%d bytes of RAM used by target contexts\n", tcTargetInit());
	clock_t time0 = clock();
	printf("Testing %d nonce exchange with no error insertion\n", TESTS);
	for (int i = 0; i < TESTS; i++) {
        int err = TestNonceExchange(0);
        if (err) {
            printf("Error = %d", err);
            return 1;
        }
	}
	printf("Testing %d nonce exchange with error insertion\n", TESTS);
	for (int i = 1; i <= TESTS; i++) {
        int err = TestNonceExchange(i);
        if (!err) {
            printf("Error = %d", err);
            return 1;
        }
	}
	tcTargetInit(); // best to wipe state when finishing
    double cpu_time_used = 1e6 * ((double) (clock() - time0)) / CLOCKS_PER_SEC / TESTS;
	printf("PASSED!\n%f microseconds per nonce exchange", cpu_time_used);
	return 0;
}
