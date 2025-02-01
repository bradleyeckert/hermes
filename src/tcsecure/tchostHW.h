#ifndef __TCHOSTHW_H__
#define __TCHOSTHW_H__

#include <stdint.h>

/** Point to a 128-bit key in the key set. Keys may concatenate to 256-bit.
 * @param n Key selector
 * @return Pointer to the (read-only) key, NULL if the key is bad.
 */
const uint8_t * tchKeyN(unsigned int n);


/** Generate a run of random bytes
 * @param out dest Destination
 * @param in size Length in bytes, hard-limited to 32
 * @return 0 if the random number is random, other if error
 */
int tchRNGfunction(uint8_t *dest, unsigned int size);


#endif /* __TCHOSTHW_H__ */
