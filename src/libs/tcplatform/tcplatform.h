#ifndef __TCPLATFORM_H__
#define __TCPLATFORM_H__

#include <stddef.h>

/** Generate a run of random bytes
 * @param out dest Destination
 * @param in size Length in bytes, hard-limited to 32
 * @return 0 if the random number is random, other if error
 */
int tcRNGfunction(uint8_t *dest, unsigned int size);

/** Fetch a 32-byte private key based on its index
 * @param out dest Destination
 * @param in kid
 * @return Returns 0 for success, 1 for invalid index, 2 for blank key
 */
int tcFetchKey(uint8_t *dest, unsigned int kid);

/** Reset the MCU
 */
void tcHardReset(void);

#endif /* __TCPLATFORM_H__ */
