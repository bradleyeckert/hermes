#ifndef __HERMES_HW_H__
#define __HERMES_HW_H__

#include <stdint.h>

/** Generate a random bytes
 * @return 0 to 255 random number, 256 if error
 */
int getc_TRNG(void);

/** Write a new set of keys
 * @param  48-byte key set
 * @return Address of new set of keys, NULL if could not update
 */
uint8_t * UpdateHermesKeySet(uint8_t* keyset);

/** Return set of keys
 * @return Address of 48-byte set of keys, NULL if missing
 */
uint8_t * HermesKeySet(void);

#endif /* __HERMES_HW_H__ */
