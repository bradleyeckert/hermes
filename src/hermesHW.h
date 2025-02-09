#ifndef __HERMES_HW_H__
#define __HERMES_HW_H__

#include <stdint.h>

/** Generate a random bytes
 * @return 0 to 255 random number, 256 if error
 */
int getc_TRNG(void);


#endif /* __HERMES_HW_H__ */
