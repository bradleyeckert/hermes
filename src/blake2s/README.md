# Size-optimized version of Blake2s

Adapted from the [reference](https://github.com/BLAKE2/BLAKE2) implementation.

The API uses stream orientation so that RAM-constrained systems can handle long messages.

## API

```C
/** HMAC initialization
 * @param ctx   HMAC context
 * @param key   Key, 16 bytes
 * @param hsize Expected hash length in bytes
 * @param ctr   64-bit counter to prevent replay attacks, may be 0
 * @return      Actual hash length in bytes (0 if bogus)
 */
int b2s_hmac_init(blake2s_state *S, const uint8_t *key, int hsize, uint64_t ctr);

/** HMAC append byte
 * @param ctx   HMAC context
 * @param c     Byte to add to HMAC
 */
void b2s_hmac_putc(blake2s_state *S, uint8_t c);

/** HMAC append byte
 * @param ctx   HMAC context
 * @param out   Output hash
 * @return      Hash length in bytes
 */
int b2s_hmac_final(blake2s_state *S, uint8_t *out);
```
