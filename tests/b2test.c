/* Blake2s tests
*/
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "./src/blake2s.h"
#include "blake2-kat.h"

static int blake2s( void *out, int outlen, const void *in, int inlen, const void *key )
{
  blake2s_state S[1];

  /* Verify parameters */
  if ( NULL == in && inlen > 0 ) return -1;

  if ( NULL == out ) return -1;

  if( !outlen || outlen > BLAKE2S_OUTBYTES ) return -1;

  if( b2s_hmac_init( S, key, outlen, 0 ) < 0 ) return -1;

  b2s_hmac_puts( S, ( const uint8_t * )in, inlen );
  b2s_hmac_final( S, out );
  return 0;
}

int main( void )
{
  uint8_t key[BLAKE2S_KEYBYTES];
  uint8_t buf[BLAKE2_KAT_LENGTH];
  uint8_t hash[BLAKE2S_OUTBYTES];
  int i, step;

  for( i = 0; i < BLAKE2S_KEYBYTES; ++i ) key[i] = ( uint8_t )i;

  for( i = 0; i < BLAKE2_KAT_LENGTH; ++i ) buf[i] = ( uint8_t )i;

  /* Test simple API */
  for( i = 0; i < BLAKE2_KAT_LENGTH; ++i )
  {
    blake2s( hash, BLAKE2S_OUTBYTES, buf, i, key );

    if( 0 != memcmp( hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES ) )
    {
      goto fail;
    }
  }

  /* Test streaming API */
  for(step = 1; step < BLAKE2S_BLOCKBYTES; ++step) {
    for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
      uint8_t hash[BLAKE2S_OUTBYTES];
      blake2s_state S;
      uint8_t * p = buf;
      int mlen = i;
      int err = 0;

      if( (err = b2s_hmac_init(&S, key, BLAKE2S_OUTBYTES, 0)) < 0 ) {
        goto fail;
      }

      while (mlen >= step) {
        if ( (err = b2s_hmac_puts(&S, p, step)) < 0 ) {
          goto fail;
        }
        mlen -= step;
        p += step;
      }
      if ( (err = b2s_hmac_puts(&S, p, mlen)) < 0) {
        goto fail;
      }
      if ( (err = b2s_hmac_final(&S, hash)) < 0) {
        goto fail;
      }

      if (0 != memcmp(hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES)) {
        goto fail;
      }
    }
  }

  puts( "ok" );
  return 0;
fail:
  puts("error");
  return -1;
}
