# hermes
AEAD-secured ports (UARTs, etc.)

Status: Encrypted message passing works.

Needs robustification against bit errors.

The idea of bumping the HMAC key after each block has to be scrapped. Pairing needs a fixed HMAC key.
Occasional key rotation would address that.

Also needs key rotation functions.

