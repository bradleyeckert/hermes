# hermes
AEAD-secured ports (UARTs, etc.)

Status: Encrypted message passing works.

Needs:
- Robustification against bit errors.
- Key rotation functions.
- Error insertion to test recovery.

At this point, all packets get an ACK response. Availabiity must be checked before sending to ensure an ACK came back. If an HMAC failure is detected, a NACK should be returned and the FSM should re-send.

Packet counters hCtr?x are implemented but not used yet. They should be included in the hash function so that a different key is used for each message hash.