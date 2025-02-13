# Hermes - Cryptographic protection for serial ports

Cybersecurity for embedded systems has been getting a lot of scrutiny due to such systems being exploited in spectacular Bond-villain-level cyber attacks. Encrypted UARTs are now a thing, possibly turning into a mandated thing down the road. Already in some markets, encryption is mandated for data crossing enclosure boundaries. `hermes` encrypts UART traffic using a small memory footprint. While it uses xchacha20-siphash for AEAD by default, other encryption and HMAC schemes are easily added (AES-SHA, SH4-SH3, etc).

`hermes` achieves its small footprint by not trying to copy the SSL/TLS usage model that was made for the Internet. The usage model is closer to that of NFT cards like Mifare DESFire: many cards, few readers. A Mifare card reader is expected to have network connectivity so it can get the required key from a server if it doesn't already have it. Likewise, one of the devices using Hermes is assumed to have an Internet connection for getting the required keys from a remote server or internal key vault. In other words, `hermes` uses a closed ecosystem.

Manufacturers already operate a closed ecosystem for their products. `hermes` is meant more for manufacturers who need a UART to securely access their systems remotely or in the field. A secure channel facilitates update pushing, which is another emerging cybersecurity requirement. There is no need for highly complex encryption schemes that have more ways to go wrong.

In particular, the PKE used in SSL/TLS requires a X.509 certificate. An embedded system without Internet access would need a root certificate. A private root certificate can be considered similar to a master key because it acts as the foundational trust element within a private certificate authority (CA), essentially "signing" and validating all other certificates issued within that system, making it the key component for establishing trust within that closed network, just like a master key unlocks multiple doors in a building; its security is crucial as compromising it could compromise the entire trust structure within that private network. The discovery of the root certificate in one device would compromise all devices.

Without PKE, there is no spoofing. Key management relies on key escrow instead. Anti-spoofing relies on he security of the escrow.

## AEAD

[Wikipedia](https://en.wikipedia.org/wiki/Authenticated_encryption):
> Authenticated encryption with associated data (AEAD) is a variant of AE that allows the message to include "associated data" (AD, additional non-confidential information, a.k.a. "additional authenticated data", AAD). A recipient can check the integrity of both the associated data and the confidential information in a message.

`hermes` uses a symmetric algorithm for encryption and a keyed HMAC (hash) algorithm for message integrity.

The default protocol used by `hermes` is XChaCha20-SipHash. Xchacha20 is a long-IV version of [ChaCha20](https://en.wikipedia.org/wiki/Salsa20). For forward compatibility, a 128-bit IV is used instead of XChaCha20's 192-bit IV. [SipHash](https://en.wikipedia.org/wiki/SipHash) is a keyed HMAC. A version with 16-byte output authenticates the entire message, including the plaintext header, so that the header cannot be altered.

Cryptographic functions are called through function pointers held in the port's `struct`. Other AEAD algorithms may be plugged in by using the default setup as a template. To keep it simple, the following lengths are fixed:

- 256-bit Encryption key
- 128-bit Encryption IV
- 128-bit HMAC key
- 128-bit HMAC hash

## Language dependencies

* C99
* Little-endian byte order
* Hardware-specific functions in `*HW.c` file(s)

Most of the byte-order dependency comes from using `memcpy` to move data and from byte arrays. It could be replaced with a `MEMCPY` macro that substitutes a byte-reversing version of `memcpy` for big-endian targets.

## Hardware requirements

* True random number generator
* 32-bit CPU such as ARM or RISC-V
* On-chip Flash memory for code and keys
* UART

## Pairing

Key management is outside the scope of `hermes`. Pairing assumes that both ends of the communication channel have the same private keys. A pairing handshake between Alice and Bob proceeds as follows:

- Alice sends a random 128-bit IV to Bob
- Bob sends a random 128-bit IV to Alice

The IV is sent encrypted using a one-time-use random IV, which is in plaintext, so that it is kept secret. Each communication session starts with a different IV so that the keystream never repeats.

After the pairing handshake is finished, `hermesAvail(&Alice)` returns 0 if synchronization has been lost due to data corruption. The connection will have to be re-paired with `hermesPair(&Alice)`.

## Key management

The only plaintext sent over the port, besides headers, is boilerplate information that should be used to supply a UUID. A key vault would use the UUID to look up the key. `hermesBoiler(&Alice)` triggers a boilerplate response from Bob. The response is sent to a handler function that will use it to look up the keys.

A host PC connected to a target MCU through a UART would keep track of keys for different targets. Depending on security requirements, the host PC can keep those keys on the cloud or in a file in encrypted format.

`hermes` should support key rotation. Given the key address, a function in `hermesHW.c` would write the new key. This specialized function is platform-specific since it writes to Flash.

## Message format

The message format consists of a header, a payload, and a digital signature (HMAC). A header always contains the message length and protocol ID. The first byte of the header is a tag byte indicating what kind of message it is. The tag ranges from `18` to `1F`.

The simplest message is a Boilerplate Query, `18-04-00-FB-12`, which means:

- 18 Tag: Request boilerplate
- 0006 Length: 16-bit big-endian, spans all tokens up to `12`.
- FFF9 ~Length: Ones complement of Length.
- 12 End: End-of-message marker

The length field is a byte count, not a token count. Bytes have a range of 0 to 255. Tokens are 8-bit values that get sent over the wire. Bytes are usually one token, but sometimes two. The data stream does not contain any `11`, `12`, or `13` (hex) tokens. Any byte between `10` and `13` is encoded as a 2-byte sequence of `10` followed by a token between `00` and `03`. `11`, `12`, and `13` are reserved for PHY usage. Soft flow control uses `11` for XON and `13` for XOFF, so `hermes` does not use them. All messages end in a `12` end-of-message marker.

`12` tokens should be sent occasionally between packets to clear up synchronization issues caused by communication glitches. The receiver can end up in a "wait for end" state, which an extra `12` will fix. A `12` when the FSM is waiting for a message will be ignored.

The FSM can be reset at any time with a `10-04` sequence, which re-pairs the connection.

Headers start with a tag. Depending on the tag, messages have optional fields like payload and hash. There two messages that are not encrypted: Boilerplate Query and Boilerplate Response. All others use AEAD - they are encrypted and authenticated.

The rationale for a 2-byte default length is that a >64KB message is not reasonable, because one bit error would destroy the entire message. If you really want to support longer messages, change `HERMES_LENGTH_LENGTH`.

Messages that overflow the receive buffer are ignored (the receiver waits for `12`). A long message can be sent in a file by, for each 32KB block, writing the boilerplate, IV setup, and message (including HMAC) to a file. The blocks in the file are encrypted and authenticated by whatever produced them. They are tamper-proof. They can only be read by using the boilerplate to look up keys.

### Boilerplate messages

Boilerplate messages are plaintext, so they do not get a hash. The Boilerplate Query is `18-04-00-FB-12`, which triggers a Boilerplate Response. The allowed length of a boilerplate is up to 64 bytes, the minimum receive buffer size. Boilerplate responses longer than 64-byte are truncated, so the receiver will wait for a `12`.

The boilerplate contains a UUID. For example, the CH32V20x and CH32V30x MCUs contain a 96-bit ESIG. To use the ESIG in the boilerplate, `memcpy` would move 12 bytes from address `0x1FFFF7E8` to a RAM buffer used by the boilerplate. Other boilerplate items include the AEAD protocol used (0 means XChaCha20-SipHash), HMAC length (8 or 16 bytes), and Length field length (2, 3, or 4). The default data structure for `hermes` is:

- Length of the boilerplate in bytes, should be less than 65. Default is 18.
- 3-byte "nyb" string (nyb = None of your business)
- 13-byte UUID
- 1-byte AEAD format identifier

The AEAD format identifier packs bitfields as follows:

- b2:b0 = AEAD protocol. 0 = XChaCha20-SipHash.
- b4:b3 = reserved, default is 10.
- b6:b5 = Message length width minus 1. Default is 01, meaning 2-byte length field.
- b7 = HMAC length. 0 = 16-byte, 1 = 8-byte. Default is 0.

### IV setup messages

The messages used for pairing are a specific length, which depends on the IV length. A sample Send IV message looks like this:

```
1A-35-00-CA                                      Header
29-BE-E1-D6-52-49-F1-E9-B3-DB-87-3E-24-0D-06-47  mIV
A5-BD-C1-C1-CF-88-FC-4E-15-2D-05-6F-93-59-02-8B  cIV
02                                               receiver buffer size in 64-byte blocks
98-79-1F-9E-03-D4-F0-E6-0F-39-EE-9D-16-8B-64-08  HMAC
12                                               end-of-message
```

The pairing request, `1A-35-00-CA-...`, triggers the above message. Upon reception of the setup message, the receiver sends a response setup message in the same format but with the tag `1B` instead of `1A`.

## Acknowledge handshake

Each encrypted message elicits an ACK response. The ACK counters of each port stay synchronized when everything is operating normally.

## Error recovery

Errors in the header usually throw the keystreams out of sync. The only recovery is a re-pair sequence, which occurs after the data stops streaming (a `12` is seen).

Errors in the message (or HMAC) cause a HMAC failure, but don't affect keystream sync. In that case, the original message is sent re-encrypted using new keystream segment, which rules out replay attacks.
