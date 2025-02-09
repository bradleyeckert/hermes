# Hermes - Cryptographic protection for serial ports

Cybersecurity for embedded systems has been getting a lot of scrutiny due to such systems being exploited in spectacular Bond-villain-level cyber attacks. Encrypted UARTs are now a thing, possibly turning into a mandated thing down the road. Already in some markets, encryption is mandated for data crossing enclosure boundaries. `hermes` encrypts UART traffic using a small memory footprint. While it uses xchacha20-siphash for AEAD by default, other encryption and HMAC schemes are easily added (AES-SHA, SH4-SH3, etc).

`hermes` achieves its small footprint by not trying to copy the SSL/TLS usage model that was made for the Internet. The usage model is closer to that of NFT cards like Mifare DESFire: many cards, few readers. A Mifare card reader is expected to have network connectivity so it can get the required key from a server if it doesn't already have it. Likewise, one of the devices using Hermes is assumed to have an Internet connection for getting the required keys from a remote server or internal key vault. In other words, `hermes` uses a closed ecosystem.

Manufacturers already operate a closed ecosystem for their products. `hermes` is meant more for manufacturers who need a UART to securely access their systems remotely or in the field. A secure channel facilitates update pushing, which is another emerging cybersecurity requirement. There is no need for highly complex encryption schemes that have more ways to go wrong.

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

A session can encrypt up to 2^32 messages before it is forced to re-pair. 

## Key management

The only plaintext sent over the port, besides headers, is boilerplate information that should be used to supply a UUID. A key vault would use the UUID to look up the key. `hermesBoiler(&Alice)` triggers a boilerplate response from Bob. The response is sent to a handler function that will use it to look up the keys.

A host PC connected to a target MCU through a UART would keep track of keys for different targets. Depending on security requirements, the host PC can keep those keys on the cloud or in a file in encrypted format.

`hermes` should support key rotation. Given the key address, a function in `hermesHW.c` would write the new key. This specialized function is platform-specific since it writes to Flash.
