# Hermes - Cryptographic protection for serial ports

Cybersecurity for embedded systems has been getting a lot of scrutiny due to such systems being exploited in spectacular Bond-villain-level cyber attacks. Encrypted UARTs are now a thing, possibly turning into a mandated thing down the road. Already in some markets, encryption is mandated for data crossing enclosure boundaries. `hermes` encrypts UART traffic using a small memory footprint. While it uses xchacha20-siphash for AEAD by default, other encryption and HMAC schemes are easily added (AES-SHA, SH4-SH3, etc).

`hermes` achieves its small footprint by not trying to copy the SSL/TLS usage model that was made for the Internet. The usage model is closer to that of NFT cards like Mifare DESFire: many cards, few readers. A Mifare card reader is expected to have network connectivity so it can get the required key from a server if it doesn't already have it. Likewise, one of the devices using Hermes is assumed to have an Internet connection for getting the required keys from a remote server or key vault. In other words, `hermes` uses a closed ecosystem.

Manufacturers already operate a closed ecosystem for their products. `hermes` is meant more for manufacturers who need a UART to securely access their systems remotely or in the field. A secure channel facilitates update pushing, which is another emerging cybersecurity requirement. Pre-shared keys avoid PKE.

The PKE used in SSL/TLS requires a X.509 certificate. An embedded system without Internet access would need a root certificate. A private root certificate can be considered similar to a master key because it acts as the foundational trust element within a private certificate authority (CA), essentially "signing" and validating all other certificates issued within that system, making it the key component for establishing trust within that closed network, just like a master key unlocks multiple doors in a building; its security is crucial as compromising it could compromise the entire trust structure within that private network. The discovery of the root certificate in one device would compromise all devices.

The use of a "pinned key" (public key baked into the firmware) would move custody of the master (private) key to the server. If the server can be trusted with a master key, PKE is okay. But then if the system is two devices connected by a UART, a master key is hidden in one of the devices unless it has Internet. In that case, key management still falls onto a host so `hermes` does not implement PKE. 

Without PKE, there is no spoofing. Key management relies on key escrow instead. Anti-spoofing relies on he security of the escrow.

## AEAD

[Wikipedia](https://en.wikipedia.org/wiki/Authenticated_encryption):
> Authenticated encryption with associated data (AEAD) is a variant of AE that allows the message to include "associated data" (AD, additional non-confidential information, a.k.a. "additional authenticated data", AAD). A recipient can check the integrity of both the associated data and the confidential information in a message.

`hermes` uses a symmetric algorithm for encryption and a keyed HMAC (hash) algorithm for message integrity.

The default protocol used by `hermes` is XChaCha20-SipHash. Xchacha20 is a long-IV version of [ChaCha20](https://en.wikipedia.org/wiki/Salsa20). For forward compatibility, a 128-bit IV is used instead of XChaCha20's 192-bit IV. [SipHash](https://en.wikipedia.org/wiki/SipHash) is a keyed HMAC. A version with 16-byte output authenticates the entire message, including the plaintext header, so that the header cannot be altered.

Cryptographic functions are called through function pointers held in the port's `struct`. Other AEAD algorithms may be plugged in by using the default setup as a template. To keep it simple, the following lengths are fixed:

- 256-bit Encryption key
- 128-bit HMAC key
- 128-bit Encryption IV
- 128-bit HMAC hash

The keyed hash includes a 64-bit counter that gets incremented after each hash, which rules out replay attacks.

## Escape sequences

`hermes` uses escape sequences to reserve characters for framing messages in UART streams. The most common ending on terminal input is a newline, `\n`, or 0x0A. The binary stream has its `\n` translated to 0x0B 0x00 when sent across a wire, reserving `\n` for the actual end-of-message.

## Language dependencies

* C99
* Little-endian byte order
* Hardware-specific functions in `*HW.c` file(s)

Most of the byte-order dependency comes from using `memcpy` to move data to and from byte arrays. It could be replaced with a `MEMCPY` macro that substitutes a byte-reversing version of `memcpy` for big-endian targets.

## Hardware requirements

* True random number generator
* 32-bit CPU such as ARM or RISC-V
* On-chip Flash memory for code and keys
* UART

The true random number generator is used to generate unique IVs, not keys, so the quality of its entropy is not critical. The idea is to avoid IV reuse. A reused IV is unlikely to be useful to an attacker since they would need the previous keystream, only obtainable from the plaintext (which they wouldn't have).

## Pairing

Key management is outside the scope of `hermes`. Pairing assumes that both ends of the communication channel have the same private keys. A pairing handshake between Alice and Bob proceeds as follows:

- Bob sends a pairing request to Alice
- Alice sends a random 128-bit IV to Bob
- Bob sends a random 128-bit IV to Alice

The IV is sent encrypted using a one-time-use random IV, which is in plaintext. Each communication session starts with a different IV so that the keystream never repeats. The hash key is changed after each message as extra protection against replay attacks.

After the pairing handshake is finished, `hermesAvail(&Alice)` returns 0 if synchronization has been lost due to data corruption. The connection will have to be re-paired with `hermesPair(&Alice)`.

Communication is ACKed, so it requires a successful IV setup in both directions.

## Key management

The only plaintext sent over the port, besides message tags, is boilerplate information that should be used to supply a UUID. A key vault would use the UUID to look up the key. `hermesBoiler(&Alice)` triggers a boilerplate response from Bob. The response is sent to a handler function that will use it to look up the keys.

A host PC connected to a target MCU through a UART would keep track of keys for different targets. Depending on security requirements, the host PC can keep those keys on the cloud or in a file in encrypted format.

`hermes` supports key rotation in `hermesHW.c`. This specialized function is platform-specific since it writes to Flash. Specifics are outside the scope of `hermes`, but keys should have a HMAC signed with a unique (to each device, but permanent) private key. The key set is 64 bytes total: 32 bytes for the encryption key, 16 bytes for the HMAC key, and 16 bytes for the key-set (optional) HMAC.

## Boilerplate messages

Boilerplate messages are plaintext, so they do not get a hash. The allowed length of a boilerplate is up to 128 bytes, the minimum receive buffer size. Boilerplate responses longer than 128-byte are truncated, so the receiver will wait for an end-of-message token.

The boilerplate contains a UUID. For example, the CH32V20x and CH32V30x MCUs contain a 96-bit ESIG. To use the ESIG in the boilerplate, `memcpy` would move 12 bytes from address `0x1FFFF7E8` to a RAM buffer used by the boilerplate. Other boilerplate items include the AEAD protocol used (0 means XChaCha20-SipHash) and HMAC length (8 or 16 bytes). The default data structure for `hermes` is:

- Length of the boilerplate in bytes, should be less than 65. Default is 18.
- 3-byte "nyb" string (nyb = None of your business)
- 13-byte UUID
- 1-byte AEAD format identifier

The AEAD format identifier packs bitfields as follows:

- b2:b0 = AEAD protocol. 0 = XChaCha20-SipHash.
- b6:b3 = reserved, default is 0110.
- b7 = HMAC length. 0 = 16-byte, 1 = 8-byte. Default is 0.

## Acknowledge handshake

Each encrypted message elicits an ACK response. The ACK counters of each port stay synchronized when everything is operating normally.

Errors are handled by re-transmitting messages that didn't get through, as shown in `test.c`.

## File streaming

The same scheme used for messaging can be used for encrypting files. The port writes to the file with the transmit channel and reads from it with the receive channel.

A file should consist of:

- A boilerplate
- A challenge to set a random IV
- Authenticated message(s)

File-like streaming is used for writing. Creating the file writes the boilerplate and challenge. Writing to the file appends a block at a time to the output. Every `1<<HERMES_FILE_MESSAGE_SIZE` bytes, the message HMAC is written and a new message is begun. The sequence of messages is serialized. Each message aligns with a `1<<HERMES_FILE_MESSAGE_SIZE` block of storage. For example, using `9` for `HERMES_FILE_MESSAGE_SIZE` pads each chunk to 512 bytes. Message overhead is about 28 bytes, so a 512-byte block (the size used for file storage) would use 94.5% of the block for payload data.

Closing the file saves any remaining data in the block and writes the HMAC. Hermes does not impose a length limit on the file, but it does require each message length to be a multiple of 16 bytes. The way to meet this requirement is to write to the file 16 or 32 bytes at a time.

For example, a 24-bit stereo CODEC produces 6-byte samples. Five samples pack into 32 bytes, with 2 unused bytes (maybe used as telemetry). Any data not a multiple of 16 bytes long is padded with zeros.

File reading is outside the scope of Hermes. Messages can only be read from the beginning, so the utility of reading them with Hermes would be limited. But, the file reading demo is `test/read.c`. The file is created by `test/test.c`.

## Modern UARTs

The buffer size is affected by the latency of USB-serial conversion. Supposing a 4ms round trip time (host to target to host), you probably want messages to amount to that span of time. At 1 MBPS, a UART can send 400 bytes in 4 ms. You would want 512- or 256-byte buffers.

Rather than rely on handshaking, data can be streamed out of the UART as a file stream. It is authenticated after each block. Such one-way communication doesn't care about USB latency or whether there is anything connected to the port.

In the WCH platform, `printf` is built on the `int _write(int fd, char *buf, int size)` primitive. Since `size` could be anything, but is usually not much, `printf` initializes by sending a boilerplate and nonce. Each `printf` uses a non-acknowledged send. When the number of bytes sent crosses a threshold, the boilerplate and nonce may be re-sent in case the terminal got lost. Each `printf` ( or `hermesStreamOut`) is one AEAD message. If the message is too big for the receive buffer the message will be lost, so make sure the receive buffer is bigger than `printf` will ever need.

