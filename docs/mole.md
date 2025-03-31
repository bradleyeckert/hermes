# Mole - Cryptographic protection for serial ports

Cybersecurity for embedded systems has been getting a lot of scrutiny due to such systems being exploited in spectacular Bond-villain-level cyber attacks. Encrypted UARTs are now a thing, possibly turning into a mandated thing down the road. Already in some markets, encryption is mandated for data crossing enclosure boundaries. `mole` encrypts UART traffic using a small memory footprint. While it uses xchacha20-siphash for AEAD by default, other encryption and HMAC schemes are easily added (AES-SHA, SH4-SH3, etc).

`mole` achieves its small footprint by not trying to copy the SSL/TLS usage model that was made for the Internet. The usage model is closer to that of NFT cards like Mifare DESFire: many cards, few readers. A Mifare card reader is expected to have network connectivity so it can get the required key from a server if it doesn't already have it. Likewise, one of the devices using Mole is assumed to have an Internet connection for getting the required keys from a remote server or key vault. In other words, `mole` uses a closed ecosystem.

Manufacturers already operate a closed ecosystem for their products. `mole` is meant more for manufacturers who need a UART to securely access their systems remotely or in the field. A secure channel facilitates update pushing, which is another emerging cybersecurity requirement. Pre-shared keys avoid PKE. Without PKE, there is no spoofing.

The tradeoff between pre-shared vs public keys is influenced by advanced Man-in-The-Middle (MiTM) spoofing [tools](https://slava-moskvin.medium.com/extracting-firmware-every-method-explained-e94aa094d0dd) that create self-signed HTTPS certificates. There are also tools to defeat SSL pinning. You have to wonder what's next.

With pre-shared keys, an authorized user must securely log into the key server and download the key in order to pair a UART connection. Key management relies on key escrow instead. Anti-spoofing relies on the security of the escrow.

## AEAD

[Wikipedia](https://en.wikipedia.org/wiki/Authenticated_encryption):
> Authenticated encryption with associated data (AEAD) is a variant of AE that allows the message to include "associated data" (AD, additional non-confidential information, a.k.a. "additional authenticated data", AAD). A recipient can check the integrity of both the associated data and the confidential information in a message.

`mole` uses a symmetric algorithm for encryption and a keyed HMAC (hash) algorithm for message integrity.

The default protocol used by `mole` is XChaCha20-SipHash. Xchacha20 is a long-IV version of [ChaCha20](https://en.wikipedia.org/wiki/Salsa20). For forward compatibility, a 128-bit IV is used instead of XChaCha20's 192-bit IV. [SipHash](https://en.wikipedia.org/wiki/SipHash) is a keyed HMAC. A version with 16-byte output authenticates the entire message, including the plaintext header, so that the header cannot be altered.

Cryptographic functions are called through function pointers held in the port's `struct`. Other AEAD algorithms may be plugged in by using the default setup as a template. To keep it simple, the following lengths are fixed:

- 256-bit Encryption key
- 128-bit HMAC key
- 128-bit Encryption IV
- 128-bit HMAC hash

The keyed hash includes a 64-bit counter that gets incremented after each hash, which rules out replay attacks.

## Escape sequences

`mole` uses escape sequences to reserve characters for framing messages in UART streams. The most common ending on terminal input is a newline, `\n`, or 0x0A. The binary stream has its `\n` translated to 0x0B 0x00 when sent across a wire, reserving `\n` for the actual end-of-message.

`mole` messages begin with a character less than blank (<0x20) and end with `\n` (0x0A). Cooked terminal input can be directed elsewhere because it begins with (>0x1F). The underlying UART interface can buffer input until `\n` before sending it on.

## Language dependencies

- C99
- Little-endian byte order
- Hardware-specific functions in `*HW.c` file(s)

Most of the byte-order dependency comes from using `memcpy` to move data to and from byte arrays. It could be replaced with a `MEMCPY` macro that substitutes a byte-reversing version of `memcpy` for big-endian targets.

## Hardware requirements

- True random number generator
- 32-bit CPU such as ARM or RISC-V
- On-chip Flash memory for code and keys
- UART

The true random number generator is used to generate unique 128-bit IVs to avoid IV reuse. Each session starts with a random IV and lasts as long as the port is in use without any errors or resets.

If an IV were to be reused, and the ciphertext has been logged (by sniffing UART traffic), the two sessions could be XORed to leak data that may be useful. The probably of it happening would be 2<sup>-64</sup> due to the Birthday Problem if the numbers are actually random. 2<sup>64</sup> sessions, at 1 session per hour, would be 600 billion years.

## Pairing

Key management is outside the scope of `mole`. Pairing assumes that both ends of the communication channel have the same private keys. They are pre-shared. A pairing handshake between Alice and Bob proceeds as follows:

- Bob sends a pairing request to Alice
- Alice sends a random 128-bit IV to Bob
- Bob sends a random 128-bit IV to Alice

The IV is sent encrypted using a one-time-use random IV, which is in plaintext. Each communication session starts with a different IV so that the keystream never repeats. The hash key is changed after each message as extra protection against replay attacks.

After the pairing handshake is finished, `moleAvail(&Alice)` returns 0 if synchronization has been lost due to data corruption. The connection will have to be re-paired with `molePair(&Alice)`.

Pairing initializes the keystream. Messages use 16-byte chunks of that keystream. As long as a different IV is used for each pairing sequence, the keystream does not repeat.

## Key management

The only plaintext sent over the port, besides message tags, is boilerplate information that should be used to supply a UUID. A key vault would use the UUID to look up the key. `moleBoiler(&Alice)` triggers a boilerplate response from Bob. The response is sent to a handler function that will use it to look up the keys.

A host PC connected to a target MCU through a UART would keep track of keys for different targets. Depending on security requirements, the host PC can keep those keys on the cloud or in a file in encrypted format.

`mole` supports key rotation through `uint8_t* ctx->mole_WrKeyFn(uint8_t* keyset)`. This specialized function is platform-specific since it writes to Flash. Specifics are outside the scope of `mole`, but keys are expected to be signed with a 16-byte HMAC. The key set is 64 bytes total: 32 bytes for the encryption key, 16 bytes for the HMAC key, and 16 bytes for the key-set HMAC. The key-set is signed by the HMAC key and a master key `HERMES_KEY_HASH_KEY`. Such HMAC checking is not necessary. If an attacker could program a new key, it would only brick the port.

The `int moleReKey(port_ctx *ctx, const uint8_t *key)` function sends a message with new 64-byte key set, encrypted with the existing key set. Its HMAC is checked before the key set is programmed.

The programming function could program multiple copies of the key set in case one is corrupted.
If `moleAddPort` reports a bad key, there is at least a backup.

## Boilerplate messages

Boilerplate messages are plaintext, so they do not get a hash. The allowed length of a boilerplate is up to the minimum receive buffer size. Boilerplate responses longer than that are truncated, so the receiver will wait for an end-of-message token.

The boilerplate contains a UUID. For example, the CH32V20x and CH32V30x MCUs contain a 96-bit ESIG. To use the ESIG in the boilerplate, `memcpy` would move 12 bytes from address `0x1FFFF7E8` to a RAM buffer used by the boilerplate. Other boilerplate items include the AEAD protocol used (0 means XChaCha20-SipHash) and HMAC length (8 or 16 bytes). The default data structure for `mole` is:

- Length of the boilerplate in bytes, should be less than 65. Default is 18.
- 3-byte "nyb" string (nyb = None of your business)
- 13-byte UUID
- 1-byte AEAD format identifier
- Optional CRC

The AEAD format identifier packs bitfields as follows:

- b2:b0 = AEAD protocol. 0 = XChaCha20-SipHash.
- b6:b3 = reserved, default is 0110.
- b7 = HMAC length. 0 = 16-byte, 1 = 8-byte. Default is 0.

A received boilerplate is sent to a handler function with src and length parameters. It is a counted string that is zero-terminated so there are multiple ways to get the length. The length should match the count.

## File streaming

The same scheme used for messaging can be used for encrypting files. The port writes to the file with the transmit channel and reads from it with the receive channel.

A file should consist of:

- A boilerplate
- A challenge to set a random IV
- Authenticated message(s)

File-like streaming is used for writing. Creating the file writes the boilerplate and challenge. Writing to the file appends a block at a time to the output. Every `1<<HERMES_FILE_MESSAGE_SIZE` bytes, the message HMAC is written and a new message is begun. The sequence of messages is serialized. Each message aligns with a `1<<HERMES_FILE_MESSAGE_SIZE` block of storage. For example, using `9` for `HERMES_FILE_MESSAGE_SIZE` pads each chunk to 512 bytes. Message overhead is about 28 bytes, so a 512-byte block (the size used for file storage) would use 94.5% of the block for payload data.

Closing the file saves any remaining data in the block and writes the HMAC. Mole does not impose a length limit on the file, but it does require each message length to be a multiple of 16 bytes. The way to meet this requirement is to write to the file 16 or 32 bytes at a time.

For example, a 24-bit stereo CODEC produces 6-byte samples. Five samples pack into 32 bytes, with 2 unused bytes (maybe used as telemetry). Any data not a multiple of 16 bytes long is padded with zeros.

File reading is outside the scope of Mole. Messages can only be read from the beginning, so the utility of reading them with Mole would be limited. But, the file reading demo is `test/read.c`. The file is created by `test/test.c`.

## Modern UARTs

The buffer size is affected by the latency of USB-serial conversion. Supposing a 4ms round trip time (host to target to host), you probably want messages to amount to that span of time. At 1 MBPS, a UART can send 400 bytes in 4 ms. You would want 512- or 256-byte buffers.

Data can be streamed out of the UART as a file stream. It is authenticated after each block. Such one-way communication doesn't care about USB latency or whether there is anything connected to the port.

In the WCH platform, `printf` is built on the `int _write(int fd, char *buf, int size)` primitive. Since `size` could be anything, but is usually not much, `printf` initializes by sending a boilerplate and nonce. Each `printf` uses a non-acknowledged send. When the number of bytes sent crosses a threshold, the boilerplate and nonce may be re-sent in case the terminal got lost. Each `printf` ( or `moleStreamOut`) is one AEAD message. If the message is too big for the receive buffer the message will be lost, so make sure the receive buffer is bigger than `printf` will ever need.

## Implementation

Streams are byte-wise processed, with incoming bytes fed into a FSM one at a time and outgoing bytes fed to an output function. The basic flow is:

- Incoming ciphertext --> `int molePutc(port_ctx *ctx, uint8_t c);`
- `void (*mole_plainFn)(const uint8_t *src, uint16_t length);` --> Plaintext to app
- Plaintext from app --> `int moleSend(port_ctx *ctx, const uint8_t *m, uint32_t bytes);`
- `void (*mole_ciphrFn)(uint8_t c);` --> Outgoing ciphertext

Underlying functions (those with various dependencies) are late-bound in the port_ctx struct to simplify reuse. There is no heap usage. Instead, `mole` implements its own memory allocation. It rurns out that each port needs about 1KB for context and buffers.

`void (*mole_plainFn)(const uint8_t *src, uint16_t length);` is the workhorse of `mole`. It accepts a plaintext message. Any transmission errors will cause a "bad HMAC" failure, which is handled by dropping the packet and resetting the connection by exchanging new nonces.

## Legal considerations

Cybersecurity is meant to protect devices and data from tampering, not give IoT manufacturers God-like powers.
Unfortunately, the two overlap. Any application that uses Mole should make private data inaccessible to the manufacturer. There are laws that address this:

- The GDPR, applicable in Europe
- The "Internet of Things Cybersecurity Improvement Act of 2020" in the US
- The Cybersecurity Law of the People's Republic of China
- Internet of Things (IoT) Security and Safety Framework in Japan
- The Personal Information Protection and Electronic Documents Act (PIPEDA) in Canada

### The key-escrow problem

The use of pre-shared keys puts the onus of key secrecy on the manufacturer. Whoever is trusted with the family jewels must not allow copies of them to get out into the wild. Otherwise, the affected devices would need re-keying.

In the context of UART encryption, PKE is an option if the public keys are whitelisted. For example, the device can be hardwired to accept only the host's public key. No other hosts can spoof the device. This requires the host to be ultra-secure with its private key, so it has the same secrecy problem.

Pre-shared keys are generated at provisioning, which is the same time the device's MCU is loaded with firmware.
A utility generates random keys and merges them into the firmware image just before JTAG programming. It also saves them to a database. Such activity must be done in a secure location that protects the keys.

