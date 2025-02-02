# Towards a secure tether

The host-target communication interface (sometimes called a *tether*) typical of Forth cross-development environments relies on a UART or Ethernet connection. Due to many high-profile Bond-villain-level cybersecurity failures, emerging cybersecurity regulations (even if they don't currently apply to you) are making plaintext-over-UART a thing of the past. As a general rule, any communications that cross an enclosure boundary should be encrypted. If no plaintext appears on PCB wiring, that's even better.

On one hand, backdoors are generally discouraged since an attacker could exploit them. On the other hand, cybersecurity and other considerations demand a means of system update -- in other words, a kind of secure backdoor.

One approach to the problem is to eliminate the tether in production devices. If hardware needs to be debugged, you would disable anti-rollback measures and flash the device with the debug version. The other approach is to design the tether for security. Good security means the tether can be used to push firmware updates.

Assuming the host side of the tether is a secure environment simplifies things considerably. Pre-distributed keys avoid the headaches of public key exchange. While TLS style PKE is often secure, HTTPS does not consider self-signed certificates secure. Even without Man-in-the-Middle attacks snatching keys, PKE small enough for embedded systems is not very quantum-resistant.

PKE is avoided altogether. The host is under the control of the same organization that controls all of the targets. For example, the target's manufacturer. The manufacturer would be responsible for key management, key rotation, and provisioning of targets with unique keys. This use case is similar to that of Mifare DESFire cards: many targets, few hosts. A Mifare card reader is expected to have network connectivity so it can get the required key from a server if it doesn't already have it.

## Nonce forwarding

All messages are authenticated with an HMAC using the XChaCha20 stream cipher and Siphash keyed hash. A communication session starts with nonce forwarding. If tether synchronization is lost, nonce forwarding fixes it. Nonce exchange (or nonce handshake) occurs in two steps:

1. The host sends a nonce to the target
2. The target sends a nonce to the host

Nonce wrapping is facilitatied by authenticated XChaCha20, making for simple but secure nonce transfer. Nonce wrapping could be used for one-way communication too. The message would start with a wrapped nonce and then use that nonce to encrypt the rest of the message. The purpose of that is to avoid keystream reuse. 

A wrapped nonce has four components:

1. 3-byte header: Tag, length, format (length includes format and the following data)
2. X: 192-bit random nonce
3. Y: 192-bit random nonce encrypted with key KE and nonce X
4. 64-bit HMAC of X and Y using key KH

The receiving end checks the HMAC using KH and if it's good, decrypts Y using KE and X. It then initializes XChaCha20 with KE and Y.

An attacker can see X but not tamper with it. X is there to randomize the nonce of the Y message. If KE and KH are known, X could be used to recover Y, revealing any messages encrypted using those keys. The nonces protect against analysis and replay attacks.

The wrapped nonce packet contains length byte N, which is 57 for the above packet. The number of bytes in Y is N-33. Increasing N to 89 would include a random 32-byte user nonce to support add-ons like AES-256-CBC. The maximum allowed N is 255 (subject to buffer space) which would give a Y of 222 bytes.

## AEAD encrypted 2-way traffic

Nonce forwarding initializes XChaCha20. The keystream is used in short bursts, so each tether command (or response) is encrypted with a small part of the keystream. Ciphertext versions of the original plaintext message have an 8-byte HMAC appended.

Tether messages consist of a plaintext tag to identify the message type and an AEAD encrypted message. The HMAC key is incremented by 1 after each message. If there is a communication bit error, the HMAC fails and synchronization is lost. After that, all HMACs will fail. So, if a HMAC fails new nonce forwarding is performed immediately.

## Target hardware requirements

* True random number generator
* 32-bit CPU such as ARM or RISC-V
* On-chip Flash memory for code and keys
* Connection to the host

## Implementation

The AEAD should have built-in-self-test code to ensure that it hasn't been tampered with.

## Crypto functions

The `XChaCha20` and `csiphash` libraries are included as Git submodules. They should be used without modification so they don't have to be forked.

The XChaCha20-csiphash combination was chosen for AEAD because it is cryptographically strong, resistant to side-channel attacks, and doesn't use a lot of RAM. SipHash is not a one-way function, but for keyed HMAC that doesn't matter. It's not bad for lightweight AEAD.

If your industry guidelines require FIPS-140 encryption, messages should be encrypted by AES-CBC or AES-GCM before re-encryption with Xchacha20. The keyed HMAC already protects against bit-flipping attacks. Double encryption costs little and gives you a 2-layer defense.
