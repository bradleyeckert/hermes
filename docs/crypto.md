# Towards a secure tether

The host-target communication interface (sometimes called a *tether*) typical of Forth cross-development environments relies on a UART or Ethernet connection. Due to many high-profile Bond-villain-level cybersecurity failures, emerging cybersecurity regulations (even if they don't currently apply to you) are making plaintext-over-UART a thing of the past. As a general rule, any communications that cross an enclosure boundary should be encrypted. If no plaintext appears on PCB wiring, that's even better.

On one hand, backdoors are generally discouraged since an attacker could exploit them. On the other hand, cybersecurity and other considerations demand a means of system update -- in other words, a kind of secure backdoor.

One approach to the problem is to eliminate the tether in production devices. If hardware needs to be debugged, you would disable anti-rollback measures and flash the device with the debug version. The other approach is to design the tether for security. Good security means the tether can be used to push firmware updates.

Assuming the host side of the tether is a secure environment simplifies things considerably. Pre-distributed keys avoid the headaches of public key exchange. While TLS style PKE is often secure, HTTPS does not consider self-signed certificates secure. Even without Man-in-the-Middle attacks snatching keys, PKE small enough for embedded systems is not very quantum-resistant.

PKE is avoided altogether. The host is under the control of the same organization that controls all of the targets. For example, the target's manufacturer. The manufacturer would be responsible for key management, key rotation, and provisioning of targets with unique keys.

The authentication mechanism is similar to that of Mifare DESFire cards, which is a similar use case: many targets, few hosts. A Mifare card reader is expected to have network connectivity so it can get the required key from a server if it doesn't already have it. 

The cryptography used by DESFire can be improved upon. 3DES and AES have possible side-channel attacks like PSA. XChaCha20 as a fast, secure cipher resistant to PSAs. It is often paired with the Poly1305 hash, but Poly1305 is unsuitable for fixed keys. SipHash-2-4 used for the keyed HMAC instead.

A secure connection has three phases:

1. Authentication handshake to establish nonces
2. AEAD encrypted 2-way traffic 
3. Disconnection and key wipe

## Authentication handshake to establish nonces

Now that ephemeral keys are established, symmetric encryption and digital signing are possible. The host requests authentication from the target. After that authentication uses a 3-pass authentication handshake to set up random nonces:

### 1. Challenge from target:
The target generates a 24-byte random number (to be used as the H>T nonce), encrypts it with the shared secret key and a constant IV, and sends it to the host as a challenge.

Target side: Generate random number, Initialize XChaCha20(TX) and encrypt the number, Return 24-byte challenge.

Resolved IVs: Target TX

### 2. Challenge from host:
The host decrypts the received challenge, generates its own random number (RX nonce), encrypts it with the shared key and H>T nonce IV, and sends it back to the target.

Host side: Initialize XChaCha20(TX) using the same key and constant IV as the target, decrypt the 24-byte challenge and use it as the TX nonce. Initialize XChaCha20(TX) using the new nonce. Encrypt a 24-byte random number (the RX nonce) and return the 40-byte response: 24-byte ciphertext and 16-byte HMAC tag. Initialize XChaCha20(RX) using the RX nonce.

Resolved IVs: Host RX, Host TX

### 3. Verification:
The target decrypts the host's challenge and if it's successful, the authentication is complete and a secure communication channel is established. Digital signing via AEAD ensures that the host's response is valid. The newly decrypted host challenge will now be used as the T>H nonce.

Target side: Authenticate the signature. If it's good, initialize XChaCha20(RX) and XChaCha20(TX) with the decrypted message as the nonce.

Resolved IVs: Target RX

The target side uses two authentication functions and the host uses one. All three are in the `tcsecure.h` file along with an encrypt and a decrypt function.

Encryption and decryption increment SipHash's IV (a number added to the key) each time to prevent replay attacks. The `authenticate_ctx` data structure encapsulates everything needed for AEAD.

## AEAD encrypted 2-way traffic

The authentication handshake initializes XChaCha20-SipHash2.4 with a random 192-bit nonce. The keystream is used in short bursts, so each tether command (or response) is encrypted with a small part of the keystream. Ciphertext versions of the original plaintext message have an 8-byte signature appended. The receiver assumes the last 8 bytes to be a signature.

## Disconnection and key wipe

When the connection is closed, the keys and the cryptographic contexts are cleared by filling stack RAM with 0 and clearing the stack.

## Target hardware requirements

* True random number generator
* 32-bit CPU such as ARM or RISC-V
* On-chip Flash memory for code and keys
* Connection to the host

## Implementation

The AEAD should have built-in-self-test code to ensure that it hasn't been tampered with.

Authentication sets up random IVs. The contexts must be loaded with the keys before authentication.

Each short message, between N bytes (between 1 and 1k), is encrypted or decrypted with the next N bytes of the ChaCha20 keystream. The next 64-byte block of the keystream is obtained as needed.

## Crypto functions

The `XChaCha20` and `csiphash` libraries are included as Git submodules. The tether's `tcsecure` library calls functions in them. It also calls platform-specific functions in `tcplatform.c`.
