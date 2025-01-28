# Backdoor crytography

## Towards a secure tether

The host-target communication interface (sometimes called a *tether*) typical of Forth cross-development environments relies on a UART or Ethernet connection. Due to many high-profile Bond-villain-level cybersecurity failures, emerging cybersecurity regulations (even if they don't currently apply to you) are making plaintext-over-UART a thing of the past. As a general rule, any communications that cross an enclosure boundary should be encrypted. If no plaintext appears on PCB wiring, that's even better.

On one hand, backdoors are generally discouraged since an attacker could exploit them. On the other hand, cybersecurity and other considerations demand a means of system update -- in other words, a kind of secure backdoor.

One approach to the problem is to eliminate the tether in production devices. If hardware needs to be debugged, you would disable anti-rollback measures and flash the device with the debug version. The other approach is to design the tether for security. Good security means the tether can be used to push firmware updates.

Strong security uses AEAD encryption. In this case, XChaCha20-Poly1305. The security relies on choosing a unique nonce for every message (or tether session) encrypted. Compared to AES-GCM, implementations of XChaCha20-Poly1305 are less vulnerable to timing attacks.

The authentication handshake initializes XChaCha20-Poly1305 with a random 192-bit nonce. The keystream is used in short bursts, so each tether command (or response) is encrypted with a small part of the keystream. Ciphertext versions of the original plaintext message have a 16-byte signature appended. The receiver assumes the last 16 bytes to be a signature. The private signing key used by Poly1305 must be unique to each message. This is handled by adding a 64-bit counter to the key and incrementing the counter after each message.

Poly1305's onetime-key requirement is handled across sessions by generating new private keys. These are random keys that span one session. PKE uses MicroECC for ECDH key exchange and ECDSA certificate signing. It's similar to how SSH/TLS works, but without a bunch of legacy bloat.

You may wonder how TLS or anything like it is secure when "TLS inspection" is a thing. TLS inspection is Man-in-the-Middle bridging of two spoofed TLS connections. It can see everything. It needs a surrepitiously-installed certificate on the computer to be spied on. Without this hack, TLS is theoretically secure. PKE algorithms have increasing quantum resistance problems, so allowance should be made for PKE upgrades.

## Authentication for static keys (not used)

The host requests authentication from the target. After that authentication uses a 3-pass authentication handshake:

### 1. Challenge from target:
The target generates a 24-byte random number (to be used as the H>T nonce), encrypts it with the shared secret key and a constant IV, and sends it to the host as a challenge.

The sender **MUST NOT** use poly1305_auth to authenticate more than one message under the same key. Therefore, the challenge from the target is not signed. No problem. Without the key, a Man in the Middle cannot spoof the host. It can only modify the message, which would prevent authentication.

Target side: Generate random number, Initialize XChaCha20(TX) and encrypt the number, Return 24-byte challenge.

Resolved IVs: Target TX

### 2. Challenge from host:
The host decrypts the received challenge, generates its own random number (RX nonce), encrypts it with the shared key and H>T nonce IV, and sends it back to the target.

Host side: Initialize XChaCha20(TX) using the same key and constant IV as the target, decrypt the 24-byte challenge and use it as the TX nonce. Initialize XChaCha20(TX) and Poly1305(TX) using the new nonce. Encrypt a 24-byte random number (the RX nonce) and return the 40-byte response: 24-byte ciphertext and 16-byte HMAC tag. Initialize XChaCha20(RX) and Poly1305(RX) using the RX nonce.

Resolved IVs: Host RX, Host TX

### 3. Verification:
The target decrypts the host's challenge and if it's successful, the authentication is complete and a secure communication channel is established. Digital signing via AEAD ensures that the host's response is valid. The newly decrypted host challenge will now be used as the T>H nonce.

Target side: Authenticate the signature. If it's good, initialize XChaCha20(RX) and Poly1305(TX) with the decrypted message as the nonce.

Resolved IVs: Target RX

The target side uses two authentication functions and the host uses one. All three are in the `tcsecure.h` file along with an encrypt and a decrypt function.

Encryption and decryption re-initialize Poly1305 with each message, incrementing IV each time. So, all of the keys and IVs need to be remembered throughout the session. The `authenticate_ctx` data structure encapsulates everything needed for AEAD.

## Target hardware requirements

* True random number generator
* 32-bit CPU such as ARM or RISC-V
* On-chip Flash memory for code and keys
* Connection to the host

## Implementation

The AEAD should have built-in-self-test code to ensure that it hasn't been tampered with.

Authentication sets up random IVs. The contexts must be loaded with the keys before authentication.

Each short message, between N bytes (between 1 and 1k), is encrypted or decrypted with the next N bytes of the ChaCha20 keystream. The next 64-byte block of the keystream is obtained as needed.

The cyphertext of the N-byte message is input to the Poly1305 hash.

## Crypto functions

The `XChaCha20` and `poly1305` libraries are included as Git submodules. The tether's `tcsecure` library calls functions in them. It also calls platform-specific functions in `tcplatform.c`.
