# Backdoor crytography

## Towards a secure tether

The host-target communication interface (sometimes called a *tether*) typical of Forth cross-development environments relies on a UART or Ethernet connection. Due to many high-profile Bond-villain-level cybersecurity failures, emerging cybersecurity regulations (even if they don't currently apply to you) are making plaintext-over-UART a thing of the past. As a general rule, any communications that cross an enclosure boundary should be encrypted. If no plaintext appears on PCB wiring, that's even better.

On one hand, backdoors are generally discouraged since an attacker could exploit them. On the other hand, cybersecurity and other considerations demand a means of system update -- in other words, a kind of secure backdoor.

One approach to the problem is to eliminate the tether in production devices. If hardware needs to be debugged, you would disable anti-rollback measures and flash the device with the debug version. The other approach is to design the tether for security. Good security means the tether can be used to push firmware updates.

Strong security uses AEAD encryption. In this case, ChaCha20-Poly1305, which is used in IPsec, SSH, TLS 1.2, DTLS 1.2, TLS 1.3, etc. The security relies on choosing a unique nonce for every message (or tether session) encrypted. Compared to AES-GCM, implementations of ChaCha20-Poly1305 are less vulnerable to timing attacks.

The tether uses ChaCha20-Poly1305 a little differently than TLS (RFC 8439). The authentication handshake initializes ChaCha20-Poly1305 with a random 96-bit nonce. ChaCha20 uses a fixed private encryption key. The nonce is hashed with the fixed private signature key to provide the one-time key for Poly1305. These two keys are stored such that nothing but the tether code can access them.

The reason the keys are fixed (and unique to each target device) is to enable key management without public key exchange (PKE). PKE is supposedly secure, but the fact that deep packet inspection of TLS is a thing indicates that it's not. The lack of complaints from governments regarding HTTPS and E2E encryption is not reassuring. Self-signed SSL certificates on embedded systems seem a little dicey. Finally, PKE has (or will have) quantum-resistance problems. For all of these reasons, the security risks of fixed keys outweigh the benefits of ephemeral SSL keys.

The keystream is used in short bursts, so each tether command (or response) is encrypted with a small part of the keystream. The final tether command is a signature, which is the current 16-byte HMAC. The target detects when a signature is invalid or missing. The target saves the expected HMAC before evaluating the input, just as the host does. The last command is a “signature” command which sends the expected HMAC.

## Authentication

H→T	The host sends a “read boilerplate” command to the target.

T→H	The target responds with a boilerplate containing a unique identifier (UID) and the list of supported commands. The host may use the UID to look up the target’s key. The host and target keys must match for the endpoints to be paired.

H→T	The host sends an “unlock” command, which is a request to authenticate the target using a specific key, such as the Crypto key.

T→H	The target responds with a 12-byte random number (challenge) encrypted using the specified key and a fixed IV. The host decrypts the challenge using the same key and sends the result back to the target. The random number is the nonce for the session.

H→T	The host sends The target verifies the response and, if successful, sends an authentication status back to the host. It now accepts functions Fn4 to Fn9. The tether now expects incoming data to be encrypted and will return encrypted data. END sets the RXfull flag.

The target chooses the random challenge, so a fake host cannot use a replay attack to connect to the target. The target is the side with information that must be secured. The host side does not have any secrets accessible by UART, so a fake target using a replay attack to establish a connection is not useful.

## Target hardware requirements

* True random number generator
* 32-bit CPU such as ARM or RISC-V
* On-chip Flash memory for code and keys
* Connection to the host

## Testing

The AEAD should have built-in-self-test code to ensure that it hasn't been tampered with.

Short message use of the AEAD initializes once as follows:

1. Get 32-byte key_c, 32-byte key_s, and 12-byte random nonce.
2. Initialize ChaCha20 with key_c and nonce.
3. Initialize Poly1305 with key_s.
4. Get the hash of the nonce and use it to initialize Poly1305.

Each short message, between N bytes (between 1 and 1k), is encrypted or decrypted with the next N bytes of the ChaCha20 keystream. The next 64-byte block of the keystream is obtained as needed.

The cyphertext of the N-byte message is input to the Poly1305 hash. The 16-byte tag is extracted from the poly1305_context using a version of poly1305_finish that does not modify the context.

There are contexts for the recaive and transmit streams. The total amount of RAM needed for these structures is about 520 bytes.
