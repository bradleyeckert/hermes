# Files

- [mole.md](mole.md) is an overview of **mole**.
- `IEC 62304` is a set of documents created by applying the IEC 62304 software development standard to **mole**. 

## Summary of mole.c by GitHub Copilot

"Explain how the code in mole.c works"

*Copilot:*

The code in mole.c implements a secure, authenticated, and encrypted communication protocol, primarily designed for use over UARTs or similar streams. Here’s a high-level explanation of how it works:

1. Context and Memory Management
- The code uses a statically allocated memory pool (context_memory) for runtime context objects, avoiding dynamic memory allocation.
- The Allocate function manages this pool, handing out memory for cryptographic contexts and buffers.

2. Key Management and Derivation
- Keys are derived from a passcode using a Key Derivation Function (KDF) based on repeated hashing (KDF function).
- The moleNewKeys function tests the provided key, then derives HMAC and encryption keys for the session.

3. Packet Framing and Escaping
- Data is sent in packets, with special handling to escape control bytes (like end-of-packet markers) to avoid accidental termination.
- Functions like SendByteU, SendByte, and SendN handle this escaping and byte-wise output.

4. Encryption and Authentication
- The protocol uses AEAD (Authenticated Encryption with Associated Data) via XChaCha and Blake2s (as seen from the includes and function pointers).
- Each packet is encrypted and authenticated with an HMAC. The HMAC is checked on receipt to ensure integrity and authenticity.

5. Sending Data
- Functions like moleSendMsg, moleSend, and moleFileOut handle sending messages or files.
- Data is buffered, encrypted, and sent in blocks. Each block or message is authenticated with an HMAC.

6. Receiving Data
- The molePutc function is a state machine that processes incoming bytes, handles escape sequences, and reconstructs packets.
- It verifies HMACs, decrypts payloads, and dispatches messages to appropriate handlers.

7. Session and IV Management
- Initialization vectors (IVs) are exchanged and authenticated at the start of a session (SendIV, SendHeader).
- The protocol supports re-keying and pairing, allowing secure key updates and session resets.

8. Special Features
- Boilerplate packets are used for initial identification and setup.
- Admin commands and passcodes are supported for privileged operations.
- The code is designed to be robust against synchronization loss, with mechanisms to reset and re-pair if HMACs fail.

9. Debugging and Tracing
- If MOLE_TRACE is enabled, the code outputs detailed debug information about packet contents and cryptographic operations.

Summary:
mole.c is a compact, efficient implementation of a secure, authenticated, and encrypted communication protocol for
embedded or resource-constrained environments. It manages its own memory, handles key derivation, packet framing,
encryption, authentication, and robust error handling, making it suitable for secure device-to-device communication.
