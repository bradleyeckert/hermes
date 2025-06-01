# Mole
AEAD-secured ports (UARTs, etc.) in C99 for MCUs

`mole` was written to:

1. "Lock down" UART ports in a way that complies with real cybersecurity requirements
2. Encrypt and sign data logs and audio recordings saved to files
3. Minimize the memory footprint by keeping it simple.
4. Boot an MCU from an image encrypted and authenticated in SPI Flash.

It uses pre-arranged private keys, so it can output encrypted messages without a 2-way handshake.
Messages sent out the UART will appear as gibberish unless the receiver looks up
the private keys from its key store and decrypts the message stream.

Making the UART connector easily accessible does not reduce cybersecurity in any way.
Without the keyset, it is essentially locked down.

Mole is intended for use in key-escrow-based file encryption.
The file (or any stream of bytes) is encrypted,
but it includes a UUID that allows the encryption and signing keys to be looked up.

The decryption function can be used to securely boot from the above file stored in SPI Flash.
The boot image would launch if its digital signature authenticates.

## Key management

Managing the pre-arranged keys is outside the scope of **mole**.

In a real application, pre-arranged keys should be unique-per-device.
They require a supporting infrastructure where keys can be securely looked up.
Pre-arranged keys avoid the false sense of security of UART
anti-spoofing measures based self-signed certificates.
That only works if the certificate can be pinned to a physically secure server.

## Tests
`moletest.c` - A simulation of two ports connected by a noisy null-modem cable

`randkey.c` - Utility to generate a random keyset: 32-byte user passcode, 16-byte admin passcode,
and 16-byte HMAC: total of 64 bytes.

## Folder structure

`/src` C99 source code for `mole`  
`/src/tests` Tests (each test file has a `main` function)  
`/docs` Documentation for `mole`
