# Mole
AEAD-secured ports (UARTs, etc.) in C99 for MCUs

I wrote `mole` for three reasons:

1. "Lock down" UART ports in a way that complies with real cybersecurity requirements
2. Encrypt and sign data logs and audio recordings saved to files
3. Minimize the memory footprint by keeping it simple.

It uses pre-arranged private keys, so it can output encrypted messages without a 2-way handshake. Boot messages sent out the UART will appear as gibberish unless the receiver looks up the private keys from its key store and decrypts the message stream.

Making the UART connector easily accessible does not reduce cybersecurity in any way. Without the keyset, it is totally locked down.

## Tests
`moletest.c` - A simulation of two ports connected by a noisy null-modem cable

`read.c` - Code for decrypting the `demofile.bin` created by `test.c`

`randkey.c` - Utility to generate a random keyset: 32-byte user passcode, 16-byte admin passcode, and 16-byte HMAC total 64 bytes.

## Folder structure

`/src` C99 source code for `mole`  
`/src/blake2s` Blake2s repository (submodule)  
`/src/xchacha` XChaCha20 repository (submodule)  
`/src/tests` Tests (each test file has a `main` function)  
`/docs` Documentation for `mole`

---
Note: Contains [submodules](https://www.geeksforgeeks.org/how-to-clone-git-repositories-including-submodules/). Use `git clone --recurse <url>` to clone. `git submodule update --remote --recursive` will update to latest.
