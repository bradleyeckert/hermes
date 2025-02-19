# hermes
AEAD-secured ports (UARTs, etc.) in C99 for MCUs

I wrote `hermes` for three reasons:

1. "Lock down" UART ports in a way that complies with real cybersecurity requirements
2. Encrypt and sign data logs and audio recordings saved to files
3. Minimize the memory footprint by keeping it simple.

It uses pre-arranged private keys, so it can output encrypted messages without a 2-way handshake. Boot messages sent out the UART will appear as gibberish unless the receiver looks up the private keys from its key store and decrypts the message stream.

Making the UART connector easily accessible does not reduce cybersecurity in any way. Without the keys, it is totally locked down.
## tests
`test.c` - A simulation of two ports connected by a noisy null-modem cable

`read.c` - Code for decrypting the `demofile.bin` created by `test.c`
