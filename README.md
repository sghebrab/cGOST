# cGOST
### A C implementation of the GOST symmetric block cipher

This program is meant to implement the GOST symmetric block cipher in the C programming language.
As of now, the project is newly born and it is very basic. In the future it will surely evolve.

For now, all you can do is compile the source code and run it, passing to it an integer number which represents the lenght in blocks of the random plaintext that will be generated as a sample. Then, a random 256-bit key will be generated and will be use to first encrypt and then decrypt the random plaintext for the sole purpose of demonstrating the correctness of the implementation.
