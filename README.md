# cGOST
### A C implementation of the GOST symmetric block cipher

This program is meant to implement the GOST symmetric block cipher in the C programming language.

The simplest way to see it working now is cloning the repo, launching the run.sh bash script and watch the results. The invoked compiled program will generate 640 random bits (64 per block * 10, the first argument), a random 256-bit key, a random 64-bit IV and will encrypt and then decrypt these bits using the cipher in CBC mode (mode 2). Plaintext, IV, key and both encryption and decryption results will be printed.

Speaking about performance,16384 blocks, which correspond to exactly 1 Mb, will take approximately 0.07s to be encrypted or decrypted. This means that, on average, the throughput of the program is of around 14 Mb/s.
