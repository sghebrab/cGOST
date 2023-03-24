#!/bin/bash

# Create the shared library object
gcc -c -fPIC GOST.c -o GOST.o
gcc -shared GOST.o -o GOST.so

# Compile again the source into an executable, just to test the program
gcc GOST.c -o GOST.o
./GOST.o 10 2
