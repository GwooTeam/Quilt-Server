# !/bin/bash
gcc -m64 -D_LINUX -o dmodule *.c -L. -lNCrypto
