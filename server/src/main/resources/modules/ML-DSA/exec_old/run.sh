# !/bin/bash
gcc -m64 -D_LINUX -o dmodule ../sr/*.c -L. -lNCrypto
