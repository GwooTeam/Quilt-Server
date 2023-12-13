#!/bin/bash

gcc -m64 -D_LINUX -o mmodule ../sr/*.c -L. -lNSMac #  && ./run

# rm run
