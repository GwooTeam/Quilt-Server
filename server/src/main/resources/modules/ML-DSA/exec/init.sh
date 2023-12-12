#!/bin/bash
# 현재 디렉터리 경로를 LD_LIBRARY_PATH에 추가
export LD_LIBRARY_PATH=$(pwd)

sudo cp libNCrypto.so /lib/libNSCrypto.so
