#!/bin/bash

cd lib/openssl

if [ "$1" = "shared" ]; then
    if [ ! -f "libcrypto.so" ] || [ ! -f "libssl.so" ]; then
        # configure OpenSSL
        ./config -fPIC shared --release

        # build OpenSSL
        make -j4
    fi
elif [ "$1" = "no-shared" ]; then
    if [ ! -f "libcrypto.a" ] || [ ! -f "libssl.a" ]; then
        # configure OpenSSL
        ./config -fPIC no-shared --release

        # build OpenSSL
        make -j4
    fi
fi
