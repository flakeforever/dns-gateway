#!/bin/bash

# ARM64 cross-compilation script
export CROSS_COMPILE=aarch64-linux-gnu-

cd lib/openssl
./Configure linux-aarch64 no-shared no-shared no-tests no-apps
make -j$(nproc)

echo "openssl compilation completed!"
