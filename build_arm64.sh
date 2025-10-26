#!/bin/bash

# ARM64 cross-compilation script
export CROSS_COMPILE=aarch64-linux-gnu-
export CC=aarch64-linux-gnu-gcc
export CXX=aarch64-linux-gnu-g++
export AR=aarch64-linux-gnu-ar
export RANLIB=aarch64-linux-gnu-ranlib
export LD=aarch64-linux-gnu-ld

# Clean old build directory
rm -rf build

# Create build directory and compile
mkdir -p build
cd build
cmake ..
make -j$(nproc)

echo "ARM64 compilation completed!"
echo "Executable location: build/dns-gatewaydns-gateway"
