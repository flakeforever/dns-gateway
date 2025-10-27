# GitHub Actions Workflows

## Release Workflow

### 📦 `release.yml`

Automatically builds and releases multi-platform binaries when a version tag is pushed.

#### Supported Platforms

- **linux-amd64**: x86_64 Linux (64-bit Intel/AMD)
- **linux-386**: i686 Linux (32-bit x86)
- **linux-arm64**: ARM64/aarch64 Linux
- **linux-armv7**: ARMv7 Linux (32-bit ARM)
- **linux-mips**: MIPS Linux (big-endian)
- **linux-mipsel**: MIPS Linux (little-endian)

#### How it works

1. **Build OpenSSL**: Compiles OpenSSL statically for each platform
2. **Cache OpenSSL**: Caches build to speed up future runs
3. **Build DNS Gateway**: Cross-compiles dns-gateway with static OpenSSL
4. **Strip binary**: Reduces binary size
5. **Package**: Creates tar.gz and SHA256 checksums
6. **Release**: Publishes to GitHub Releases (on version tags)

#### Usage

##### Create a release

```bash
# Tag your commit
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# GitHub Actions will automatically:
# - Build binaries for all 6 platforms
# - Create a GitHub Release
# - Upload all artifacts (13 files total)
```

##### Manual trigger

You can also trigger the workflow manually from the GitHub Actions tab:

1. Go to "Actions" → "Build and Release"
2. Click "Run workflow"
3. Select branch/tag
4. Click "Run workflow"

#### Build process

The workflow follows the same process as the local build scripts.

**For AMD64 (native):**
```bash
cd lib/openssl
./Configure linux-x86_64 no-shared no-tests no-apps
make -j$(nproc)

cd ../..
mkdir build && cd build
cmake ..
make -j$(nproc)
```

**For 386 (32-bit x86):**
```bash
cd lib/openssl
./Configure linux-x86 no-shared no-tests no-apps
make -j$(nproc)

cd ../..
mkdir build && cd build
cmake -DCMAKE_C_FLAGS=-m32 -DCMAKE_CXX_FLAGS=-m32 ..
make -j$(nproc)
```

**For ARM64 (cross-compile):**
```bash
export CROSS_COMPILE=aarch64-linux-gnu-
cd lib/openssl
./Configure linux-aarch64 no-shared no-tests no-apps
make -j$(nproc)

cd ../..
export CC=aarch64-linux-gnu-gcc
export CXX=aarch64-linux-gnu-g++
mkdir build && cd build
cmake ..
make -j$(nproc)
```

**For ARMv7 (cross-compile):**
```bash
export CROSS_COMPILE=arm-linux-gnueabihf-
cd lib/openssl
./Configure linux-armv4 no-shared no-tests no-apps
make -j$(nproc)

cd ../..
export CC=arm-linux-gnueabihf-gcc
export CXX=arm-linux-gnueabihf-g++
mkdir build && cd build
cmake ..
make -j$(nproc)
```

**For MIPS/MIPSEL (cross-compile):**
```bash
export CROSS_COMPILE=mips-linux-gnu-  # or mipsel-linux-gnu-
cd lib/openssl
./Configure linux-mips32 no-shared no-tests no-apps
make -j$(nproc)

cd ../..
export CC=mips-linux-gnu-gcc  # or mipsel-linux-gnu-gcc
export CXX=mips-linux-gnu-g++
mkdir build && cd build
cmake ..
make -j$(nproc)
```

#### Cache

OpenSSL builds are cached to speed up subsequent builds. The cache is invalidated when:
- OpenSSL version changes (`lib/openssl/VERSION.dat`)
- Platform configuration changes

**Build time comparison:**
- **First build** (no cache): ~60-90 minutes for all platforms
- **Subsequent builds** (with cache): ~15-30 minutes for all platforms

#### Artifacts

Each build produces **13 files** in total:

**Binary archives:**
- `dns-gateway-linux-amd64.tar.gz`
- `dns-gateway-linux-386.tar.gz`
- `dns-gateway-linux-arm64.tar.gz`
- `dns-gateway-linux-armv7.tar.gz`
- `dns-gateway-linux-mips.tar.gz`
- `dns-gateway-linux-mipsel.tar.gz`

**Checksums:**
- `dns-gateway-<platform>.tar.gz.sha256` (6 files)
- `SHA256SUMS` (combined checksums)

#### Platform Target Devices

**linux-amd64 (x86_64)**
- Modern servers, desktops, laptops
- Ubuntu, Debian, CentOS, RHEL, Fedora
- Most cloud instances (AWS, GCP, Azure)

**linux-386 (i686)**
- Older 32-bit PC systems
- Legacy embedded devices
- Some older VPS instances

**linux-arm64 (aarch64)**
- Raspberry Pi 4, 5, 400
- ARM-based servers (Ampere, Graviton)
- Modern NAS devices
- OpenWrt ARM64 routers

**linux-armv7 (armv7l)**
- Raspberry Pi 2, 3, Zero 2 W
- Older ARM devices and routers
- OpenWrt ARMv7 devices
- Many embedded systems

**linux-mips (big-endian)**
- Atheros AR series routers
- MediaTek-based routers
- Some OpenWrt devices

**linux-mipsel (little-endian)**
- Broadcom-based routers (most home routers)
- ASUS, Netgear, TP-Link routers
- Many OpenWrt devices

#### Adding more platforms

To add more platforms (e.g., RISC-V, PowerPC), add entries to the matrix:

```yaml
matrix:
  config:
    # ... existing platforms
    - name: linux-riscv64
      arch: riscv64
      cc: riscv64-linux-gnu-gcc
      cxx: riscv64-linux-gnu-g++
      openssl_target: linux64-riscv64
      cross_compile: riscv64-linux-gnu-
```

Don't forget to install the corresponding cross-compilation tools in the "Install build dependencies" step:

```yaml
elif [ "${{ matrix.config.name }}" == "linux-riscv64" ]; then
  sudo apt-get install -y \
    gcc-riscv64-linux-gnu \
    g++-riscv64-linux-gnu \
    binutils-riscv64-linux-gnu
fi
```

## Troubleshooting

### Build fails with "OpenSSL not found"

Check that the OpenSSL build step completed successfully:
- Review the OpenSSL build logs in the workflow output
- Clear the cache and rebuild (Actions → Caches → Delete)
- Verify the OpenSSL Configure command for the target platform
- Check cross-compilation tools are correctly installed

### Binary doesn't run on target platform

**Check architecture match:**
```bash
file dns-gateway
# Should show correct architecture (e.g., ARM aarch64, MIPS, etc.)
```

**Check static linking:**
```bash
ldd dns-gateway
# Should show "not a dynamic executable"
```

**Check glibc compatibility:**
- The binary requires glibc 2.17+ on the target system
- For very old systems, you may need to build on an older Ubuntu version

### Cross-compilation fails

**For ARM platforms:**
- Ensure correct cross-compiler is installed
- Check `CROSS_COMPILE` environment variable is set
- Verify OpenSSL target matches the architecture

**For MIPS platforms:**
- Confirm endianness (MIPS vs MIPSEL)
- Some routers may need additional flags
- Test on actual hardware or QEMU

### Cache issues

**Clear specific cache:**
1. Go to Actions → Caches
2. Find cache key (e.g., `openssl-linux-arm64-<hash>`)
3. Delete the cache
4. Re-run the workflow

**Clear all caches:**
```bash
# Using GitHub CLI
gh cache delete --all
```

### Build timeout

If builds are timing out:
- OpenSSL compilation is the slowest step (~8-12 min per platform)
- Consider removing less common platforms (MIPS) if not needed
- Use cache effectively (subsequent builds are much faster)

### Testing binaries locally

**Using QEMU:**
```bash
# Install QEMU
sudo apt-get install qemu-user-static

# Test ARM binary
qemu-aarch64-static ./dns-gateway --version

# Test MIPS binary
qemu-mips-static ./dns-gateway --version
```

**Using Docker:**
```bash
# Test ARM64 binary
docker run --rm -v $(pwd):/app --platform linux/arm64 debian:bookworm /app/dns-gateway --version

# Test ARMv7 binary
docker run --rm -v $(pwd):/app --platform linux/arm/v7 debian:bookworm /app/dns-gateway --version
```

## Release Notes Template

The workflow automatically generates release notes with:
- Download links for all platforms
- SHA256 checksum links
- Installation instructions
- Platform compatibility information
- Quick start guide

You can customize the release notes by editing the "Generate release notes" step in `release.yml`.
