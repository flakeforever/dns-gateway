# DNS Gateway

<img src="https://github.com/flakeforever/dns-gateway/blob/main/dns-gateway.png" alt="DNS Gateway Logo" width="400" height="150">

A lightweight DNS proxy server designed for **secure DNS over proxy networks**. Built with C++20 coroutines and single-threaded event loop architecture, optimized for high availability when accessing encrypted DNS servers through SOCKS5 proxies.

[![License](https://img.shields.io/badge/license-Boost%201.0-blue.svg)](LICENSE_1_0.txt)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)

## Why DNS Gateway?

**Designed for proxy-based DNS privacy protection**

While general DNS privacy tools work well in direct network environments, DNS Gateway is specifically engineered for scenarios where encrypted DNS servers must be accessed through proxy networks (SOCKS5). It provides:

- **High availability** through multi-instance connection pooling and intelligent load balancing
- **Minimal latency** via Keep-Alive connection reuse across proxy chains
- **Automatic failover** with active health checking and graceful degradation
- **Resource efficiency** with single-threaded async I/O suitable for embedded devices

**Typical use case:** Accessing Cloudflare DoH, Google DoT, or Quad9 through SOCKS5 proxies for privacy protection in restricted networks.

## Core Features

### 🚀 High Availability Design

- **Multi-instance connection pool**: Configure multiple instances per upstream server
- **Least Requests load balancing**: Intelligent request distribution based on cumulative load
- **Active health checking**: Configurable health probes with automatic instance recovery
- **Keep-Alive connection reuse**: Significantly reduces TLS handshake overhead through proxies
- **Three-tier state management**: Active → Degraded → Offline with automatic promotion/demotion
- **Fair load distribution**: Automatic counter reset on topology changes

### 🔒 Security & Privacy

- **DNS over HTTPS (DoH)**: RFC 8484 compliant with HTTP/2 multiplexing support
- **DNS over TLS (DoT)**: TLS 1.3 encrypted transport
- **SOCKS5 proxy integration**: Seamless proxy support for all upstream protocols
- **TLS certificate verification**: Custom CA certificates and mutual TLS authentication

### ⚡ Performance & Efficiency

- **HTTP/2 multiplexing**: Single connection handles 200+ concurrent requests
- **High throughput**: 20,000 QPS theoretical capacity (@10ms latency), 1,000+ QPS (@200ms via proxy)
- **Object pooling**: Configurable DNS request object pool (default 200) controls max concurrency
- **Single-threaded event loop**: Asio coroutine-based async I/O, minimal lock contention
- **Low memory footprint**: < 50MB runtime memory, suitable for resource-constrained devices
- **Smart connection reuse**: Keep-Alive reduces TLS handshake overhead through proxies

### 📊 Intelligent Routing

- **Domain-based routing**: Flexible routing rules for different domain groups
- **Static DNS records**: Local resolution with zero latency
- **DNS caching**: TTL-aware caching reduces upstream queries
- **Multi-group management**: Different resolution strategies per domain group

### 📈 Monitoring

- **HTTP API**: Real-time metrics and health status
- **Detailed statistics**: Request counts, success rates, response times per instance
- **Connection state tracking**: Monitor Active/Degraded/Offline status
- **Structured logging**: Error/Warning/Info/Debug levels

## Quick Start

### Build

```bash
git clone https://github.com/flakeforever/dns-gateway.git
cd dns-gateway
git submodule update --init --recursive

mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Run

```bash
./dns-gateway -c dns-gateway.json
dig @127.0.0.1 google.com
```

For detailed configuration options, please refer to the configuration documentation.

## Architecture

### Why Single-Threaded Event Loop?

**DNS Gateway's workload is I/O-bound, not CPU-bound:**

```
Request processing breakdown:
  - DNS parsing:        ~1ms   (0.7% CPU)
  - TLS encryption:     ~2ms   (1.3% CPU)  
  - Waiting for proxy:  ~80%   (I/O wait)
  - Waiting for upstream: ~80% (I/O wait)

Single-threaded advantages:
  ✓ Minimal lock contention (locks only for shared data structures)
  ✓ Low memory footprint (single thread stack)
  ✓ Efficient coroutine context switching
  ✓ CPU available for other coroutines while waiting for I/O

Synchronization approach:
  - std::mutex: Used for protecting connection pool metadata
  - std::atomic: Used for statistics counters
  - async_mutex_lock: Async lock for upstream instance access and shared resources
  - Most operations are naturally serialized by single-threaded execution
```

### Upstream Protocol Comparison

#### Multiplexing Support

| Protocol | Multiplexing | Concurrency Model | Configuration |
|----------|-------------|-------------------|---------------|
| **UDP** | ✅ Yes | Object pool | `max_concurrent` (default: 200) |
| **HTTP/1.1 TLS** | ❌ No | Multiple instances | `instances` per upstream |
| **HTTP/2 DoH** | ✅ Yes | Object pool | `max_concurrent` (default: 200) |

**Multiplexing advantages**:
- Single connection handles all concurrent requests
- Lower connection overhead (especially via proxy)
- Pre-allocated object pool minimizes allocations
- Back-pressure mechanism prevents overload

**Multiple instances benefits** (HTTP/1.1):
- Parallel requests to same upstream
- Continued operation if some instances fail
- Load balancing via Least Requests algorithm

#### Theoretical Performance Comparison

**Direct Connection (10ms average latency)**:

| Protocol | Instances | Pool Size | Total Concurrency | Theoretical QPS | Notes |
|----------|-----------|-----------|-------------------|----------------|-------|
| UDP | 1 | 10 | 10 | 1,000 QPS | Basic config |
| UDP | 1 | 200 | 200 | 20,000 QPS | High concurrency |
| UDP | 5 | 200 | 1,000 | 100,000 QPS | **Multiplied effect** |
| HTTP/1.1 TLS | 10 | - | 10 | 1,000 QPS | No multiplexing |
| HTTP/1.1 TLS | 100 | - | 100 | 10,000 QPS | Impractical (high overhead) |
| HTTP/2 DoH | 1 | 10 | 10 | 1,000 QPS | Basic config |
| HTTP/2 DoH | 1 | 200 | 200 | 20,000 QPS | High concurrency |
| HTTP/2 DoH | 5 | 200 | 1,000 | 100,000 QPS | **Multiplied effect** |

**Via Proxy (100ms average latency)**:

| Protocol | Instances | Pool Size | Total Concurrency | Theoretical QPS | Notes |
|----------|-----------|-----------|-------------------|----------------|-------|
| UDP | 1 | 10 | 10 | 100 QPS | Basic config |
| UDP | 1 | 200 | 200 | 2,000 QPS | High concurrency |
| UDP | 5 | 200 | 1,000 | 10,000 QPS | **Multiplied effect** |
| HTTP/1.1 TLS | 10 | - | 10 | 100 QPS | No multiplexing |
| HTTP/1.1 TLS | 100 | - | 100 | 1,000 QPS | High overhead |
| HTTP/2 DoH | 1 | 10 | 10 | 100 QPS | Basic config |
| HTTP/2 DoH | 1 | 200 | 200 | 2,000 QPS | High concurrency |
| HTTP/2 DoH | 5 | 200 | 1,000 | 10,000 QPS | **Multiplied effect** |

**Key Insights**:
- **Multiplexing protocols (UDP/HTTP/2)**: Support **both** pool size and multiple instances
  - Total concurrency = instances × pool size
  - 5 instances × 200 pool = 1,000 concurrent requests
- **HTTP/1.1**: Only instance count affects concurrency (no pool multiplier)
  - Requires 100 instances to match 1 HTTP/2 instance with 100 pool size
- **Proxy scenario**: Multiplexing advantage is even more pronounced
  - HTTP/2 (5 instances × 200 pool) = 10,000 QPS
  - HTTP/1.1 (100 instances) = 1,000 QPS (10× more connections for same QPS)

**Formula**: `QPS = Total Concurrency / Average Latency`
- **Multiplexing**: Total Concurrency = instances × pool size
- **Non-multiplexing**: Total Concurrency = instance count

### Health Check Mechanism

```
Active probing:
  - Configurable check_interval (recommend 45-90 seconds)
  - Custom check_domains per upstream
  - Independent per-instance health tracking

State transitions:
  Active → Degraded:   Some instances fail health checks
  Degraded → Active:   Recovery attempt succeeds
  Degraded → Offline:  5 consecutive recovery attempts fail
  Offline → Active:    Recovery attempt succeeds after cooling period

Load balancing behavior:
  - Active:    Participates in load balancing
  - Degraded:  Excluded from load balancing, prioritized for recovery attempts
  - Offline:   Excluded from load balancing, periodic recovery attempts

Recovery mechanism:
  - Degraded connections get higher priority for recovery checks
  - Automatic retry with exponential backoff
  - No manual intervention needed
```

## Use Cases

- **Encrypted DNS via proxy networks**: Access DoH/DoT servers through SOCKS5 proxies for privacy protection
- **Home network privacy**: Deploy on routers/gateways (OpenWrt, Merlin firmware, ARM boards)
- **Embedded devices**: Low resource requirements suitable for IoT gateways, Raspberry Pi, NanoPi
- **Enterprise networks**: Internal DNS caching and forwarding with unified security policies

## License

This project is licensed under the Boost Software License 1.0. See [LICENSE_1_0.txt](LICENSE_1_0.txt).

## Credits

- [Asio](https://think-async.com/Asio/) - Cross-platform C++ async I/O library
- [OpenSSL](https://www.openssl.org/) - TLS/SSL and cryptography library
- [nlohmann/json](https://github.com/nlohmann/json) - Modern C++ JSON library
