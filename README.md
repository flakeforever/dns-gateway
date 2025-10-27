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

- **DNS over HTTPS (DoH)**: RFC 8484 compliant
- **DNS over TLS (DoT)**: TLS 1.3 encrypted transport
- **SOCKS5 proxy integration**: Seamless proxy support for all upstream protocols
- **TLS certificate verification**: Custom CA certificates and mutual TLS authentication

### ⚡ Performance & Efficiency

- **Single-threaded event loop**: Asio coroutine-based async I/O, minimal lock contention
- **Low memory footprint**: < 50MB runtime memory, suitable for resource-constrained devices
- **High concurrency**: 100+ QPS on single core, I/O-bound optimized
- **Object pooling**: Configurable DNS request object pool to minimize allocations

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
  - std::atomic: Used for statistics counters and coroutine locks
  - await_coroutine_lock: Async lock for upstream instance access
  - Most operations are naturally serialized by single-threaded execution
```

### Connection Pool Strategy

```

Benefits of multiple instances:
  ✓ Parallel requests to same upstream
  ✓ Load distribution across instances  
  ✓ Continued operation if some instances fail
  ✓ Graceful degradation under heavy load

Load balancing: Least Requests algorithm
  - Track cumulative requests per instance
  - Route new requests to instance with lowest count
  - Automatically favors faster-responding instances
  - Reset counters on topology changes for fairness
```

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
