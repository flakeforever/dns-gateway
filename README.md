<img src="https://github.com/flakeforever/dns-gateway/blob/main/dns-gateway.png" alt="DNS Gateway Logo" width="400" height="150">

DNS Gateway is a lightweight, efficient, and reliable recursive DNS gateway. It is built on top of asio and openssl libraries and utilizes multi-threading and C++20 coroutine mechanisms to provide excellent concurrency and scalability.

## Key Features

### Lightweight

DNS Gateway is designed with a focus on lightweightness, minimizing the utilization of system resources. It relies only on asio (standalone) + openssl as its underlying dependencies, avoiding unnecessary complexity and additional dependencies. Commonly used resources are allocated only once during the loading process, reducing resource allocation and deallocation overhead.

### Comprehensive Functionality

DNS Gateway offers a rich set of features, making it a comprehensive DNS gateway solution. It supports multiple upstream protocols, including:

- `UDP`: Enables communication with upstream DNS servers using the UDP protocol.
- `DNS over HTTPS`: Provides support for DNS resolution over encrypted HTTPS connections, ensuring privacy and security.
- `DNS over TLS`: Facilitates DNS resolution over TLS connections, offering an additional layer of encryption and authentication.
- `SOCKS5`: Allows accessing upstream servers through SOCKS5 proxies, providing flexibility and compatibility for different network setups.

Additionally, DNS Gateway provides domain routing functionality, allowing specific domains to be resolved by designated upstream servers. It also supports local static resolution and caching, enhancing resolution efficiency and response speed.

### High Efficiency

DNS Gateway strives for high efficiency in terms of performance. It provides a configurable thread pool that delivers remarkable concurrency performance even in single-threaded operation. Leveraging multi-threading asynchronous and C++20 coroutine mechanisms, DNS Gateway can handle multiple concurrent requests simultaneously, delivering fast and efficient DNS resolution services. Moreover, DNS Gateway supports a heartbeat mechanism to periodically check the availability of proxies and upstream servers, ensuring stable and reliable operation.

### Reliability

Reliability and stability are fundamental aspects of DNS Gateway's design. By supporting multiple upstream protocols and proxy access methods, DNS Gateway offers redundancy and failover mechanisms to ensure the availability of DNS resolution. It also incorporates caching functionality to reduce reliance on upstream servers and provide quick responses, while refreshing the cache based on TTL to maintain data accuracy.

## Getting Started

Please refer to the [Quick Start Guide](/docs/quickstart.md) for detailed instructions on how to install, configure, and run DNS Gateway.

## Compiling Instructions

To compile DNS Gateway, follow these steps:

1. Clone the project repository using Git:

   ```bash
   git clone <repository_url>
   cd your_path
   ```
 
2. Update the submodule dependencies:
   
   ```bash
   git submodule update --init
   ```
 
3. Create a build directory and navigate into it:

   ```bash
   mkdir build
   cd build
   ```
 
4. Run CMake to generate the build files:
   
   ```bash
   cmake ..
   ```
 
5. Build the project using the chosen build system (e.g., make):

   ```bash
   make
   ```
    
## Contributing

If you are interested in DNS Gateway and would like to contribute to the project, please refer to the [Contribution Guidelines](/docs/contributing.md) for more information.
