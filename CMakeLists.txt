#
#  File: CMakeLists.txt
#  Description: This file contains the implementation of...
#
#  Copyright (c) 2003-2023 The DNS-Gateway Authors.
#
#  Distributed under the Boost Software License, Version 1.0. (See accompanying
#  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
#

cmake_minimum_required(VERSION 3.18)
project(dns-gateway VERSION 1.0)

set(SOURCES
    lib/CxxUrl/url.cpp
    main.cpp  
)

set(DNS_SOURCES
    dns_buffer.cpp
    dns_cache.cpp
    dns_config.cpp
    dns_error.cpp
    dns_gateway.cpp
    dns_monitor.cpp
    dns_object.cpp
    dns_package.cpp
    dns_router.cpp
    dns_static.cpp
    dns_upstream.cpp
    dns_upstream_pool.cpp
    operation.cpp
)

set(COMMON_SOURCES
    log.cpp
)

set(SOCKS_SOURCES
    socks_buffer.cpp
    socks_client.cpp
    socks_common.cpp
    socks_error.cpp
)

list(TRANSFORM COMMON_SOURCES PREPEND "common/")
list(APPEND SOURCES ${COMMON_SOURCES})

list(TRANSFORM SOCKS_SOURCES PREPEND "socks/")
list(APPEND SOURCES ${SOCKS_SOURCES})

list(TRANSFORM DNS_SOURCES PREPEND "dns/")
list(APPEND SOURCES ${DNS_SOURCES})

add_executable(dns-gateway ${SOURCES} ${COMMON_SOURCES} ${DNS_SOURCES} ${SOCKS_SOURCES})

include_directories(.)

# include asio
include_directories(lib/asio/asio/include)
include_directories(lib/openssl/include)

target_compile_features(dns-gateway PRIVATE cxx_std_20)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(dns-gateway PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/lib/openssl")
set(OPENSSL_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/lib/openssl/include")
set(OPENSSL_USE_STATIC_LIBS TRUE) # Prefer static linking
set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/libssl.a")
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/libcrypto.a")
set(OPENSSL_LIBRARIES "${OPENSSL_SSL_LIBRARY}" "${OPENSSL_CRYPTO_LIBRARY}")

# Find OpenSSL (optional, for validation)
# find_package(OpenSSL REQUIRED)

set(CMAKE_EXE_LINKER_FLAGS "-static")

# Link OpenSSL statically
target_link_libraries(dns-gateway PRIVATE
    ${OPENSSL_SSL_LIBRARY}
    ${OPENSSL_CRYPTO_LIBRARY}
)

set(CMAKE_BUILD_TYPE Release)

install(TARGETS dns-gateway
    RUNTIME DESTINATION usr/bin
)