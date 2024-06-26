#
#  File: CMakeLists.txt
#  Description: This file contains the implementation of...
#
#  Copyright (c) 2003-2023 The DNS-Gateway Authors.
#
#  Distributed under the Boost Software License, Version 1.0. (See accompanying
#  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
#

cmake_minimum_required(VERSION 3.0)
project(dns-gateway VERSION 1.0)

set(SOURCES
    lib/CxxUrl/url.cpp

    config.cpp
    main.cpp  
)

set(DNS_SOURCES
    operation.cpp

    dns_buffer.cpp
    dns_cache.cpp
    dns_error.cpp
    dns_gateway.cpp
    dns_log.cpp
    dns_object.cpp
    dns_package.cpp
    dns_router.cpp
    dns_static.cpp
    dns_upstream.cpp
)

set(SOCKS_SOURCES
    socks_buffer.cpp
    socks_client.cpp
    socks_common.cpp
    socks_error.cpp
)

list(TRANSFORM SOCKS_SOURCES PREPEND "dns/socks/")
list(APPEND SOURCES ${SOCKS_SOURCES})

list(TRANSFORM DNS_SOURCES PREPEND "dns/")
list(APPEND SOURCES ${DNS_SOURCES})

add_executable(dns-gateway ${SOURCES} ${DNS_SOURCES} ${SOCKS_SOURCES})

# include asio
include_directories(lib/asio/asio/include)

target_compile_features(dns-gateway PRIVATE cxx_std_20)
target_compile_options(dns-gateway PRIVATE -Wall -Wextra -Wno-unused-parameter)

target_link_libraries(dns-gateway PRIVATE
    libssl.so
    libcrypto.so
)

set(CMAKE_BUILD_TYPE Release)

install(TARGETS dns-gateway
    RUNTIME DESTINATION usr/bin
)