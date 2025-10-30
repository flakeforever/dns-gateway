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

# Detect cross-compilation from CROSS_COMPILE environment variable
if(DEFINED ENV{CROSS_COMPILE})
    set(CROSS_PREFIX $ENV{CROSS_COMPILE})
    # Extract architecture from CROSS_COMPILE (e.g., aarch64-linux-gnu- -> aarch64)
    string(REGEX REPLACE "^([^-]+)-.*" "\\1" DETECTED_ARCH "${CROSS_PREFIX}")
    
    set(CMAKE_SYSTEM_NAME Linux)
    set(CMAKE_SYSTEM_PROCESSOR ${DETECTED_ARCH})
    set(CMAKE_C_COMPILER ${CROSS_PREFIX}gcc)
    set(CMAKE_CXX_COMPILER ${CROSS_PREFIX}g++)
    set(CMAKE_AR ${CROSS_PREFIX}ar)
    set(CMAKE_RANLIB ${CROSS_PREFIX}ranlib)
    set(CMAKE_STRIP ${CROSS_PREFIX}strip)
endif()

project(dns-gateway VERSION 3.1)

# ========================================
# Build OpenSSL first
# ========================================
include(ExternalProject)

# Detect architecture for OpenSSL config
# In cross-compilation, CMAKE_SYSTEM_PROCESSOR may be set from compiler detection
set(TARGET_ARCH "${CMAKE_SYSTEM_PROCESSOR}")

if(CMAKE_CROSSCOMPILING)
    # Extract architecture from compiler name
    # e.g., aarch64-linux-gnu-gcc -> aarch64
    get_filename_component(COMPILER_NAME "${CMAKE_C_COMPILER}" NAME)
    if(COMPILER_NAME MATCHES "^([^-]+)-")
        set(TARGET_ARCH "${CMAKE_MATCH_1}")
    endif()
endif()

if(TARGET_ARCH MATCHES "x86_64|amd64|AMD64")
    set(OPENSSL_ARCH "linux-x86_64")
elseif(TARGET_ARCH MATCHES "aarch64|arm64")
    set(OPENSSL_ARCH "linux-aarch64")
elseif(TARGET_ARCH MATCHES "armv7")
    set(OPENSSL_ARCH "linux-armv4")
elseif(TARGET_ARCH MATCHES "i386|i686")
    set(OPENSSL_ARCH "linux-x86")
elseif(TARGET_ARCH MATCHES "mips64")
    set(OPENSSL_ARCH "linux64-mips64")
elseif(TARGET_ARCH MATCHES "mips")
    set(OPENSSL_ARCH "linux-mips32")
else()
    message(WARNING "Unknown architecture ${TARGET_ARCH}, using linux-generic32")
    set(OPENSSL_ARCH "linux-generic32")
endif()

set(OPENSSL_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib/openssl")

# No extra configure args needed - rely on environment variables from build script
set(OPENSSL_CONFIGURE_EXTRA_ARGS "")

message(STATUS "========================================")
message(STATUS "OpenSSL Configuration:")
message(STATUS "  Architecture:    ${OPENSSL_ARCH}")
message(STATUS "  Cross-compile:   ${CMAKE_CROSSCOMPILING}")
if(CMAKE_CROSSCOMPILING)
    message(STATUS "  Cross prefix:    ${OPENSSL_CROSS_COMPILE}")
    message(STATUS "  C Compiler:      ${CMAKE_C_COMPILER}")
endif()
message(STATUS "  Source:          ${OPENSSL_SOURCE_DIR}")
message(STATUS "  Build in place:  YES (no install)")
message(STATUS "========================================")

# Build OpenSSL in-source, no install step
# OpenSSL will automatically use ${CROSS_COMPILE}gcc based on environment variable
ExternalProject_Add(openssl_build
    SOURCE_DIR ${OPENSSL_SOURCE_DIR}
    CONFIGURE_COMMAND ${OPENSSL_SOURCE_DIR}/Configure
        ${OPENSSL_ARCH}
        no-shared
        no-tests
        no-apps
    BUILD_COMMAND make -j
    INSTALL_COMMAND ""
    BUILD_IN_SOURCE 1
    LOG_CONFIGURE 1
    LOG_BUILD 1
)

set(OPENSSL_ROOT_DIR "${OPENSSL_SOURCE_DIR}")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_SOURCE_DIR}/include")
set(OPENSSL_SSL_LIBRARY "${OPENSSL_SOURCE_DIR}/libssl.a")
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_SOURCE_DIR}/libcrypto.a")

# ========================================
# nghttp2 static library
# ========================================
message(STATUS "Configuring nghttp2...")

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
set(ENABLE_APP OFF CACHE BOOL "" FORCE)
set(ENABLE_HPACK_TOOLS OFF CACHE BOOL "" FORCE)
set(ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ENABLE_DOC OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_THREADS ON CACHE BOOL "" FORCE)
set(ENABLE_HTTP3 OFF CACHE BOOL "" FORCE)

add_subdirectory(lib/nghttp2 EXCLUDE_FROM_ALL)

message(STATUS "nghttp2 configured successfully")

# ========================================
# Source files
# ========================================
set(SOURCES
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
    dns_utils.cpp
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

# ========================================
# Include directories
# ========================================
include_directories(.)
include_directories(lib/asio/asio/include)
include_directories(lib/json/include)
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(
    ${CMAKE_SOURCE_DIR}/lib/nghttp2/lib/includes
    ${CMAKE_BINARY_DIR}/lib/nghttp2/lib/includes
)

add_definitions(-DASIO_STANDALONE)

# ========================================
# Executable
# ========================================
add_executable(dns-gateway ${SOURCES})

target_compile_features(dns-gateway PRIVATE cxx_std_20)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(dns-gateway PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

# ========================================
# Dependencies
# ========================================
# Ensure OpenSSL is built before dns-gateway
add_dependencies(dns-gateway openssl_build)

# Full static linking for embedded systems
# Note: This causes linker warnings about dlopen, getaddrinfo, gethostbyname
# These warnings are safe to ignore if the target system has the same glibc version
set(CMAKE_EXE_LINKER_FLAGS "-static")

# Link libraries
target_link_libraries(dns-gateway PRIVATE
    nghttp2                      # nghttp2 static library
    ${OPENSSL_SSL_LIBRARY}       # OpenSSL SSL
    ${OPENSSL_CRYPTO_LIBRARY}    # OpenSSL Crypto
    pthread
    dl
)

# ========================================
# Build configuration
# ========================================
set(CMAKE_BUILD_TYPE Release)

install(TARGETS dns-gateway
    RUNTIME DESTINATION usr/bin
)

# ========================================
# Summary
# ========================================
message(STATUS "========================================")
message(STATUS "Build Summary:")
message(STATUS "  Project:      ${PROJECT_NAME} v${PROJECT_VERSION}")
message(STATUS "  Build Type:   ${CMAKE_BUILD_TYPE}")
message(STATUS "  System:       ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Processor:    ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "  C Compiler:   ${CMAKE_C_COMPILER}")
message(STATUS "  CXX Compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "  OpenSSL:      ${OPENSSL_ARCH} (static)")
message(STATUS "  nghttp2:      Static library")
message(STATUS "  Static Link:  Enabled")
message(STATUS "========================================")
