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

# ========================================
# Build OpenSSL FIRST (before project() and compiler detection)
# ========================================
set(OPENSSL_SOURCE_DIR "${CMAKE_SOURCE_DIR}/lib/openssl")
set(OPENSSL_SSL_LIBRARY "${OPENSSL_SOURCE_DIR}/libssl.a")
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_SOURCE_DIR}/libcrypto.a")

# Check if OpenSSL libraries exist, build if not
if(NOT EXISTS "${OPENSSL_SSL_LIBRARY}" OR NOT EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
    message(STATUS "========================================")
    message(STATUS "OpenSSL libraries not found, building...")
    message(STATUS "========================================")
    
    # Determine target architecture
    # Check if building 32-bit on 64-bit system (linux-386)
    if(CMAKE_C_FLAGS MATCHES "-m32")
        set(TARGET_ARCH "i686")
        set(OPENSSL_CFLAGS "-m32")
        message(STATUS "Detected 32-bit build flags (-m32)")
    else()
        # Try to extract from compiler name (for cross-compilation)
        get_filename_component(COMPILER_NAME "${CMAKE_C_COMPILER}" NAME)
        if(COMPILER_NAME MATCHES "^(x86_64|aarch64|arm|i686|mips64|mips)-")
            set(TARGET_ARCH "${CMAKE_MATCH_1}")
            message(STATUS "Detected architecture from compiler: ${TARGET_ARCH}")
        else()
            # Fall back to system processor
            set(TARGET_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
            message(STATUS "Using system processor: ${TARGET_ARCH}")
        endif()
        set(OPENSSL_CFLAGS "")
    endif()
    
    if(TARGET_ARCH MATCHES "x86_64|amd64|AMD64")
        set(OPENSSL_TARGET "linux-x86_64")
    elseif(TARGET_ARCH MATCHES "aarch64|arm64")
        set(OPENSSL_TARGET "linux-aarch64")
    elseif(TARGET_ARCH MATCHES "armv7")
        set(OPENSSL_TARGET "linux-armv4")
    elseif(TARGET_ARCH MATCHES "i386|i686")
        set(OPENSSL_TARGET "linux-x86")
    else()
        set(OPENSSL_TARGET "linux-generic64")
    endif()
    
    message(STATUS "Target: ${OPENSSL_TARGET}")
    
    # Simple build - let OpenSSL detect the toolchain from CROSS_COMPILE
    message(STATUS "Building OpenSSL...")
    
    # Set CFLAGS for OpenSSL if needed (e.g., -m32 for linux-386)
    if(OPENSSL_CFLAGS)
        execute_process(
            COMMAND bash -c "CFLAGS='${OPENSSL_CFLAGS}' ./Configure ${OPENSSL_TARGET} no-shared no-tests no-apps"
            WORKING_DIRECTORY ${OPENSSL_SOURCE_DIR}
            RESULT_VARIABLE CONFIG_RESULT
        )
    else()
        execute_process(
            COMMAND ./Configure ${OPENSSL_TARGET} no-shared no-tests no-apps
            WORKING_DIRECTORY ${OPENSSL_SOURCE_DIR}
            RESULT_VARIABLE CONFIG_RESULT
        )
    endif()
    
    if(NOT CONFIG_RESULT EQUAL 0)
        message(FATAL_ERROR "OpenSSL configure failed!")
    endif()
    
    execute_process(
        COMMAND make -j4
        WORKING_DIRECTORY ${OPENSSL_SOURCE_DIR}
        RESULT_VARIABLE BUILD_RESULT
    )
    
    if(NOT BUILD_RESULT EQUAL 0)
        message(FATAL_ERROR "OpenSSL build failed!")
    endif()
    
    # Verify libraries were built
    if(NOT EXISTS "${OPENSSL_SSL_LIBRARY}" OR NOT EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
        message(FATAL_ERROR "OpenSSL libraries not found after build!")
    endif()
    
    message(STATUS "OpenSSL build completed successfully")
endif()

# ========================================
# NOW set cross-compilation tools (after OpenSSL built)
# ========================================
if(DEFINED ENV{CROSS_COMPILE})
    set(CROSS_PREFIX $ENV{CROSS_COMPILE})
    message(STATUS "Detected CROSS_COMPILE: ${CROSS_PREFIX}")
    
    set(CMAKE_C_COMPILER ${CROSS_PREFIX}gcc)
    set(CMAKE_CXX_COMPILER ${CROSS_PREFIX}g++)
    set(CMAKE_AR ${CROSS_PREFIX}ar)
    set(CMAKE_RANLIB ${CROSS_PREFIX}ranlib)
    set(CMAKE_STRIP ${CROSS_PREFIX}strip)
    
    string(REGEX REPLACE "^([^-]+)-.*" "\\1" DETECTED_ARCH "${CROSS_PREFIX}")
    set(CMAKE_SYSTEM_NAME Linux)
    set(CMAKE_SYSTEM_PROCESSOR ${DETECTED_ARCH})
endif()

# ========================================
# Initialize project (after OpenSSL and compiler setup)
# ========================================
project(dns-gateway VERSION 3.1)

set(OPENSSL_ROOT_DIR "${OPENSSL_SOURCE_DIR}")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_SOURCE_DIR}/include")

message(STATUS "========================================")
message(STATUS "OpenSSL Configuration:")
message(STATUS "  Include:         ${OPENSSL_INCLUDE_DIR}")
message(STATUS "  SSL Library:     ${OPENSSL_SSL_LIBRARY}")
message(STATUS "  Crypto Library:  ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "========================================")

# ========================================
# nghttp2 static library
# ========================================
message(STATUS "Configuring nghttp2...")

# Ensure cross-compilation tools are available to nghttp2
if(CMAKE_CROSSCOMPILING)
    message(STATUS "  nghttp2 cross-compile tools:")
    message(STATUS "    AR:      ${CMAKE_AR}")
    message(STATUS "    RANLIB:  ${CMAKE_RANLIB}")
endif()

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
# Note: OpenSSL is pre-built by workflow or manually

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
