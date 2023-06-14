//
// File: socks_buffer.hpp
// Description: This file contains the implementation of...
//
// Copyright (c) 2003-2023 The DNS-Gateway Authors.
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// This project uses the Asio library (https://think-async.com/Asio/) under the Boost Software License (https://www.boost.org/LICENSE_1_0.txt).
// This project uses OpenSSL (https://www.openssl.org) under the OpenSSL License (https://www.openssl.org/source/license.html).
//

#include <algorithm>
#include <cstring>
#include <cstdint>
#include "socks_common.hpp"

namespace socks
{
    class socks_buffer
    {
    public:
        socks_buffer(size_t initial_capacity = 0);
        ~socks_buffer();

        void clear();
        void reserve(size_t new_capacity);
        void resize(size_t new_size);

        void write_8bits(uint8_t value);
        void write_16bits(uint16_t value);
        void write_string(const std::string &str);
        void write_buffer(const char *buffer, size_t length);
        bool write_address(socks::address_type address_type, const std::string &address, uint16_t port);

        uint8_t read_8bits();
        uint16_t read_16bits();
        std::string read_string();
        bool read_buffer(char *buffer, size_t length);
        bool read_address(socks::address_type address_type, std::string &address, uint16_t &port);

        char *data() const;
        size_t size() const;

        size_t position() const;
        void set_position(size_t new_position);

    private:
        char *data_;
        size_t size_;
        size_t capacity_;
        size_t position_;
    };
}