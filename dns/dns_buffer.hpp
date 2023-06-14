//
// File: dns_buffer.hpp
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

#pragma once

#include <algorithm>
#include <cstring>
#include <cstdint>
#include <map>
#include "property.hpp"

namespace dns
{
    class dns_buffer_property
    {
    public:
        PROPERTY_READONLY(size_t, capacity);
        PROPERTY_READWRITE(size_t, position);
        PROPERTY_READONLY(size_t, size);
    };

    class dns_buffer : public dns_buffer_property
    {
    public:
        dns_buffer(size_t initial_capacity = 0);
        ~dns_buffer();

        void clear();
        void reserve(size_t new_capacity);
        void resize(size_t new_size);

        void write_8bits(uint8_t value);
        void write_16bits(uint16_t value);
        void write_32bits(uint32_t value);
        void write_buffer(const char *buffer, size_t length);
        size_t calculate_domain_size(const std::string &domain) const;
        void write_domain(const std::string &domain);
        void write_text(const std::string& str);

        uint8_t read_8bits();
        uint16_t read_16bits();
        uint32_t read_32bits();
        bool read_buffer(char *buffer, size_t length);
        std::string read_domain();
        std::string read_text();

        uint8_t *data() const;

    private:
        uint8_t *data_;
        char name_buffer_[256];
        std::map<std::string, uint16_t> label_map_;
    };
}