//
// File: dns_buffer.cpp
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

#include "dns_buffer.hpp"
#include "dns_error.hpp"
#include "dns_log.hpp"
#include <stack>
#include <arpa/inet.h>
#include <sstream>

namespace dns
{
    dns_buffer::dns_buffer(uint8_t *buffer, int buffer_size)
        : buffer_(buffer), buffer_size_(buffer_size)
    {
        size_ = 0;
        position_ = 0;
    }

    dns_buffer::~dns_buffer()
    {
        clear();
    }

    void dns_buffer::clear()
    {
        position(0);
        label_map_.clear();
    }

    void dns_buffer::assert_buffer(size_t operation_size)
    {
        if (position_ > buffer_size_ || position_ + operation_size > buffer_size_)
        {
            throw std::system_error(
                dns::errc::make_error_code(dns::errc::error_code::buffer_out_of_range));
        }
    }

    void dns_buffer::write_8bits(uint8_t value)
    {
        assert_buffer(sizeof(uint8_t));

        buffer_[position_++] = static_cast<char>(value);
        size_ = std::max(size_, position_);
    }

    void dns_buffer::write_16bits(uint16_t value)
    {
        assert_buffer(sizeof(uint16_t));

        value = htons(value);
        char *ptr = reinterpret_cast<char *>(&value);
        std::copy(ptr, ptr + 2, buffer_ + position_);
        position_ += 2;
        size_ = std::max(size_, position_);
    }

    void dns_buffer::write_32bits(uint32_t value)
    {
        assert_buffer(sizeof(uint32_t));

        value = htonl(value);
        char *ptr = reinterpret_cast<char *>(&value);
        std::copy(ptr, ptr + 4, buffer_ + position_);
        position_ += 4;
        size_ = std::max(size_, position_);
    }

    void dns_buffer::write_buffer(const char *buffer, size_t length)
    {
        assert_buffer(length);

        std::copy(buffer, buffer + length, buffer_ + position_);
        position_ += length;
        size_ = std::max(size_, position_);
    }

    uint16_t dns_buffer::get_label_ptr(const std::string label)
    {
        auto it = label_map_.find(label);
        if (it != label_map_.end())
        {
            return it->second;
        }

        return 0;
    }

    // Write a domain to the buffer
    void dns_buffer::write_domain(const std::string domain)
    {
        std::string curren_label = domain;
        std::string curren_name = domain;

        uint16_t label_ptr = get_label_ptr(curren_label);
        while (label_ptr == 0)
        {
            std::string sub_name = "";
            size_t dotPos = curren_name.find('.');
            if (dotPos != std::string::npos)
            {
                sub_name = curren_name.substr(0, dotPos);
                curren_name = curren_name.substr(dotPos + 1);
            }
            else
            {
                sub_name = curren_name;
                curren_name = "";
            }

            // write new label
            if (sub_name == "" || sub_name.length() > dns::max_label_size)
            {
                throw std::system_error(
                    dns::errc::make_error_code(dns::errc::error_code::buffer_format_error));
            }

            size_t start_pos = position_;
            write_text(sub_name);

            if (curren_name == "")
            {
                break;
            }

            label_map_[curren_label] = start_pos;
            curren_label = curren_name;

            label_ptr = get_label_ptr(curren_label);
        }

        if (curren_name != "" && label_ptr > 0)
        {
            uint16_t offset = label_ptr | 0xC000;
            write_16bits(offset);
        }
        else
        {
            write_8bits(0);
        }
    }

    void dns_buffer::write_text(const std::string text)
    {
        write_8bits(static_cast<uint16_t>(text.length()));
        write_buffer(text.c_str(), text.length());
    }

    uint8_t dns_buffer::read_8bits()
    {
        assert_buffer(sizeof(uint8_t));
        return static_cast<uint8_t>(buffer_[position_++]);
    }

    uint16_t dns_buffer::read_16bits()
    {
        assert_buffer(sizeof(uint16_t));

        uint16_t value;
        char *ptr = reinterpret_cast<char *>(&value);
        std::copy(buffer_ + position_, buffer_ + position_ + 2, ptr);
        position_ += 2;
        return ntohs(value);
    }

    uint32_t dns_buffer::read_32bits()
    {
        assert_buffer(sizeof(uint32_t));

        uint32_t value;
        char *ptr = reinterpret_cast<char *>(&value);
        std::copy(buffer_ + position_, buffer_ + position_ + 4, ptr);
        position_ += 4;
        return ntohl(value);
    }

    void dns_buffer::read_buffer(char *buffer, size_t length)
    {
        assert_buffer(length);

        std::copy(buffer_ + position_, buffer_ + position_ + length, buffer);
        position_ += length;
    }

    // Read a domain from the buffer
    std::string dns_buffer::read_domain()
    {
        std::string result = "";
        size_t current_pos = 0;

        uint8_t len = read_8bits();
        while (len != 0)
        {
            std::string label = "";
            if ((len & 0xC0) == 0xC0) // Check if it is a pointer
            {
                uint16_t offset = ((len & 0x3F) << 8) | read_8bits();

                if (current_pos == 0)
                {
                    current_pos = position_;
                }

                position_ = offset;
            }
            else
            {
                position_ -= 1;
                label = read_text();
                if (label == "" || label.length() > dns::max_label_size)
                {
                    throw std::system_error(
                        dns::errc::make_error_code(dns::errc::error_code::buffer_format_error));
                }

                if (result != "")
                {
                    result += ".";
                }

                result += label;
            }

            len = read_8bits();
        }

        if (current_pos > 0)
        {
            position_ = current_pos;
        }

        return result;
    }

    std::string dns_buffer::read_text()
    {
        uint8_t length = read_8bits();
        char *buffer = new char[length + 1];
        read_buffer(buffer, length);

        buffer[length] = '\0';
        std::string str(buffer);
        delete[] buffer;
        return str;
    }

    char *dns_buffer::data() const
    {
        return (char *)&buffer_[0];
    }
}