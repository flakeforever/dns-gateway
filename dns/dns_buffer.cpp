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
#include <stack>
#include <arpa/inet.h>

namespace dns
{
    dns_buffer::dns_buffer(size_t initial_capacity)
        : data_(nullptr)
    {
        size_ = 0;
        capacity_ = 0;
        position_ = 0;

        reserve(initial_capacity);
    }

    dns_buffer::~dns_buffer()
    {
        clear();

        if (data_)
        {
            delete[] data_;
            data_ = nullptr;
        }        
    }

    void dns_buffer::clear()
    {
        resize(0);
        position(0);
        label_map_.clear();
    }

    void dns_buffer::reserve(size_t new_capacity)
    {
        if (new_capacity > capacity_)
        {
            uint8_t *new_data = new uint8_t[new_capacity];
            if (data_)
            {
                std::copy(data_, data_ + size_, new_data);
                delete[] data_;
            }
            data_ = new_data;
            capacity_ = new_capacity;
        }
    }

    void dns_buffer::resize(size_t new_size)
    {
        if (new_size < size_)
        {
            size_ = new_size;
            position_ = std::min(position_, size_);
        }
        else if (new_size > size_)
        {
            reserve(new_size);
            std::memset(data_ + size_, 0, new_size - size_);
            size_ = new_size;
            position_ = std::min(position_, size_);
        }
    }

    void dns_buffer::write_8bits(uint8_t value)
    {
        reserve(size_ + 1);
        data_[position_++] = static_cast<char>(value);
        size_ = std::max(size_, position_);
    }

    void dns_buffer::write_16bits(uint16_t value)
    {
        reserve(size_ + 2);

        value = htons(value);
        char *ptr = reinterpret_cast<char *>(&value);
        std::copy(ptr, ptr + 2, data_ + position_);
        position_ += 2;
        size_ = std::max(size_, position_);
    }

    void dns_buffer::write_32bits(uint32_t value)
    {
        reserve(size_ + 4);

        value = htonl(value);
        char *ptr = reinterpret_cast<char *>(&value);
        std::copy(ptr, ptr + 4, data_ + position_);
        position_ += 4;
        size_ = std::max(size_, position_);
    }

    void dns_buffer::write_buffer(const char *buffer, size_t length)
    {
        reserve(size_ + length);
        std::copy(buffer, buffer + length, data_ + position_);
        position_ += length;
        size_ = std::max(size_, position_);
    }

    // Write a domain to the buffer
    void dns_buffer::write_domain(const std::string &domain)
    {
        size_t start_pos = position_;

        // Split the domain into labels
        std::string::size_type label_start = 0;
        std::string::size_type label_end = domain.find('.');
        std::string label;
        bool first_label = true;

        while (label_end != std::string::npos)
        {
            label = domain.substr(label_start, label_end - label_start);

            // Check if the label already exists in the label map
            auto it = label_map_.find(label);
            if (it != label_map_.end())
            {
                // Write a compressed pointer to the existing label
                uint16_t offset = it->second | 0xC000;
                write_16bits(offset);
                return;
            }

            // Write the label length and data to the buffer
            uint8_t label_length = static_cast<uint8_t>(label.length());
            write_8bits(label_length);
            write_buffer(label.c_str(), label_length);

            // Add the label to the label map
            if (!first_label)
                label_map_[label] = start_pos;

            start_pos = position_;

            // Move to the next label
            label_start = label_end + 1;
            label_end = domain.find('.', label_start);
            first_label = false;
        }

        // Write the final label and the terminating zero
        label = domain.substr(label_start);
        uint8_t label_length = static_cast<uint8_t>(label.length());
        write_8bits(label_length);
        write_buffer(label.c_str(), label_length);
        write_8bits(0);

        // Add the label to the label map
        if (!first_label)
            label_map_[label] = start_pos;
    }

    void dns_buffer::write_text(const std::string &str)
    {
        write_8bits(static_cast<uint16_t>(str.length()));
        write_buffer(str.c_str(), str.length());
    }

    uint8_t dns_buffer::read_8bits()
    {
        if (position_ < size_)
        {
            return static_cast<uint8_t>(data_[position_++]);
        }
        else
        {
            // process exception
            return 0;
        }
    }

    uint16_t dns_buffer::read_16bits()
    {
        if (position_ + 2 <= size_)
        {
            uint16_t value;
            char *ptr = reinterpret_cast<char *>(&value);
            std::copy(data_ + position_, data_ + position_ + 2, ptr);
            position_ += 2;
            return ntohs(value);
        }
        else
        {
            // process exception or error
            return 0;
        }
    }

    uint32_t dns_buffer::read_32bits()
    {
        if (position_ + 4 <= size_)
        {
            uint32_t value;
            char *ptr = reinterpret_cast<char *>(&value);
            std::copy(data_ + position_, data_ + position_ + 4, ptr);
            position_ += 4;
            return ntohl(value);
        }
        else
        {
            // process exception or error
            return 0;
        }
    }

    bool dns_buffer::read_buffer(char *buffer, size_t length)
    {
        if (position_ + length <= size_)
        {
            std::copy(data_ + position_, data_ + position_ + length, buffer);
            position_ += length;
        }
        else
        {
            return false;
        }

        return true;
    }

    // Read a domain from the buffer
    std::string dns_buffer::read_domain()
    {
        uint8_t len;
        int i = 0;
        std::stack<uint16_t> pointers;

        while (data_[position_] != 0)
        {
            len = read_8bits();

            // Check if it is an offset of a previously appeared name
            if ((len & 0xC0) == 0xC0) // Pointer
            {
                uint16_t offset = ((len & 0x3F) << 8) | read_8bits();
                offset &= 0x3FFF;

                // Push the current position before jumping to the offset
                pointers.push(position_);

                position_ = offset;
            }
            else
            {
                read_buffer(name_buffer_ + i, len);
                i += len;
                name_buffer_[i] = '.';
                i++;
            }
        }

        if (data_[position_] == 0)
            position_++;

        while (!pointers.empty())
        {
            position_ = pointers.top();
            pointers.pop();
        }

        name_buffer_[i - 1] = 0;
        std::string domain(name_buffer_);
        return domain;
    }

    std::string dns_buffer::read_text()
    {
        uint8_t length = read_8bits();
        char *buffer = new char[length + 1];
        if (read_buffer(buffer, length))
        {
            buffer[length] = '\0';
            std::string str(buffer);
            delete[] buffer;
            return str;
        }
        else
        {
            delete[] buffer;
            return "";
        }
    }

    uint8_t *dns_buffer::data() const
    {
        return data_;
    }
}