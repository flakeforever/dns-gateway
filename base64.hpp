//
// File: base64.hpp
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

#include <cstring>
#include <string>
#include <vector>

namespace base64
{
    std::string encode(const char *data, size_t length);
    size_t decode(const std::string &base64_string, char *output, size_t output_size);

    namespace internal
    {
        const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        inline bool is_base64(char c)
        {
            return (std::isalnum(c) || (c == '+') || (c == '/'));
        }
    }

    std::string encode(const char *data, size_t length)
    {
        const unsigned char *bytes_to_encode = reinterpret_cast<const unsigned char *>(data);
        size_t in_len = length;

        std::string encoded_string;
        encoded_string.reserve(((in_len + 2) / 3) * 4);

        for (size_t i = 0; i < in_len; i += 3)
        {
            unsigned char byte1 = bytes_to_encode[i];
            unsigned char byte2 = (i + 1 < in_len) ? bytes_to_encode[i + 1] : 0;
            unsigned char byte3 = (i + 2 < in_len) ? bytes_to_encode[i + 2] : 0;

            unsigned char char1 = byte1 >> 2;
            unsigned char char2 = ((byte1 & 0x03) << 4) | (byte2 >> 4);
            unsigned char char3 = ((byte2 & 0x0F) << 2) | (byte3 >> 6);
            unsigned char char4 = byte3 & 0x3F;

            encoded_string.push_back(internal::base64_chars[char1]);
            encoded_string.push_back(internal::base64_chars[char2]);
            encoded_string.push_back(internal::base64_chars[char3]);
            encoded_string.push_back(internal::base64_chars[char4]);
        }

        size_t padding_size = 3 - (in_len % 3);
        if (padding_size < 3)
        {
            encoded_string.replace(encoded_string.size() - padding_size, padding_size, padding_size, '=');
        }

        return encoded_string;
    }

    size_t decode(const std::string &base64_string, char *output, size_t output_size)
    {
        size_t in_len = base64_string.size();
        if (in_len % 4 != 0)
        {
            return 0;
        }

        size_t out_len = (in_len / 4) * 3;
        if (base64_string[in_len - 1] == '=')
        {
            out_len--;
            if (base64_string[in_len - 2] == '=')
            {
                out_len--;
            }
        }

        if (out_len > output_size)
        {
            return 0;
        }

        std::vector<unsigned char> decoded_bytes;
        decoded_bytes.reserve(out_len);

        size_t i = 0;
        while (i < in_len)
        {
            unsigned char char1 = internal::base64_chars.find(base64_string[i++]);
            unsigned char char2 = internal::base64_chars.find(base64_string[i++]);
            unsigned char char3 = internal::base64_chars.find(base64_string[i++]);
            unsigned char char4 = internal::base64_chars.find(base64_string[i++]);

            unsigned char byte1 = (char1 << 2) | (char2 >> 4);
            unsigned char byte2 = ((char2 & 0x0F) << 4) | (char3 >> 2);
            unsigned char byte3 = ((char3 & 0x03) << 6) | char4;

            decoded_bytes.push_back(byte1);
            if (char3 != static_cast<unsigned char>('='))
            {
                decoded_bytes.push_back(byte2);
            }
            if (char4 != static_cast<unsigned char>('='))
            {
                decoded_bytes.push_back(byte3);
            }
        }

        std::memcpy(output, decoded_bytes.data(), out_len);
        return out_len;
    }
} // namespace base64
