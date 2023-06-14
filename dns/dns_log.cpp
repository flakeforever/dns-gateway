//
// File: dns_log.cpp
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

#include "dns_log.hpp"

namespace dns
{
    dns_logger logger(log_level::info);
    
    dns_logger::dns_logger(log_level level)
    {
        level_ = level;
    }

    void dns_logger::debug(const char *format, ...)
    {
        va_list args;
        va_start(args, format);
        log(log_level::debug, format, args);
        va_end(args);
    }

    void dns_logger::info(const char *format, ...)
    {
        va_list args;
        va_start(args, format);
        log(log_level::info, format, args);
        va_end(args);
    }

    void dns_logger::warning(const char *format, ...)
    {
        va_list args;
        va_start(args, format);
        log(log_level::warning, format, args);
        va_end(args);
    }

    void dns_logger::error(const char *format, ...)
    {
        va_list args;
        va_start(args, format);
        log(log_level::error, format, args);
        va_end(args);
    }

    void dns_logger::log(log_level msg_level, const char *format, va_list args)
    {
        if (msg_level >= level_)
        {
            std::stringstream ss;
            format_message(ss, format, args);
            output_log(msg_level, ss.str());
        }
    }

    void dns_logger::format_message(std::stringstream &ss, const char *format, va_list args)
    {
        char buffer[256];
        vsnprintf(buffer, sizeof(buffer), format, args);
        ss << buffer;
    }

    void dns_logger::output_log(log_level msg_level, const std::string &message)
    {
        std::string level_str;
        switch (msg_level)
        {
        case log_level::debug:
            level_str = "debug";
            break;
        case log_level::info:
            level_str = "info";
            break;
        case log_level::warning:
            level_str = "warning";
            break;
        case log_level::error:
            level_str = "error";
            break;
        }

        std::time_t now = std::time(nullptr);
        std::string time_str = std::ctime(&now);
        time_str.pop_back(); // Remove trailing newline character

        std::cout << "[" << level_str << "] "
                  << "[" << time_str << "] " << message << std::endl;
    }
}
