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

#pragma once

#include <iostream>
#include <sstream>
#include <ctime>
#include <cstdarg>
#include "property.hpp"

namespace dns
{
    enum class log_level
    {
        debug,
        info,
        warning,
        error
    };

    class logger_property
    {
    public:
        PROPERTY_READWRITE(log_level, level);
    };

    class dns_logger : public logger_property
    {
    public:
        dns_logger(log_level level = log_level::info);

        void debug(const char *format, ...);
        void info(const char *format, ...);
        void warning(const char *format, ...);
        void error(const char *format, ...);

    private:
        void log(log_level msg_level, const char *format, va_list args);
        void format_message(std::stringstream &ss, const char *format, va_list args);
        void output_log(log_level msg_level, const std::string &message);
    };

    extern dns_logger logger;
}