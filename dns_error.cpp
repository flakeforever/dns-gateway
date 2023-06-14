//
// File: dns_errors.cpp
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

#include "dns_error.hpp"

namespace dns
{
    namespace errc
    {
        const std::error_category &dns_error_category()
        {
            static dns_error_category_impl instance;
            return instance;
        }

        std::error_code make_error_code(dns::errc::error_code ec)
        {
            return std::error_code(static_cast<int>(ec), dns_error_category());
        }

        const char *dns_error_category_impl::name() const noexcept
        {
            return "dns_error_category";
        }

        std::string dns_error_category_impl::message(int ev) const noexcept
        {
            switch (static_cast<dns::errc::error_code>(ev))
            {
            case error_code::no_error:
                return "No error";
            case error_code::unknown_error:
                return "Unknown error";
            case error_code::client_not_ready:
                return "Client is not ready";
            case error_code::connection_error:
                return "Connection error";
            case error_code::request_failed:
                return "Request failed: Network error";
            case error_code::request_timeout:
                return "Request timeout: DNS lookup failed";
            case error_code::buffer_not_enough:
                return "DNS buffer is not enough";
            case error_code::http_header_invalid:
                return "HTTP header is invalid";
            case error_code::http_data_error:
                return "HTTP data error";
            }

            return "Unknown error: " + std::to_string(ev);
        }
    }
}