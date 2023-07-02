//
// File: dns_errors.hpp
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

#include <system_error>

namespace dns
{
    namespace errc
    {
        enum class error_code
        {
            no_error = 0,
            unknown_error = 1000,
            client_not_ready,
            connection_error,
            
            request_failed,
            request_timeout,
            buffer_not_enough,
            buffer_format_error,
            buffer_out_of_range,
            http_header_invalid,
            http_data_error,
        };

        class dns_error_category_impl : public std::error_category
        {
        public:
            const char *name() const noexcept override;
            std::string message(int ev) const noexcept override;
        };

        std::error_code make_error_code(dns::errc::error_code ec);
    }
}