//
// File: log.hpp
// Description: This file contains the implementation of...
//
// Copyright (c) 2003-2025 The DNS-Gateway Authors.
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// This project uses the Asio library (https://think-async.com/Asio/) under the
// Boost Software License (https://www.boost.org/LICENSE_1_0.txt). This project
// uses OpenSSL (https://www.openssl.org) under the OpenSSL License
// (https://www.openssl.org/source/license.html).
//

#pragma once

#include <dns/property.hpp>
#include <cstdarg>
#include <ctime>
#include <iostream>
#include <mutex>
#include <sstream>

namespace common {
enum class log_level { debug, info, warning, error };

class logger_property {
public:
  PROPERTY_READWRITE(log_level, level);
};

class logger : public logger_property {
public:
  logger(log_level level = log_level::info);

  void debug(const char *format, ...);
  void info(const char *format, ...);
  void warning(const char *format, ...);
  void error(const char *format, ...);

private:
  void log(log_level msg_level, const char *format, va_list args);
  void format_message(std::stringstream &ss, const char *format, va_list args);
  void output_log(log_level msg_level, const std::string &message);
  
  std::mutex mutex_;  // 保护日志输出的互斥锁
};

extern logger log;
} // namespace common

