//
// File: log.cpp
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

#include "log.hpp"

namespace common {
logger log(log_level::debug);

logger::logger(log_level level) { level_ = level; }

void logger::debug(const char *format, ...) {
  if (log_level::debug >= level_) {
    va_list args;
    va_start(args, format);
    log(log_level::debug, format, args);
    va_end(args);
  }
}

void logger::info(const char *format, ...) {
  if (log_level::info >= level_) {
    va_list args;
    va_start(args, format);
    log(log_level::info, format, args);
    va_end(args);
  }
}

void logger::warning(const char *format, ...) {
  if (log_level::warning >= level_) {
    va_list args;
    va_start(args, format);
    log(log_level::warning, format, args);
    va_end(args);
  }
}

void logger::error(const char *format, ...) {
  if (log_level::error >= level_) {
    va_list args;
    va_start(args, format);
    log(log_level::error, format, args);
    va_end(args);
  }
}

void logger::log(log_level msg_level, const char *format, va_list args) {
  if (msg_level >= level_) {
    // 加锁保护整个日志输出过程
    std::lock_guard<std::mutex> lock(mutex_);
    std::stringstream ss;
    format_message(ss, format, args);
    output_log(msg_level, ss.str());
  }
}

void logger::format_message(std::stringstream &ss, const char *format,
                                va_list args) {
  char buffer[256];
  vsnprintf(buffer, sizeof(buffer), format, args);
  ss << buffer;
}

void logger::output_log(log_level msg_level, const std::string &message) {
  std::string level_str;
  switch (msg_level) {
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

  std::cout << "[" << level_str << "] " << message << std::endl;

  // std::time_t now = std::time(nullptr);
  // std::string time_str = std::ctime(&now);
  // time_str.pop_back(); // Remove trailing newline character

  // std::cout << "[" << level_str << "] "
  //           << "[" << time_str << "] " << message << std::endl;
}
} // namespace common

