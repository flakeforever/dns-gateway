//
// File: socks_buffer.cpp
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

#include "socks_buffer.hpp"

namespace socks {
socks_buffer::socks_buffer(size_t initial_capacity)
    : data_(nullptr), size_(0), capacity_(0), position_(0) {
  reserve(initial_capacity);
}

socks_buffer::~socks_buffer() { clear(); }

void socks_buffer::clear() {
  if (data_) {
    delete[] data_;
    data_ = nullptr;
  }
  size_ = 0;
  capacity_ = 0;
  position_ = 0;
}

void socks_buffer::reserve(size_t new_capacity) {
  if (new_capacity > capacity_) {
    char *new_data = new char[new_capacity];
    if (data_) {
      std::copy(data_, data_ + size_, new_data);
      delete[] data_;
    }
    data_ = new_data;
    capacity_ = new_capacity;
  }
}

void socks_buffer::resize(size_t new_size) {
  if (new_size < size_) {
    size_ = new_size;
    position_ = std::min(position_, size_);
  } else if (new_size > size_) {
    reserve(new_size);
    std::memset(data_ + size_, 0, new_size - size_);
    size_ = new_size;
    position_ = std::min(position_, size_);
  }
}

void socks_buffer::write_8bits(uint8_t value) {
  reserve(size_ + 1);
  data_[position_++] = static_cast<char>(value);
  size_ = std::max(size_, position_);
}

void socks_buffer::write_16bits(uint16_t value) {
  reserve(size_ + 2);
  char *ptr = reinterpret_cast<char *>(&value);
  std::copy(ptr, ptr + 2, data_ + position_);
  position_ += 2;
  size_ = std::max(size_, position_);
}

void socks_buffer::write_string(const std::string &str) {
  uint8_t length = static_cast<uint8_t>(str.length());
  reserve(size_ + 1 + length);
  data_[position_++] = static_cast<char>(length);
  std::copy(str.begin(), str.end(), data_ + position_);
  position_ += length;
  size_ = std::max(size_, position_);
}

void socks_buffer::write_buffer(const char *buffer, size_t length) {
  reserve(size_ + length);
  std::copy(buffer, buffer + length, data_ + position_);
  position_ += length;
  size_ = std::max(size_, position_);
}

bool socks_buffer::write_address(socks::address_type address_type,
                                 const std::string &address, uint16_t port) {
  if (address_type == socks::address_type::ipv4) {
    char ipv4_buffer[4];
    if (inet_pton(AF_INET, address.c_str(), ipv4_buffer)) {
      write_buffer(ipv4_buffer, sizeof(ipv4_buffer));
    } else {
      return false;
    }
  } else if (address_type == socks::address_type::domain) {
    write_string(address);
  } else if (address_type == socks::address_type::ipv6) {
    char ipv6_buffer[16];
    if (inet_pton(AF_INET6, address.c_str(), ipv6_buffer)) {
      write_buffer(ipv6_buffer, sizeof(ipv6_buffer));
    } else {
      return false;
    }
  }
  uint16_t port_value = htons(port);
  write_16bits(port_value);

  return true;
}

uint8_t socks_buffer::read_8bits() {
  if (position_ < size_) {
    return static_cast<uint8_t>(data_[position_++]);
  } else {
    // process exception
    return 0;
  }
}

uint16_t socks_buffer::read_16bits() {
  if (position_ + 2 <= size_) {
    uint16_t value;
    char *ptr = reinterpret_cast<char *>(&value);
    std::copy(data_ + position_, data_ + position_ + 2, ptr);
    position_ += 2;
    return value;
  } else {
    // process exception or error
    return 0;
  }
}

std::string socks_buffer::read_string() {
  if (position_ < size_) {
    uint8_t length = static_cast<uint8_t>(data_[position_++]);
    if (position_ + length <= size_) {
      std::string str(data_ + position_, data_ + position_ + length);
      position_ += length;
      return str;
    } else {
      // process exception
      return "";
    }
  } else {
    // process exception
    return "";
  }
}

bool socks_buffer::read_buffer(char *buffer, size_t length) {
  if (position_ + length <= size_) {
    std::copy(data_ + position_, data_ + position_ + length, buffer);
    position_ += length;
  } else {
    return false;
  }

  return true;
}

bool socks_buffer::read_address(socks::address_type address_type,
                                std::string &address, uint16_t &port) {
  if (address_type == socks::address_type::ipv4) {
    char ipv4_buffer[4];
    if (!read_buffer(ipv4_buffer, sizeof(ipv4_buffer))) {
      return false;
    }
    char ipv4_address[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, ipv4_buffer, ipv4_address, sizeof(ipv4_address))) {
      address = ipv4_address;
    } else {
      return false;
    }
  } else if (address_type == socks::address_type::domain) {
    address = read_string();
    if (address.empty()) {
      return false;
    }
  } else if (address_type == socks::address_type::ipv6) {
    char ipv6_buffer[16];
    if (!read_buffer(ipv6_buffer, sizeof(ipv6_buffer))) {
      return false;
    }
    char ipv6_address[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, ipv6_buffer, ipv6_address, sizeof(ipv6_address))) {
      address = ipv6_address;
    } else {
      return false;
    }
  }

  uint16_t port_value = read_16bits();
  port = ntohs(port_value);
  return true;
}

char *socks_buffer::data() const { return data_; }

size_t socks_buffer::size() const { return size_; }

size_t socks_buffer::position() const { return position_; }

void socks_buffer::set_position(size_t new_position) {
  position_ = std::min(new_position, size_);
}
} // namespace socks