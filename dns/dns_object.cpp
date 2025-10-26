//
// File: dns_object.cpp
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

#include "dns_object.hpp"
#include "operation.hpp"

namespace dns {
dns_object::dns_object() {}

dns_object::~dns_object() {}

dns_object_pool::dns_object_pool(asio::any_io_executor executor, int min_pools,
                                 int max_pool)
    : executor_(executor), min_pools_(min_pools), max_pool_(max_pool) {
  init_object(min_pools_);
}

asio::awaitable<dns_object *> dns_object_pool::get_object() {
  await_coroutine_lock lock(executor_, locked_);
  co_await lock.get_lock();

  // Check if there is an available object in static_objects_
  if (!static_objects_.empty()) {
    auto object = static_objects_.back();
    static_objects_.pop_back();
    active_objects_.push_back(object);
    co_return object;
  }

  if (static_objects_.size() + active_objects_.size() >= max_pool_) {
    co_return nullptr;
  }

  // Create a dynamic_object and add it to active_objects_
  auto object = new dns_object();
  object->type_ = dns_object::object_type::dynamic_object;
  active_objects_.push_back(object);
  co_return object;
}

asio::awaitable<void> dns_object_pool::release_object(dns_object *object) {
  await_coroutine_lock lock(executor_, locked_);
  co_await lock.get_lock();

  // Remove the object from active_objects_
  active_objects_.erase(
      std::remove(active_objects_.begin(), active_objects_.end(), object),
      active_objects_.end());

  // Check the object type and handle accordingly
  if (object->type_ == dns_object::object_type::static_object) {
    static_objects_.push_back(object);
  } else {
    delete object; // Release the dynamic object
  }

  co_return;
}

void dns_object_pool::init_object(int min_pools) {
  for (int i = 0; i < min_pools; ++i) {
    auto object = new dns_object();
    object->type_ = dns_object::object_type::static_object;
    static_objects_.push_back(object);
  }
}
} // namespace dns