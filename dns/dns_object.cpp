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
dns_object::dns_object() 
    : completed_(false), error_code_{}, wakeup_signal_(nullptr) {}

dns_object::~dns_object() {}

void dns_object::init_for_request(asio::any_io_executor executor) {
  if (!wakeup_signal_) {
    wakeup_signal_ = std::make_shared<async_event>(executor);
  } else {
    wakeup_signal_->reset();
  }
  completed_.store(false, std::memory_order_release);
  error_code_.clear();
}

dns_object_pool::dns_object_pool(asio::any_io_executor executor, int min_pools,
                                 int max_pool)
    : executor_(executor), mutex_(executor), min_pools_(min_pools), max_pool_(max_pool) {
  init_object(min_pools_);
}

asio::awaitable<dns_object *> dns_object_pool::get_object() {
  async_mutex_lock lock(mutex_);
  co_await lock.get_lock();

  // Check if there is an available object in static_objects_
  dns_object *object = nullptr;
  if (!static_objects_.empty()) {
    object = static_objects_.back();
    static_objects_.pop_back();
    active_objects_.push_back(object);
  } else {
    if (static_objects_.size() + active_objects_.size() >= max_pool_) {
      co_return nullptr;
    }

    // Create a dynamic_object and add it to active_objects_
    object = new dns_object();
    object->type_ = dns_object::object_type::dynamic_object;
    active_objects_.push_back(object);
  }

  // Initialize object for request (done at construction/retrieval time)
  object->init_for_request(executor_);
  
  co_return object;
}

asio::awaitable<void> dns_object_pool::release_object(dns_object *object) {
  async_mutex_lock lock(mutex_);
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