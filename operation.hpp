//
// File: operation.hpp
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

#include <cstdlib>
#include <iostream>
#include <chrono>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <vector>
#include <asio.hpp>
#include <asio/experimental/awaitable_operators.hpp>

using namespace asio;
using namespace asio::experimental::awaitable_operators;

class semaphore_object : public std::enable_shared_from_this<semaphore_object>
{
    // Define your custom object, add members and methods as per your requirements
};

class semaphore
{
public:
    explicit semaphore();

    void add_object(std::shared_ptr<semaphore_object> obj);
    std::shared_ptr<semaphore_object> get_object();
    void notify(std::shared_ptr<semaphore_object> obj);

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    std::vector<std::shared_ptr<semaphore_object>> objects_;
};

class async_wait
{
public:
    async_wait(asio::any_io_executor executor);

    asio::awaitable<void> wait_until(std::chrono::milliseconds duration,
                                     std::function<void(bool &)> callback);
    asio::awaitable<void> wait_until(std::chrono::milliseconds duration,
                                     std::function<asio::awaitable<void>(bool &)> callback);

protected:
    asio::awaitable<void> wait(std::chrono::milliseconds duration);

private:
    asio::steady_timer timer_;
};

class async_execute
{
public:
    async_execute(asio::any_io_executor executor);

    asio::awaitable<void> execute_until(std::chrono::milliseconds duration,
                                        std::function<asio::awaitable<void>(asio::steady_timer &)> callback);

    bool timeout() const;

protected:
    asio::awaitable<void> check_timeout(std::chrono::milliseconds duration);

    bool timeout_;

private:
    asio::steady_timer timer_;
};
