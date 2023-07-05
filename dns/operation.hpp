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
public:
    semaphore_object();

private:
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

class await_wait
{
public:
    await_wait(asio::any_io_executor executor);

    asio::awaitable<void> wait_until(std::chrono::milliseconds duration,
                                     std::function<void(bool &)> callback);
    asio::awaitable<void> wait_until(std::chrono::milliseconds duration,
                                     std::function<asio::awaitable<void>(bool &)> callback);

protected:
    asio::awaitable<void> wait(std::chrono::milliseconds duration);

private:
    asio::steady_timer timer_;
};

class coroutine_mutex
{
public:
    std::mutex mutex_;
    int access_count_ = 0;
};

class await_lock
{
public:
    await_lock(asio::any_io_executor executor, std::mutex &mutex);

    asio::awaitable<void> check_lock()
    {
        while (!lock_.owns_lock())
        {
            co_await wait(std::chrono::milliseconds(10));
            lock_.try_lock();
        }

        co_return;
    };
    
    std::unique_lock<std::mutex> lock_;
private:
    asio::awaitable<void> wait(std::chrono::milliseconds duration)
    {
        auto now = std::chrono::steady_clock::now();
        auto deadline = now + duration;

        timer_.expires_at(deadline);
        co_await timer_.async_wait(asio::use_awaitable);
    };

    asio::steady_timer timer_;
};

class await_coroutine_lock
{
public:
    await_coroutine_lock(asio::any_io_executor executor, coroutine_mutex *mutex)
        :await_lock_(executor, mutex->mutex_), timer_(executor)
    {
        mutex_ = mutex;
    }

    ~await_coroutine_lock()
    {
        mutex_->access_count_--;
    }

    asio::awaitable<void> check_lock()
    {
        co_await await_lock_.check_lock();

        while (mutex_->access_count_ != 0)
        {
            co_await wait(std::chrono::milliseconds(10));
        }

        mutex_->access_count_++;
        co_return;
    }; 

private:
    asio::awaitable<void> wait(std::chrono::milliseconds duration)
    {
        auto now = std::chrono::steady_clock::now();
        auto deadline = now + std::chrono::milliseconds(duration);

        timer_.expires_at(deadline);
        co_await timer_.async_wait(asio::use_awaitable);
    };

    coroutine_mutex *mutex_;
    await_lock await_lock_;
    asio::steady_timer timer_;
};

class await_timeout_execute
{
public:
    await_timeout_execute(asio::any_io_executor executor);

    asio::awaitable<void> execute_until(std::chrono::milliseconds duration,
                                        std::function<asio::awaitable<void>(asio::steady_timer &)> callback);

    bool timeout() const;

protected:
    asio::awaitable<void> check_timeout(std::chrono::milliseconds duration);

    bool timeout_;

private:
    asio::steady_timer timer_;
};
