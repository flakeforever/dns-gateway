//
// File: operation.cpp
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

#include "operation.hpp"

await_wait::await_wait(asio::any_io_executor executor)
    : timer_(executor)
{
}

asio::awaitable<void> await_wait::wait_until(std::chrono::milliseconds duration, std::function<void(bool &)> callback)
{
    bool finished = false;
    while (!finished)
    {
        co_await wait(duration);
        callback(finished);
    }
}

asio::awaitable<void> await_wait::wait_until(std::chrono::milliseconds duration, std::function<asio::awaitable<void>(bool &)> callback)
{
    bool finished = false;
    while (!finished)
    {
        co_await wait(duration);
        co_await callback(finished);
    }
}

asio::awaitable<void> await_wait::wait(std::chrono::milliseconds duration)
{
    auto now = std::chrono::steady_clock::now();
    auto deadline = now + duration;

    timer_.expires_at(deadline);
    co_await timer_.async_wait(asio::use_awaitable);
}

await_lock::await_lock(asio::any_io_executor executor, std::mutex &mutex)
    : lock_(mutex), timer_(executor)
{
}

asio::awaitable<void> await_lock::check_lock()
{
    while (!lock_.owns_lock())
    {
        co_await wait(std::chrono::milliseconds(check_interval));
        lock_.try_lock();
    }

    co_return;
}

asio::awaitable<void> await_lock::wait(std::chrono::milliseconds duration)
{
    auto now = std::chrono::steady_clock::now();
    auto deadline = now + duration;

    timer_.expires_at(deadline);
    co_await timer_.async_wait(asio::use_awaitable);
}

await_coroutine_lock::await_coroutine_lock(asio::any_io_executor executor, coroutine_mutex *mutex)
    : mutex_(mutex), await_lock_(executor, mutex->mutex_), timer_(executor)
{
    own_lock_ = false;
}

await_coroutine_lock::~await_coroutine_lock()
{
    if (own_lock_)
    {
        mutex_->access_count_.store(0, std::memory_order_relaxed);
    }
}

asio::awaitable<void> await_coroutine_lock::check_lock()
{
    co_await await_lock_.check_lock();

    while (mutex_->access_count_.load(std::memory_order_relaxed) != 0)
    {
        co_await wait(std::chrono::milliseconds(check_interval));
    }

    mutex_->access_count_.store(1, std::memory_order_relaxed);
    own_lock_ = true;

    co_return;
}

asio::awaitable<void> await_coroutine_lock::wait(std::chrono::milliseconds duration)
{
    auto now = std::chrono::steady_clock::now();
    auto deadline = now + std::chrono::milliseconds(duration);

    timer_.expires_at(deadline);
    co_await timer_.async_wait(asio::use_awaitable);
}

await_timeout_execute::await_timeout_execute(asio::any_io_executor executor)
    : timeout_(false), timer_(executor)
{
}

asio::awaitable<void> await_timeout_execute::execute_until(
    std::chrono::milliseconds duration, std::function<asio::awaitable<void>(asio::steady_timer &)> callback)
{
    try
    {
        /**
        The logic below ensures that the check_timeout condition is evaluated first before the callback.
        This change was made to address a design flaw where placing the callback first could result in
        the callback returning too quickly, before the asynchronous timer is even started.
        By swapping the order, we ensure that the timeout condition is checked first, allowing enough time
        for the asynchronous timer to start before invoking the callback.
        */
        co_await (check_timeout(duration) && callback(timer_));
    }
    catch (const std::exception &e)
    {
        // ignore all system errors
    }

    co_return;
}

bool await_timeout_execute::timeout() const
{
    return timeout_;
}

asio::awaitable<void> await_timeout_execute::check_timeout(std::chrono::milliseconds duration)
{
    try
    {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(duration);

        timer_.expires_at(deadline);
        co_await timer_.async_wait(asio::use_awaitable);
        timeout_ = true;
    }
    catch (const std::system_error &e)
    {
        // ignore cancel timer error
        if (e.code() != asio::error::operation_aborted)
        {
            // throw other errors
            throw e;
        }

        co_return;
    }

    // throw time out error
    throw std::system_error(std::make_error_code(std::errc::timed_out));
}
