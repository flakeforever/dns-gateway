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

semaphore_object::semaphore_object()
{
}

semaphore::semaphore()
{
}

void semaphore::add_object(std::shared_ptr<semaphore_object> obj)
{
    std::lock_guard<std::mutex> lock(mutex_);
    objects_.push_back(obj);
}

std::shared_ptr<semaphore_object> semaphore::get_object()
{
    std::unique_lock<std::mutex> lock(mutex_);
    condition_.wait(lock, [this]
                    { return !objects_.empty(); });

    auto obj = objects_.back();
    objects_.pop_back();

    return obj;
}

void semaphore::notify(std::shared_ptr<semaphore_object> obj)
{
    // obj->cancel_timer(); // Cancel the timer for the object
    // obj->print_elapsed_time(); // Print the elapsed time
    {
        std::lock_guard<std::mutex> lock(mutex_);
        objects_.push_back(obj);
    }

    condition_.notify_one();
}

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
    : lock_(mutex, std::try_to_lock), timer_(executor)
{
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
