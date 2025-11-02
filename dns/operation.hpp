//
// File: operation.hpp
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

#include <asio.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <vector>

using namespace asio;
using namespace asio::experimental::awaitable_operators;

constexpr int check_interval = 10;

class async_event {
public:
    explicit async_event(asio::any_io_executor executor)
        : executor_(executor), count_(0) {}

    asio::awaitable<void> wait() {
        // Check if signal is available
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (count_ > 0) {
                --count_;
                co_return;
            }
        }
        
        // Create a timer with shared ownership
        auto timer = std::make_shared<asio::steady_timer>(executor_);
        timer->expires_at(asio::steady_timer::time_point::max());
        
        // Register this timer as a waiter (shared_ptr ensures it stays alive)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            waiters_.push_back(timer);
        }
        
        // Wait on the timer (will be cancelled by notify())
        asio::error_code ec;
        co_await timer->async_wait(asio::redirect_error(asio::use_awaitable, ec));
        
        // Timer was cancelled or errored, check if we got the signal
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // Try to find and remove ourselves from waiters
            auto it = std::find(waiters_.begin(), waiters_.end(), timer);
            if (it != waiters_.end()) {
                // Still in queue, we were woken spuriously or timed out
                // Remove ourselves and check count
                waiters_.erase(it);
                
                if (count_ > 0) {
                    --count_;
                    co_return;
                }
            } else {
                // Not in queue, notify() removed us and we got the signal
                co_return;
            }
        }
        
        // Spurious wakeup without signal, should not happen with this design
        // but wait again to be safe
        co_await wait();
    }

    void notify() {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!waiters_.empty()) {
            auto timer = waiters_.front();
            waiters_.pop_front();
            lock.unlock();
            // Cancel the timer in the executor context to wake up the waiting coroutine
            asio::post(executor_, [timer]() {
                timer->cancel();
            });
        } else {
            ++count_;
        }
    }

    void reset() {
        std::unique_lock<std::mutex> lock(mutex_);
        // Cancel all waiting timers in the executor context and clear the queue
        auto timers_to_cancel = waiters_;
        waiters_.clear();
        count_ = 0;
        lock.unlock();
        
        // Cancel timers in executor context
        for (auto& timer : timers_to_cancel) {
            asio::post(executor_, [timer]() {
                timer->cancel();
            });
        }
    }

private:
    asio::any_io_executor executor_;
    std::mutex mutex_;
    int count_;
    std::deque<std::shared_ptr<asio::steady_timer>> waiters_;
};

class async_wait {
public:
  explicit async_wait(asio::any_io_executor executor) : timer_(executor) {}

  asio::awaitable<void> wait_until(std::chrono::milliseconds duration,
                                   std::function<void(bool &)> callback) {
    bool finished = false;
    while (!finished) {
      co_await wait(duration);
      callback(finished);
    }
  }

  asio::awaitable<void>
  wait_until(std::chrono::milliseconds duration,
             std::function<asio::awaitable<void>(bool &)> callback) {
    bool finished = false;
    while (!finished) {
      co_await wait(duration);
      co_await callback(finished);
    }
  }

protected:
  asio::awaitable<void> wait(std::chrono::milliseconds duration) {
    auto now = std::chrono::steady_clock::now();
    auto deadline = now + duration;

    timer_.expires_at(deadline);
    co_await timer_.async_wait(asio::use_awaitable);
  }

private:
  asio::steady_timer timer_;
};

class async_timeout_execute {
public:
  explicit async_timeout_execute(asio::any_io_executor executor)
      : timeout_(false), timer_(executor) {}

  asio::awaitable<void> execute_until(
      std::chrono::milliseconds duration,
      std::function<asio::awaitable<void>(asio::steady_timer &)> callback) {
    try {
      /**
      The logic below ensures that the check_timeout condition is evaluated first
      before the callback. This change was made to address a design flaw where
      placing the callback first could result in the callback returning too
      quickly, before the asynchronous timer is even started. By swapping the
      order, we ensure that the timeout condition is checked first, allowing
      enough time for the asynchronous timer to start before invoking the
      callback.
      */
      co_await (check_timeout(duration) && callback(timer_));
    } catch (const std::exception &e) {
      // ignore all system errors
    }

    co_return;
  }

  bool timeout() const { return timeout_; }

protected:
  asio::awaitable<void> check_timeout(std::chrono::milliseconds duration) {
    try {
      auto deadline =
          std::chrono::steady_clock::now() + std::chrono::milliseconds(duration);

      timer_.expires_at(deadline);
      co_await timer_.async_wait(asio::use_awaitable);
      timeout_ = true;
    } catch (const std::system_error &e) {
      // ignore cancel timer error
      if (e.code() != asio::error::operation_aborted) {
        // throw other errors
        throw e;
      }

      co_return;
    }

    // throw time out error
    throw std::system_error(std::make_error_code(std::errc::timed_out));
  }

  bool timeout_;

private:
  asio::steady_timer timer_;
};

class async_mutex {
public:
    explicit async_mutex(asio::any_io_executor ex)
        : executor_(std::move(ex)), locked_(false) {}

    // Non-copyable
    async_mutex(const async_mutex&) = delete;
    async_mutex& operator=(const async_mutex&) = delete;

    // Acquire lock
    asio::awaitable<void> lock() {
        if (!locked_.exchange(true, std::memory_order_acquire)) {
            co_return;
        }

        // Wait for lock to be released
        asio::steady_timer waiter(executor_);
        auto waiter_ptr = std::make_shared<asio::steady_timer>(std::move(waiter));

        {
            std::scoped_lock<std::mutex> guard(waiters_mutex_);
            waiters_.push_back(waiter_ptr);
        }

        asio::error_code ec;
        co_await waiter_ptr->async_wait(asio::redirect_error(asio::use_awaitable, ec));

        // Woken up normally
        co_return;
    }

    // Try to acquire lock without blocking
    bool try_lock() noexcept {
        bool expected = false;
        return locked_.compare_exchange_strong(expected, true, std::memory_order_acquire);
    }

    // Release lock
    void unlock() {
        std::shared_ptr<asio::steady_timer> next_waiter;

        {
            std::scoped_lock<std::mutex> guard(waiters_mutex_);
            if (!waiters_.empty()) {
                next_waiter = waiters_.front();
                waiters_.pop_front();
            } else {
                locked_.store(false, std::memory_order_release);
            }
        }

        // Wake up next waiter (if any)
        if (next_waiter) {
            asio::post(executor_, [next_waiter]() {
                next_waiter->cancel();
            });
        }
    }

private:
    asio::any_io_executor executor_;
    std::atomic_bool locked_;
    std::mutex waiters_mutex_;
    std::deque<std::shared_ptr<asio::steady_timer>> waiters_;
};

// RAII wrapper for async_mutex to automatically release the lock
class async_mutex_lock {
  public:
      explicit async_mutex_lock(async_mutex& m)
          : mutex_(m), owns_lock_(false) {}
  
      ~async_mutex_lock() {
          // Automatically release the lock if owned
          if (owns_lock_) {
              mutex_.unlock();
          }
      }
  
      // Non-copyable
      async_mutex_lock(const async_mutex_lock&) = delete;
      async_mutex_lock& operator=(const async_mutex_lock&) = delete;
  
      // Coroutine-friendly method to acquire the lock
      asio::awaitable<void> get_lock() {
          co_await mutex_.lock();
          owns_lock_ = true;
          co_return;
      }
  
      // Check if the lock is currently owned
      bool owns_lock() const noexcept { return owns_lock_; }
  
  private:
      async_mutex& mutex_;
      bool owns_lock_;
  };