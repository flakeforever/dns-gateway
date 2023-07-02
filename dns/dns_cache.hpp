//
// File: dns_cache.hpp
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

#include <iostream>
#include <unordered_map>
#include <string>
#include <memory>
#include <mutex>
#include <map>
#include "dns_log.hpp"
// #include <message.h>
#include "operation.hpp"
#include "dns_package.hpp"

namespace dns
{
    const int max_ttl_time = 60; // seconds

    int64_t get_current_time();

    class dns_cache_entry
    {
    public:
        dns_cache_entry()
            : create_time_(0),
              ttl_(0),
              access_count_(0),
              ghost_(false)
        {
        }

        std::string domain_;
        int64_t create_time_;
        uint32_t ttl_;
        size_t access_count_;
        bool ghost_;

        char buffer_[dns::buffer_size];
        uint16_t buffer_size_;
        // dns::dns_package package_;
        // dns::Message message_;
        std::mutex mutex_;

    private:
    };

    class dns_cache
    {
    public:
        dns_cache(asio::any_io_executor executor)
            : executor_(executor)
        {
            last_update_time_ = dns::get_current_time();
        }

        bool init_cache(size_t max_cache)
        {
            // Create and allocate cache entries
            for (size_t i = 0; i < max_cache; i++)
            {
                dns_cache_entry *entry = new dns_cache_entry();
                free_cache_.push_back(entry);
            }

            // Check if allocation was successful
            return (free_cache_.size() == max_cache);
        }

        asio::awaitable<dns_cache_entry *> pop_free_cache()
        {
            await_lock lock(executor_, mutex_);
            co_await lock.check_lock();

            if (free_cache_.empty())
            {
                co_return nullptr; // No free cache entry available
            }

            // Get the first entry from free_cache_
            dns_cache_entry *cache_entry = free_cache_.front();

            // Remove it from free_cache_
            free_cache_.erase(free_cache_.begin());
            co_return cache_entry;
        }

        asio::awaitable<void> add_cache(const std::string &domain, uint8_t type, dns_cache_entry *cache_entry)
        {
            std::string key = generate_key(domain, type);

            // Lock the mutex before modifying cache_
            await_lock lock(executor_, mutex_);
            co_await lock.check_lock();

            // Add cache entry to cache_ map
            if (cache_.find(key) != cache_.end())
            {
                free_cache_.push_back(cache_entry);
                logger.debug("cache entry %s is exists", cache_entry->domain_.c_str());
            }
            else
            {
                cache_[key] = cache_entry;
                logger.debug("add cache entry %s query_domain %s", cache_entry->domain_.c_str(), domain.c_str());
            }

            co_return;
        }

        asio::awaitable<dns_cache_entry *> query_cache(const std::string &domain, uint8_t type)
        {
            std::string key = generate_key(domain, type);

            // Lock the mutex before accessing cache_
            await_lock lock(executor_, mutex_);
            co_await lock.check_lock();
            
            // update cache
            co_await update();

            // Check if cache entry exists in cache_
            auto it = cache_.find(key);
            if (it != cache_.end())
            {
                dns_cache_entry *cache_entry = it->second;

                await_lock lock(executor_, cache_entry->mutex_);
                co_await lock.check_lock();

                cache_entry->access_count_++; // Increment access count
                logger.debug("query cache entry %s query_domain %s", cache_entry->domain_.c_str(), domain.c_str());
                co_return cache_entry; // Return cache entry
            }

            co_return nullptr; // Cache entry not found
        }

        asio::awaitable<void> update()
        {
            int64_t current_time = dns::get_current_time();

            // Check if the time difference is less than 1000 milliseconds
            if (current_time - last_update_time_ < 1000)
            {
                co_return; // Skip update
            }

            // Iterate over cache_ map and check each cache entry
            auto it = cache_.begin();
            while (it != cache_.end())
            {
                dns_cache_entry *cache_entry = it->second;

                {
                    await_lock lock(executor_, cache_entry->mutex_);
                    co_await lock.check_lock();

                    // Check if cache entry has expired based on ttl
                    if (current_time >= cache_entry->create_time_ + cache_entry->ttl_ * 1000)
                    {
                        logger.info("remove cache entry %s", cache_entry->domain_.c_str());
                        // Move cache entry from cache_ to free_cache_
                        free_cache_.push_back(cache_entry);
                        it = cache_.erase(it);
                        continue; // Continue to next iteration
                    }

                    // Check if the cache entry is a ghost entry
                    if (cache_entry->ghost_)
                    {
                        if (cache_entry->access_count_ > 0)
                        {
                            cache_entry->access_count_--;
                        }
                        else
                        {
                            logger.info("remove ghost cache entry %s", cache_entry->domain_.c_str());
                            // Move ghost cache entry from cache_ to free_cache_
                            free_cache_.push_back(cache_entry);
                            it = cache_.erase(it);
                            continue; // Continue to next iteration
                        }
                    }

                    // Adjust the cache entry's status based on access count
                    if (cache_entry->access_count_ >= 2)
                    {
                        cache_entry->ghost_ = true;
                    }
                    else
                    {
                        cache_entry->ghost_ = false;
                    }

                    cache_entry->access_count_ = 0; // Reset access count
                    ++it;                           // Move to next iteration
                }
            }

            last_update_time_ = current_time; // Update last_update_time
        }

    private:
        std::string generate_key(const std::string &domain, uint8_t type)
        {
            // Generate key based on domain and type
            return domain + "_" + std::to_string(type);
        }

        std::vector<dns_cache_entry *> free_cache_;
        std::map<std::string, dns_cache_entry *> cache_;
        int64_t last_update_time_;

        asio::any_io_executor executor_;
        std::mutex mutex_;
    };
}
