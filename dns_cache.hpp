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
#include "dns_log.hpp"
#include "dns_package.hpp"

namespace dns
{
    const int max_ttl_time = 60; // seconds

    int get_current_time();

    class dns_cache_entry : public std::enable_shared_from_this<dns_cache_entry>
    {
    public:
        dns_cache_entry()
            : create_time_(get_current_time()),
              ttl_(0),
              // cache_ttl_(0),
              access_count_(0),
              ghost_(false)
        {
        }

        void lock()
        {
            mutex_.lock();
        }

        void unlock()
        {
            mutex_.unlock();
        }

        std::string domain;
        int create_time_;
        uint32_t ttl_;
        // uint32_t cache_ttl_;
        dns::dns_package dns_package_;
        size_t access_count_;
        bool ghost_;

    private:
        std::mutex mutex_;
    };

    class dns_cache
    {
    public:
        dns_cache()
        {
        }

        bool init_cache(size_t max_cache)
        {
            // Create and allocate cache entries
            for (size_t i = 0; i < max_cache; i++)
            {
                std::shared_ptr<dns_cache_entry> entry = std::make_shared<dns_cache_entry>();
                free_cache_.push_back(entry);
            }

            // Check if allocation was successful
            return (free_cache_.size() == max_cache);
        }

        std::shared_ptr<dns_cache_entry> pop_free_cache()
        {
            std::lock_guard<std::mutex> lock(mutex_); // Lock the mutex

            if (free_cache_.empty())
            {
                return nullptr; // No free cache entry available
            }

            // Get the first entry from free_cache_
            std::shared_ptr<dns_cache_entry> cache_entry = free_cache_.front();

            // Remove it from free_cache_
            free_cache_.erase(free_cache_.begin());

            return cache_entry;
        }

        void add_cache(const std::string &domain, dns::anwser_type type, std::shared_ptr<dns_cache_entry> cache_entry)
        {
            std::string key = generate_key(domain, type);

            // Lock the mutex before modifying cache_
            std::lock_guard<std::mutex> lock(mutex_);

            // Add cache entry to cache_ map
            cache_[key] = cache_entry;

            logger.debug("add cache entry %s", cache_entry->domain.c_str());
        }

        std::shared_ptr<dns_cache_entry> query_cache(const std::string &domain, dns::anwser_type type)
        {
            std::string key = generate_key(domain, type);

            // Lock the mutex before accessing cache_
            std::lock_guard<std::mutex> lock(mutex_);

            // Check if cache entry exists in cache_
            auto it = cache_.find(key);
            if (it != cache_.end())
            {
                std::shared_ptr<dns_cache_entry> cache_entry = it->second;
                cache_entry->access_count_++; // Increment access count
                logger.debug("query cache entry %s", cache_entry->domain.c_str());
                return cache_entry; // Return cache entry
            }

            return nullptr; // Cache entry not found
        }

        void update()
        {
            int current_time = get_current_time();

            // Lock the mutex before modifying cache_
            std::lock_guard<std::mutex> lock(mutex_);

            // Iterate over cache_ map and check each cache entry
            auto it = cache_.begin();
            while (it != cache_.end())
            {
                std::shared_ptr<dns_cache_entry> cache_entry = it->second;

                cache_entry->lock();
                // Check if cache entry has expired based on ttl
                if (current_time >= static_cast<int>(cache_entry->create_time_ + cache_entry->ttl_))
                {
                    logger.debug("remove cache entry %s", cache_entry->domain.c_str());
                    // Move cache entry from cache_ to free_cache_
                    free_cache_.push_back(cache_entry);
                    it = cache_.erase(it);
                    cache_entry->unlock();
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
                        logger.debug("remove ghost cache entry %s", cache_entry->domain.c_str());
                        // Move ghost cache entry from cache_ to free_cache_
                        free_cache_.push_back(cache_entry);
                        it = cache_.erase(it);
                        cache_entry->unlock();
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
                cache_entry->unlock();
                ++it; // Move to next iteration
            }
        }

    private:
        std::string generate_key(const std::string &domain, dns::anwser_type type)
        {
            // Generate key based on domain and type
            return domain + "_" + std::to_string(static_cast<int>(type));
        }

        std::vector<std::shared_ptr<dns_cache_entry>> free_cache_;
        std::map<std::string, std::shared_ptr<dns_cache_entry>> cache_;
        std::mutex mutex_;
    };
}
