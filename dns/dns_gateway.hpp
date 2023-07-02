//
// File: dns_gateway.hpp
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
#include <vector>
#include "dns_cache.hpp"
#include "dns_log.hpp"
#include "dns_package.hpp"
#include "dns_router.hpp"
#include "dns_upstream.hpp"
#include "operation.hpp"
#include "property.hpp"

namespace dns
{
    constexpr int dns_port = 53;
    constexpr int coroutine_timeout = 5000;

    enum class object_type
    {
        static_object = 0,
        dynmaic_object = 1,
    };

    class dns_object
    {
    public:
        dns_object();
        ~dns_object();

        object_type type_;
        int64_t active_time_;

        // dns raw data
        char buffer_[dns::buffer_size];
        int buffer_length_;
        asio::ip::udp::endpoint remote_endpoint_;
        // dns::dns_package package_;

        // dns question
        uint16_t question_id_;
        std::string question_domain_;
        uint8_t question_type_;

        int status_;
    };

    class dns_object_pool
    {
    public:
        dns_object_pool(asio::any_io_executor executor, int min_pools, int max_pool)
            : executor_(executor), min_pools_(min_pools), max_pool_(max_pool)
        {
            init_object(min_pools_);
            last_update_time_ = dns::get_current_time();
        }

        asio::awaitable<dns_object *> get_object()
        {
            await_lock lock(executor_, mutex_);
            co_await lock.check_lock();

            update();
            // Check if there is an available object in static_objects_
            if (!static_objects_.empty())
            {
                auto object = static_objects_.back();
                static_objects_.pop_back();
                active_objects_.push_back(object);
                object->active_time_ = dns::get_current_time();
                co_return object;
            }

            if (static_objects_.size() + active_objects_.size() >= max_pool_)
            {
                co_return nullptr;
            }

            // Create a dynamic_object and add it to active_objects_
            auto object = new dns_object();
            object->type_ = object_type::dynmaic_object;
            active_objects_.push_back(object);
            object->active_time_ = dns::get_current_time();
            co_return object;
        }

        asio::awaitable<void> release_object(dns_object *object)
        {
            await_lock lock(executor_, mutex_);
            co_await lock.check_lock();

            // Remove the object from active_objects_
            active_objects_.erase(std::remove(active_objects_.begin(), active_objects_.end(), object), active_objects_.end());

            // Check the object type and handle accordingly
            if (object->type_ == object_type::static_object)
            {
                static_objects_.push_back(object);
            }
            else
            {
                delete object; // Release the dynamic object
            }

            co_return;
        }

    private:
        void init_object(int min_pools)
        {
            for (int i = 0; i < min_pools; ++i)
            {
                auto object = new dns_object();
                object->type_ = object_type::static_object;
                static_objects_.push_back(object);
            }
        }

        void update()
        {
            int64_t current_time = dns::get_current_time();

            // Check if the elapsed time exceeds the threshold for updating
            if (current_time - last_update_time_ < 1000)
            {
                return; // Skip the update if the elapsed time is less than 1 second
            }

            // for (auto it = active_objects_.begin(); it != active_objects_.end();)
            // {
            //     auto object = *it;
            //     int object_age = (current_time - object->active_time_) / 1000;

            //     if (object_age > 10)
            //     {
            //         logger.error("Object %p exceeded the allowed active time.", object);
            //         it = active_objects_.erase(it);

            //         if (object->type_ == object_type::static_object)
            //         {
            //             static_objects_.push_back(object);
            //         }
            //         else
            //         {
            //             delete object; // Release the dynamic object
            //         }
            //     }
            //     else
            //     {
            //         ++it;
            //     }
            // }

            if (active_objects_.size() > 0)
            {
                logger.warning("active_objects %d", active_objects_.size());
            }

            last_update_time_ = current_time;
        }

        asio::any_io_executor executor_;
        std::mutex mutex_;
        std::vector<dns_object *> static_objects_;
        std::vector<dns_object *> active_objects_;
        int64_t last_update_time_;

        size_t min_pools_;
        size_t max_pool_;
    };

    class dns_gateway_propery
    {
    public:
        PROPERTY_READWRITE(bool, active);
        PROPERTY_READONLY(bool, terminated);
        PROPERTY_READONLY(bool, checker_started);
    };

    class dns_gateway : public dns_gateway_propery
    {
    public:
        dns_gateway(asio::any_io_executor executor,
                    asio::ip::udp::resolver::protocol_type protocol, uint16_t port,
                    int min_pools, int max_pools);
        dns_gateway(asio::any_io_executor executor,
                    std::string address, uint16_t port,
                    int min_pools, int max_pools);

        asio::awaitable<void> run_process();

        dns_router &get_router();
        dns_cache &get_cache();

        asio::awaitable<void> wait_terminated();
        asio::any_io_executor get_executor();

        std::vector<std::shared_ptr<dns_upstream>> upstreams_;
        std::vector<std::string> check_domains;

    protected:
        void start_checker();
        asio::awaitable<int> do_receive();
        void set_active(const bool &value) override;
        asio::awaitable<bool> handle_dns_static(
            std::shared_ptr<dns::dns_object> dns_object, std::string request_domain, dns::anwser_type request_type);
        asio::awaitable<bool> handle_query_cache(dns::dns_object *dns_object);
        asio::awaitable<bool> handle_create_cache(dns::dns_object *dns_object);
        asio::awaitable<bool> handle_dns_request(dns::dns_object *dns_object);

    private:
        asio::any_io_executor executor_;
        uint16_t port_;
        asio::ip::udp::socket udp_socket_;
        dns_object_pool object_pool_;
        asio::ip::udp::endpoint remote_endpoint_;

        dns_router router_;
        dns_cache cache_;
        char buffer_[dns::buffer_size];
        int object_id_;
    };
}
