//
// File: dns_gateway.cpp
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

#include <thread>
#include "dns_gateway.hpp"
#include "dns_buffer.hpp"
#include "dns_cache.hpp"
#include "dns_package.hpp"

namespace dns
{
    dns_gateway::dns_gateway(asio::any_io_executor executor, std::string address, uint16_t port, int max_works)
        : executor_(std::move(executor)),
          port_(port),
          udp_socket_(executor_, asio::ip::udp::endpoint(asio::ip::make_address(address), port)),
          semaphore_()
    {
        init_semaphore(max_works);
    }

    asio::awaitable<void> dns_gateway::run_process()
    {
        active_ = true;
        while (active_)
        {
            try
            {
                // receive data from udp listening
                int length = co_await do_receive();

                // get a dns object from queue
                std::shared_ptr<semaphore_object> object = semaphore_.get_object();
                std::shared_ptr<dns::dns_object> dns_object = std::static_pointer_cast<dns::dns_object>(object);

                // init dns object
                memcpy(dns_object->buffer_, buffer_, length);
                dns_object->buffer_length_ = length;
                dns_object->remote_endpoint_ = remote_endpoint_;

                // define a coroutine for request
                auto request_coroutine = [&](std::shared_ptr<dns::dns_object> new_object) -> asio::awaitable<void>
                {
                    // parse request data
                    new_object->dns_package_.reset();
                    new_object->dns_package_.parse(new_object->buffer_, new_object->buffer_length_);
                    // new_object->dns_package_.output();

                    if (!new_object->dns_package_.questions_.size())
                    {
                        // push back a dns object to queue
                        semaphore_.notify(dns_object);
                        co_return;
                    }

                    // get request domain and type
                    std::string request_domain = new_object->dns_package_.questions_[0]->q_name();
                    dns::anwser_type request_type =
                        static_cast<dns::anwser_type>(new_object->dns_package_.questions_[0]->q_type());

                    // handle dns static
                    bool status = co_await handle_dns_static(new_object, request_domain, request_type);
                    if (status)
                    {
                        semaphore_.notify(new_object);
                        co_return;
                    }

                    // handle dns cache
                    status = co_await handle_query_cache(new_object, request_domain, request_type);
                    if (status)
                    {
                        semaphore_.notify(new_object);
                        co_return;
                    }

                    // handle dns request
                    co_await handle_dns_request(new_object, request_domain, request_type);

                    semaphore_.notify(new_object);
                    co_return;
                };

                // create a new coroutine for request
                co_spawn(executor_, request_coroutine(dns_object), detached);
            }
            catch (const std::exception &e)
            {
                logger.error("error: %s", e.what());
                break;
            }
        }

        terminated_ = true;
        co_return;
    }

    dns_router &dns_gateway::get_router()
    {
        return router_;
    }

    dns_cache &dns_gateway::get_cache()
    {
        return cache_;
    }

    asio::any_io_executor dns_gateway::get_executor()
    {
        return executor_;
    }

    void dns_gateway::set_active(const bool &value)
    {
        active_ = value;

        if (!active_)
        {
            if (udp_socket_.is_open())
            {
                udp_socket_.close();
            }
        }
        else
        {
            start_checker();
        }
    }

    asio::awaitable<bool> dns_gateway::handle_dns_static(
        std::shared_ptr<dns::dns_object> dns_object, std::string request_domain, dns::anwser_type request_type)
    {
        if (dns_object->dns_package_.questions_.size() == 1)
        {
            // check domain static
            std::vector<std::string> static_values = router_.get_statics().get_static_values(request_domain, request_type);

            if (static_values.size() > 0)
            {
                for (auto value : static_values)
                {
                    dns_object->dns_package_.add_anwser(request_domain, request_type, value);
                }

                //  Forward the response to the client
                dns_object->buffer_length_ =
                    dns_object->dns_package_.dump(dns_object->buffer_, sizeof(dns_object->buffer_));

                co_await udp_socket_.async_send_to(
                    asio::buffer(dns_object->buffer_, dns_object->buffer_length_),
                    dns_object->remote_endpoint_,
                    asio::use_awaitable);

                co_return true;
            }
        }

        co_return false;
    }

    bool dns_gateway::handle_create_cache(
        std::shared_ptr<dns::dns_object> dns_object, std::string request_domain, dns::anwser_type request_type)
    {
        std::shared_ptr<dns_cache_entry> cache_entry = cache_.pop_free_cache();
        if (cache_entry == nullptr)
        {
            cache_.update();
        }

        cache_entry = cache_.pop_free_cache();
        if (cache_entry != nullptr)
        {
            cache_entry->domain = request_domain;
            cache_entry->dns_package_.reset();
            cache_entry->dns_package_.parse(dns_object->buffer_, dns_object->buffer_length_);
            cache_entry->create_time_ = get_current_time();
            cache_entry->ttl_ = cache_entry->dns_package_.get_ttl();
            // cache_entry->cache_ttl_ = cache_entry->ttl_;

            // if (cache_entry->cache_ttl_ > 60)
            // {
            //     cache_entry->cache_ttl_ = 60;
            // }

            cache_.add_cache(request_domain, request_type, cache_entry);
            return true;
        }

        return false;
    }

    asio::awaitable<bool> dns_gateway::handle_query_cache(
        std::shared_ptr<dns::dns_object> dns_object, std::string request_domain, dns::anwser_type request_type)
    {
        std::shared_ptr<dns_cache_entry> cache_entry = cache_.query_cache(request_domain, request_type);
        if (cache_entry != nullptr)
        {
            cache_entry->lock();
            cache_entry->dns_package_.id(dns_object->dns_package_.id());

            int elapsed_time = get_current_time() - cache_entry->create_time_;
            int remaining_ttl = cache_entry->ttl_ - elapsed_time;

            // Ensure remaining TTL is at least 1
            if (remaining_ttl <= 0)
            {
                remaining_ttl = 1;
            }

            cache_entry->dns_package_.set_ttl(remaining_ttl);

            //  Forward the response to the client
            dns_object->buffer_length_ =
                cache_entry->dns_package_.dump(dns_object->buffer_, sizeof(dns_object->buffer_));

            cache_entry->unlock();

            co_await udp_socket_.async_send_to(
                asio::buffer(dns_object->buffer_, dns_object->buffer_length_),
                dns_object->remote_endpoint_,
                asio::use_awaitable);

            co_return true;
        }

        co_return false;
    }

    asio::awaitable<bool> dns_gateway::handle_dns_request(
        std::shared_ptr<dns::dns_object> dns_object, std::string request_domain, dns::anwser_type request_type)
    {
        bool result = false;
        // get an upstream group by domain
        std::shared_ptr<dns_upstream_group> current_group = router_.default_group;
        uint8_t group_id = router_.get_route(request_domain);
        std::shared_ptr<dns::dns_upstream_group> upstream_group = router_.get_group(group_id);

        if (upstream_group)
        {
            current_group = upstream_group;
            dns::logger.debug("route : %s -> %s", request_domain.c_str(), upstream_group->name().c_str());
        }
        else
        {
            dns::logger.debug("default route : %s -> %s",
                              request_domain.c_str(), router_.default_group->name().c_str());
        }

        // get an upstream
        std::shared_ptr<dns_upstream> dns_upstream = current_group->get_next_upstream();

        // define a handle for response
        auto handle_response = [&](std::error_code ec, const char *data, uint16_t data_length) -> asio::awaitable<void>
        {
            if (!ec)
            {
                // Note that using shared_ptr in a new coroutine requires re-referencing
                std::shared_ptr<dns::dns_object> current_object = dns_object;

                // parse dns data from response
                current_object->dns_package_.reset();
                current_object->dns_package_.parse(data, data_length);
                // current_object->dns_package_.output();

                //  Forward the response to the client
                current_object->buffer_length_ =
                    current_object->dns_package_.dump(current_object->buffer_, sizeof(current_object->buffer_));

                // update dns cache
                handle_create_cache(current_object, request_domain, request_type);

                co_await udp_socket_.async_send_to(
                    asio::buffer(current_object->buffer_, current_object->buffer_length_),
                    current_object->remote_endpoint_,
                    asio::use_awaitable);

                result = true;
            }
            else
            {
                logger.error("error: %d message: %s", ec.value(), ec.message().c_str());
            }
        };

        // request to upstream
        co_await dns_upstream->send_request(dns_object->buffer_, dns_object->buffer_length_, handle_response);
        co_return result;
    }

    asio::awaitable<void> dns_gateway::wait_terminated()
    {
        async_wait async_wait(executor_);
        co_await async_wait.wait_until(
            std::chrono::milliseconds(10),
            [&](bool &finished)
            {
                if (terminated_ && !checker_started_)
                {
                    finished = true;
                }
            });
    }

    void dns_gateway::init_semaphore(int max_works)
    {
        for (int i = 0; i < max_works; i++)
        {
            std::shared_ptr<dns::dns_object> dns_object = std::make_shared<dns::dns_object>();
            semaphore_.add_object(dns_object);
        }
    }

    asio::awaitable<int> dns_gateway::do_receive()
    {
        co_return co_await udp_socket_.async_receive_from(asio::buffer(buffer_), remote_endpoint_, asio::use_awaitable);
    }

    void dns_gateway::start_checker()
    {
        if (!check_domains.size())
        {
            logger.error("handle_check failed : check_domains is null");
            return;
        }

        auto handle_check = [&]() -> asio::awaitable<void>
        {
            int domain_index = 0;
            char buffer[dns::buffer_size];
            dns_package request_package;

            checker_started_ = true;
            while (active_)
            {
                try
                {
                    std::string domain = check_domains[domain_index];
                    domain_index = (domain_index + 1) % check_domains.size();

                    for (const auto &upstream : upstreams_)
                    {
                        if (upstream->check_enabled())
                        {
                            asio::steady_timer::time_point now = asio::steady_timer::clock_type::now();
                            std::chrono::milliseconds time_diff =
                                std::chrono::duration_cast<std::chrono::seconds>(now - upstream->last_request_time());

                            if (time_diff >= std::chrono::seconds(upstream->check_interval()))
                            {
                                request_package.reset();
                                request_package.add_question(domain, dns::anwser_type::a);
                                int length = request_package.dump(buffer, dns::buffer_size);

                                // define a handle for response
                                auto handle_response = [&](std::error_code ec, const char *data, uint16_t data_length) -> asio::awaitable<void>
                                {
                                    if (ec)
                                    {
                                        logger.error("error: %d message: %s", ec.value(), ec.message().c_str());
                                    }

                                    co_return;
                                };

                                co_await upstream->send_request(buffer, length, handle_response);
                            }
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    logger.error("handle_check failed : %s", e.what());
                }

                asio::steady_timer timer(executor_, std::chrono::milliseconds(250));
                co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
            }

            checker_started_ = false;
            co_return;
        };

        co_spawn(executor_, handle_check, detached);
    }
}
