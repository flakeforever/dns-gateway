//
// File: dns_router.cpp
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

#include "dns_router.hpp"
#include "dns_log.hpp"

namespace dns
{
    dns_upstream_group::dns_upstream_group(asio::any_io_executor executor)
        : executor_(executor), current_index_(0)
    {
    }

    void dns_upstream_group::add_upstream(std::shared_ptr<dns_upstream> upstream)
    {
        upstreams_.push_back(upstream);
    }

    asio::awaitable<std::shared_ptr<dns_upstream>> dns_upstream_group::get_next_upstream()
    {
        await_coroutine_lock lock(executor_, locked_);
        co_await lock.get_lock();

        // Get the next upstream in a round-robin fashion
        size_t size = upstreams_.size();
        if (size > 0)
        {
            std::shared_ptr<dns_upstream> upstream = upstreams_[current_index_];
            current_index_ = (current_index_ + 1) % size; // Update the current index
            co_return upstream;
        }
        else
        {
            co_return nullptr;
        }
    }

    dns_router::dns_router(asio::any_io_executor executor)
        : executor_(executor)
    {
    }

    std::shared_ptr<dns_upstream_group> dns_router::create_group(const std::string &name)
    {
        std::shared_ptr<dns_upstream_group> group = std::make_shared<dns::dns_upstream_group>(executor_);
        group->id(get_next_group_id());
        group->name(name);
        upstream_groups_[group->id()] = group;

        return upstream_groups_[group->id()];
    }

    std::shared_ptr<dns_upstream_group> dns_router::get_group(uint8_t group_id)
    {
        return upstream_groups_[group_id];
    }

    std::shared_ptr<dns_upstream_group> dns_router::get_group(const std::string &name)
    {
        for (const auto &pair : upstream_groups_)
        {
            if (pair.second->name() == name)
            {
                return pair.second;
            }
        }

        return nullptr;
    }

    void dns_router::add_route(const std::string &domain, uint8_t group_id)
    {
        insert_to_trie(root_, domain, group_id);
    }

    asio::awaitable<uint8_t> dns_router::get_route(const std::string &domain)
    {
        await_coroutine_lock lock(executor_, locked_);
        co_await lock.get_lock();

        co_return search_in_trie(root_, domain);
    }
    
    uint8_t dns_router::get_next_group_id()
    {
        return next_group_id_++;
    }

    void dns_router::insert_to_trie(trie_node *node, const std::string &domain, uint8_t group_id)
    {
        for (int i = domain.length() - 1; i >= 0; --i)
        {
            char c = domain[i];
            if (!node->children.count(c))
            {
                node->children[c] = new trie_node();
            }
            node = node->children[c];
        }
        node->group_id = group_id;
    }

    uint8_t dns_router::search_in_trie(trie_node *node, const std::string &domain)
    {
        for (int i = domain.length() - 1; i >= 0; --i)
        {
            char c = domain[i];
            if (node->children.count(c))
            {
                node = node->children[c];
            }
            else
            {
                break;
            }
        }
        return node->group_id;
    }
}
