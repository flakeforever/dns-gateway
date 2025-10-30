//
// File: dns_gateway.cpp
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

#include "dns_gateway.hpp"
#include "dns_buffer.hpp"
#include "dns_cache.hpp"
#include "dns_package.hpp"
#include <thread>

namespace dns {
dns_gateway::dns_gateway(asio::any_io_executor executor,
                         asio::ip::udp::resolver::protocol_type protocol,
                         uint16_t port, int min_pools, int max_pools, 
                         uint16_t monitor_port)
    : executor_(executor), port_(port), monitor_port_(monitor_port),
      udp_socket_(executor, asio::ip::udp::endpoint(protocol, port)),
      object_pool_(executor, min_pools, max_pools), router_(executor),
      statics_(executor), cache_(executor), upstream_pool_(executor),
      monitor_(executor, upstream_pool_, monitor_port), active_(false) {}

dns_gateway::dns_gateway(asio::any_io_executor executor, std::string address,
                         uint16_t port, int min_pools, int max_pools,
                         uint16_t monitor_port)
    : executor_(executor), port_(port), monitor_port_(monitor_port),
      udp_socket_(executor, asio::ip::udp::endpoint(
                                asio::ip::make_address(address), port)),
      object_pool_(executor, min_pools, max_pools), router_(executor),
      statics_(executor), cache_(executor), upstream_pool_(executor),
      monitor_(executor, upstream_pool_, monitor_port), active_(false) {}

std::string endpoint_to_string(const asio::ip::udp::endpoint &endpoint) {
  std::string address = endpoint.address().to_string();
  unsigned short port = endpoint.port();

  return address + ":" + std::to_string(port);
}

asio::awaitable<void> dns_gateway::run_process() {
  active_ = true;
  while (active_) {
    try {
      // receive data from udp listening
      int length = co_await do_receive();

      if (length <= 0) {
        common::log.error("length error");
        continue;
      }

      dns::dns_package package;
      try {
        if (!package.parse(recv_buffer_, length)) {
          continue;
        }
      } catch (const std::exception &e) {
        common::log.error("DNS exception occured when parsing incoming data");
        continue;
      }

      if (package.flag_qr() != 0 || package.que_count() == 0 ||
          package.questions_.size() == 0) {
        continue;
      }

      // get a dns object from queue
      dns::dns_object *dns_object = co_await object_pool_.get_object();
      if (dns_object == nullptr) {
        common::log.error("dns_object is null");
        continue;
      }

      // init dns object
      memset(dns_object->buffer_, 0, sizeof(dns_object->buffer_));
      memcpy(dns_object->buffer_, recv_buffer_, length);
      dns_object->buffer_length_ = length;

      dns_object->question_id_ = package.id();
      dns_object->question_domain_ = package.questions_[0]->q_name();
      dns_object->question_type_ = package.questions_[0]->q_type();
      dns_object->remote_endpoint_ = remote_endpoint_;

      common::log.debug("request %d %s type %d from %s", dns_object->question_id_,
                   dns_object->question_domain_.c_str(),
                   dns_object->question_type_,
                   endpoint_to_string(dns_object->remote_endpoint_).c_str());

      // define a coroutine for request
      auto request_coroutine =
          [&](dns::dns_object *new_object) -> asio::awaitable<void> {
        try {
          // handle dns static
          bool status = co_await handle_dns_static(new_object);
          if (!status) {
            // handle dns cache
            status = co_await handle_query_cache(new_object);
            if (!status) {
              // handle dns request
              co_await handle_dns_request(new_object);
            }
          }
        } catch (const std::exception &e) {
          common::log.error("request_coroutine error: %s", e.what());
        }

        co_await object_pool_.release_object(new_object);
        co_return;
      };

      // create a new coroutine for request
      co_spawn(executor_, request_coroutine(dns_object), detached);
    } catch (const std::exception &e) {
      common::log.error("process error: %s", e.what());
      break;
    }
  }

  terminated_ = true;
  co_return;
}

asio::awaitable<void> dns_gateway::start() {
  common::log.info("initializing dns_gateway");
  
  // Set gateway as active
  active_ = true;
  
  // Initialize upstream pool
  co_await upstream_pool_.init();
  common::log.info("upstream pool initialized");
  
  // Start monitor HTTP server (if enabled)
  if (monitor_port_ > 0) {
    asio::co_spawn(
        executor_, monitor_.start(),
        [](std::exception_ptr e) {
          if (e) {
            try {
              std::rethrow_exception(e);
            } catch (const std::exception &ex) {
              common::log.error("monitor server error: %s", ex.what());
            }
          }
        });
    common::log.info("monitor HTTP server starting on port %d", monitor_port_);
  } else {
    common::log.info("monitor HTTP server disabled (port not configured)");
  }
  
  // common::log.info("dns_gateway initialization completed");
}

void dns_gateway::stop() {
  common::log.info("stopping dns_gateway");
  
  // Set gateway as inactive
  active_ = false;
  
  // Stop monitor HTTP server (if it was started)
  if (monitor_port_ > 0) {
    monitor_.stop();
  }
  
  // Close socket
  if (udp_socket_.is_open()) {
    udp_socket_.close();
  }
  
  common::log.info("dns_gateway stopped");
}

dns_router &dns_gateway::get_router() { return router_; }

dns_statics &dns_gateway::get_statics() { return statics_; }

dns_cache &dns_gateway::get_cache() { return cache_; }

dns_upstream_pool &dns_gateway::get_upstream_pool() { return upstream_pool_; }

dns_monitor &dns_gateway::get_monitor() { return monitor_; }

asio::any_io_executor dns_gateway::get_executor() { return executor_; }


asio::awaitable<bool>
dns_gateway::handle_dns_static(dns::dns_object *dns_object) {
  std::vector<std::string> static_values;

  {
    await_coroutine_lock lock(executor_, statics_.locked_);
    co_await lock.get_lock();

    // check domain static
    static_values = co_await statics_.get_static_values(
        dns_object->question_domain_,
        static_cast<dns::anwser_type>(dns_object->question_type_));
  }

  if (static_values.size() == 0) {
    co_return false;
  }

  dns::dns_package package;
  try {
    if (!package.parse(dns_object->buffer_, dns_object->buffer_length_)) {
      co_return false;
    }
  } catch (const std::exception &e) {
    co_return false;
  }

  if (package.flag_qr() != static_cast<uint8_t>(dns::qr_type::request) ||
      package.que_count() > 1) {
    co_return false;
  }

  try {
    for (auto value : static_values) {
      package.add_anwser(
          dns_object->question_domain_,
          static_cast<dns::anwser_type>(dns_object->question_type_), value);
    }

    dns_object->buffer_length_ =
        package.dump(dns_object->buffer_, sizeof(dns_object->buffer_));
  } catch (const std::exception &e) {
    common::log.error("package dump error: %s", e.what());
    co_return false;
  }

  if (dns_object->buffer_length_ == 0) {
    common::log.error("package dump: buffer_length_ == 0");
    co_return false;
  }

  co_await udp_socket_.async_send_to(
      asio::buffer(dns_object->buffer_, dns_object->buffer_length_),
      dns_object->remote_endpoint_, asio::use_awaitable);

  co_return true;
}

asio::awaitable<bool>
dns_gateway::handle_create_cache(dns::dns_object *dns_object) {
  dns::dns_package package;
  try {
    if (!package.parse(dns_object->buffer_, dns_object->buffer_length_)) {
      co_return false;
    }
  } catch (const std::exception &e) {
    co_return false;
  }

  if (package.flag_qr() != static_cast<uint8_t>(dns::qr_type::response) ||
      package.flag_rcode() !=
          static_cast<uint8_t>(dns::rcode_type::ok_response) ||
      package.que_count() > 1 || package.ans_count() == 0) {
    co_return false;
  }

  await_coroutine_lock lock(executor_, cache_.locked_);
  co_await lock.get_lock();

  dns_cache_entry *cache_entry = co_await cache_.get_free_cache();
  if (cache_entry != nullptr) {
    cache_entry->domain_ = dns_object->question_domain_;
    cache_entry->create_time_ = dns::get_current_time();
    cache_entry->set_ttl(package.get_ttl());

    memcpy(cache_entry->buffer_, dns_object->buffer_,
           dns_object->buffer_length_);
    cache_entry->buffer_size_ = dns_object->buffer_length_;

    co_await cache_.add_cache(dns_object->question_domain_,
                              dns_object->question_type_, cache_entry);
    co_return true;
  }

  co_return false;
}

asio::awaitable<bool>
dns_gateway::handle_query_cache(dns::dns_object *dns_object) {
  bool status = false;

  {
    await_coroutine_lock lock(executor_, cache_.locked_);
    co_await lock.get_lock();

    dns_cache_entry *cache_entry = co_await cache_.query_cache(
        dns_object->question_domain_, dns_object->question_type_);
    if (cache_entry != nullptr) {
      dns::dns_package package;

      try {
        status = package.parse(cache_entry->buffer_, cache_entry->buffer_size_);
      } catch (const std::exception &e) {
        status = false;
      }

      if (status) {
        package.id(dns_object->question_id_);
        package.set_ttl(cache_entry->get_ttl());

        try {
          dns_object->buffer_length_ =
              package.dump(dns_object->buffer_, sizeof(dns_object->buffer_));
        } catch (const std::exception &e) {
          common::log.error("package dump error: %s", e.what());
          status = false;
        }

        if (dns_object->buffer_length_ == 0) {
          common::log.error("package dump: buffer_length_ == 0");
          status = false;
        }
      }
    }
  }

  if (status) {
    co_await udp_socket_.async_send_to(
        asio::buffer(dns_object->buffer_, dns_object->buffer_length_),
        dns_object->remote_endpoint_, asio::use_awaitable);
    co_return true;
  }

  co_return false;
}

asio::awaitable<bool>
dns_gateway::handle_dns_request(dns::dns_object *dns_object) {
  bool result = false;

  // get group name from router by domain
  std::string group_name = co_await router_.get_route_group_name(dns_object->question_domain_);
  
  if (group_name.empty()) {
    common::log.error("no route found for domain: %s", 
                      dns_object->question_domain_.c_str());
    co_return false;
  }

  common::log.debug("route: %s -> group '%s'", 
                    dns_object->question_domain_.c_str(), group_name.c_str());

  // get upstream from pool_group
  std::shared_ptr<dns_upstream> dns_upstream =
      co_await upstream_pool_.get_next_upstream(group_name);

  if (dns_upstream == nullptr) {
    common::log.error("dns_upstream is null");
    co_return false;
  }

  // Record start time for response time measurement
  auto start_time = std::chrono::steady_clock::now();

  // define a handle for response
  bool status = co_await dns_upstream_request(dns_upstream, dns_object);
  
  // Calculate response time and record statistics to upstream instance
  auto end_time = std::chrono::steady_clock::now();
  auto response_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
  
  // Record request statistics to upstream instance
  dns_upstream->record_request(status, response_time);
  if (status) {
    dns::dns_package package;
    try {
      status = package.parse(dns_object->buffer_, dns_object->buffer_length_);
    } catch (const std::exception &e) {
      status = false;
    }

    if (status) {
      // update dns cache
      co_await handle_create_cache(dns_object);

      common::log.debug("response %d %s type %d from %s:%d", dns_object->question_id_,
                   dns_object->question_domain_.c_str(),
                   dns_object->question_type_,
                   dns_upstream->host().c_str(), dns_upstream->port());

      dns_object->buffer_length_ =
          package.dump(dns_object->buffer_, sizeof(dns_object->buffer_));
    }

    co_await udp_socket_.async_send_to(
        asio::buffer(dns_object->buffer_, dns_object->buffer_length_),
        dns_object->remote_endpoint_, asio::use_awaitable);

    result = true;
  } else {
    co_await dns_upstream_close(dns_upstream);
  }

  co_return result;
}

asio::awaitable<bool>
dns_gateway::dns_upstream_request(std::shared_ptr<dns_upstream> dns_upstream,
                                  dns::dns_object *dns_object) {
  bool result = false;

  // define a handle for response
  bool status = false;
  auto handle_response = [&](std::error_code ec, const char *data,
                             uint16_t data_length) -> asio::awaitable<void> {
    if (!ec) {
      if (data_length > dns::buffer_size) {
        co_return;
      }

      // update dns cache
      memcpy(dns_object->buffer_, data, data_length);
      dns_object->buffer_length_ = data_length;

      status = true;
    } else {
      common::log.error("error: %d message: %s", ec.value(), ec.message().c_str());
      status = false;
    }

    co_return;
  };

  await_timeout_execute timeout_execute(executor_);
  co_await timeout_execute.execute_until(
      std::chrono::milliseconds(dns::coroutine_timeout),
      [&](asio::steady_timer &timer) -> asio::awaitable<void> {
        try {
          // Only use lock for non-multiplexing upstreams (DoT/DoH)
          // Multiplexing upstreams (UDP) support concurrent requests
          if (!dns_upstream->supports_multiplexing()) {
            await_coroutine_lock lock(executor_, dns_upstream->locked_);
            co_await lock.get_lock();
          }

          bool status = co_await dns_upstream->is_open();
          if (!status) {
            status = co_await dns_upstream->open();
          }

          if (status) {
            common::log.info("request %d %s type %d to %s:%d",
                        dns_object->question_id_,
                        dns_object->question_domain_.c_str(),
                        dns_object->question_type_,
                        dns_upstream->host().c_str(), dns_upstream->port());

            result = co_await dns_upstream->send_request(
                dns_object->buffer_, dns_object->buffer_length_,
                handle_response);
          } else {
            common::log.error("dns_upstream is closed");
          }
        } catch (const std::exception &e) {
          common::log.error("request error: %s", e.what());
        }

        if (!timeout_execute.timeout()) {
          timer.cancel();
        }
      });

  co_return result;
}

asio::awaitable<void>
dns_gateway::dns_upstream_close(std::shared_ptr<dns_upstream> dns_upstream) {
  await_timeout_execute timeout_execute(executor_);
  co_await timeout_execute.execute_until(
      std::chrono::milliseconds(dns::coroutine_timeout),
      [&](asio::steady_timer &timer) -> asio::awaitable<void> {
        try {
          // Only use lock for non-multiplexing upstreams (DoT/DoH)
          // Multiplexing upstreams (UDP) can be closed concurrently
          if (!dns_upstream->supports_multiplexing()) {
            await_coroutine_lock lock(executor_, dns_upstream->locked_);
            co_await lock.get_lock();
          }

          co_await dns_upstream->close();
        } catch (const std::exception &e) {
          common::log.error("close error: %s", e.what());
        }

        if (!timeout_execute.timeout()) {
          timer.cancel();
        }
      });
}

asio::awaitable<void> dns_gateway::wait_terminated() {
  await_wait wait(executor_);
  co_await wait.wait_until(std::chrono::milliseconds(10), [&](bool &finished) {
    if (terminated_) {
      finished = true;
    }
  });
}

asio::awaitable<int> dns_gateway::do_receive() {
  memset(recv_buffer_, 0, sizeof(recv_buffer_));
  co_return co_await udp_socket_.async_receive_from(
      asio::buffer(recv_buffer_), remote_endpoint_, asio::use_awaitable);
}
} // namespace dns
