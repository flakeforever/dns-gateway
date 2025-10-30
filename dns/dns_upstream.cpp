//
// File: dns_upstream.cpp
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

#include "dns_upstream.hpp"
#include "dns_package.hpp"
#include "../common/log.hpp"
#include <sstream>

using asio::awaitable;

namespace dns {
dns_upstream::dns_upstream(asio::any_io_executor executor)
    : executor_(std::move(executor)) {
  host_ = "";
  port_ = 0;
  proxy_type_ = socks::proxy_type::none;
  proxy_host_ = "";
  proxy_port_ = 0;
  check_enabled_ = false;
  check_interval_ = 0;
  last_request_time_ = asio::steady_timer::clock_type::now();
}

asio::awaitable<bool> dns_upstream::send_request(const char *data,
                                                 uint16_t data_length,
                                                 handle_response handler) {
  last_request_time_ = asio::steady_timer::clock_type::now();
  co_return true;
}

void dns_upstream::set_proxy(socks::proxy_type proxy_type,
                             std::string proxy_host, uint16_t proxy_port) {
  proxy_type_ = proxy_type;
  proxy_host_ = proxy_host;
  proxy_port_ = proxy_port;
}

asio::awaitable<bool> dns_upstream::open() { co_return true; }

asio::awaitable<void> dns_upstream::close() { co_return; }

asio::awaitable<bool> dns_upstream::check() {
  // Base implementation: always return true (for UDP)
  // UDP is connectionless, no need for validation
  co_return true;
}

void dns_upstream::record_request(bool success, std::chrono::milliseconds response_time) {
  request_count_.fetch_add(1, std::memory_order_relaxed);
  total_response_time_ms_.fetch_add(response_time.count(), std::memory_order_relaxed);
  
  // Also increment cumulative counter (never reset, used for load balancing)
  cumulative_requests_.fetch_add(1, std::memory_order_relaxed);
  
  if (success) {
    success_count_.fetch_add(1, std::memory_order_relaxed);
  } else {
    failed_count_.fetch_add(1, std::memory_order_relaxed);
  }
}

void dns_upstream::set_check_domains(const std::string &domains) {
  check_domains_.clear();
  
  if (domains.empty()) {
    return;
  }
  
  // Parse comma-separated domains
  std::stringstream ss(domains);
  std::string domain;
  
  while (std::getline(ss, domain, ',')) {
    // Remove leading and trailing spaces
    size_t start = domain.find_first_not_of(" \t\r\n");
    size_t end = domain.find_last_not_of(" \t\r\n");
    
    if (start != std::string::npos && end != std::string::npos) {
      domain = domain.substr(start, end - start + 1);
      if (!domain.empty()) {
        check_domains_.push_back(domain);
      }
    }
  }
  
  check_domain_index_.store(0, std::memory_order_relaxed);
}

std::string dns_upstream::get_next_check_domain() {
  if (check_domains_.empty()) {
    // Return a default domain based on the host
    if (host_.find("dns.google") != std::string::npos) {
      return "dns.google";
    } else if (host_.find("quad9") != std::string::npos) {
      return "dns.quad9.net";
    } else if (host_.find("cloudflare") != std::string::npos) {
      return "one.one.one.one";
    } else if (host_.find("adguard") != std::string::npos) {
      return "dns.adguard.com";
    } else {
      return "dns.google";  // Default fallback
    }
  }
  
  // Round-robin selection
  size_t current_index = check_domain_index_.fetch_add(1, std::memory_order_relaxed);
  return check_domains_[current_index % check_domains_.size()];
}

asio::awaitable<bool> dns_upstream::is_open() { co_return false; }

asio::awaitable<void> dns_upstream::execute_handler(handle_response handler,
                                                    std::error_code error,
                                                    const char *data,
                                                    size_t size) {
  std::error_code new_ec(error.value(), error.category());

  if (new_ec) {
    handle_exception(new_ec);
  }

  if (handler) {
    co_await handler(new_ec, data, size);
  }
}

asio::awaitable<void> dns_upstream::execute_handler(handle_response handler,
                                                    std::system_error error,
                                                    const char *data,
                                                    size_t size) {
  const std::error_code &ec = error.code();
  std::error_code new_ec(ec.value(), ec.category());

  co_await execute_handler(handler, new_ec, data, size);
}

asio::awaitable<void> dns_upstream::execute_handler(handle_response handler,
                                                    dns::errc::error_code error,
                                                    const char *data,
                                                    size_t size) {
  std::error_code ec = dns::errc::make_error_code(error);
  co_await execute_handler(handler, ec, data, size);
}

void dns_upstream::handle_exception(std::error_code error) {}

// ========================================
// dns_multiplexing_upstream implementation
// ========================================

dns_multiplexing_upstream::dns_multiplexing_upstream(asio::any_io_executor executor)
    : dns_upstream(executor) {
}

dns_multiplexing_upstream::~dns_multiplexing_upstream() {
  // Ensure recv_loop is stopped
  recv_active_.store(false, std::memory_order_release);
}

asio::awaitable<bool> dns_multiplexing_upstream::open() {
  // Check if already open (idempotent operation)
  if (recv_active_.load(std::memory_order_acquire)) {
    common::log.debug("Multiplexing upstream already open");
    co_return true;
  }
  
  // 1. Call subclass protocol_open()
  bool opened = co_await protocol_open();
  if (!opened) {
    common::log.error("Multiplexing upstream protocol_open() failed");
    co_return false;
  }
  
  // 2. Start receive loop (only if not already active)
  bool expected = false;
  if (recv_active_.compare_exchange_strong(expected, true, std::memory_order_release)) {
    asio::co_spawn(executor_, 
                   [self = shared_from_this()]() { 
                     return std::static_pointer_cast<dns_multiplexing_upstream>(self)->recv_loop(); 
                   },
                   asio::detached);
    
    common::log.info("Multiplexing upstream opened, recv_loop started");
  } else {
    common::log.debug("Multiplexing upstream recv_loop already started by another coroutine");
  }
  
  co_return true;
}

asio::awaitable<void> dns_multiplexing_upstream::close() {
  common::log.warning("Multiplexing upstream close() called");
  // Stop receive loop
  recv_active_.store(false, std::memory_order_release);
  
  // Clean up all pending requests
  std::vector<std::shared_ptr<pending_request>> pending_list;
  {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    for (auto& [tid, req] : pending_requests_) {
      pending_list.push_back(req);
    }
    pending_requests_.clear();
  }
  
  // Mark all pending requests as failed and wake them up
  for (auto& req : pending_list) {
    req->error_code = errc::make_error_code(errc::error_code::request_failed);
    req->completed.store(true, std::memory_order_release);
    // ⭐ Wake up waiting coroutines
    req->wakeup_signal->cancel();
  }
  
  if (!pending_list.empty()) {
    common::log.debug("Multiplexing upstream closed, canceled %zu pending requests",
                      pending_list.size());
  }
  
  // Call subclass protocol_close()
  co_await protocol_close();
  
  common::log.info("Multiplexing upstream closed");
  co_return;
}

asio::awaitable<bool> dns_multiplexing_upstream::is_open() {
  co_return co_await protocol_is_open();
}

asio::awaitable<bool> dns_multiplexing_upstream::send_request(
    const char *data, uint16_t data_length, handle_response handler) {
  
  // Read original TID from buffer
  uint16_t original_tid = (static_cast<uint8_t>(data[0]) << 8) |
                          static_cast<uint8_t>(data[1]);
  
  if (!recv_active_.load(std::memory_order_acquire)) {
    common::log.warning("Multiplexing send_request called but recv_loop not active");
    co_await execute_handler(handler, errc::error_code::request_failed);
    co_return false;
  }
  
  // Error tracking (for use outside catch block, where co_await is permitted)
  bool has_exception = false;
  std::string exception_msg;
  
  // 1. Allocate multiplexing TID
  uint16_t multiplex_tid = allocate_transaction_id();
  
  // 2. Modify TID in-place (no copy needed!)
  char *mutable_data = const_cast<char*>(data);
  mutable_data[0] = static_cast<char>(multiplex_tid >> 8);
  mutable_data[1] = static_cast<char>(multiplex_tid & 0xFF);
  
  // 3. Create pending request (using caller's buffer for response)
  auto req = std::make_shared<pending_request>(executor_, multiplex_tid, mutable_data);
  req->original_tid = original_tid;
  req->handler = handler;
  
  // 4. Register to pending map
  {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    pending_requests_[multiplex_tid] = req;
    
    size_t pending_size = pending_requests_.size();
    if (pending_size > 50) {
      common::log.warning("High pending count: %zu", pending_size);
    }
  }
  
  // 5. Send request and wait for response
  // Note: No internal timeout - rely on external timeout (dns_gateway layer)
  // If timeout occurs, dns_gateway will call close() which will wake up all waiting requests
    last_request_time_ = asio::steady_timer::clock_type::now();
  
  bool success = false;
  
  try {
    // Send request (using modified buffer in-place)
    int length = co_await protocol_send(mutable_data, data_length);

    if (length != data_length) {
      common::log.warning("Send failed: multiplex_tid=0x%04X, sent=%d, expected=%d",
                          multiplex_tid, length, data_length);
      has_exception = true;
      exception_msg = "Send incomplete";
    } else {
      common::log.debug("Multiplexing send: original_tid=0x%04X -> multiplex_tid=0x%04X",
                        original_tid, multiplex_tid);
      
      // Wait for response (indefinitely, until response arrives or close() is called)
      success = co_await wait_for_response(req);
    }
  } catch (const std::exception &e) {
    has_exception = true;
    exception_msg = e.what();
  }
  
  // Cleanup pending request
  {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    auto it = pending_requests_.find(multiplex_tid);
    if (it != pending_requests_.end()) {
      pending_requests_.erase(it);
    }
  }
  
  // Handle errors
  if (has_exception) {
    common::log.warning("send_request exception: %s", exception_msg.c_str());
      co_await execute_handler(handler, errc::error_code::request_failed);
    co_return false;
  }
  
  if (!success) {
    common::log.debug("Request failed or closed: multiplex_tid=0x%04X", multiplex_tid);
    co_await execute_handler(handler, errc::error_code::request_failed);
    co_return false;
  }
  
      co_return true;
    }

asio::awaitable<void> dns_multiplexing_upstream::recv_loop() {
  char recv_buffer[dns::buffer_size];
  
  common::log.debug("Multiplexing recv_loop started");
  
  while (recv_active_.load(std::memory_order_acquire)) {
    try {
      // Receive data from protocol layer
      int length = co_await protocol_recv(recv_buffer, sizeof(recv_buffer));
      
      // Check for error or connection closed
      if (length < 0) {
        common::log.warning("protocol_recv returned error (%d), exiting recv_loop", length);
        break;  // Exit loop on error
      }
      
      if (length < 12) {
        common::log.debug("Received invalid packet, size=%d", length);
        continue;
      }
      
      // Parse multiplexing TID (DNS header first 2 bytes)
      uint16_t multiplex_tid = (static_cast<uint8_t>(recv_buffer[0]) << 8) |
                               static_cast<uint8_t>(recv_buffer[1]);
      
      // Find corresponding pending request
      std::shared_ptr<pending_request> req;
      {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        auto it = pending_requests_.find(multiplex_tid);
        if (it != pending_requests_.end()) {
          req = it->second;
          pending_requests_.erase(it);
        }
      }
      
      if (req) {
        // ⭐ KEY: Restore original TID to response buffer
        recv_buffer[0] = static_cast<char>(req->original_tid >> 8);
        recv_buffer[1] = static_cast<char>(req->original_tid & 0xFF);
        
        // Copy to response buffer
        req->response_length = length;
        std::memcpy(req->response_buffer, recv_buffer, length);
        req->completed.store(true, std::memory_order_release);
        
        // ⭐ Wake up the waiting coroutine by canceling its wakeup signal
        req->wakeup_signal->cancel();
        
        common::log.debug("Multiplexing recv: multiplex_tid=0x%04X -> restored original_tid=0x%04X",
                          multiplex_tid, req->original_tid);
        
        // Execute handler with restored TID
        co_await execute_handler(req->handler, 
                                 errc::error_code::no_error,
                                 req->response_buffer, 
                                 req->response_length);
      } else {
        common::log.debug("Unmatched response: multiplex_tid=0x%04X (timeout or canceled)",
                          multiplex_tid);
      }
      
    } catch (const std::exception &e) {
      if (recv_active_.load(std::memory_order_acquire)) {
        common::log.warning("recv_loop exception: %s", e.what());
      }
      break;
    }
  }
  
  common::log.debug("Multiplexing recv_loop terminated");
}

asio::awaitable<bool> dns_multiplexing_upstream::wait_for_response(
    std::shared_ptr<pending_request> req) {
  
  try {
    // ⭐ Wait indefinitely for wakeup signal (no timeout!)
    // The wakeup_signal will be canceled when:
    // 1. Response arrives (by recv_loop)
    // 2. close() is called (by external timeout or shutdown)
    co_await req->wakeup_signal->async_wait(asio::use_awaitable);
  } catch (const std::system_error &e) {
    // Timer was canceled - this is the normal wakeup path
  }
  
  // Check if completed successfully
  if (req->completed.load(std::memory_order_acquire) && req->response_length > 0) {
    co_return true;
  }

  co_return false;
}

uint16_t dns_multiplexing_upstream::allocate_transaction_id() {
  uint16_t tid = next_transaction_id_.fetch_add(1, std::memory_order_relaxed);
  
  // Skip 0 as it's not a valid transaction ID
  if (tid == 0) {
    tid = next_transaction_id_.fetch_add(1, std::memory_order_relaxed);
  }
  
  // Check for collision (rare but possible in high concurrency)
  {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    int collision_count = 0;
    while (pending_requests_.count(tid) && collision_count < 100) {
      tid = next_transaction_id_.fetch_add(1, std::memory_order_relaxed);
      if (tid == 0) {
        tid = next_transaction_id_.fetch_add(1, std::memory_order_relaxed);
      }
      collision_count++;
    }
    
    if (collision_count > 0) {
      common::log.debug("TID collision detected, retried %d times", collision_count);
    }
  }
  
  return tid;
}

size_t dns_multiplexing_upstream::get_pending_count() const {
  std::lock_guard<std::mutex> lock(pending_mutex_);
  return pending_requests_.size();
}

// ========================================
// dns_udp_upstream implementation
// ========================================

dns_udp_upstream::dns_udp_upstream(asio::any_io_executor executor,
                                   std::string host, uint16_t port)
    : dns_multiplexing_upstream(executor), client_(executor) {
  host_ = host;
  port_ = port;
}

asio::awaitable<bool> dns_udp_upstream::protocol_open() {
  client_.set_proxy(proxy_type_, proxy_host_, proxy_port_);
  bool result = co_await client_.associate(host_, port_);
  
  if (result) {
    common::log.info("UDP %s:%d - associated successfully", host_.c_str(), port_);
  } else {
    common::log.error("UDP %s:%d - failed to associate", host_.c_str(), port_);
  }
  
  co_return result;
}

asio::awaitable<void> dns_udp_upstream::protocol_close() {
  client_.release();
  common::log.info("UDP %s:%d - released", host_.c_str(), port_);
  co_return;
}

asio::awaitable<bool> dns_udp_upstream::protocol_is_open() {
  co_return client_.is_associated();
}

asio::awaitable<int> dns_udp_upstream::protocol_send(const char *data, size_t length) {
  int sent = co_await client_.send(data, length);
  
  if (sent != static_cast<int>(length)) {
    common::log.warning("UDP %s:%d - send incomplete: sent=%d, expected=%zu",
                        host_.c_str(), port_, sent, length);
  }
  
  co_return sent;
}

asio::awaitable<int> dns_udp_upstream::protocol_recv(char *buffer, size_t buffer_size) {
  int received = co_await client_.recv(buffer, buffer_size);
  
  if (received < 0) {
    common::log.warning("UDP %s:%d - recv failed: %d", host_.c_str(), port_, received);
  }
  
  co_return received;
}

dns_tls_upstream::dns_tls_upstream(asio::any_io_executor executor,
                                   std::string host, uint16_t port)
    : dns_upstream(executor), executor_(executor) {
  host_ = host;
  port_ = port;

  client_ = nullptr;
}

dns_tls_upstream::~dns_tls_upstream() {
  disconnect();

  if (tls_context_) {
    delete tls_context_;
  }
}

asio::awaitable<bool> dns_tls_upstream::check() {
  // Validation check: send a test DNS query to verify connection is working
  // This prevents servers from closing idle connections or treating as attack
  try {
    // Use configured check domain or auto-detect based on provider
    std::string check_domain = get_next_check_domain();
    
    dns_package package;
    package.add_question(check_domain.c_str(), dns::anwser_type::a);
    
    char validation_buffer[dns::buffer_size];
    int length = package.dump(validation_buffer, sizeof(validation_buffer));
    
    if (length > 0) {
      bool validation_passed = false;
      
      auto validation_handler = [&](std::error_code ec, const char *data,
                                     uint16_t data_length) -> asio::awaitable<void> {
        if (!ec && data_length > 0) {
          validation_passed = true;
        }
        co_return;
      };
      
      // Send validation request
      bool send_result = co_await send_request(validation_buffer, length, validation_handler);
      
      if (send_result && validation_passed) {
        co_return true;
      }
    }
  } catch (const std::exception &e) {
    common::log.debug("TLS/HTTPS %s:%d - health check exception: %s",
                      host_.c_str(), port_, e.what());
  }
  
  co_return false;
}

asio::awaitable<bool> dns_tls_upstream::open() {
  if (client_ == nullptr) {
    create_client();
  }

  bool connected = co_await connect();
  
  if (!connected) {
    co_return false;
  }
  
  // Immediately validate the connection after establishing
  bool check_result = co_await check();
  
  if (check_result) {
    common::log.debug("TLS/HTTPS upstream %s:%d opened and validated",
                      host_.c_str(), port_);
    co_return true;
  } else {
    common::log.warning("TLS/HTTPS connection validation failed for %s:%d, closing",
                        host_.c_str(), port_);
    disconnect();
    co_return false;
  }
}

asio::awaitable<void> dns_tls_upstream::close() {
  disconnect();
  co_return;
}

asio::awaitable<bool> dns_tls_upstream::is_open() {
  if (client_ == nullptr)
    co_return false;

  co_return is_connected();
}

asio::awaitable<bool> dns_tls_upstream::send_request(const char *data,
                                                     uint16_t data_length,
                                                     handle_response handler) {
  try {
    // send dns request
    last_request_time_ = asio::steady_timer::clock_type::now();

    dns_buffer request_buffer((uint8_t *)buffer_, sizeof(buffer_));
    request_buffer.write_16bits(data_length);
    request_buffer.write_buffer(data, data_length);

    common::log.debug("TLS %s:%d - sending request, size=%d bytes", 
                      host_.c_str(), port_, request_buffer.size());
    co_await client_->write(request_buffer.data(), request_buffer.size());
    common::log.debug("TLS %s:%d - request sent, waiting for response", 
                      host_.c_str(), port_);

    int buffer_length = co_await client_->read_some(buffer_, sizeof(buffer_));

    common::log.debug("TLS %s:%d - received %d bytes", 
                      host_.c_str(), port_, buffer_length);

    if (buffer_length > 0) {
      if (!keep_alive_) {
        disconnect();
      }

      dns_buffer response_buffer((uint8_t *)buffer_, buffer_length);
      uint16_t response_length = response_buffer.read_16bits();

      common::log.debug("TLS %s:%d - response parsed, dns_length=%d bytes", 
                        host_.c_str(), port_, response_length);

      co_await execute_handler(handler, errc::error_code::no_error,
                               response_buffer.data() + 2, response_length);
      co_return true;
    } else {
      common::log.warning("TLS %s:%d - empty response received", 
                          host_.c_str(), port_);
    }
  } catch (const std::exception &e) {
    common::log.warning("TLS %s:%d - request failed: %s", 
                        host_.c_str(), port_, e.what());
    try {
      disconnect();
    } catch (const std::exception &e) {
    }
  }

  co_return false;
}

void dns_tls_upstream::create_client() {
  // Use tls_client method to support both TLSv1.2 and TLSv1.3
  tls_context_ = new asio::ssl::context(asio::ssl::context::tls_client);

  if (security_verify_) {
    tls_context_->set_default_verify_paths();
    tls_context_->set_options(ssl::context::default_workarounds | 
                              ssl::context::no_sslv2 | 
                              ssl::context::no_sslv3 | 
                              ssl::context::no_tlsv1 | 
                              ssl::context::no_tlsv1_1);
    // tls_context_->set_verify_mode(asio::ssl::verify_peer);

    if (ca_certificate_ != "") {
      tls_context_->load_verify_file(ca_certificate_);
    } else {
      tls_context_->load_verify_file("/etc/ssl/certs/ca-certificates.crt");
    }
  } else {
    tls_context_->set_verify_mode(asio::ssl::verify_none);
  }

  if (certificate_ != "") {
    tls_context_->use_certificate_file(certificate_, asio::ssl::context::pem);
  }

  if (private_key_ != "") {
    tls_context_->use_private_key_file(private_key_, asio::ssl::context::pem);
  }

  client_ = std::make_shared<socks::socks_tls_client>(executor_, *tls_context_);
}

asio::awaitable<bool> dns_tls_upstream::connect() {
  client_->set_proxy(proxy_type_, proxy_host_, proxy_port_);

  bool status = co_await client_->connect(host_, port_);
  co_return status;
}

void dns_tls_upstream::dns_tls_upstream::disconnect() { client_->disconnect(); }

bool dns_tls_upstream::is_connected() { return client_->is_connected(); }

void dns_tls_upstream::handle_exception(std::error_code error) {
  if (error) {
    disconnect();
  }
}

dns_https_upstream::dns_https_upstream(asio::any_io_executor executor,
                                       std::string host, uint16_t port,
                                       std::string path)
    : dns_tls_upstream(executor, host, port), path_(path) {
}

char *dns_https_upstream::search_substring(char *buffer,
                                           std::size_t buffer_length,
                                           const char *substring) {
  std::size_t substring_length = std::strlen(substring);

  for (std::size_t i = 0; i < buffer_length; ++i) {
    if (i + substring_length > buffer_length)
      break;

    if (std::memcmp(buffer + i, substring, substring_length) == 0)
      return buffer + i;
  }

  return nullptr;
}

asio::awaitable<bool>
dns_https_upstream::send_request(const char *data, uint16_t data_length,
                                 handle_response handler) {
  try {
    // send dns request
    last_request_time_ = asio::steady_timer::clock_type::now();
    std::string request_string = "";
    request_string += "POST " + path_ + " HTTP/1.1\r\n";
    request_string += "Host: " + host_ + "\r\n";
    request_string += "User-Agent: dns-gateway/3.0\r\n";
    request_string += "Accept: application/dns-message\r\n";  // RFC 8484 required
    request_string += "Content-Type: application/dns-message\r\n";

    if (keep_alive_) {
      request_string += "Connection: keep-alive\r\n";
    } else {
      request_string += "Connection: close\r\n";
    }

    request_string += "Content-Length: " + std::to_string(data_length) + "\r\n";
    request_string += "\r\n";

    uint16_t request_length = (uint16_t)request_string.length();
    std::copy(request_string.begin(), request_string.end(), buffer_);
    std::copy(data, data + data_length, buffer_ + request_length);
    request_length += data_length;

    common::log.debug("DoH %s:%d - sending HTTP request, total=%d bytes (header=%d, body=%d)", 
                      host_.c_str(), port_, request_length, request_string.length(), data_length);
    co_await client_->write(buffer_, request_length);
    common::log.debug("DoH %s:%d - HTTP request sent, waiting for response", 
                      host_.c_str(), port_);

    std::string response;
    int buffer_length = co_await client_->read_some(buffer_, sizeof(buffer_));

    common::log.debug("DoH %s:%d - received %d bytes from server", 
                      host_.c_str(), port_, buffer_length);

    char *header_end = search_substring(buffer_, buffer_length, "\r\n\r\n");
    if (header_end != buffer_ + buffer_length) {
      // Calculate the length of the data after the header
      header_end += 4;
      int data_length = buffer_length - (header_end - buffer_);

      std::string response_header(buffer_, header_end);
      http_header header = parse_http_header(response_header);
      
      common::log.debug("DoH %s:%d - HTTP response: status=%d, content_type=%s, content_length=%d, connection=%s, body_received=%d",
                        host_.c_str(), port_, header.status_code, header.content_type.c_str(), 
                        header.content_length, header.connection.c_str(), data_length);
      
      if (check_http_header(header)) {
        // Handle case where body is in a separate TLS record (Quad9 does this)
        if (data_length < header.content_length) {
          int remaining = header.content_length - data_length;
          common::log.debug("DoH %s:%d - body incomplete, reading additional %d bytes", 
                            host_.c_str(), port_, remaining);
          // Read remaining body data
          int additional_length = co_await client_->read_some(
              buffer_ + buffer_length, sizeof(buffer_) - buffer_length);
          
          common::log.debug("DoH %s:%d - read additional %d bytes", 
                            host_.c_str(), port_, additional_length);
          data_length += additional_length;
        }
        
        if (data_length == header.content_length) {
          // Check server's Connection header - server has final say
          std::string conn_lower = header.connection;
          std::transform(conn_lower.begin(), conn_lower.end(), conn_lower.begin(), ::tolower);
          
          if (!keep_alive_ || conn_lower == "close") {
            common::log.debug("DoH %s:%d - closing connection (keep_alive=%d, server_connection=%s)",
                              host_.c_str(), port_, keep_alive_, header.connection.c_str());
            disconnect();
          } else {
            common::log.debug("DoH %s:%d - keeping connection alive",
                              host_.c_str(), port_);
          }

          co_await execute_handler(handler, errc::error_code::no_error,
                                   header_end, data_length);
          co_return true;
        } else {
          common::log.warning("DoH %s:%d - data length mismatch: expected=%d, received=%d",
                              host_.c_str(), port_, header.content_length, data_length);
          co_await execute_handler(handler, errc::error_code::http_data_error);
        }
      } else {
        common::log.warning("DoH %s:%d - invalid HTTP response: status=%d, content_type=%s",
                            host_.c_str(), port_, header.status_code, header.content_type.c_str());
        co_await execute_handler(handler,
                                 errc::error_code::http_header_invalid);
      }
    } else {
      common::log.warning("DoH %s:%d - no HTTP header terminator found in %d bytes",
                          host_.c_str(), port_, buffer_length);
    }
  } catch (const std::exception &e) {
    common::log.warning("DoH %s:%d - request exception: %s",
                        host_.c_str(), port_, e.what());
    try {
      disconnect();
    } catch (const std::exception &e) {
    }
  }

  co_return false;
}

http_header
dns_https_upstream::parse_http_header(const std::string &header_string) {
  http_header header;

  size_t start_pos = header_string.find(' ');
  size_t end_pos = header_string.find(' ', start_pos + 1);
  if (start_pos != std::string::npos && end_pos != std::string::npos) {
    header.http_version = header_string.substr(0, start_pos);
    header.status_code =
        std::stoi(header_string.substr(start_pos + 1, end_pos - start_pos - 1));
    header.status_message = header_string.substr(
        end_pos + 1, header_string.find('\n', end_pos) - end_pos - 1);
  }

  size_t pos = header_string.find('\n');
  while (pos != std::string::npos && pos < header_string.length() - 1) {
    size_t separator_pos = header_string.find(':', pos);
    if (separator_pos != std::string::npos) {
      std::string key = header_string.substr(pos + 1, separator_pos - pos - 1);
      std::string value = header_string.substr(
          separator_pos + 2,
          header_string.find('\n', separator_pos) - separator_pos - 2);

      if (!value.empty() && value.back() == '\r') {
        value.pop_back();
      }

      // Convert the key to lowercase for case-insensitive comparison
      std::transform(key.begin(), key.end(), key.begin(), ::tolower);

      if (key == "server") {
        header.server = value;
      } else if (key == "date") {
        header.date = value;
      } else if (key == "content-type") {
        header.content_type = value;
      } else if (key == "connection") {
        header.connection = value;
      } else if (key == "content-length") {
        header.content_length = std::stoi(value);
      }
    }

    pos = header_string.find('\n', pos + 1);
  }

  return header;
}

bool dns_https_upstream::check_http_header(http_header header) {
  if (header.status_code != 200) {
    return false;
  }

  if (header.content_type != "application/dns-message") {
    return false;
  }

  // ignore kee-alive
  // if (header.connection != "keep-alive")
  // {
  //     return false;
  // }

  if (header.content_length == 0) {
    return false;
  }

  return true;
}

// ========================================
// HTTP/2 Upstream Implementation
// ========================================

dns_http2_upstream::dns_http2_upstream(asio::any_io_executor executor,
                                       std::string host, uint16_t port,
                                       std::string path)
    : dns_multiplexing_upstream(executor),
      ssl_context_(nullptr),
      session_(nullptr) {
  
  // Set base class properties (inherited from dns_upstream_property)
  host_ = std::move(host);
  port_ = port;
  
  // Default HTTP path
  path_ = std::move(path);
  
  // Default SSL settings
  security_verify_ = true;
  
  common::log.info("HTTP/2 upstream created: %s:%d", host_.c_str(), port_);
}

void dns_http2_upstream::create_client() {
  // Create SSL context (similar to dns_tls_upstream)
  ssl_context_ = new asio::ssl::context(asio::ssl::context::tls_client);

  if (security_verify_) {
    ssl_context_->set_default_verify_paths();
    ssl_context_->set_options(ssl::context::default_workarounds | 
                              ssl::context::no_sslv2 | 
                              ssl::context::no_sslv3 | 
                              ssl::context::no_tlsv1 | 
                              ssl::context::no_tlsv1_1);
    // ssl_context_->set_verify_mode(asio::ssl::verify_peer);

    if (ca_certificate_ != "") {
      ssl_context_->load_verify_file(ca_certificate_);
  } else {
      ssl_context_->load_verify_file("/etc/ssl/certs/ca-certificates.crt");
    }
  } else {
    ssl_context_->set_verify_mode(asio::ssl::verify_none);
  }

  if (certificate_ != "") {
    ssl_context_->use_certificate_file(certificate_, asio::ssl::context::pem);
  }

  if (private_key_ != "") {
    ssl_context_->use_private_key_file(private_key_, asio::ssl::context::pem);
  }

  client_ = std::make_shared<socks::socks_tls_client>(executor_, *ssl_context_);
}

dns_http2_upstream::~dns_http2_upstream() {
  if (session_) {
    nghttp2_session_del(session_);
    session_ = nullptr;
  }
  if (ssl_context_) {
    delete ssl_context_;
    ssl_context_ = nullptr;
  }
  common::log.info("HTTP/2 upstream destroyed: %s:%d", host_.c_str(), port_);
}

asio::awaitable<bool> dns_http2_upstream::protocol_open() {
  try {
    // Create client
    create_client();
    
    // Set proxy (from base class dns_upstream)
    client_->set_proxy(proxy_type_, proxy_host_, proxy_port_);
    
    // Set SNI
    if (!SSL_set_tlsext_host_name(client_->get_socket().native_handle(), host_.c_str())) {
      common::log.error("HTTP/2 %s:%d - Failed to set SNI", host_.c_str(), port_);
      co_return false;
    }
    
    // Set ALPN (h2)
    const unsigned char alpn[] = "\x02h2";
    if (SSL_set_alpn_protos(client_->get_socket().native_handle(), alpn, sizeof(alpn) - 1) != 0) {
      common::log.error("HTTP/2 %s:%d - Failed to set ALPN", host_.c_str(), port_);
      co_return false;
    }
    
    // Connect (supports socks5 proxy)
    bool connected = co_await client_->connect(host_, port_);
    if (!connected) {
      common::log.error("HTTP/2 %s:%d - Connection failed", host_.c_str(), port_);
      co_return false;
    }
    
    // Verify ALPN negotiated h2
    const unsigned char *alpn_selected;
    unsigned int alpn_len;
    SSL_get0_alpn_selected(client_->get_socket().native_handle(), &alpn_selected, &alpn_len);
    
    if (alpn_len == 0) {
      common::log.error("HTTP/2 %s:%d - No ALPN protocol selected by server", host_.c_str(), port_);
      client_->disconnect();
      co_return false;
    } else if (alpn_len != 2 || memcmp(alpn_selected, "h2", 2) != 0) {
      std::string selected_proto(reinterpret_cast<const char*>(alpn_selected), alpn_len);
      common::log.error("HTTP/2 %s:%d - ALPN negotiation failed: server selected '%s' instead of 'h2'", 
                       host_.c_str(), port_, selected_proto.c_str());
      client_->disconnect();
      co_return false;
    }
    
    // Initialize nghttp2 session
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
    
    int rv = nghttp2_session_client_new(&session_, callbacks, this);
    nghttp2_session_callbacks_del(callbacks);
    
    if (rv != 0) {
      common::log.error("HTTP/2 %s:%d - Failed to create session: %s",
                       host_.c_str(), port_, nghttp2_strerror(rv));
      client_->disconnect();
      co_return false;
    }
    
    // Send connection preface and SETTINGS
    nghttp2_settings_entry iv[1] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    
    rv = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, iv, 1);
    if (rv != 0) {
      common::log.error("HTTP/2 %s:%d - Failed to submit settings: %s",
                       host_.c_str(), port_, nghttp2_strerror(rv));
      // Clean up session before returning
      if (session_) {
        nghttp2_session_del(session_);
        session_ = nullptr;
      }
      co_return false;
    }
    
    // Send initial data (connection preface + SETTINGS)
    bool status = co_await send_session_data();
    if (!status) {
      common::log.error("HTTP/2 %s:%d - Failed to send connection preface", 
                       host_.c_str(), port_);
      if (session_) {
        nghttp2_session_del(session_);
        session_ = nullptr;
      }
      client_->disconnect();
      co_return false;
    }
    
    common::log.info("HTTP/2 %s:%d - Connection established", host_.c_str(), port_);
    co_return true;
    
  } catch (const std::exception &e) {
    common::log.error("HTTP/2 %s:%d - Open failed: %s",
                     host_.c_str(), port_, e.what());
    // Clean up session if it was created
    if (session_) {
      nghttp2_session_del(session_);
      session_ = nullptr;
    }
    // Clean up client
    if (client_) {
      client_->disconnect();
    }
    co_return false;
  }
}

asio::awaitable<void> dns_http2_upstream::protocol_close() {
  common::log.warning("HTTP/2 %s:%d - protocol_close() called", host_.c_str(), port_);
  try {
    if (session_) {
      nghttp2_session_terminate_session(session_, NGHTTP2_NO_ERROR);
      bool status = co_await send_session_data();
      if (!status) {
        common::log.warning("HTTP/2 %s:%d - Failed to send GOAWAY frame (non-critical)",
                           host_.c_str(), port_);
      }
      
      nghttp2_session_del(session_);
      session_ = nullptr;
    }
    
    if (client_) {
      client_->disconnect();
    }
    
    // Clean up response queue
    while (!response_ready_queue_.empty()) {
      response_ready_queue_.pop();
    }
    
    common::log.info("HTTP/2 %s:%d - Connection closed", host_.c_str(), port_);
  } catch (const std::exception &e) {
    common::log.warning("HTTP/2 %s:%d - Close error: %s",
                       host_.c_str(), port_, e.what());
  }
  
  co_return;
}

asio::awaitable<bool> dns_http2_upstream::protocol_is_open() {
  co_return (client_ && client_->is_connected() && session_);
}

asio::awaitable<int> dns_http2_upstream::protocol_send(const char *data, size_t length) {
  if (!session_) {
    co_return -1;
  }
  
  try {
    // Read TID from data (first 2 bytes, already modified by multiplexing layer)
    uint16_t multiplex_tid = (static_cast<uint8_t>(data[0]) << 8) |
                             static_cast<uint8_t>(data[1]);
    
    // Prepare HTTP/2 headers for POST request
    std::vector<nghttp2_nv> hdrs;
    
    auto make_nv = [](const char *name, const char *value) -> nghttp2_nv {
      return {(uint8_t *)name, (uint8_t *)value, strlen(name), strlen(value),
              NGHTTP2_NV_FLAG_NONE};
    };
    
    hdrs.push_back(make_nv(":method", "POST"));
    hdrs.push_back(make_nv(":scheme", "https"));
    hdrs.push_back(make_nv(":authority", host_.c_str()));
    hdrs.push_back(make_nv(":path", path_.c_str()));
    hdrs.push_back(make_nv("content-type", "application/dns-message"));
    
    std::string content_length = std::to_string(length);
    hdrs.push_back(make_nv("content-length", content_length.c_str()));
    
    // Helper struct to pass both data pointer and length to callback
    struct send_data_info {
      const char* data;
      size_t length;
      size_t offset;
    };
    
    // Create on stack (valid until function returns)
    send_data_info send_info{data, length, 0};
    
    // Data provider for request body
    nghttp2_data_provider data_prd;
    data_prd.source.ptr = &send_info;
    data_prd.read_callback = [](nghttp2_session *session, int32_t stream_id,
                                 uint8_t *buf, size_t buflen, uint32_t *data_flags,
                                 nghttp2_data_source *source,
                                 void *user_data) -> ssize_t {
      auto *info = static_cast<send_data_info *>(source->ptr);
      
      size_t remaining = info->length - info->offset;
      size_t to_copy = std::min(remaining, buflen);
      
      if (to_copy > 0) {
        memcpy(buf, info->data + info->offset, to_copy);
        info->offset += to_copy;
      }
      
      // Check if all data sent
      if (info->offset >= info->length) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      }
      
      return to_copy;
    };
    
    // Submit request with multiplex_tid as stream_user_data
    void *stream_user_data = reinterpret_cast<void*>(static_cast<uintptr_t>(multiplex_tid));
    int32_t stream_id = nghttp2_submit_request(
        session_, nullptr, hdrs.data(), hdrs.size(), &data_prd, stream_user_data);
    
    if (stream_id < 0) {
      common::log.error("HTTP/2 %s:%d - Failed to submit request: %s",
                       host_.c_str(), port_, nghttp2_strerror(stream_id));
      co_return -1;
    }
    
    bool status = co_await send_session_data();
    if (!status) {
      common::log.error("HTTP/2 %s:%d - Failed to send request data",
                       host_.c_str(), port_);
      co_return -1;
    }
    
    co_return length;
    
  } catch (const std::exception &e) {
    common::log.error("HTTP/2 %s:%d - Send failed: %s",
                     host_.c_str(), port_, e.what());
    co_return -1;
  }
}

asio::awaitable<int> dns_http2_upstream::protocol_recv(char *buffer, size_t buffer_size) {
  
  if (!session_ || !client_) {
    common::log.error("HTTP/2 %s:%d - protocol_recv: session or client is null", 
                     host_.c_str(), port_);
    co_return -1;
  }
  
  try {
    // Loop: read and process frames until we get a complete response
    while (true) {
      // Check if queue has any ready responses
      uint16_t ready_tid = 0;
      if (!response_ready_queue_.empty()) {
        ready_tid = response_ready_queue_.front();
        response_ready_queue_.pop();
      }
      
      // If we got a ready TID, fetch the data from pending_request
      if (ready_tid != 0) {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        auto it = pending_requests_.find(ready_tid);
        if (it != pending_requests_.end()) {
          auto& req = it->second;
          
          size_t copy_len = std::min(static_cast<size_t>(req->response_length), buffer_size);
          memcpy(buffer, req->response_buffer, copy_len);
          
          int result = req->response_length;
          
          // common::log.debug("HTTP/2 %s:%d - Returning response for TID=%u, length=%d",
          //                 host_.c_str(), port_, ready_tid, result);
          
          co_return result;
        } else {
          common::log.warning("HTTP/2 %s:%d - Ready TID=%u not found in pending_requests",
                            host_.c_str(), port_, ready_tid);
          // Continue to read more data
        }
      }
      
      // No ready response, continue reading and processing frames
      char read_buf[8192];
      auto bytes = co_await client_->read_some(read_buf, sizeof(read_buf));
      
      if (bytes <= 0) {
        common::log.warning("HTTP/2 %s:%d - Connection closed (read returned %d)",
                          host_.c_str(), port_, bytes);
        co_return -1;
      }
      
      // Feed data to nghttp2 (will trigger callbacks that may push to queue)
      ssize_t rv = nghttp2_session_mem_recv(session_, (const uint8_t *)read_buf, bytes);
      if (rv < 0) {
        common::log.error("HTTP/2 %s:%d - mem_recv failed: %s",
                         host_.c_str(), port_, nghttp2_strerror((int)rv));
        co_return -1;
      }
      
      // Loop back to check if callback filled any response
    }
    
  } catch (const std::exception &e) {
    common::log.error("HTTP/2 %s:%d - Recv failed: %s",
                     host_.c_str(), port_, e.what());
    co_return -1;
  }
}

// Helper: Send pending session data
asio::awaitable<bool> dns_http2_upstream::send_session_data() {
  if (!session_ || !client_) {
    co_return false;
  }
  
  int chunk_count = 0;
  while (true) {
    const uint8_t *data;
    ssize_t datalen = nghttp2_session_mem_send(session_, &data);
    
    if (datalen < 0) {
      common::log.error("HTTP/2 %s:%d - mem_send failed: %s",
                       host_.c_str(), port_, nghttp2_strerror((int)datalen));
      co_return false;
    }
    
    if (datalen == 0) {
      break;
    }
    
    chunk_count++;
    int written = co_await client_->write(reinterpret_cast<const char*>(data), datalen);
    if (written != datalen) {
      common::log.error("HTTP/2 %s:%d - Write incomplete: %d/%zu bytes", 
                       host_.c_str(), port_, written, datalen);
      co_return false;
    }
  }
  co_return true;
}

// nghttp2 callbacks
int dns_http2_upstream::on_frame_recv_callback(nghttp2_session *session,
                                               const nghttp2_frame *frame,
                                               void *user_data) {
  // auto *self = static_cast<dns_http2_upstream *>(user_data);
  (void)user_data;  // Unused
  
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      // common::log.debug("HTTP/2 - Received response headers on stream %d",
      //                  frame->hd.stream_id);
    }
    break;
  case NGHTTP2_DATA:
    // common::log.debug("HTTP/2 - Received DATA frame on stream %d",
    //                  frame->hd.stream_id);
    break;
  }
  
  return 0;
}

int dns_http2_upstream::on_data_chunk_recv_callback(nghttp2_session *session,
                                                    uint8_t flags,
                                                    int32_t stream_id,
                                                    const uint8_t *data,
                                                    size_t len,
                                                    void *user_data) {
  auto *self = static_cast<dns_http2_upstream *>(user_data);
  
  // 1. Get multiplex_tid from stream_user_data (no mapping table needed!)
  void *stream_user_data = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!stream_user_data) {
    common::log.warning("HTTP/2 - Received data for stream without user_data: stream_id=%d", stream_id);
    return 0;
  }
  uint16_t multiplex_tid = static_cast<uint16_t>(reinterpret_cast<uintptr_t>(stream_user_data));
  
  // 2. Find pending_request and fill response buffer directly
  {
    std::lock_guard<std::mutex> lock(self->pending_mutex_);
    auto it = self->pending_requests_.find(multiplex_tid);
    if (it == self->pending_requests_.end()) {
      common::log.warning("HTTP/2 - Received data for unknown multiplex_tid=%u (stream_id=%d)",
                         multiplex_tid, stream_id);
      return 0;
    }
    
    auto& req = it->second;
    
    // Check buffer size
    if (len > dns::buffer_size) {
      common::log.error("HTTP/2 - Response too large: %zu bytes (max %d)",
                       len, dns::buffer_size);
      len = dns::buffer_size;
    }
    
    // Copy data directly to pending_request's response_buffer
    memcpy(req->response_buffer, data, len);
    
    // Keep multiplex_tid in response buffer (recv_loop will restore original_tid)
    req->response_buffer[0] = static_cast<char>(multiplex_tid >> 8);
    req->response_buffer[1] = static_cast<char>(multiplex_tid & 0xFF);
    
    // Set response_length
    req->response_length = static_cast<size_t>(len);
  }
  
  // 3. Push multiplex_tid to ready queue
  self->response_ready_queue_.push(multiplex_tid);  
  return 0;
}

ssize_t dns_http2_upstream::send_callback(nghttp2_session *session,
                                         const uint8_t *data, size_t length,
                                         int flags, void *user_data) {
  // We use mem_send instead, so this is not used
  return NGHTTP2_ERR_WOULDBLOCK;
}

ssize_t dns_http2_upstream::recv_callback(nghttp2_session *session,
                                         uint8_t *buf, size_t length,
                                         int flags, void *user_data) {
  // We use mem_recv instead, so this is not used
  return NGHTTP2_ERR_WOULDBLOCK;
}

} // namespace dns