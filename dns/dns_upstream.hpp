//
// File: dns_upstream.hpp
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

#include "dns_buffer.hpp"
#include "dns_error.hpp"
#include "operation.hpp"
#include "property.hpp"
#include <socks/socks_client.hpp>
#include <asio.hpp>
#include <nghttp2/nghttp2.h>
#include <mutex>
#include <unordered_map>
#include <queue>

namespace dns {
constexpr int connect_timeout = 15000;
constexpr int request_timeout = 3500;
constexpr int doh_port = 443;
constexpr int dot_port = 853;

class dns_upstream_property {
public:
  PROPERTY_READONLY(std::string, host);
  PROPERTY_READONLY(uint16_t, port);
  PROPERTY_READONLY(socks::proxy_type, proxy_type);
  PROPERTY_READONLY(std::string, proxy_host);
  PROPERTY_READONLY(uint16_t, proxy_port);

  PROPERTY_READWRITE(bool, check_enabled);
  PROPERTY_READWRITE(int, check_interval);

  PROPERTY_READONLY(asio::steady_timer::time_point, last_request_time);
  
  // Statistics for this upstream instance (reset periodically by check)
  std::atomic<uint64_t> request_count_{0};
  std::atomic<uint64_t> success_count_{0};
  std::atomic<uint64_t> failed_count_{0};
  std::atomic<int64_t> total_response_time_ms_{0};  // Sum of all response times
  
  // Cumulative request counter
  std::atomic<uint64_t> cumulative_requests_{0};
  
  // Health check domains (parsed from comma-separated string)
  std::vector<std::string> check_domains_;
  std::atomic<size_t> check_domain_index_{0};  // For round-robin selection
};

class dns_upstream : public dns_upstream_property,
                     public std::enable_shared_from_this<dns_upstream> {
public:
  typedef std::function<asio::awaitable<void>(
      std::error_code ec, const char *data, uint16_t data_length)>
      handle_response;

  dns_upstream(asio::any_io_executor executor);

  virtual asio::awaitable<bool> open();
  virtual asio::awaitable<void> close();
  virtual asio::awaitable<bool> is_open();
  virtual asio::awaitable<bool>
  send_request(const char *data, uint16_t data_length, handle_response handler);
  virtual asio::awaitable<bool> check();
  
  // Record request statistics
  void record_request(bool success, std::chrono::milliseconds response_time);
  virtual void set_proxy(socks::proxy_type proxy_type, std::string proxy_host,
                         uint16_t proxy_port);
  
  // Set and parse health check domains (comma-separated)
  void set_check_domains(const std::string &domains);
  
  // Get next domain for health check (round-robin)
  std::string get_next_check_domain();
  
  // Check if this upstream supports concurrent requests (multiplexing)
  // UDP/multiplexing upstreams support it, TCP-based (DoT/DoH) does not
  virtual bool supports_multiplexing() const { return false; }

  std::atomic_bool locked_ = false;

protected:
  asio::awaitable<void> execute_handler(handle_response handler,
                                        std::error_code error,
                                        const char *data = nullptr,
                                        size_t size = 0);
  asio::awaitable<void> execute_handler(handle_response handler,
                                        std::system_error error,
                                        const char *data = nullptr,
                                        size_t size = 0);
  asio::awaitable<void> execute_handler(handle_response handler,
                                        dns::errc::error_code error,
                                        const char *data = nullptr,
                                        size_t size = 0);
  virtual void handle_exception(std::error_code error);

  asio::any_io_executor executor_;
  char buffer_[dns::buffer_size];

private:
};

// ========================================
// Multiplexing Upstream (Abstract Layer)
// ========================================
// Provides request/response multiplexing support for connection-oriented protocols
// Subclasses only need to implement protocol-specific send/recv methods
class dns_multiplexing_upstream : public dns_upstream {
public:
  dns_multiplexing_upstream(asio::any_io_executor executor);
  virtual ~dns_multiplexing_upstream();
  
  // Override base class methods with multiplexing support
  asio::awaitable<bool> open() override;
  asio::awaitable<void> close() override;
  asio::awaitable<bool> is_open() override;
  
  // Send request using raw buffer
  asio::awaitable<bool> send_request(const char *data, uint16_t data_length,
                                     handle_response handler) override;
  
  // Multiplexing upstreams support concurrent requests
  bool supports_multiplexing() const override { return true; }
  
  // Get pending request count (for monitoring)
  size_t get_pending_count() const;

protected:
  // ========================================
  // Protocol abstraction (pure virtual)
  // Subclasses must implement these methods
  // ========================================
  
  // Open connection/association
  virtual asio::awaitable<bool> protocol_open() = 0;
  
  // Close connection
  virtual asio::awaitable<void> protocol_close() = 0;
  
  // Check if connection is open
  virtual asio::awaitable<bool> protocol_is_open() = 0;
  
  // Send raw data
  virtual asio::awaitable<int> protocol_send(const char *data, size_t length) = 0;
  
  // Receive raw data
  virtual asio::awaitable<int> protocol_recv(char *buffer, size_t buffer_size) = 0;
  
  // ========================================
  // Protected members for derived classes
  // ========================================
  
  // Pending request structure
  struct pending_request {
    uint16_t transaction_id;      // Multiplexing TID
    uint16_t original_tid;         // Original client TID
    handle_response handler;
    std::atomic<bool> completed{false};
    char *response_buffer;         // ⭐ Pointer to external buffer (from dns_object)
    size_t response_length{0};
    std::error_code error_code;
    std::shared_ptr<asio::steady_timer> wakeup_signal;  // Signal for waking up waiting coroutine
    
    pending_request(asio::any_io_executor exec, uint16_t tid, char *buffer)
      : transaction_id(tid),
        original_tid(0),
        response_buffer(buffer),   // ⭐ Store pointer to external buffer
        response_length(0),
        wakeup_signal(std::make_shared<asio::steady_timer>(exec)) {
      // Set to never expire (will be canceled to signal completion)
      wakeup_signal->expires_at(asio::steady_timer::time_point::max());
    }
  };
  
  // Pending requests map (transaction_id -> pending_request)
  std::unordered_map<uint16_t, std::shared_ptr<pending_request>> pending_requests_;
  mutable std::mutex pending_mutex_;

private:
  // ========================================
  // Multiplexing core implementation
  // ========================================
  
  // Continuous receive loop
  asio::awaitable<void> recv_loop();
  
  // Wait for specific request to complete (no internal timeout)
  asio::awaitable<bool> wait_for_response(std::shared_ptr<pending_request> req);
  
  // Allocate unique transaction ID
  uint16_t allocate_transaction_id();
  
  // Receive loop control
  std::atomic<bool> recv_active_{false};
  
  // Transaction ID allocator
  std::atomic<uint16_t> next_transaction_id_{1};
};

class dns_udp_upstream : public dns_multiplexing_upstream {
public:
  dns_udp_upstream(asio::any_io_executor executor, std::string host,
                   uint16_t port);

protected:
  // Implement protocol abstraction for UDP
  asio::awaitable<bool> protocol_open() override;
  asio::awaitable<void> protocol_close() override;
  asio::awaitable<bool> protocol_is_open() override;
  asio::awaitable<int> protocol_send(const char *data, size_t length) override;
  asio::awaitable<int> protocol_recv(char *buffer, size_t buffer_size) override;

private:
  socks::socks_udp_client client_;
};

class dns_tls_property {
  PROPERTY_READWRITE(bool, security_verify);
  PROPERTY_READWRITE(std::string, ca_certificate);
  PROPERTY_READWRITE(std::string, certificate);
  PROPERTY_READWRITE(std::string, private_key);
  PROPERTY_READWRITE(bool, keep_alive);
};

class dns_tls_upstream : public dns_tls_property, public dns_upstream {
public:
  dns_tls_upstream(asio::any_io_executor executor, std::string host,
                   uint16_t port);
  ~dns_tls_upstream();

  virtual asio::awaitable<bool> open() override;
  virtual asio::awaitable<void> close() override;
  virtual asio::awaitable<bool> is_open() override;
  virtual asio::awaitable<bool> send_request(const char *data,
                                             uint16_t data_length,
                                             handle_response handler) override;
  virtual asio::awaitable<bool> check() override;

protected:
  void create_client();
  asio::awaitable<bool> connect();
  void disconnect();
  bool is_connected();

  void handle_exception(std::error_code error) override;

  asio::any_io_executor executor_;
  asio::ssl::context *tls_context_;
  std::shared_ptr<socks::socks_tls_client> client_;

  char buffer_[dns::buffer_size];
};

class http_header {
public:
  std::string http_version;
  int status_code;
  std::string status_message;
  std::string server;
  std::string date;
  std::string content_type;
  std::string connection;
  int content_length;
};

class dns_https_upstream : public dns_tls_upstream {
public:
  dns_https_upstream(asio::any_io_executor executor, std::string host,
                     uint16_t port, std::string path);

  asio::awaitable<bool> send_request(const char *data, uint16_t data_length,
                                     handle_response handler) override;

protected:
  http_header parse_http_header(const std::string &header_string);
  bool check_http_header(http_header header);
  char *search_substring(char *buffer, std::size_t buffer_length,
                         const char *substring);

private:
  std::string path_;
};

// ========================================
// HTTP/2 (DoH) Upstream
// ========================================
class dns_http2_property {
  PROPERTY_READWRITE(bool, security_verify);
  PROPERTY_READWRITE(std::string, ca_certificate);
  PROPERTY_READWRITE(std::string, certificate);
  PROPERTY_READWRITE(std::string, private_key);
  PROPERTY_READWRITE(std::string, path);  // HTTP path, e.g., "/dns-query"
};

class dns_http2_upstream : public dns_http2_property,
                           public dns_multiplexing_upstream {
public:
  dns_http2_upstream(asio::any_io_executor executor, std::string host,
                     uint16_t port, std::string path);
  ~dns_http2_upstream();

protected:
  // Implement protocol abstraction for HTTP/2
  asio::awaitable<bool> protocol_open() override;
  asio::awaitable<void> protocol_close() override;
  asio::awaitable<bool> protocol_is_open() override;
  asio::awaitable<int> protocol_send(const char *data, size_t length) override;
  asio::awaitable<int> protocol_recv(char *buffer, size_t buffer_size) override;

private:
  void create_client();
  
  // SSL/TLS connection via socks proxy
  asio::ssl::context *ssl_context_;
  std::shared_ptr<socks::socks_tls_client> client_;
  
  // HTTP/2 session
  nghttp2_session* session_;
  
  // Response ready queue (for protocol_recv to return)
  // Multiple streams may complete during one nghttp2_session_mem_recv call
  // Queue stores multiplex_tid of ready responses (data is in pending_request)
  // Note: No mutex needed - only accessed by recv_loop coroutine and its callbacks
  std::queue<uint16_t> response_ready_queue_;
  
  // Internal helpers
  asio::awaitable<bool> send_session_data();
  static int on_frame_recv_callback(nghttp2_session *session,
                                    const nghttp2_frame *frame,
                                    void *user_data);
  static int on_data_chunk_recv_callback(nghttp2_session *session,
                                         uint8_t flags, int32_t stream_id,
                                         const uint8_t *data, size_t len,
                                         void *user_data);
  static ssize_t send_callback(nghttp2_session *session,
                               const uint8_t *data, size_t length,
                               int flags, void *user_data);
  static ssize_t recv_callback(nghttp2_session *session,
                               uint8_t *buf, size_t length,
                               int flags, void *user_data);
};

} // namespace dns