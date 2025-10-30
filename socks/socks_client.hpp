//
// File: socks_client.hpp
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

#include "socks_buffer.hpp"
#include "socks_common.hpp"
#include "socks_error.hpp"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <list>
#include <memory>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <set>
#include <string>
#include <utility>

namespace socks {
constexpr int socks_buffer_size = 1024;
constexpr int udp_buffer_size = 4096;

enum class proxy_type {
  none = 0,
  socks4 = 4,
  socks5 = 5,
};

enum class proxy_command {
  connect = 1,
  bind,
  udp_associate,
};

enum class reply_status {
  succeeded,
  general_socks_server_failure,
  connection_not_allowed_by_ruleset,
  network_unreachable,
  host_unreachable,
  connection_refused,
  ttl_expired,
  command_not_supported,
  address_type_not_supported,
  unassigned,
};

class socks_base_client
    : public std::enable_shared_from_this<socks_base_client> {
public:
  socks_base_client(asio::any_io_executor executor);

  void set_auth(bool user_auth, const std::string &username,
                const std::string &password);
  void set_proxy(proxy_type type, const std::string &proxy_address,
                 uint16_t proxy_port);

protected:
  asio::awaitable<bool> connect(asio::ip::tcp::socket &socket,
                                const std::string &remote_address,
                                uint16_t remote_port);

  void check_methods(uint8_t methods);
  void check_reply(reply_status reply);

  virtual asio::awaitable<bool> connect_socks5(asio::ip::tcp::socket &socket);
  virtual asio::awaitable<bool> connect_proxy(asio::ip::tcp::socket &socket);
  virtual asio::awaitable<bool> request_socks5(asio::ip::tcp::socket &socket);
  virtual asio::awaitable<bool> request_command(asio::ip::tcp::socket &socket,
                                                uint8_t command);

protected:
  asio::any_io_executor executor_;

  proxy_type proxy_type_;
  std::string proxy_address_;
  uint16_t proxy_port_;

  bool user_auth_;
  std::string username_;
  std::string password_;

  std::string remote_address_;
  uint16_t remote_port_;
  address_type remote_type_;

  std::string bind_address_;
  uint16_t bind_port_;
  address_type bind_type_;

  socks_buffer socks_buffer_;
};

class socks_tcp_client : public socks_base_client {
public:
  socks_tcp_client(asio::any_io_executor executor);

  asio::awaitable<bool> connect(const std::string &remote_address,
                                uint16_t remote_port);
  void disconnect();

  asio::awaitable<int> write(const char *data, uint16_t data_length);
  asio::awaitable<int> read(char *data, uint16_t data_length);

  asio::ip::tcp::socket &get_socket();
  bool is_connected();

protected:
  asio::awaitable<bool> connect_socks5(asio::ip::tcp::socket &socket) override;

private:
  asio::ip::tcp::socket socket_;
};

class socks_tls_client : public socks_base_client {
public:
  socks_tls_client(asio::any_io_executor executor,
                   asio::ssl::context &ssl_context);
  ~socks_tls_client();

  asio::awaitable<bool> connect(const std::string &host, uint16_t port);
  void disconnect();

  asio::awaitable<int> write(const char *data, uint16_t data_length);
  asio::awaitable<int> read(char *data, uint16_t data_length);
  asio::awaitable<int> read_some(char *data, uint16_t data_length);

  asio::ssl::stream<asio::ip::tcp::socket> &get_socket();
  bool is_connected();

protected:
  asio::awaitable<bool> connect_socks5(asio::ip::tcp::socket &socket) override;

private:
  // bool verify_certificate(bool preverified, asio::ssl::verify_context& ctx);

  asio::ssl::stream<asio::ip::tcp::socket> tls_socket_;
};

class socks_udp_client : public socks_base_client {
public:
  socks_udp_client(asio::any_io_executor executor);

  asio::awaitable<bool> associate(const std::string &remote_address,
                                  uint16_t remote_port);
  void release();

  asio::awaitable<int> send(const char *data, uint16_t data_length);
  asio::awaitable<int> recv(char *data, uint16_t data_length);

  asio::ip::udp::socket &get_socket();
  bool is_associated();

protected:
  asio::awaitable<bool> connect_socks5(asio::ip::tcp::socket &socket) override;
  asio::awaitable<int> send_socks(const char *data, uint16_t data_length);
  asio::awaitable<int> recv_socks(char *data, uint16_t data_length);
  bool open_udp_socket();
  void keep_proxy_connection();

private:
  asio::ip::tcp::socket socket_;
  asio::ip::udp::socket udp_socket_;
  asio::ip::udp::resolver resolver_;
  asio::ip::udp::resolver::results_type endpoints_;

  socks_buffer send_buffer_;
  socks_buffer recv_buffer_;
  int send_buffer_size_;
  int recv_buffer_size_;
};
} // namespace socks