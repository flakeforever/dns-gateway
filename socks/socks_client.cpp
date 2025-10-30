//
// File: socks_client.cpp
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

#include "socks_client.hpp"
#include "../common/log.hpp"
#include <regex>

#define PRINT_EXCEPTION(e)                                                     \
  std::printf("(%s) Exception: %s\n", __FUNCTION__, (e).what())

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::redirect_error;
using asio::use_awaitable;
using asio::ip::tcp;

namespace socks {
socks_base_client::socks_base_client(asio::any_io_executor executor)
    : executor_(std::move(executor)) {
  username_ = "";
  password_ = "";
  user_auth_ = false;

  remote_address_ = "";
  remote_port_ = 0;

  proxy_type_ = proxy_type::none;
  proxy_address_ = "";
  proxy_port_ = 0;

  socks_buffer_.reserve(socks_buffer_size);
}

asio::awaitable<bool>
socks_base_client::connect(asio::ip::tcp::socket &socket,
                           const std::string &remote_address,
                           uint16_t remote_port) {
  remote_address_ = remote_address;
  remote_port_ = remote_port;
  remote_type_ = get_address_type(remote_address_);

  common::log.debug("socks connect to %s:%d, type: %d", remote_address_.c_str(), 
                    remote_port_, (int)remote_type_);

  if (proxy_type_ == proxy_type::none) {
    asio::ip::tcp::resolver resolver(executor_);
    asio::ip::tcp::resolver::results_type endpoints =
        resolver.resolve(remote_address_, std::to_string(remote_port_));

    try {
      // connect proxy server
      co_await asio::async_connect(socket, endpoints, asio::use_awaitable);
      common::log.debug("direct connect success to %s:%d", remote_address_.c_str(), 
                        remote_port_);
    } catch (const std::system_error &e) {
      common::log.error("direct connect failed to %s:%d, error: %s", 
                        remote_address_.c_str(), remote_port_, e.what());
      socket.cancel();
      socket.close();

      throw e;
    }

    co_return true;
  } else if (proxy_type_ == proxy_type::socks4) {
    throw std::system_error(socks::errc::make_error_code(
        socks::errc::error_code::unsupported_version));
  } else if (proxy_type_ == proxy_type::socks5) {
    co_return co_await connect_socks5(socket);
  }
}

void socks_base_client::set_auth(bool user_auth, const std::string &username,
                                 const std::string &password) {
  user_auth_ = user_auth;
  username_ = username;
  password_ = password;
}

void socks_base_client::set_proxy(proxy_type type,
                                  const std::string &proxy_address,
                                  uint16_t proxy_port) {
  proxy_type_ = type;
  proxy_address_ = proxy_address;
  proxy_port_ = proxy_port;
}

void socks_base_client::check_methods(uint8_t methods) {
  if (methods != 0 && methods != 2) {
    throw std::system_error(socks::errc::make_error_code(
        socks::errc::error_code::unsupported_authentication_method));
  }
}

void socks_base_client::check_reply(reply_status reply) {
  switch (reply) {
  case reply_status::succeeded:
    break;
  case reply_status::general_socks_server_failure:
    throw std::system_error(socks::errc::make_error_code(
        socks::errc::error_code::general_socks_server_failure));
    break;
  case reply_status::connection_not_allowed_by_ruleset:
    throw std::system_error(socks::errc::make_error_code(
        socks::errc::error_code::connection_not_allowed_by_ruleset));
    break;
  case reply_status::network_unreachable:
    throw std::system_error(socks::errc::make_error_code(
        socks::errc::error_code::network_unreachable));
    break;
  case reply_status::host_unreachable:
    throw std::system_error(socks::errc::make_error_code(
        socks::errc::error_code::host_unreachable));
    break;
  case reply_status::connection_refused:
    throw std::system_error(socks::errc::make_error_code(
        socks::errc::error_code::connection_refused));
    break;
  case reply_status::ttl_expired:
    throw std::system_error(
        socks::errc::make_error_code(socks::errc::error_code::ttl_expired));
    break;
  case reply_status::command_not_supported:
    throw std::system_error(socks::errc::make_error_code(
        socks::errc::error_code::command_not_supported));
    break;
  case reply_status::address_type_not_supported:
    throw std::system_error(socks::errc::make_error_code(
        socks::errc::error_code::address_type_not_supported));
    break;
  case reply_status::unassigned:
    throw std::system_error(
        socks::errc::make_error_code(socks::errc::error_code::unassigned));
    break;
  }
}

asio::awaitable<bool>
socks_base_client::connect_proxy(asio::ip::tcp::socket &socket) {
  common::log.debug("connecting to proxy %s:%d", proxy_address_.c_str(), proxy_port_);
  
  asio::ip::tcp::resolver resolver(executor_);
  asio::ip::tcp::resolver::results_type endpoints =
      resolver.resolve(proxy_address_, std::to_string(proxy_port_));

  try {
    // connect proxy server
    co_await asio::async_connect(socket, endpoints, asio::use_awaitable);
    common::log.debug("proxy connection established to %s:%d", proxy_address_.c_str(), 
                      proxy_port_);
  } catch (const std::system_error &e) {
    common::log.error("proxy connection failed to %s:%d, error: %s", 
                      proxy_address_.c_str(), proxy_port_, e.what());
    socket.close();
    throw e;
  }

  co_return true;
}

asio::awaitable<bool>
socks_base_client::request_socks5(asio::ip::tcp::socket &socket) {
  common::log.debug("requesting socks5 authentication, user_auth: %d", user_auth_);
  
  // request auth
  uint8_t version = (uint8_t)proxy_type::socks5;
  uint8_t methods_count = 1;
  uint8_t methods = 0;

  socks_buffer_.resize(0);
  socks_buffer_.set_position(0);
  socks_buffer_.write_8bits(version);
  socks_buffer_.write_8bits(methods_count);

  if (user_auth_)
    methods = 0x2;

  socks_buffer_.write_8bits(methods);

  try {
    co_await asio::async_write(
        socket, asio::buffer(socks_buffer_.data(), socks_buffer_.size()),
        asio::use_awaitable);

    // response auth
    socks_buffer_.resize(socks_buffer_size);
    co_await socket.async_read_some(
        asio::buffer(socks_buffer_.data(), socks_buffer_.size()),
        asio::use_awaitable);
  } catch (const std::system_error &e) {
    socket.close();
    throw e;
  }

  socks_buffer_.set_position(0);
  version = socks_buffer_.read_8bits();
  methods = socks_buffer_.read_8bits();

  if (version != (uint8_t)proxy_type::socks5) {
    throw std::system_error(socks::errc::make_error_code(
        socks::errc::error_code::unsupported_version));
  }

  check_methods(methods);

  common::log.debug("socks5 auth method selected: %d", methods);

  if (methods == 2) {
    socks_buffer_.resize(0);
    socks_buffer_.set_position(0);
    socks_buffer_.write_8bits(1);
    socks_buffer_.write_string(username_);
    socks_buffer_.write_string(password_);

    try {
      co_await asio::async_write(
          socket, asio::buffer(socks_buffer_.data(), socks_buffer_.size()),
          asio::use_awaitable);

      // response auth with username and password
      socks_buffer_.resize(socks_buffer_size);
      co_await socket.async_read_some(
          asio::buffer(socks_buffer_.data(), socks_buffer_.size()),
          asio::use_awaitable);
    } catch (const std::system_error &e) {
      socket.close();
      throw e;
    }

    socks_buffer_.set_position(0);
    version = socks_buffer_.read_8bits();
    uint8_t status = socks_buffer_.read_8bits();

    if (version != 1) {
      throw std::system_error(socks::errc::make_error_code(
          socks::errc::error_code::unsupported_authentication_version));
    }

    if (status != 0) {
      common::log.error("socks5 authentication failed, status: %d", status);
      throw std::system_error(socks::errc::make_error_code(
          socks::errc::error_code::authentication_error));
    }
    
    common::log.debug("socks5 user authentication success");
  }

  co_return true;
}

asio::awaitable<bool>
socks_base_client::request_command(asio::ip::tcp::socket &socket,
                                   uint8_t command) {
  common::log.debug("socks5 request command: %d to %s:%d", command, 
                    remote_address_.c_str(), remote_port_);
  
  // request auth
  uint8_t version = (uint8_t)proxy_type::socks5;
  uint8_t reserved = 0;
  uint8_t addr_type = (uint8_t)remote_type_;

  socks_buffer_.resize(0);
  socks_buffer_.set_position(0);
  socks_buffer_.write_8bits(version);
  socks_buffer_.write_8bits(command);
  socks_buffer_.write_8bits(reserved);
  socks_buffer_.write_8bits(addr_type);
  socks_buffer_.write_address(remote_type_, remote_address_, remote_port_);

  try {
    co_await asio::async_write(
        socket, asio::buffer(socks_buffer_.data(), socks_buffer_.size()),
        asio::use_awaitable);

    socks_buffer_.resize(socks_buffer_size);
    co_await socket.async_read_some(
        asio::buffer(socks_buffer_.data(), socks_buffer_.size()),
        asio::use_awaitable);
  } catch (const std::system_error &e) {
    socket.close();
    throw e;
  }

  uint8_t reply;

  socks_buffer_.set_position(0);
  version = socks_buffer_.read_8bits();
  reply = socks_buffer_.read_8bits();
  reserved = socks_buffer_.read_8bits();
  addr_type = socks_buffer_.read_8bits();

  bind_type_ = (address_type)addr_type;

  if (version != (uint8_t)proxy_type::socks5) {
    throw std::system_error(socks::errc::make_error_code(
        socks::errc::error_code::unsupported_version));
  }

  check_reply(static_cast<reply_status>(reply));

  socks_buffer_.read_address(bind_type_, bind_address_, bind_port_);
  common::log.debug("socks5 command success, bind_address: %s:%d", 
                    bind_address_.c_str(), bind_port_);

  co_return true;
}

asio::awaitable<bool>
socks_base_client::connect_socks5(asio::ip::tcp::socket &socket) {
  bool connected = co_await connect_proxy(socket);

  if (!connected) {
    co_return false;
  }

  bool status = co_await request_socks5(socket);

  if (!status) {
    co_return false;
  }

  co_return true;
}

socks_tcp_client::socks_tcp_client(asio::any_io_executor executor)
    : socks_base_client(executor), socket_(executor) {}

asio::awaitable<bool>
socks_tcp_client::connect(const std::string &remote_address,
                          uint16_t remote_port) {
  common::log.debug("socks_tcp_client connecting to %s:%d", 
                    remote_address.c_str(), remote_port);
  co_return co_await ::socks::socks_base_client::connect(
      socket_, remote_address, remote_port);
}

void socks_tcp_client::disconnect() {
  if (socket_.is_open()) {
    socket_.close();
  }
}

asio::awaitable<int> socks_tcp_client::write(const char *data,
                                             uint16_t data_length) {
  try {
    co_return co_await asio::async_write(
        socket_, asio::buffer(data, data_length), asio::use_awaitable);
  } catch (const std::system_error &e) {
    disconnect();
    throw e;
  }
}

asio::awaitable<int> socks_tcp_client::read(char *data, uint16_t data_length) {
  try {
    co_return co_await asio::async_read(
        socket_, asio::buffer(data, data_length), asio::use_awaitable);
  } catch (const std::system_error &e) {
    disconnect();
    throw e;
  }
}

asio::ip::tcp::socket &socks_tcp_client::get_socket() { return socket_; }

bool socks_tcp_client::is_connected() { return socket_.is_open(); }

asio::awaitable<bool>
socks_tcp_client::connect_socks5(asio::ip::tcp::socket &socket) {
  bool status = co_await ::socks::socks_base_client::connect_socks5(socket);

  if (!status)
    co_return false;

  status = co_await request_command(socket, (uint8_t)proxy_command::connect);

  if (!status)
    co_return false;

  // redirct supported
  // TODO

  co_return true;
}

socks_tls_client::socks_tls_client(asio::any_io_executor executor,
                                   asio::ssl::context &ssl_context)
    : socks_base_client(executor), tls_socket_(executor, ssl_context) {}

socks_tls_client::~socks_tls_client() {}

// bool socks_tls_client::verify_certificate(bool preverified,
// asio::ssl::verify_context& ctx)
// {
//     // The verify callback can be used to check whether the certificate that
//     is
//     // being presented is valid for the peer. For example, RFC 2818 describes
//     // the steps involved in doing this for HTTPS. Consult the OpenSSL
//     // documentation for more details. Note that the callback is called once
//     // for each certificate in the certificate chain, starting from the root
//     // certificate authority.

//     // In this example we will simply print the certificate's subject name.
//     char subject_name[256];
//     X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
//     X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
//     std::cout << "Verifying " << subject_name << "\n";

//     return preverified;
// }

asio::awaitable<bool> socks_tls_client::connect(const std::string &host,
                                                uint16_t port) {
  bool status = co_await ::socks::socks_base_client::connect(
      (asio::ip::tcp::socket &)tls_socket_.lowest_layer(), host, port);

  if (!status)
    co_return false;

  if (!SSL_set_tlsext_host_name(tls_socket_.native_handle(), host.c_str())) {
    std::error_code ec{static_cast<int>(::ERR_get_error()),
                       asio::error::get_ssl_category()};
    throw std::system_error{ec};
  }

  try {
    // https handshake
    tls_socket_.set_verify_mode(asio::ssl::verify_peer);
    // tls_socket_.set_verify_callback(
    //     std::bind(&socks_tls_client::verify_certificate, this,
    //     std::placeholders::_1, std::placeholders::_2));

    co_await tls_socket_.async_handshake(asio::ssl::stream_base::client,
                                         asio::use_awaitable);
  } catch (const std::system_error &e) {
    disconnect();
    throw e;
  }

  co_return true;
}

void socks_tls_client::disconnect() {
  SSL_clear(tls_socket_.native_handle());

  if (tls_socket_.lowest_layer().is_open()) {
    tls_socket_.lowest_layer().close();
  }
}

asio::awaitable<int> socks_tls_client::write(const char *data,
                                             uint16_t data_length) {
  try {
    co_return co_await asio::async_write(
        tls_socket_, asio::buffer(data, data_length), asio::use_awaitable);
  } catch (const std::system_error &e) {
    disconnect();
    throw e;
  }
}

asio::awaitable<int> socks_tls_client::read(char *data, uint16_t data_length) {
  try {
    co_return co_await asio::async_read(
        tls_socket_, asio::buffer(data, data_length), asio::use_awaitable);
  } catch (const std::system_error &e) {
    disconnect();
    throw e;
  }
}

asio::awaitable<int> socks_tls_client::read_some(char *data, uint16_t data_length) {
  try {
    co_return co_await tls_socket_.async_read_some(
        asio::buffer(data, data_length), asio::use_awaitable);
  } catch (const std::system_error &e) {
    disconnect();
    throw e;
  }
}

asio::ssl::stream<asio::ip::tcp::socket> &socks_tls_client::get_socket() {
  return tls_socket_;
}

bool socks_tls_client::is_connected() {
  int state = SSL_get_state(tls_socket_.native_handle());
  return tls_socket_.lowest_layer().is_open() && state == TLS_ST_OK;
}

asio::awaitable<bool>
socks_tls_client::connect_socks5(asio::ip::tcp::socket &socket) {
  bool status = co_await ::socks::socks_base_client::connect_socks5(socket);

  if (!status)
    co_return false;

  status = co_await request_command(socket, (uint8_t)proxy_command::connect);

  if (!status)
    co_return false;

  // redirct supported
  // TODO

  co_return true;
}

socks_udp_client::socks_udp_client(asio::any_io_executor executor)
    : socks_base_client(executor), socket_(executor), udp_socket_(executor),
      resolver_(executor) {
  send_buffer_.reserve(udp_buffer_size);
  recv_buffer_.reserve(udp_buffer_size);
}

asio::awaitable<bool>
socks_udp_client::associate(const std::string &remote_address,
                            uint16_t remote_port) {
  common::log.debug("socks_udp_client associate to %s:%d, proxy_type: %d", 
                    remote_address.c_str(), remote_port, (int)proxy_type_);
  
  if (proxy_type_ == proxy_type::none) {
    remote_address_ = remote_address;
    remote_port_ = remote_port;
    remote_type_ = get_address_type(remote_address_);

    endpoints_ =
        resolver_.resolve(remote_address_, std::to_string(remote_port_));
    co_return open_udp_socket();
  } else {
    co_return co_await ::socks::socks_base_client::connect(
        socket_, remote_address, remote_port);
  }
}

void socks_udp_client::release() {
  if (socket_.is_open()) {
    socket_.close();
  }

  if (udp_socket_.is_open()) {
    udp_socket_.close();
  }
}

asio::awaitable<int> socks_udp_client::send(const char *data,
                                            uint16_t data_length) {
  if (proxy_type_ == proxy_type::none) {
    if (data_length > udp_buffer_size) {
      common::log.error("udp send buffer overflow, data_length: %d", data_length);
      throw std::system_error(socks::errc::make_error_code(
          socks::errc::error_code::buffer_overflow));
    }

    send_buffer_.resize(0);
    send_buffer_.set_position(0);
    send_buffer_.write_buffer(data, data_length);

    int length = 0;

    try {
      length = co_await udp_socket_.async_send_to(
          asio::buffer(send_buffer_.data(), send_buffer_.size()),
          *endpoints_.begin(), asio::use_awaitable);
      common::log.debug("udp send success: %d bytes to %s:%d", length,
                        remote_address_.c_str(), remote_port_);
    } catch (const std::system_error &e) {
      common::log.error("udp send failed to %s:%d, error: %s", 
                        remote_address_.c_str(), remote_port_, e.what());
      release();
      throw e;
    }

    co_return length;
  } else {
    co_return co_await send_socks(data, data_length);
  }
}

asio::awaitable<int> socks_udp_client::recv(char *data, uint16_t data_length) {
  if (proxy_type_ == proxy_type::none) {
    if (data_length > udp_buffer_size) {
      common::log.error("udp recv buffer overflow, data_length: %d", data_length);
      throw std::system_error(socks::errc::make_error_code(
          socks::errc::error_code::buffer_overflow));
    }

    recv_buffer_.resize(data_length);

    int length = 0;

    try {
      length = co_await udp_socket_.async_receive(
          asio::buffer(recv_buffer_.data(), recv_buffer_.size()),
          asio::use_awaitable);
      common::log.debug("udp recv success: %d bytes from %s:%d", length,
                        remote_address_.c_str(), remote_port_);
    } catch (const std::system_error &e) {
      // ignore recv timeout
      if (e.code() != asio::error::operation_aborted) {
        common::log.error("udp recv failed from %s:%d, error: %s", 
                          remote_address_.c_str(), remote_port_, e.what());
        release();
        throw e;
      }
    }

    recv_buffer_.set_position(0);
    recv_buffer_.read_buffer(data, data_length);

    co_return length;
  } else {
    co_return co_await recv_socks(data, data_length);
  }
}

asio::ip::udp::socket &socks_udp_client::get_socket() { return udp_socket_; }

bool socks_udp_client::is_associated() {
  if (proxy_type_ == proxy_type::none) {
    return udp_socket_.is_open();
  } else if (proxy_type_ == proxy_type::socks5) {
    return socket_.is_open() && udp_socket_.is_open();
  }

  return false;
}

asio::awaitable<bool>
socks_udp_client::connect_socks5(asio::ip::tcp::socket &socket) {
  common::log.debug("socks_udp_client starting socks5 handshake");
  
  bool status = co_await ::socks::socks_base_client::connect_socks5(socket);

  if (!status)
    co_return false;

  status =
      co_await request_command(socket, (uint8_t)proxy_command::udp_associate);

  if (!status)
    co_return false;

  endpoints_ = resolver_.resolve(bind_address_, std::to_string(bind_port_));

  // open udp socket with protocol
  open_udp_socket();
  keep_proxy_connection();

  common::log.debug("socks_udp_client socks5 handshake completed");
  co_return true;
}

asio::awaitable<int> socks_udp_client::send_socks(const char *data,
                                                  uint16_t data_length) {
  uint16_t reserved = 0;
  uint8_t fragment = 0;
  uint8_t addr_type = (uint8_t)remote_type_;

  send_buffer_.resize(0);
  send_buffer_.set_position(0);
  send_buffer_.write_16bits(reserved);
  send_buffer_.write_8bits(fragment);
  send_buffer_.write_8bits(addr_type);
  send_buffer_.write_address(remote_type_, remote_address_, remote_port_);

  int head_length = send_buffer_.size();
  if (head_length + data_length > udp_buffer_size) {
    throw std::system_error(
        socks::errc::make_error_code(socks::errc::error_code::buffer_overflow));
  }

  send_buffer_.write_buffer(data, data_length);

  int length = 0;

  try {
    length = co_await udp_socket_.async_send_to(
        asio::buffer(send_buffer_.data(), send_buffer_.size()),
        *endpoints_.begin(), asio::use_awaitable);
  } catch (const std::system_error &e) {
    release();
    throw e;
  }

  co_return length - head_length;
}

asio::awaitable<int> socks_udp_client::recv_socks(char *data,
                                                  uint16_t data_length) {
  int length = 0;

  try {
    recv_buffer_.resize(udp_buffer_size);
    length = co_await udp_socket_.async_receive(
        asio::buffer(recv_buffer_.data(), recv_buffer_.size()),
        asio::use_awaitable);
  } catch (const std::system_error &e) {
    // ignore recv timeout
    if (e.code() != asio::error::operation_aborted) {
      release();
      throw e;
    }
  }

  if (length < 4) {
    throw std::system_error(
        socks::errc::make_error_code(socks::errc::error_code::udp_data_error));
  }

  recv_buffer_.set_position(0);
  uint16_t reserved = recv_buffer_.read_16bits();
  uint8_t fragment = recv_buffer_.read_8bits();

  address_type remote_type = (address_type)recv_buffer_.read_8bits();
  std::string remote_address;
  uint16_t remote_port;

  // check response
  if (reserved != 0 || fragment != 0 || remote_type == address_type::none) {
    throw std::system_error(
        socks::errc::make_error_code(socks::errc::error_code::udp_data_error));
  }

  if (!recv_buffer_.read_address(remote_type, remote_address, remote_port)) {
    throw std::system_error(
        socks::errc::make_error_code(socks::errc::error_code::udp_data_error));
  }

  // check remote port
  if (remote_port != remote_port_) {
    throw std::system_error(socks::errc::make_error_code(
        socks::errc::error_code::remote_data_error));
  }

  // check remote type
  if (remote_type != remote_type_) {
    if (remote_type_ == address_type::domain) {
      if (remote_type == address_type::ipv4 ||
          remote_type == address_type::ipv6) {
        // update remote address (domain to ip)
        remote_type_ = remote_type;
        remote_address_ = remote_address;
      } else {
        throw std::system_error(socks::errc::make_error_code(
            socks::errc::error_code::remote_data_error));
      }
    } else {
      throw std::system_error(socks::errc::make_error_code(
          socks::errc::error_code::remote_data_error));
    }
  } else {
    // check remote address
    if (remote_address != remote_address_) {
      throw std::system_error(socks::errc::make_error_code(
          socks::errc::error_code::remote_data_error));
    }
  }

  int head_length = recv_buffer_.position();
  int result_length = length - head_length;

  if (result_length > data_length) {
    throw std::system_error(
        socks::errc::make_error_code(socks::errc::error_code::buffer_overflow));
  }

  if (recv_buffer_.read_buffer(data, result_length)) {
    co_return result_length;
  }

  co_return 0;
}

bool socks_udp_client::open_udp_socket() {
  asio::ip::udp::endpoint endpoints = *endpoints_.begin();

  if (endpoints.protocol() == asio::ip::udp::v4()) {
    udp_socket_.open(asio::ip::udp::v4());
    common::log.debug("udp socket opened with IPv4");
  } else if (endpoints.protocol() == asio::ip::udp::v6()) {
    udp_socket_.open(asio::ip::udp::v6());
    common::log.debug("udp socket opened with IPv6");
  } else {
    common::log.error("unsupported udp protocol");
    return false;
  }

  return true;
}

void socks_udp_client::keep_proxy_connection() {
  co_spawn(
      executor_,
      [&]() -> asio::awaitable<void> {
        while (true) {
          try {
            socks_buffer_.resize(socks_buffer_size);
            co_await socket_.async_read_some(
                asio::buffer(socks_buffer_.data(), socks_buffer_.size()),
                asio::use_awaitable);
          } catch (const std::system_error &e) {
            release();
            co_return;
          }
        }
      },
      detached);
}
} // namespace socks
