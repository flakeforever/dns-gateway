//
// File: dns_package.hpp
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
#include <vector>
#include "dns_buffer.hpp"
#include "property.hpp"
#include <random>

namespace dns
{
    constexpr uint32_t default_ttl = 600;

    enum class qr_type
    {
        request = 0,
        response = 1
    };

    enum class rcode_type
    {
        ok_response = 0,
        formaterror_response = 1,
        serverfailure_response = 2,
        nameerror_response = 3,
        notimplemented_response = 4,
        refused_response = 5
    };

    enum class class_type
    {
        in = 1
    };

    enum class opcode_type
    {
        question = 0,  // standard Question
        iquestion = 1, // inverse Question
        status = 2,    // server status request
        notify = 4,    // request zone transfer
        update = 5     // change resource records
    };

    enum class anwser_type
    {
        a = 1,
        ns = 2,
        cname = 5,
        soa = 6,
        ptr = 12,
        mx = 15,
        txt = 16,
        aaaa = 28,
        srv = 33
    };

    class dns_question_property
    {
    public:
        PROPERTY_READWRITE(std::string, q_name);
        PROPERTY_READWRITE(uint16_t, q_type);
        PROPERTY_READWRITE(uint16_t, q_class);
    };

    class dns_question : public dns_question_property, public std::enable_shared_from_this<dns_question>
    {
    public:
        dns_question(std::string q_name, uint16_t q_type, uint16_t q_class);
    };

    class dns_answer_property
    {
    public:
        PROPERTY_READWRITE(std::string, a_name);
        PROPERTY_READWRITE(uint16_t, a_type);
        PROPERTY_READWRITE(uint16_t, a_class);
        PROPERTY_READWRITE(uint32_t, a_ttl);
    };

    class dns_answer : public dns_answer_property, public std::enable_shared_from_this<dns_answer>
    {
    public:
        dns_answer(std::string a_name, dns::anwser_type a_type, uint16_t a_class, uint32_t a_ttl);
    };

    class dns_a_answer : public dns_answer
    {
    public:
        dns_a_answer(std::string a_name, uint16_t a_class, uint32_t a_ttl);

        uint8_t addr[4];
    };

    class dns_aaaa_answer : public dns_answer
    {
    public:
        dns_aaaa_answer(std::string a_name, uint16_t a_class, uint32_t a_ttl);

        uint8_t addr[16];
    };

    class dns_cname_answer : public dns_answer
    {
    public:
        dns_cname_answer(std::string a_name, uint16_t a_class, uint32_t a_ttl);

        std::string domain;
    };

    class dns_ns_answer : public dns_answer
    {
    public:
        dns_ns_answer(std::string a_name, uint16_t a_class, uint32_t a_ttl);

        std::string domain;
    };

    class dns_txt_answer : public dns_answer
    {
    public:
        dns_txt_answer(std::string a_name, uint16_t a_class, uint32_t a_ttl);

        std::string text;
    };

    class dns_mx_answer : public dns_answer
    {
    public:
        dns_mx_answer(std::string a_name, uint16_t a_class, uint32_t a_ttl);

        uint16_t priority;
        std::string domain;
    };

    class dns_packag_property
    {
    public:
        PROPERTY_READWRITE(uint16_t, id);
        PROPERTY_READWRITE(uint16_t, flags);
        PROPERTY_READWRITE(uint16_t, que_count);
        PROPERTY_READWRITE(uint16_t, ans_count);
        PROPERTY_READWRITE(uint16_t, aut_count);
        PROPERTY_READWRITE(uint16_t, add_count);
    };

    class dns_package : public dns_packag_property, public std::enable_shared_from_this<dns_package>
    {
    public:
        dns_package();

        void add_question(std::string domain, dns::anwser_type question_type);
        void add_anwser(std::string domain, dns::anwser_type anwser_type, std::string value);

        bool parse(const char *data, uint16_t data_length);
        void output();
        int dump(char *data, uint16_t data_length);
        uint32_t get_ttl();
        void set_ttl(uint32_t ttl);
        void reset();

        uint8_t flag_qr();
        uint8_t flag_opcode();
        uint8_t flag_rcode();
        uint8_t flag_ad();
        uint8_t flag_ra();

        void flag_qr(uint8_t qr);
        void flag_opcode(uint8_t opcode);
        void flag_rcode(uint8_t rcode);
        void flag_ad(uint8_t value);
        void flag_ra(uint8_t value);

        std::vector<std::shared_ptr<dns_question>> questions_;
        std::vector<std::shared_ptr<dns_answer>> answers_;

    protected:
        std::string qr_to_string(uint8_t qr);

        std::string rcodes_to_string(uint8_t rcode);
        std::string opcode_to_string(uint8_t opcode);
        std::string rtypes_to_string(uint8_t rtype);
        std::string classes_to_string(uint8_t class_);

        std::string ipv4_to_string(uint8_t *buffer, std::size_t size);
        std::string ipv6_to_string(uint8_t *buffer, std::size_t size);
        bool string_to_ipv4(const std::string &address, uint8_t *buffer, std::size_t size);
        bool string_to_ipv6(const std::string &address, uint8_t *buffer, std::size_t size);

        uint16_t generate_id(uint16_t min_id, uint16_t max_id);

        dns_buffer buffer_;
    };
}
