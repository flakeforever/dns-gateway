//
// File: dns_package.cpp
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

#include "dns_package.hpp"
#include "dns_log.hpp"
#include "dns_upstream.hpp"

namespace dns
{
    dns_question::dns_question(std::string q_name, uint16_t q_type, uint16_t q_class)
    {
        q_name_ = q_name;
        q_type_ = q_type;
        q_class_ = q_class;
    }

    dns_answer::dns_answer(std::string a_name, dns::anwser_type a_type, uint16_t a_class, uint32_t a_ttl)
    {
        a_name_ = a_name;
        a_type_ = static_cast<uint8_t>(a_type);
        a_class_ = a_class;
        a_ttl_ = a_ttl;
    }

    dns_a_answer::dns_a_answer(std::string a_name, uint16_t a_class, uint32_t a_ttl)
        : dns_answer(a_name, dns::anwser_type::a, a_class, a_ttl)
    {
        memset(addr, 0, sizeof(addr));
    }

    uint8_t addr[4];

    dns_aaaa_answer::dns_aaaa_answer(std::string a_name, uint16_t a_class, uint32_t a_ttl)
        : dns_answer(a_name, dns::anwser_type::aaaa, a_class, a_ttl)
    {
        memset(addr, 0, sizeof(addr));
    }

    dns_cname_answer::dns_cname_answer(std::string a_name, uint16_t a_class, uint32_t a_ttl)
        : dns_answer(a_name, dns::anwser_type::cname, a_class, a_ttl)
    {
        domain = "";
    }

    dns_ns_answer::dns_ns_answer(std::string a_name, uint16_t a_class, uint32_t a_ttl)
        : dns_answer(a_name, dns::anwser_type::ns, a_class, a_ttl)
    {
        domain = "";
    }

    dns_txt_answer::dns_txt_answer(std::string a_name, uint16_t a_class, uint32_t a_ttl)
        : dns_answer(a_name, dns::anwser_type::txt, a_class, a_ttl)
    {
        text = "";
    }

    dns_mx_answer::dns_mx_answer(std::string a_name, uint16_t a_class, uint32_t a_ttl)
        : dns_answer(a_name, dns::anwser_type::mx, a_class, a_ttl)
    {
        priority = 0;
        domain = "";
    }

    dns_package::dns_package()
    {
        id_ = 0;
        flags_ = 0;
        que_count_ = 0;
        ans_count_ = 0;
        aut_count_ = 0;
        add_count_ = 0;
    }

    void dns_package::add_question(std::string domain, dns::anwser_type question_type)
    {
        id_ = generate_id(1000, 5000);
        que_count_++;

        flag_qr(static_cast<uint8_t>(dns::qr_type::request));
        flag_opcode(static_cast<uint8_t>(dns::opcode_type::question));
        flag_rcode(static_cast<uint8_t>(dns::rcode_type::ok_response));

        std::shared_ptr<dns_question> question =
            std::make_shared<dns_question>(domain, static_cast<uint16_t>(question_type), static_cast<uint16_t>(dns::class_type::in));
        questions_.push_back(question);
    }

    void dns_package::add_anwser(std::string domain, dns::anwser_type anwser_type, std::string value)
    {
        ans_count_++;

        flag_qr(static_cast<uint8_t>(dns::qr_type::response));
        flag_rcode(static_cast<uint8_t>(dns::rcode_type::ok_response));

        if (flag_ad() == 1)
        {
            // cleat flage ad
            flag_ad(0);
        }

        flag_ra(1);

        switch (anwser_type)
        {
        case anwser_type::a:
        {
            std::shared_ptr<dns_a_answer> answer =
                std::make_shared<dns_a_answer>(domain, static_cast<uint16_t>(dns::class_type::in), dns::default_ttl);

            string_to_ipv4(value, answer->addr, sizeof(answer->addr));
            answers_.push_back(answer);
            break;
        }
        case anwser_type::aaaa:
        {
            std::shared_ptr<dns_aaaa_answer> answer =
                std::make_shared<dns_aaaa_answer>(domain, static_cast<uint16_t>(dns::class_type::in), dns::default_ttl);

            string_to_ipv6(value, answer->addr, sizeof(answer->addr));
            answers_.push_back(answer);
            break;
        }
        case anwser_type::cname:
        {
            std::shared_ptr<dns_cname_answer> answer =
                std::make_shared<dns_cname_answer>(domain, static_cast<uint16_t>(dns::class_type::in), dns::default_ttl);

            answer->domain = value;
            answers_.push_back(answer);
            break;
        }
        case anwser_type::txt:
        {
            std::shared_ptr<dns_txt_answer> answer =
                std::make_shared<dns_txt_answer>(domain, static_cast<uint16_t>(dns::class_type::in), dns::default_ttl);

            answer->text = value;
            answers_.push_back(answer);
            break;
        }
        default:
            break;
        }
    }

    bool dns_package::parse(const char *data, uint16_t data_length)
    {
        dns_buffer buffer((uint8_t*)data, data_length);

        id_ = buffer.read_16bits();
        flags_ = buffer.read_16bits();
        que_count_ = buffer.read_16bits();
        ans_count_ = buffer.read_16bits();
        aut_count_ = buffer.read_16bits();
        add_count_ = buffer.read_16bits();

        for (int i = 0; i < que_count_; ++i)
        {
            std::string q_domain = buffer.read_domain();
            if (q_domain == "")
            {
                return false;
            }

            uint16_t q_type = buffer.read_16bits();
            uint16_t q_class = buffer.read_16bits();

            std::shared_ptr<dns_question> question = std::make_shared<dns_question>(q_domain, q_type, q_class);
            questions_.push_back(question);
        }    

        for (int i = 0; i < ans_count_; ++i)
        {
            std::string a_domain = buffer.read_domain();
            if (a_domain == "")
            {
                return false;
            }

            uint16_t a_type = buffer.read_16bits();
            uint16_t a_class = buffer.read_16bits();
            uint32_t a_ttl = buffer.read_32bits();
            uint16_t a_length = buffer.read_16bits();

            switch (static_cast<anwser_type>(a_type))
            {
            case anwser_type::a:
            {
                std::shared_ptr<dns_a_answer> answer = std::make_shared<dns_a_answer>(a_domain, a_class, a_ttl);
                buffer.read_buffer((char *)&answer->addr[0], a_length);
                answers_.push_back(answer);
                break;
            }
            case anwser_type::aaaa:
            {
                std::shared_ptr<dns_aaaa_answer> answer = std::make_shared<dns_aaaa_answer>(a_domain, a_class, a_ttl);
                buffer.read_buffer((char *)&answer->addr[0], a_length);
                answers_.push_back(answer);
                break;
            }
            case anwser_type::cname:
            {
                std::shared_ptr<dns_cname_answer> answer = std::make_shared<dns_cname_answer>(a_domain, a_class, a_ttl);
                answer->domain = buffer.read_domain();
                if (answer->domain == "")
                {
                    return false;
                }

                answers_.push_back(answer);
                break;
            }
            case anwser_type::ns:
            {
                std::shared_ptr<dns_ns_answer> answer = std::make_shared<dns_ns_answer>(a_domain, a_class, a_ttl);
                answer->domain = buffer.read_domain();
                if (answer->domain == "")
                {
                    return false;
                }

                answers_.push_back(answer);
                break;
            }
            case anwser_type::mx:
            {
                std::shared_ptr<dns_mx_answer> answer = std::make_shared<dns_mx_answer>(a_domain, a_class, a_ttl);
                answer->priority = buffer.read_16bits();
                answer->domain = buffer.read_domain();
                if (answer->domain == "")
                {
                    return false;
                }

                answers_.push_back(answer);
                break;
            }
            case anwser_type::txt:
            {
                std::shared_ptr<dns_txt_answer> answer = std::make_shared<dns_txt_answer>(a_domain, a_class, a_ttl);
                answer->text = buffer.read_text();
                if (answer->text == "")
                {
                    return false;
                }

                answers_.push_back(answer);
                break;
            }
            default:
                return false;
            }
        }

        return true;
    }

    void dns_package::output()
    {
        logger.debug("++++ DNS Package +++++");
        logger.debug("ID: %d", id_);
        logger.debug("FLAG: %d", flags_);
        logger.debug("\t %s", qr_to_string(flag_qr()).c_str());
        logger.debug("\t %s", opcode_to_string(flag_opcode()).c_str());
        logger.debug("\t %s", rcodes_to_string(flag_rcode()).c_str());
        logger.debug("\t");
        logger.debug("\t");
        logger.debug("\t");
        logger.debug("Question Count: %d", que_count_);
        logger.debug("Answer Count: %d", ans_count_);
        logger.debug("Auth Count: %d", aut_count_);
        logger.debug("Additional: %d", add_count_);

        for (std::shared_ptr<dns_question> q : questions_)
        {
            logger.debug("Question => Name(%s), Type(%s), Class(%s)",
                         q->q_name().c_str(), rtypes_to_string(q->q_type()).c_str(), classes_to_string(q->q_class()).c_str());
        }

        for (std::shared_ptr<dns_answer> a : answers_)
        {
            logger.debug("Answer => Name(%s), Type(%s), Class(%s), TTL(%d), ",
                         a->a_name().c_str(), rtypes_to_string(a->a_type()).c_str(), classes_to_string(a->a_class()).c_str(),
                         a->a_ttl());

            switch (static_cast<anwser_type>(a->a_type()))
            {
            case anwser_type::a:
            {
                std::shared_ptr<dns_a_answer> answer = std::dynamic_pointer_cast<dns_a_answer>(a);
                logger.debug("RData(%s)", ipv4_to_string(answer->addr, sizeof(answer->addr)).c_str());
                break;
            }
            case anwser_type::aaaa:
            {
                std::shared_ptr<dns_aaaa_answer> answer = std::dynamic_pointer_cast<dns_aaaa_answer>(a);
                logger.debug("RData(%s)", ipv6_to_string(answer->addr, sizeof(answer->addr)).c_str());
                break;
            }
            case anwser_type::cname:
            {
                std::shared_ptr<dns_cname_answer> answer = std::dynamic_pointer_cast<dns_cname_answer>(a);
                logger.debug("RData(%s)", answer->domain.c_str());
                break;
            }
            case anwser_type::ns:
            {
                std::shared_ptr<dns_ns_answer> answer = std::dynamic_pointer_cast<dns_ns_answer>(a);
                logger.debug("RData(%s)", answer->domain.c_str());
                break;
            }
            case anwser_type::mx:
            {
                std::shared_ptr<dns_mx_answer> answer = std::dynamic_pointer_cast<dns_mx_answer>(a);
                logger.debug("RData(%s %d)", answer->domain.c_str(), answer->priority);
                break;
            }
            case anwser_type::txt:
            {
                std::shared_ptr<dns_txt_answer> answer = std::dynamic_pointer_cast<dns_txt_answer>(a);
                logger.debug("RData(%s %d)", answer->text.c_str());
                break;
            }
            default:
                break;
            }
        }
    }

    int dns_package::dump(char *data, uint16_t data_length)
    {
        dns::dns_buffer buffer((uint8_t*)data, data_length);

        buffer.write_16bits(id_);
        buffer.write_16bits(flags_);
        buffer.write_16bits(que_count_);
        buffer.write_16bits(ans_count_);
        buffer.write_16bits(0);
        buffer.write_16bits(0);

        for (std::shared_ptr<dns_question> q : questions_)
        {
            buffer.write_domain(q->q_name());
            buffer.write_16bits(q->q_type());
            buffer.write_16bits(q->q_class());
        }

        for (std::shared_ptr<dns_answer> a : answers_)
        {
            buffer.write_domain(a->a_name());
            buffer.write_16bits(a->a_type());
            buffer.write_16bits(a->a_class());
            buffer.write_32bits(a->a_ttl());

            size_t length_pos = buffer.position();
            buffer.write_16bits(0);

            size_t start_pos = buffer.position();
            switch (static_cast<anwser_type>(a->a_type()))
            {
            case anwser_type::a:
            {
                std::shared_ptr<dns_a_answer> answer = std::dynamic_pointer_cast<dns_a_answer>(a);
                buffer.write_buffer((const char *)&answer->addr[0], sizeof(answer->addr));
                break;
            }
            case anwser_type::aaaa:
            {
                std::shared_ptr<dns_aaaa_answer> answer = std::dynamic_pointer_cast<dns_aaaa_answer>(a);
                buffer.write_buffer((const char *)&answer->addr[0], sizeof(answer->addr));
                break;
            }
            case anwser_type::cname:
            {
                std::shared_ptr<dns_cname_answer> answer = std::dynamic_pointer_cast<dns_cname_answer>(a);
                buffer.write_domain(answer->domain);
                break;
            }
            case anwser_type::ns:
            {
                std::shared_ptr<dns_ns_answer> answer = std::dynamic_pointer_cast<dns_ns_answer>(a);
                buffer.write_domain(answer->domain);
                break;
            }
            case anwser_type::mx:
            {
                std::shared_ptr<dns_mx_answer> answer = std::dynamic_pointer_cast<dns_mx_answer>(a);
                buffer.write_16bits(answer->priority);
                buffer.write_domain(answer->domain);
                break;
            }
            case anwser_type::txt:
            {
                std::shared_ptr<dns_txt_answer> answer = std::dynamic_pointer_cast<dns_txt_answer>(a);
                buffer.write_text(answer->text);
                break;
            }
            default:
                return 0;
            }

            size_t current_pos = buffer.position();
            uint16_t length = current_pos - start_pos;

            buffer.position(length_pos);
            buffer.write_16bits(length);
            buffer.position(current_pos);
        }

        return buffer.size();
    }

    uint32_t dns_package::get_ttl()
    {
        uint32_t result = 0;
        for (std::shared_ptr<dns_answer> a : answers_)
        {
            if (result == 0 || result < a->a_ttl())
            {
                result = a->a_ttl();
            }
        }

        return result;
    }

    void dns_package::set_ttl(uint32_t ttl)
    {
        for (std::shared_ptr<dns_answer> a : answers_)
        {
            a->a_ttl(ttl);
        }
    }

    void dns_package::reset()
    {
        id_ = 0;
        flags_ = 0;
        que_count_ = 0;
        ans_count_ = 0;
        aut_count_ = 0;
        add_count_ = 0;

        questions_.clear();
        answers_.clear();
    }

    uint8_t dns_package::flag_qr()
    {
        return (flags_ & 0x8000) >> 15;
    }

    uint8_t dns_package::flag_opcode()
    {
        return (flags_ & 0x7800) >> 11;
    }

    uint8_t dns_package::flag_rcode()
    {
        return (flags_ & 0x000F);
    }

    uint8_t dns_package::flag_ad()
    {
        return (flags_ >> 5) & 0x01;
    }

    uint8_t dns_package::flag_ra()
    {
        return (flags_ >> 7) & 0x01;
    }

    void dns_package::flag_qr(uint8_t qr)
    {
        flags_ |= (qr & 0x01) << 15;
    }

    void dns_package::flag_opcode(uint8_t opcode)
    {
        // Clear the opcode bits
        flags_ &= ~0x7800;

        // Set the new opcode
        flags_ |= (opcode << 11);
    }

    void dns_package::flag_rcode(uint8_t rcode)
    {
        flags_ |= (rcode & 0x0F) << 0;
    }

    void dns_package::flag_ad(uint8_t value)
    {
        flags_ = (flags_ & ~(0x01 << 5)) | ((value & 0x01) << 5);
    }

    void dns_package::flag_ra(uint8_t value)
    {
        flags_ = (flags_ & ~(0x01 << 7)) | ((value & 0x01) << 7);
    }

    std::string dns_package::qr_to_string(uint8_t qr)
    {
        std::string res("Unknown");
        switch (qr)
        {
        case 0:
            res = "Request";
            break;
        case 1:
            res = "Response";
            break;
        }
        return res;
    }

    std::string dns_package::rcodes_to_string(uint8_t rcode)
    {
        std::string res("Unknown");
        switch (rcode)
        {
        case 0:
            res = "Ok_Response_Type";
            break;
        case 1:
            res = "FormatError_Response_Type";
            break;
        case 2:
            res = "ServerFailure_Response_Type";
            break;
        case 3:
            res = "NameError_Response_Type";
            break;
        case 4:
            res = "NotImplemented_Response_Type";
            break;
        case 5:
            res = "Refused_Response_Type";
            break;
        }
        return res;
    }

    std::string dns_package::opcode_to_string(uint8_t opcode)
    {
        std::string res("Unknown");
        switch (opcode)
        {
        case 0:
            res = "Question";
            break;
        case 1:
            res = "IQuestion";
            break;
        case 2:
            res = "Status";
            break;
        case 4:
            res = "Notify";
            break;
        case 5:
            res = "Update";
            break;
        }
        return res;
    }

    std::string dns_package::rtypes_to_string(uint8_t rtype)
    {
        std::string res("Unknown");
        switch (rtype)
        {
        case 1:
            res = "A";
            break;
        case 2:
            res = "NS";
            break;
        case 5:
            res = "CNAME";
            break;
        case 6:
            res = "SOA";
            break;
        case 12:
            res = "PTR";
            break;
        case 15:
            res = "MX";
            break;
        case 16:
            res = "TXT";
            break;
        case 28:
            res = "AAAA";
            break;
        case 33:
            res = "SRV";
            break;
        }
        return res;
    }

    std::string dns_package::classes_to_string(uint8_t class_)
    {
        std::string res("Unknown");
        switch (class_)
        {
        case 1:
            res = "IN";
            break;
        }
        return res;
    }

    std::string dns_package::ipv4_to_string(uint8_t *buffer, std::size_t size)
    {
        char ip_string[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, buffer, ip_string, sizeof(ip_string)) != nullptr)
        {
            return std::string(ip_string);
        }
        return "";
    }

    std::string dns_package::ipv6_to_string(uint8_t *buffer, std::size_t size)
    {
        char ip_string[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, buffer, ip_string, sizeof(ip_string)) != nullptr)
        {
            return ip_string;
        }
        return "";
    }

    bool dns_package::string_to_ipv4(const std::string &address, uint8_t *buffer, std::size_t size)
    {
        if (size < 4)
        {
            return false;
        }

        if (inet_pton(AF_INET, address.c_str(), buffer) != 1)
        {
            return false;
        }

        return true;
    }

    bool dns_package::string_to_ipv6(const std::string &address, uint8_t *buffer, std::size_t size)
    {
        if (size < 16)
        {
            return false;
        }

        if (inet_pton(AF_INET6, address.c_str(), buffer) != 1)
        {
            return false;
        }

        return true;
    }

    uint16_t dns_package::generate_id(uint16_t min_id, uint16_t max_id)
    {
        std::random_device rd;
        std::mt19937 generator(rd());
        std::uniform_int_distribution<uint16_t> distribution(min_id, max_id);

        return distribution(generator);
    }
}