//
// File: property.cpp
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

#define PROPERTY_READWRITE(Type, Name)                              \
protected:                                                          \
    Type Name##_;                                                   \
                                                                    \
protected:                                                          \
    virtual void set_##Name(const Type &value) { Name##_ = value; } \
    virtual const Type &get_##Name() const { return Name##_; }      \
                                                                    \
public:                                                             \
    void Name(const Type &value) { set_##Name(value); }             \
    const Type &Name() const { return get_##Name(); }


#define PROPERTY_READONLY(Type, Name)                          \
protected:                                                     \
    Type Name##_;                                              \
                                                               \
protected:                                                     \
    virtual const Type &get_##Name() const { return Name##_; } \
                                                               \
public:                                                        \
    const Type &Name() const { return get_##Name(); }
