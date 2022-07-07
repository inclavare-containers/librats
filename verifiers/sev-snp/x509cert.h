/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _X509CERT_H
#define _X509CERT_H

#include <stdbool.h>

extern const char ask_pem[];
extern const char ark_pem[];

bool x509_validate_signature(X509 *child_cert, X509 *intermediate_cert, X509 *parent_cert);

#endif /* _X509CERT_H */
