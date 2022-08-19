/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_BASE64_H
#define _INTERNAL_BASE64_H

#include <stdint.h>
#include <string.h>

int base64_encode(const uint8_t *src, size_t len, unsigned char **output, size_t *output_len);
int base64_decode(const unsigned char *src, size_t len, uint8_t **output, size_t *output_len);

#endif