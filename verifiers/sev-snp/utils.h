/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _UTILS_H
#define _UTILS_H

#include <stdbool.h>
#include <stdint.h>
#ifndef WASM
#include "../../attesters/sev-snp/utils.h"
#endif

bool reverse_bytes(uint8_t *bytes, size_t size);

#endif /* _UTILS_H */
