/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "internal/attester.h"

rats_attester_opts_t *rats_attesters_opts[RATS_ATTESTER_TYPE_MAX];
unsigned int registerd_rats_attester_nums;

rats_attester_ctx_t *rats_attesters_ctx[RATS_ATTESTER_TYPE_MAX];
unsigned int rats_attester_nums;
