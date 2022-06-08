/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "internal/verifier.h"

rats_verifier_opts_t *rats_verifiers_opts[RATS_VERIFIER_TYPE_MAX];
unsigned int registerd_rats_verifier_nums;

rats_verifier_ctx_t *rats_verifiers_ctx[RATS_VERIFIER_TYPE_MAX];
unsigned int rats_verifier_nums;
