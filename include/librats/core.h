/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _LIBRATS_CORE_H
#define _LIBRATS_CORE_H

#include <sys/types.h>
#include <stdint.h>
#include <librats/attester.h>
#include <librats/verifier.h>

typedef struct rats_attester_ctx rats_attester_ctx_t;
typedef struct rats_verifier_ctx rats_verifier_ctx_t;

struct rats_core_context {
	rats_conf_t config;
	unsigned long flags;
	rats_attester_ctx_t *attester;
	rats_verifier_ctx_t *verifier;
};

#endif
