/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_ATTESTER_H
#define _INTERNAL_ATTESTER_H

#include <stdbool.h>
#include <stdint.h>
#include <librats/err.h>
#include <librats/core.h>

#define RATS_ATTESTERS_DIR "/usr/local/lib/librats/attesters/"

extern rats_attester_err_t rats_attester_init_static(const char *name);
extern rats_attester_err_t rats_attester_load_all(void);
extern rats_attester_err_t rats_attester_post_init(const char *name, void *handle);
extern rats_attester_err_t rats_attester_select(rats_core_context_t *, const char *);
extern rats_attester_opts_t *rats_attesters_opts[RATS_ATTESTER_TYPE_MAX];
extern rats_attester_ctx_t *rats_attesters_ctx[RATS_ATTESTER_TYPE_MAX];
extern unsigned int rats_attester_nums;
extern unsigned int registerd_rats_attester_nums;

#endif
