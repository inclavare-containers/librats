/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_VERIFIER_H
#define _INTERNAL_VERIFIER_H

#include <librats/core.h>

#ifdef OCCLUM
	#define RATS_VERIFIERS_DIR "/opt/occlum/glibc/lib/verifiers/"
#else
	#define RATS_VERIFIERS_DIR "/usr/local/lib/librats/verifiers/"
#endif

extern rats_verifier_err_t rats_verifier_init(const char *name,
					      __attribute__((unused)) const char *realpath,
					      __attribute__((unused)) void **handle);
extern rats_verifier_err_t rats_verifier_load_all(void);
extern rats_verifier_err_t rats_verifier_load_single(const char *);
extern rats_verifier_err_t rats_verifier_select(rats_core_context_t *, const char *);
extern rats_verifier_opts_t *rats_verifiers_opts[RATS_VERIFIER_TYPE_MAX];
extern rats_verifier_ctx_t *rats_verifiers_ctx[RATS_VERIFIER_TYPE_MAX];
extern unsigned int rats_verifier_nums;
extern unsigned int registerd_rats_verifier_nums;

#endif
