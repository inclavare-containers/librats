/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_CRYPTO_WRAPPER_H
#define _INTERNAL_CRYPTO_WRAPPER_H

#include <librats/crypto_wrapper.h>

#define CRYPTO_WRAPPERS_DIR "/usr/local/lib/librats/crypto_wrappers/"

extern crypto_wrapper_err_t crypto_wrapper_init_static(const char *name);
extern crypto_wrapper_err_t crypto_wrapper_load_all(void);
extern crypto_wrapper_err_t crypto_wrapper_post_init(const char *name, void *handle);
extern crypto_wrapper_err_t crypto_wrapper_select(rats_core_context_t *, const char *);

extern crypto_wrapper_ctx_t *crypto_wrappers_ctx[CRYPTO_WRAPPER_TYPE_MAX];
extern crypto_wrapper_opts_t *crypto_wrappers_opts[CRYPTO_WRAPPER_TYPE_MAX];
extern unsigned int crypto_wrappers_nums;
extern unsigned registerd_crypto_wrapper_nums;

#endif
