/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2023 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RATS_HASH_H
#define _RATS_HASH_H

#include <stddef.h>
#include <stdint.h>

#define RATS_SHA256_HASH_SIZE 32
#define RATS_SHA384_HASH_SIZE 48
#define RATS_SHA512_HASH_SIZE 64
#define RATS_MAX_HASH_SIZE    RATS_SHA512_HASH_SIZE

/* https://www.iana.org/assignments/named-information/named-information.xhtml */
typedef enum {
	RATS_HASH_ALGO_RESERVED = 0,
	RATS_HASH_ALGO_SHA256 = 1,
	RATS_HASH_ALGO_SHA384 = 7,
	RATS_HASH_ALGO_SHA512 = 8,
} rats_hash_algo_t;

static inline size_t hash_size_of_algo(uint8_t hash_algo)
{
	switch (hash_algo) {
	case RATS_HASH_ALGO_RESERVED:
		return 0;
	case RATS_HASH_ALGO_SHA256:
		return RATS_SHA256_HASH_SIZE;
	case RATS_HASH_ALGO_SHA384:
		return RATS_SHA384_HASH_SIZE;
	case RATS_HASH_ALGO_SHA512:
		return RATS_SHA512_HASH_SIZE;
	default:
		return 0;
	}
}

#endif /* _RATS_HASH_H */
