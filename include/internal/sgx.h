/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RATS_SGX_H_
#define _RATS_SGX_H_

#include <sys/endian.h>
#include <sys/types.h>

static inline uint32_t htonl(uint32_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t *s = (u_int8_t *)&x;
	return (u_int32_t)(s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3]);
#else
	return x;
#endif
}

static inline uint32_t ntohl(uint32_t x)
{
	return htonl(x);
}

static inline uint64_t htobe64(uint64_t x)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t *s = (u_int8_t *)&x;
	return (u_int64_t)(((u_int64_t)s[0]) << 56 | ((u_int64_t)s[1]) << 48 |
			   ((u_int64_t)s[2]) << 40 | ((u_int64_t)s[3]) << 32 |
			   ((u_int64_t)s[4]) << 24 | ((u_int64_t)s[5]) << 16 |
			   ((u_int64_t)s[6]) << 8 | ((u_int64_t)s[7]));
#else
	return x;
#endif
}

static inline uint64_t be64toh(uint64_t x)
{
	return htobe64(x);
}

#endif
