/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <stdio.h>
#include "rats_t.h"

#define POSSIBLE_UNUSED __attribute__((unused))

void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

double current_time(void)
{
	double curr;
	ocall_current_time(&curr);
	return curr;
}

int LowResTimer(void)
{
	int time;
	ocall_low_res_time(&time);
	return time;
}
