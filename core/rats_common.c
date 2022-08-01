/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <stdlib.h>
#ifndef SGX
#include <dlfcn.h>
#include <strings.h>
#include <dirent.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <librats/api.h>
#include <librats/log.h>
#include <internal/core.h>

#ifdef SGX
#include "rats_t.h"

extern void libattester_null_init(void);
extern void libverifier_null_init(void);
extern void libattester_sgx_ecdsa_init(void);
extern void libverifier_sgx_ecdsa_init(void);
extern void libverifier_sgx_ecdsa_qve_init(void);
extern void libattester_sgx_la_init(void);
extern void libverifier_sgx_la_init(void);
#endif
//clang-format on

rats_core_context_t rats_global_core_context;

/* The global log level used by log.h */
rats_log_level_t rats_global_log_level = RATS_LOG_LEVEL_DEFAULT;

#ifdef SGX
void rats_exit(void)
{
    ocall_exit();
}

rats_log_level_t rats_loglevel_getenv(const char *name)
{
    char *log_level_str = NULL;
    size_t log_level_len = 32;

    log_level_str = calloc(1, log_level_len);
    if (!log_level_str) {
        RATS_ERR("failed to calloc log level string\n");
        return -1;
    }

    ocall_getenv(name, log_level_str, log_level_len);
    if (log_level_str) {
        if (!strcmp(log_level_str, "debug") || !strcmp(log_level_str, "DEBUG")) {
            free(log_level_str);
            return RATS_LOG_LEVEL_DEBUG;
        } else if (!strcmp(log_level_str, "info") || !strcmp(log_level_str, "INFO")) {
            free(log_level_str);
            return RATS_LOG_LEVEL_INFO;
        } else if (!strcmp(log_level_str, "warn") || !strcmp(log_level_str, "WARN")) {
            free(log_level_str);
            return RATS_LOG_LEVEL_WARN;
        } else if (!strcmp(log_level_str, "error") || !strcmp(log_level_str, "ERROR")) {
            free(log_level_str);
            return RATS_LOG_LEVEL_ERROR;
        } else if (!strcmp(log_level_str, "fatal") || !strcmp(log_level_str, "FATAL")) {
            free(log_level_str);
            return RATS_LOG_LEVEL_FATAL;
        } else if (!strcmp(log_level_str, "off") || !strcmp(log_level_str, "OFF")) {
            free(log_level_str);
            return RATS_LOG_LEVEL_NONE;
        }
    }

    return RATS_LOG_LEVEL_DEFAULT;
}

rats_attester_err_t rats_attester_init(const char *name, __attribute__((unused)) const char *realpath,
        __attribute__((unused)) void **handle)
{
    rats_attester_err_t err;

    if (!strcmp(name, "nullattester")) {
        libattester_null_init();
        err = rats_attester_post_init(name, NULL);
        if (err != RATS_ATTESTER_ERR_NONE)
            return err;
    } else if (!strcmp(name, "sgx_ecdsa")) {
        libattester_sgx_ecdsa_init();
        err = rats_attester_post_init(name, NULL);
        if (err != RATS_ATTESTER_ERR_NONE)
            return err;
    } else if (!strcmp(name, "sgx_la")) {
        libattester_sgx_la_init();
        err = rats_attester_post_init(name, NULL);
        if (err != RATS_ATTESTER_ERR_NONE)
            return err;
    }
    else
        return RATS_ATTESTER_ERR_INVALID;

    return RATS_ATTESTER_ERR_NONE;
}

rats_verifier_err_t rats_verifier_init(const char *name, __attribute__((unused)) const char *realpath,
        __attribute__((unused)) void **handle)
{
	rats_verifier_err_t err;

    if (!strcmp(name, "nullverifier")) {
        libverifier_null_init();
        err = rats_verifier_post_init(name, NULL);
        if (err != RATS_VERIFIER_ERR_NONE)
            return err;
    } else if (!strcmp(name, "sgx_ecdsa")) {
        libverifier_sgx_ecdsa_init();
        err = rats_verifier_post_init(name, NULL);
        if (err != RATS_VERIFIER_ERR_NONE)
            return err;
    } else if (!strcmp(name, "sgx_ecdsa_qve")) {
        libverifier_sgx_ecdsa_qve_init();
        err = rats_verifier_post_init(name, NULL);
        if (err != RATS_VERIFIER_ERR_NONE)
            return err;
    } else if (!strcmp(name, "sgx_la")) {
        libverifier_sgx_la_init();
        err = rats_verifier_post_init(name, NULL);
        if (err != RATS_VERIFIER_ERR_NONE)
            return err;
    }
    else
        return RATS_VERIFIER_ERR_INVALID;

    return RATS_VERIFIER_ERR_NONE;
}

ssize_t rats_write(int fd, const void *buf, size_t count)
{
    ssize_t rc;
    int sgx_status = ocall_write(&rc, fd, buf, count);
    if (SGX_SUCCESS != sgx_status) {
        RATS_ERR("sgx failed to write data, sgx status: 0x%04x\n", sgx_status);
    }

    return rc;
}

ssize_t rats_read(int fd, void *buf, size_t count)
{
    ssize_t rc;
    int sgx_status = ocall_read(&rc, fd, buf, count);
    if (SGX_SUCCESS != sgx_status) {
        RATS_ERR("sgx failed to read data, sgx status: 0x%04x\n", sgx_status);
    }

    return rc;
}

uint64_t rats_opendir(const char *name)
{
    uint64_t dir;

    int sgx_status = ocall_opendir(&dir, name);
    if (sgx_status != SGX_SUCCESS) {
        RATS_ERR("sgx failed to open %s, sgx status: 0x%04x\n", name, sgx_status);
    }

    return dir;
}

int rats_readdir(uint64_t dirp, rats_dirent **ptr)
{
    int ret = 0;

    *ptr = (rats_dirent *)calloc(1, sizeof(rats_dirent));
    if (!ptr) {
        RATS_ERR("failed to calloc memory in rats_readdir\n");
        return -1;
    }
    ocall_readdir(&ret, dirp, *ptr);

    return ret;
}

int rats_closedir(uint64_t dir)
{
    int ret = 0;
    ocall_closedir(&ret, dir);

    return ret;
}
#else
void rats_exit(void)
{
    exit(EXIT_FAILURE);
}

rats_log_level_t rats_loglevel_getenv(const char *name)
{
    char *log_level_str = log_level_str = getenv(name);
    if (log_level_str) {
        if (!strcasecmp(log_level_str, "debug"))
            return RATS_LOG_LEVEL_DEBUG;
        else if (!strcasecmp(log_level_str, "info"))
            return RATS_LOG_LEVEL_INFO;
        else if (!strcasecmp(log_level_str, "warn"))
            return RATS_LOG_LEVEL_WARN;
        else if (!strcasecmp(log_level_str, "error"))
            return RATS_LOG_LEVEL_ERROR;
        else if (!strcasecmp(log_level_str, "fatal"))
            return RATS_LOG_LEVEL_FATAL;
        else if (!strcasecmp(log_level_str, "off"))
            return RATS_LOG_LEVEL_NONE;
    }

    return RATS_LOG_LEVEL_DEFAULT;
}

rats_attester_err_t rats_attester_init(const char *name, __attribute__((unused)) const char *realpath,
        __attribute__((unused)) void **handle)
{
    *handle = dlopen(realpath, RTLD_LAZY);
    if (*handle == NULL) {
        RATS_ERR("failed on dlopen(): %s\n", dlerror());
        return RATS_ATTESTER_ERR_DLOPEN;
    }

    return RATS_ATTESTER_ERR_NONE;
}

rats_verifier_err_t rats_verifier_init(const char *name, __attribute__((unused)) const char *realpath,
        __attribute__((unused)) void **handle)
{
    *handle = dlopen(realpath, RTLD_LAZY);
    if (*handle == NULL) {
        RATS_ERR("failed on dlopen(): %s\n", dlerror());
        return RATS_VERIFIER_ERR_DLOPEN;
    }

    return RATS_VERIFIER_ERR_NONE;
}

ssize_t rats_write(int fd, const void *buf, size_t count)
{
    ssize_t rc;
    rc = write(fd, buf, count);

    return rc;
}

ssize_t rats_read(int fd, void *buf, size_t count)
{
    ssize_t rc;
    rc = read(fd, buf, count);

    return rc;
}

uint64_t rats_opendir(const char *name)
{
    uint64_t dir;
    dir = (uint64_t)opendir(name);

    return dir;
}

int rats_readdir(uint64_t dirp, rats_dirent **ptr)
{
    int ret = 0;

    *ptr = readdir((DIR *)dirp);
    if (*ptr == NULL)
        ret = 1;

    return ret;
}

int rats_closedir(uint64_t dir)
{
    return closedir((DIR *)dir);
}
#endif
