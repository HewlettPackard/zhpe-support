/*
 * Copyright (C) 2017-2018 Hewlett Packard Enterprise Development LP.
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _ZHPEQ_UTIL_H_
#define _ZHPEQ_UTIL_H_

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <sys/socket.h>

/* Do extern "C" without goofing up emacs. */
#ifndef _EXTERN_C_SET
#define _EXTERN_C_SET
#ifdef  __cplusplus
#define _EXTERN_C_BEG extern "C" {
#define _EXTERN_C_END }
#else
#define _EXTERN_C_BEG
#define _EXTERN_C_END
#endif
#endif

_EXTERN_C_BEG

#define NOOPTIMIZE      asm volatile("")

#define ARRAY_SIZE(_x)  (sizeof(_x) / sizeof(_x[0]))

#define TO_PTR(_int)    (void *)(uintptr_t)(_int)

#define FREE(_ptr,_free)                                        \
do {                                                            \
    if (_ptr) {                                                 \
        _free(_ptr);                                            \
        (_ptr) = NULL;                                          \
    }                                                           \
} while (0)

#define FD_CLOSE(_fd)                                           \
do {                                                            \
    if ((_fd) >= 0) {                                           \
        close(_fd);                                             \
        (_fd) = -1;                                             \
    }                                                           \
} while (0)

typedef long long       llong;
typedef unsigned long long ullong;

extern const char       *appname;
extern size_t           page_size;

union sockaddr_in46 {
    uint64_t            alignment;
    /* sa_family common to all, sin_port common to IPv4/6. */
    struct {
        sa_family_t     sa_family;
        in_port_t       sin_port;
    };
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
};

static inline size_t sockaddr_len(const void *addr)
{
    const union sockaddr_in46 *sa = addr;

    switch (sa->sa_family) {

    case AF_INET:
        return sizeof(struct sockaddr_in);

    case AF_INET6:
        return sizeof(struct sockaddr_in6);

    default:
        return 0;
    }
}

static inline bool sockaddr_valid(const void *addr, size_t addr_len,
                                  bool check_len)
{
    size_t              len = sockaddr_len(addr);

    if (!len)
        return false;

    return (!check_len || addr_len >= len);
}

static inline void sockaddr_cpy(union sockaddr_in46 *dst, const void *src)
{
    memcpy(dst, src, sockaddr_len(src));
}

static inline union sockaddr_in46 *sockaddr_dup(const void *addr)
{
    union sockaddr_in46 *ret = NULL;
    size_t              addr_len = sockaddr_len(addr);

    if (addr_len)
        ret = malloc(sizeof(*ret));
    if (ret)
        memcpy(ret, addr, addr_len);

    return ret;
}

static inline int sockaddr_cmp(const void *addr1, const void *addr2)
{
    int                 ret;
    const union sockaddr_in46 *sa1 = addr1;
    const union sockaddr_in46 *sa2 = addr2;

    ret = memcmp(&sa1->sa_family, &sa2->sa_family, sizeof(sa1->sa_family));
    if (ret)
        goto done;

    switch (sa1->sa_family) {

    case AF_INET:
        ret = memcmp(&sa1->addr4.sin_addr, &sa2->addr4.sin_addr,
                     sizeof(sa1->addr4.sin_addr));
        break;

    case AF_INET6:
        ret = memcmp(&sa1->addr6.sin6_addr, &sa2->addr6.sin6_addr,
                     sizeof(sa1->addr6.sin6_addr));
        break;

    default:
        ret = -1;
        break;
    }

    if (ret)
        goto done;

    ret = memcmp(&sa1->sin_port, &sa2->sin_port, sizeof(sa1->sin_port));
 done:
    return ret;
}

static inline const char *sockaddr_ntop(const union sockaddr_in46 *sa,
                                        char *buf, size_t len)
{
    const char          *ret = NULL;

    switch (sa->sa_family) {

    case AF_INET:
        ret = inet_ntop(AF_INET, &sa->addr4.sin_addr, buf, len);
        break;

    case AF_INET6:
        ret = inet_ntop(AF_INET6, &sa->addr6.sin6_addr, buf, len);
        break;

    default:
        if (*buf && len)
            buf[0] = '\0';
        errno = EAFNOSUPPORT;
        break;
    }

    return ret;
}

void zhpeq_util_init(char *argv0, int default_log_level, bool use_syslog);

void print_dbg(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));

void print_info(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));

void print_err(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));

char *errf_str(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));

void print_usage(bool use_stdout, const char *fmt, ...)
    __attribute__ ((format (printf, 2, 3)));

void print_errs(const char *callf, uint line, char *errf_str,
                int err, const char *errs);

void print_func_errs(const char *callf, uint line, const char *errf,
                     const char *arg, int err, const char *errs);

void print_func_errns(const char *callf, uint line, const char *errf,
                      llong arg, bool arg_hex, int err, const char *errs);

void print_func_err(const char *callf, uint line, const char *errf,
                    const char *arg, int err);

void print_func_errn(const char *callf, uint line, const char *errf,
                     llong arg, bool arg_hex, int err);

void print_range_err(const char *callf, uint line, const char *name,
                     int64_t val, int64_t min, int64_t max);

void print_urange_err(const char *callf, uint line, const char *name,
                      uint64_t val, uint64_t min, uint64_t max);

char *get_cpuinfo_val(FILE *fp, char *buf, size_t buf_size,
                      uint field, const char *name, ...);

uint64_t get_tsc_freq(void);

static inline double cycles_to_usec(uint64_t delta, uint64_t loops)
{
    return (delta * 1.0e6) / ((double)get_tsc_freq() * loops);
}

static inline uint64_t get_cycles(volatile uint32_t *cpup)
{
    uint32_t lo;
    uint32_t hi;
    uint32_t cpu;

    asm volatile("rdtscp" : "=a" (lo), "=d" (hi), "=c" (cpu) : :);

    if (cpup)
        *cpup = cpu;

    return ((uint64_t)hi << 32 | lo);
}

static inline void abort_if_minus1(int ret, const char *callf, uint line)
{
    if (ret == -1) {
        ret = errno;
        print_err("%s,%u:returned error %d:%s\n",
                  callf, line, ret, strerror(ret));
        abort();
    }
}

#define clock_gettime(...) \
    abort_if_minus1(clock_gettime(__VA_ARGS__), __FUNCTION__, __LINE__)

#define clock_gettime_monotonic(...) \
    clock_gettime(CLOCK_MONOTONIC, __VA_ARGS__)

static inline uint64_t ts_delta(struct timespec *ts_beg,
                                struct timespec *ts_end)
{
    return ((uint64_t)1000000000) * (ts_end->tv_sec - ts_beg->tv_sec) +
        (ts_end->tv_nsec - ts_beg->tv_nsec);
}

enum {
    PARSE_NUM           = 0,
    PARSE_KB            = 1,
    PARSE_KIB           = 2,
};

int parse_kb_uint64_t(const char *callf, uint line,
                      const char *name, const char *sp, uint64_t *val,
                      int base, uint64_t min, uint64_t max, int flags);

enum {
    CHECK_EAGAIN_OK     = 1,
    CHECK_SHORT_IO_OK   = 2,
};

int check_func_io(const char *callf, uint line, const char *errf,
                  const char *arg, size_t req, ssize_t res,
                  int flags);

int check_func_ion(const char *callf, uint line, const char *errf,
                   long arg, bool arg_hex, size_t req, ssize_t res,
                   int flags);

int do_getaddrinfo(const char *node, const char *service,
                   int family, int socktype, bool passive,
                   struct addrinfo **res);

int connect_sock(const char *node, const char *service);

void random_seed(uint seed);

uint random_range(uint start, uint end);

uint *random_array(uint *array, uint entries);

void *_do_malloc(const char *callf, uint line, size_t size);

#define do_malloc(...) \
    _do_malloc(__FUNCTION__, __LINE__, __VA_ARGS__)

void *_do_calloc(const char *callf, uint line, size_t nmemb, size_t size);

#define do_calloc(...) \
    _do_calloc(__FUNCTION__, __LINE__, __VA_ARGS__)

void _do_free(const char *callf, uint line, void *ptr);

#define do_free(...) \
    _do_free(__FUNCTION__, __LINE__, __VA_ARGS__)

bool _expected_saw(const char *callf, uint line,
                   const char *label, uintptr_t expected, uintptr_t saw);

#define expected_saw(...) \
    _expected_saw(__FUNCTION__, __LINE__, __VA_ARGS__)

char *_sockaddr_port_str(const char *callf, uint line, const void *addr);

#define sockaddr_port_str(...) \
    _sockaddr_port_str(__FUNCTION__, __LINE__, __VA_ARGS__)

char *_sockaddr_str(const char *callf, uint line, const void *addr);

#define sockaddr_str(...) \
    _sockaddr_str(__FUNCTION__, __LINE__, __VA_ARGS__)

int _do_getsockname(const char *callf, uint line,
                    int fd, union sockaddr_in46 *sa);

#define do_getsockname(...) \
    _do_getsockname(__FUNCTION__, __LINE__, __VA_ARGS__)

int _do_getpeername(const char *callf, uint line,
                    int fd, union sockaddr_in46 *da);

#define do_getpeername(...) \
    _do_getpeername(__FUNCTION__, __LINE__, __VA_ARGS__)

int _sock_send_blob(const char *callf, uint line, int fd,
                    const void *blob, size_t blob_len);

#define sock_send_blob(...) \
    _sock_send_blob(__FUNCTION__, __LINE__, __VA_ARGS__)

int _sock_recv_fixed_blob(const char *callf, uint line,
                          int fd, void *blob, size_t blob_len);

#define sock_recv_fixed_blob(...) \
    _sock_recv_fixed_blob(__FUNCTION__, __LINE__, __VA_ARGS__)

int _sock_recv_var_blob(const char *callf, uint line,
                        int fd, size_t extra_len,
                        void **blob, size_t *blob_len);

#define sock_recv_var_blob(...) \
    _sock_recv_var_blob(__FUNCTION__, __LINE__, __VA_ARGS__)

static inline int sock_send_string(int fd, const char *s)
{
    return sock_send_blob(fd, s, (s ? strlen(s) : 0));
}

static inline int sock_recv_string(int fd, char **s)
{
    int                 ret;
    void                *blob;
    size_t              blob_len;

    ret = sock_recv_var_blob(fd, 1, &blob, &blob_len);
    *s = blob;

    return ret;
}

static inline char *_strdup_or_null(const char *callf, uint line,
                                    const char *str)
{
    char                *ret = (str ? strdup(str) : NULL);

    if (str && !ret)
        print_func_err(callf, line, "strdup", "", errno);

    return ret;
}

#define strdup_or_null(...) \
    _strdup_or_null(__FUNCTION__, __LINE__, __VA_ARGS__)

#define fab_cq_read(...) \
    _fab_cq_read(__FUNCTION__, __LINE__, __VA_ARGS__)

static void inline abort_if_nonzero(int ret, const char *callf, uint line)
{
    if (ret) {
        print_err("%s,%u:returned unexpected value %d\n", callf, line, ret);
        abort();
    }
}

#define cond_init(...) \
    abort_if_nonzero(pthread_cond_init(__VA_ARGS__), __FUNCTION__, __LINE__)

#define cond_destroy(...) \
    abort_if_nonzero(pthread_cond_destroy(__VA_ARGS__), __FUNCTION__, __LINE__)

#define cond_signal(...) \
    abort_if_nonzero(pthread_cond_signal(__VA_ARGS__), __FUNCTION__, __LINE__)

#define cond_broadcast(...) \
    abort_if_nonzero(pthread_cond_broadcast(__VA_ARGS__), \
                     __FUNCTION__, __LINE__)

#define cond_wait(...) \
    abort_if_nonzero(pthread_cond_wait(__VA_ARGS__), __FUNCTION__, __LINE__)

#define mutex_init(...) \
    abort_if_nonzero(pthread_mutex_init(__VA_ARGS__), __FUNCTION__, __LINE__)

#define mutex_destroy(...) \
    abort_if_nonzero(pthread_mutex_destroy(__VA_ARGS__), \
                     __FUNCTION__, __LINE__)

#define mutex_lock(...) \
    abort_if_nonzero(pthread_mutex_lock(__VA_ARGS__), __FUNCTION__, __LINE__)

#define mutex_unlock(...) \
    abort_if_nonzero(pthread_mutex_unlock(__VA_ARGS__), __FUNCTION__, __LINE__)

#define spin_init(...) \
    abort_if_nonzero(pthread_spin_init(__VA_ARGS__), __FUNCTION__, __LINE__)

#define spin_destroy(...) \
    abort_if_nonzero(pthread_spin_destroy(__VA_ARGS__), __FUNCTION__, __LINE__)

#define spin_lock(...) \
    abort_if_nonzero(pthread_spin_lock(__VA_ARGS__), __FUNCTION__, __LINE__)

#define spin_unlock(...) \
    abort_if_nonzero(pthread_spin_unlock(__VA_ARGS__), __FUNCTION__, __LINE__)


#ifdef _BARRIER_DEFINED
#warning _BARRIER_DEFINED already defined
#undef _BARRIER_DEFINED
#endif

#if defined(__x86_32__) || defined( __x86_64__)

#define _BARRIER_DEFINED

static inline void smp_mb(void)
{
    asm volatile("mfence":::"memory");
}

static inline void smp_rmb(void)
{
    asm volatile("lfence":::"memory");
}

static inline void smp_wmb(void)
{
    asm volatile("sfence":::"memory");
}

#endif

#ifndef _BARRIER_DEFINED
#error No barrier support for this architecture
#endif

#undef _BARRIED_DEFINED

_EXTERN_C_END

#ifdef _EXTERN_C_SET
#undef _EXTERN_C_SET
#undef _EXTERN_C_BEG
#undef _EXTERN_C_END
#endif

#endif /* _ZHPEQ_UTIL_H_ */
