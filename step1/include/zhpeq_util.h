/*
 * Copyright (C) 2017-2020 Hewlett Packard Enterprise Development LP.
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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <uuid/uuid.h>

#include <x86intrin.h>

#include <zhpe_externc.h>

_EXTERN_C_BEG

/* Type checking macros */
#ifdef container_of
#undef container_of
#endif
#define container_of(ptr, type, member)                         \
({                                                              \
    typeof( ((type *)0)->member ) *_ptr = (ptr);                \
    (type *)((char *)_ptr - offsetof(type, member));            \
})

#ifndef max
#undef max
#endif
#define max(_a, _b)                                             \
({                                                              \
    __auto_type         __ret = (_a);                           \
    __auto_type         __b = (_b);                             \
    /* Force compilation error if different types. */           \
    typeof(&__ret)      __p MAYBE_UNUSED = &__b;                \
                                                                \
    if (__b > __ret)                                            \
        __ret = __b;                                            \
    __ret;                                                      \
})

#ifndef min
#undef min
#endif
#define min(_a, _b)                                             \
({                                                              \
    __auto_type         __ret = (_a);                           \
    __auto_type         __b = (_b);                             \
    /* Force compilation error if different types. */           \
    typeof(&__ret)      __p MAYBE_UNUSED;                       \
    __p = &__b;                                                 \
                                                                \
    if (__b < __ret)                                            \
        __ret = __b;                                            \
    __ret;                                                      \
})


#define arithcmp(_a, _b)                                        \
({                                                              \
    __auto_type         __a = (_a);                             \
    __auto_type         __b = (_b);                             \
    /* Force compilation error if different types. */           \
    typeof(&__a)        __p MAYBE_UNUSED;                       \
    __p = &__b;                                                 \
                                                                \
     ((__a) < (__b) ? -1 : ((__a) > (__b) ? 1 : 0));            \
})

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(_x)  (sizeof(_x) / sizeof(_x[0]))
#endif

#define TO_PTR(_int)    (void *)(uintptr_t)(_int)
#define VPTR(_p, _o)    (void *)((char *)(_p) + _o)

#define FREE_IF(_ptr,_free)                                     \
do {                                                            \
    if (_ptr) {                                                 \
        _free(_ptr);                                            \
        (_ptr) = NULL;                                          \
    }                                                           \
} while (0)

#define FD_CLOSE(_fd)                                           \
({                                                              \
    int                 __ret = 0;                              \
                                                                \
    if ((_fd) >= 0) {                                           \
        if (close(_fd) == -1)                                   \
            __ret = -errno;                                     \
        (_fd) = -1;                                             \
    }                                                           \
    __ret;                                                      \
})

typedef long long       llong;
typedef unsigned long long ullong;
typedef unsigned char   uchar;

extern const char       *zhpeu_appname;

/* Borrow AF_APPLETALK since it should never be seen. */
#define AF_ZHPE                 ((sa_family_t)AF_APPLETALK)
#define ZHPE_ADDRSTRLEN         ((size_t)37)
#define ZHPE_SZQ_WILDCARD       (0)     /* Valid, but reserved by driver. */
#define ZHPE_SZQ_INVAL          (~(uint32_t)0)

#define ZHPE_GCID_MASK          (((uint32_t)1 << ZHPE_GCID_BITS) - 1)
#define ZHPE_CTXID_MASK         (((uint32_t)1 << ZHPE_CTXID_BITS) - 1)

#define ZHPE_SZQ_FLAGS_MASK     (0xFFU << ZHPE_CTXID_BITS)
#define ZHPE_SZQ_FLAGS_FAM      (1U << ZHPE_CTXID_BITS)

struct sockaddr_zhpe {
    sa_family_t         sz_family;
    uuid_t              sz_uuid;
    uint32_t            sz_queue;       /* Network byte order */
};

uint32_t zhpeu_uuid_to_gcid(const uuid_t uuid);
void zhpeu_install_gcid_in_uuid(uuid_t uuid, uint32_t gcid);
bool zhpeu_uuid_gcid_only(const uuid_t uuid);

union sockaddr_in46 {
    /* sa_family common to all, sin_port common to IPv4/6. */
    struct {
        sa_family_t     sa_family;
        in_port_t       sin_port;
    };
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
    struct sockaddr_zhpe zhpe;
};

static_assert(sizeof(union sockaddr_in46) <= sizeof(struct sockaddr_in6),
              "sockaddr_in46 len");
static_assert(INET6_ADDRSTRLEN >= ZHPE_ADDRSTRLEN, "ZHPE_ADDRSTRLEN");

#ifdef __GNUC__

#ifdef _BARRIER_DEFINED
#warning _BARRIER_DEFINED already defined
#undef _BARRIER_DEFINED
#endif

#ifdef __x86_64__

#define _BARRIER_DEFINED

#define barrier()       asm volatile("" ::: "memory")

/*
 * But atomic_thread_fence() didn't generate the fences I wanted when I
 * tested it.
 */

static inline void smp_mb(void)
{
    _mm_mfence();
}

static inline void smp_rmb(void)
{
    _mm_lfence();
}

static inline void smp_wmb(void)
{
    _mm_sfence();
}

static inline void io_rmb(void)
{
    _mm_lfence();
}

static inline void io_wmb(void)
{
    _mm_sfence();
}

static inline void io_mb(void)
{
    _mm_mfence();
}

#define L1_CACHE_BYTES  ((size_t)64)

static inline void nop(void)
{
    asm volatile("nop");
}

static inline uint64_t get_tsc_cycles(volatile uint32_t *cpup)
{
    uint64_t            ret;
    uint32_t            cpu;

    ret = _rdtscp(&cpu);

    if (cpup)
        *cpup = cpu;

    return ret;
}

/*
 * According to the kernel source, in 64-bit mode, these work without
 * checking for zero on Intel, despite the documentation. AMD has documented
 * the desired behavior.
 */
static inline int fls32(uint32_t v)
{
    int                 ret = -1;

    asm("bsrl %1,%0" : "+r" (ret) : "rm" (v));

    return ret + 1;
}

static inline int ffs32(uint32_t v)
{
    int                 ret = -1;

    asm("bsfl %1,%0" : "+r" (ret) : "rm" (v));

    return ret + 1;
}

static inline int fls64(uint64_t v)
{
    int                 ret = -1;

    asm("bsrq %1,%q0" : "+r" (ret) : "rm" (v));

    return ret + 1;
}

static inline int ffs64(uint64_t v)
{
    int                 ret = -1;

    asm("bsfq %1,%q0" : "+r" (ret) : "rm" (v));

    return ret + 1;
}

#endif

#ifndef _BARRIER_DEFINED
#error No barrier support for this architecture
#endif

#undef _BARRIED_DEFINED

#define PACKED          __attribute__ ((packed));
#define INT32_ALIGNED   __attribute__ ((aligned (__alignof__(int32_t))));
#define INT64_ALIGNED   __attribute__ ((aligned (__alignof__(int64_t))));
#define INT128_ALIGNED  __attribute__ ((aligned (__alignof__(__int128_t))));
#define CACHE_ALIGNED   __attribute__ ((aligned (L1_CACHE_BYTES)))

#define MAYBE_UNUSED    __attribute__((unused))
#define NO_RETURN       __attribute__ ((__noreturn__))
#define PRINTF_ARGS(_a, _b) __attribute__ ((format (printf, _a, _b)))

#ifndef likely
#define likely(_x)      __builtin_expect(!!(_x), 1)
#endif
#ifndef unlikely
#define unlikely(_x)    __builtin_expect(!!(_x), 0)
#endif

#endif /* __GNUC__ */

static inline int zhpeu_update_error(int old, int new)
{
    return ((unlikely(new < 0) && old >= 0) ? new : old);
}

void zhpeu_util_init(char *argv0, int default_log_level, bool use_syslog);
void zhpeu_print_dbg(const char *fmt, ...) PRINTF_ARGS(1, 2);
void zhpeu_print_info(const char *fmt, ...) PRINTF_ARGS(1, 2);
void zhpeu_print_err(const char *fmt, ...) PRINTF_ARGS(1, 2);
void zhpeu_print_usage(bool use_stdout, const char *fmt, ...) PRINTF_ARGS(2, 3);
void zhpeu_print_func_err(const char *callf, uint line, const char *errf,
                          const char *arg, int err);
void zhpeu_print_func_errn(const char *callf, uint line, const char *errf,
                           llong arg, bool arg_hex, int err);
void zhpeu_print_range_err(const char *callf, uint line, const char *name,
                           int64_t val, int64_t min, int64_t max);
void zhpeu_print_urange_err(const char *callf, uint line, const char *name,
                            uint64_t val, uint64_t min, uint64_t max);

void zhpeu_fatal(const char *callf, uint line, const char *errf, int ret);
void zhpeu_err(const char *callf, uint line, const char *errf, int ret);
void zhpeu_dbg(const char *callf, uint line, const char *errf, int ret);

#define zhpeu_syscall(_err_handler, _func, ...)                 \
({                                                              \
    long                 __ret = _func(__VA_ARGS__);            \
                                                                \
    if (unlikely(__ret == -1)) {                                \
        __ret = -errno;                                         \
        _err_handler(__func__, __LINE__, #_func, __ret);        \
    }                                                           \
    __ret;                                                      \
})

#define zhpeu_posixcall(_err_handler, _func, ...)               \
({                                                              \
    int                  __ret = -_func(__VA_ARGS__);           \
                                                                \
    if (unlikely(__ret))                                        \
        _err_handler(__func__, __LINE__, #_func, __ret);        \
    __ret;                                                      \
})

#define zhpeu_posixcall_errorok(_err_handler, _func, _err, ...) \
({                                                              \
    int                  __ret = -_func(__VA_ARGS__);           \
    int                  __err = (_err);                        \
                                                                \
    if (unlikely(__ret) && __ret != __err)                      \
        _err_handler(__func__, __LINE__, #_func, __ret);        \
    __ret;                                                      \
})

#define zhpeu_call_neg(_err_handler, _func, _rtype, ...)        \
({                                                              \
    _rtype               __ret = _func(__VA_ARGS__);            \
                                                                \
    if (unlikely(__ret < 0))                                    \
        _err_handler(__func__, __LINE__, #_func, __ret);        \
    __ret;                                                      \
})

#define zhpeu_call_neg_errorok(_err_handler, _func, _rtype, _err, ...) \
({                                                              \
    _rtype               __ret = _func(__VA_ARGS__);            \
    int                  __err = (_err);                        \
                                                                \
    if (unlikely(__ret < 0 ) && __ret != __err)                 \
        _err_handler(__func__, __LINE__, #_func, __ret);        \
    __ret;                                                      \
})

#define zhpeu_call_null(_err_handler, _func, _rtype, ...)       \
({                                                              \
    _rtype              __ret = _func(__VA_ARGS__);             \
    int                 __saved_errno;                          \
                                                                \
    if (unlikely((void *)__ret == NULL)) {                      \
        __saved_errno = errno;                                  \
        _err_handler(__func__, __LINE__, #_func, -errno);       \
        errno = __saved_errno;                                  \
    }                                                           \
    __ret;                                                      \
})

static inline sa_family_t zhpeu_sockaddr_family(const void *addr)
{
    const union sockaddr_in46 *sa = addr;

    return sa->sa_family;
}

uint32_t zhpeu_sockaddr_porth(const void *addr);
size_t zhpeu_sockaddr_len(const void *addr);
bool zhpeu_sockaddr_valid(const void *addr, size_t addr_len, bool check_len);
void zhpeu_sockaddr_cpy(union sockaddr_in46 *dst, const void *src);
void *zhpeu_sockaddr_dup(const void *addr);
int zhpeu_sockaddr_cmp(const void *addr1, const void *addr2, uint flags);
#define ZHPEU_SACMP_ADDR_ONLY   (0x1)
#define ZHPEU_SACMP_PORT_ONLY   (0x2)
bool zhpeu_sockaddr_inet(const void *addr);
bool zhpeu_sockaddr_wildcard(const void *addr);
bool zhpeu_sockaddr_loopback(const void *addr, bool loopany);
void zhpeu_sockaddr_6to4(void *addr);

const char *zhpeu_sockaddr_ntop(const void *addr, char *buf, size_t len);
char *zhpeu_sockaddr_str(const void *addr);

#define zhpeu_expected_saw(_lbl, _expected, _saw)               \
({                                                              \
    bool                __ret;                                  \
    const char          *__lbl = (_lbl);                        \
    __auto_type         __e = (_expected);                      \
    __auto_type         __s = (_saw);                           \
    /* Force compilation error if different types. */           \
    typeof(&__e)        __p MAYBE_UNUSED = &__s;                \
                                                                \
    __ret = (__e == __s);                                       \
    if (unlikely(!__ret)) {                                     \
        zhpeu_print_err("%s,%u:%s expected 0x%llx, "            \
                        " saw 0x%llx\n", __func__, __LINE__,    \
                        __lbl, (ullong)__e, (ullong)__s);       \
    }                                                           \
    __ret;                                                      \
})

/* Trying to rely on stdatomic.h with less verbosity.
 * I'm not at all convinced they do the right thing with fences, in general,
 * but on x86 atomic adds and cmpxchg are full barriers. So the only relaxed
 * thing I use are loads/stores.
 */

#define atm_load(_p)                                            \
    atomic_load_explicit(_p, memory_order_acquire)
#define atm_load_rlx(_p)                                        \
    atomic_load_explicit(_p, memory_order_relaxed)

#define atm_store(_p, _v)                                       \
    atomic_store_explicit(_p, _v, memory_order_release)
#define atm_store_rlx(_p, _v)                                   \
    atomic_store_explicit(_p, _v, memory_order_relaxed)

#define atm_add(_p, _v)                                         \
    atomic_fetch_add_explicit(_p, _v, memory_order_acq_rel)

#define atm_and(_p, _v)                                         \
    atomic_fetch_and_explicit(_p, _v, memory_order_acq_rel)

#define atm_or(_p, _v)                                          \
    atomic_fetch_or_explicit(_p, _v, memory_order_acq_rel)

#define atm_sub(_p, _v)                                         \
    atomic_fetch_sub_explicit(_p, _v, memory_order_acq_rel)

#define atm_xchg(_p, _v)                                        \
    atomic_exchange_explicit(_p, _v, memory_order_acq_rel)

#define atm_xor(_p, _v)                                         \
    atomic_fetch_xor_explicit(_p, _v, memory_order_acq_rel)

#define atm_cmpxchg(_p, _oldp, _new)                            \
    atomic_compare_exchange_strong_explicit(                    \
        _p, _oldp, _new, memory_order_acq_rel, memory_order_acquire)

#define atm_inc(_p)     atm_add(_p, 1)
#define atm_dec(_p)     atm_sub(_p, 1)

struct zhpeu_init_time {
    uint64_t            (*get_cycles)(volatile uint32_t *cpup);
    uint64_t            freq;
    void                (*clflush_range)(const void *p, size_t len, bool fence);
    void                (*clwb_range)(const void *p, size_t len, bool fence);
    uint64_t            pagesz;
    uint64_t            l1sz;
};

extern struct zhpeu_init_time *zhpeu_init_time;

#define MSEC_PER_SEC    ((uint64_t)1000)
#define USEC_PER_SEC    ((uint64_t)1000000)
#define NSEC_PER_SEC    ((uint64_t)1000000000)

static inline double cycles_to_usec(uint64_t delta, uint64_t loops)
{
    return (((double)delta * USEC_PER_SEC) /
            ((double)zhpeu_init_time->freq * loops));
}

static inline uint64_t usec_to_cycles(uint64_t usec)
{
    return (usec * zhpeu_init_time->freq / USEC_PER_SEC);
}

static inline uint64_t nsec_to_cycles(uint64_t nsec)
{
    return (nsec * zhpeu_init_time->freq / NSEC_PER_SEC);
}

/* On any hardware we care about, rdtsc will work for timing. */

#ifdef __x86_64__

#define get_cycles(_cpup)       get_tsc_cycles(_cpup)
/*
 * rdtsc interferes less with instruction pipeline and is better suited
 * for approximate timing uses.
 */
#define get_cycles_approx()     _rdtsc()

#else

static inline uint64_t get_cycles(volatile uint32_t *cpup)
{
    return zhpeu_init_time->get_cycles(cpup);
}

#define get_cycles_approx()     get_cycles(NULL)

#endif

static inline uint64_t get_tsc_freq(void)
{
    return zhpeu_init_time->freq;
}

static inline void clflush_range(const void *addr, size_t length, bool fence)
{
    zhpeu_init_time->clflush_range(addr, length, fence);
}

static inline void clwb_range(const void *addr, size_t length, bool fence)
{
    zhpeu_init_time->clwb_range(addr, length, fence);
}

#define clock_gettime(...)                                      \
    zhpeu_syscall(zhpeu_fatal, clock_gettime, __VA_ARGS__)

#define clock_gettime_monotonic(...)                            \
    clock_gettime(CLOCK_MONOTONIC, __VA_ARGS__)

#define gettimeofday(...)                                       \
    zhpeu_syscall(zhpeu_fatal, gettimeofday, __VA_ARGS__)

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

int zhpeu_parse_kb_uint64_t(const char *name, const char *sp, uint64_t *val,
                            int base, uint64_t min, uint64_t max, int flags);

enum {
    CHECK_EAGAIN_OK     = 1,
    CHECK_SHORT_IO_OK   = 2,
};

int zhpeu_check_func_io(const char *callf, uint line, const char *errf,
                        const char *arg, size_t req, ssize_t res,
                        int flags);
int zhpeu_check_func_ion(const char *callf, uint line, const char *errf,
                         long arg, bool arg_hex, size_t req, ssize_t res,
                         int flags);

int zhpeu_sock_getaddrinfo(const char *node, const char *service,
                           int family, int socktype, bool passive,
                           struct addrinfo **res);
int zhpeu_sock_getsockname(int fd, union sockaddr_in46 *sa);
int zhpeu_sock_getpeername(int fd, union sockaddr_in46 *da);
int zhpeu_sock_connect(const char *node, const char *service);
int zhpeu_sock_send_blob(int fd, const void *blob, size_t blob_len);
int zhpeu_sock_recv_fixed_blob(int fd, void *blob, size_t blob_len);
int zhpeu_sock_recv_var_blob(int fd, size_t extra_len,
                             void **blob, size_t *blob_len);
int zhpeu_sock_send_string(int fd, const char *s);
int zhpeu_sock_recv_string(int fd, char **s);

void zhpeu_random_seed(uint seed);
uint zhpeu_random_range(uint start, uint end);
uint *zhpeu_random_array(uint *array, uint entries);

int zhpeu_munmap(void *addr, size_t length);
void *zhpeu_mmap(void *addr, size_t length, int prot, int flags,
                 int fd, off_t offset);


#define ZHPEU_TM_STR_LEN        (35)
char *zhpeu_tm_to_str(char *str, size_t max_len, struct tm *tm, uint nsec);

char *zhpeu_get_cpuinfo_val(FILE *fp, char *buf, size_t buf_size,
                            uint field, const char *name, ...);

/* Calls where errors should *never* really happen. */

#define cond_init(...)                                          \
    zhpeu_posixcall(zhpeu_fatal, pthread_cond_init, __VA_ARGS__)
#define cond_destroy(...)                                       \
    zhpeu_posixcall(zhpeu_fatal, pthread_cond_destroy, __VA_ARGS__)
#define cond_signal(...)                                        \
    zhpeu_posixcall(zhpeu_fatal, pthread_cond_signal, __VA_ARGS__)
#define cond_broadcast(...)                                     \
    zhpeu_posixcall(zhpeu_fatal, pthread_cond_broadcast, __VA_ARGS__)
#define cond_wait(...)                                          \
    zhpeu_posixcall(zhpeu_fatal, pthread_cond_wait, __VA_ARGS__)
#define cond_timedwait(...)                                     \
    zhpeu_posixcall_errorok(zhpeu_fatal, pthread_cond_timedwait,\
                            -ETIMEDOUT, __VA_ARGS__)
#define mutexattr_settype(...)                                  \
    zhpeu_posixcall(zhpeu_fatal, pthread_mutexattr_settype, __VA_ARGS__)
#define mutexattr_init(...)                                     \
    zhpeu_posixcall(zhpeu_fatal, pthread_mutexattr_init, __VA_ARGS__)
#define mutexattr_destroy(...)                                  \
    zhpeu_posixcall(zhpeu_fatal, pthread_mutexattr_destroy, __VA_ARGS__)
#define mutex_init(...)                                         \
    zhpeu_posixcall(zhpeu_fatal, pthread_mutex_init, __VA_ARGS__)
#define mutex_destroy(...)                                      \
    zhpeu_posixcall(zhpeu_fatal, pthread_mutex_destroy, __VA_ARGS__)
#define mutex_lock(...)                                         \
    zhpeu_posixcall(zhpeu_fatal, pthread_mutex_lock, __VA_ARGS__)
#define mutex_trylock(...)                                      \
    zhpeu_posixcall_errorok(pthread_mutex_trylock, EBUSY, __VA_ARGS__)
#define mutex_unlock(...)                                       \
    zhpeu_posixcall(zhpeu_fatal, pthread_mutex_unlock, __VA_ARGS__)
#define spin_init(...)                                          \
    zhpeu_posixcall(zhpeu_fatal, pthread_spin_init, __VA_ARGS__)
#define spin_destroy(...)                                       \
    zhpeu_posixcall(zhpeu_fatal, pthread_spin_destroy, __VA_ARGS__)
#define spin_lock(...)                                          \
    zhpeu_posixcall(zhpeu_fatal, pthread_spin_lock, __VA_ARGS__)
#define spin_unlock(...)                                        \
    zhpeu_posixcall(zhpeu_fatal, pthread_spin_unlock, __VA_ARGS__)

/* publib-like no-fail APIs without publib. */

#define xposix_memalign(...)                                    \
    zhpeu_posixcall(zhpeu_fatal, posix_memalign, __VA_ARGS__)
#define xmalloc(...)                                            \
    zhpeu_call_null(zhpeu_fatal, malloc, void *, __VA_ARGS__)
#define xrealloc(...)                                           \
    zhpeu_call_null(zhpeu_fatal, realloc, void *, __VA_ARGS__)
#define xcalloc(...)                                            \
    zhpeu_call_null(zhpeu_fatal, calloc, void *, __VA_ARGS__)
#define xasprintf(...)                                          \
    zhpeu_syscall(zhpeu_fatal, zhpeu_asprintf, __VA_ARGS__)

/* Keep _GNU_SOURCE out of the headers. */
int zhpeu_asprintf(char **ret, const char *fmt, ...) PRINTF_ARGS(2, 3);
#define _zhpeu_asprintf(...)                                    \
    zhpeu_syscall(zhpeu_err, zhpeu_asprintf,  __VA_ARGS__)

void zhpeu_yield(void);
#define yield()         zhpeu_yield()

static inline void *malloc_aligned(size_t alignment, size_t size)
{
    void                *ret;

    errno = posix_memalign(&ret, alignment, size);
    if (unlikely(errno))
        ret = NULL;

    return ret;
}

static inline void *malloc_cachealigned(size_t size)
{
    return malloc_aligned(zhpeu_init_time->l1sz, size);
}

static inline void *calloc_aligned(size_t alignment, size_t nmemb, size_t size)
{
    void                *ret;

    /* Revisit:add check for overflow? */
    size *= nmemb;
    ret = malloc_aligned(alignment, size);
    if (likely(ret))
        memset(ret, 0, size);

    return ret;
}

static inline void *calloc_cachealigned(size_t nmemb, size_t size)
{
    return calloc_aligned(zhpeu_init_time->l1sz, nmemb, size);
}

#define xmalloc_aligned(...)                                    \
    zhpeu_call_null(zhpeu_fatal, malloc_aligned, void *, __VA_ARGS__)
#define xmalloc_cachealigned(...)                               \
    zhpeu_call_null(zhpeu_fatal, malloc_cachealigned, void *, __VA_ARGS__)
#define xcalloc_aligned(...)                                    \
    zhpeu_call_null(zhpeu_fatal, calloc_aligned, void *, __VA_ARGS__)
#define xcalloc_cachealigned(...)                               \
    zhpeu_call_null(zhpeu_fatal, calloc_cachealigned, void *, __VA_ARGS__)

#define xstrdup_or_null(_s)                                     \
({                                                              \
    void                *__ret;                                 \
    const char          *__s = (_s);                            \
                                                                \
    if (likely(__s))                                            \
        __ret = zhpeu_call_null(zhpeu_fatal, strdup, char *,    \
                                __s);                           \
    else                                                        \
        __ret = NULL;                                           \
                                                                \
    __ret;                                                      \
})

#define xmemdup(_mem, _bytes)                                   \
({                                                              \
    void                *__ret;                                 \
    const void          *__mem = (_mem);                        \
    size_t              __bytes = (_bytes);                     \
                                                                \
    if (likely(__mem && __bytes)) {                             \
        __ret = xmalloc(__bytes);                               \
        memcpy(__ret, __mem, __bytes);                          \
    }                                                           \
                                                                \
    __ret;                                                      \
})

#define _strdup_or_null(_s)                                     \
({                                                              \
    void                *__ret;                                 \
    const char          *__s = (_s);                            \
                                                                \
    if (likely(__s))                                            \
        __ret = zhpeu_call_null(zhpeu_err, strdup, char *, __s);\
    else                                                        \
        __ret = NULL;                                           \
                                                                \
    __ret;                                                      \
})

#define _memdup(_mem, _bytes)                                   \
({                                                              \
    void                *__ret;                                 \
    const void          *__mem = (_mem);                        \
    size_t              __bytes = (_bytes);                     \
                                                                \
    if (likely(__mem && __bytes)) {                             \
        __ret = _malloc(__bytes);                               \
        memcpy(__ret, __mem, __bytes);                          \
    }                                                           \
                                                                \
    __ret;                                                      \
})

/*
 * Wrappers for calls where errors may not necessaily be fatal.
 * Leading '_' allows callers a choice to not use the wrappers.
 */

#define _posix_memalign(...)                                    \
    zhpeu_posixcall(zhpeu_err, posix_memalign, __VA_ARGS__)
#define _malloc(...)                                            \
    zhpeu_call_null(zhpeu_err, malloc, void *, __VA_ARGS__)
#define _realloc(...)                                           \
    zhpeu_call_null(zhpeu_err, realloc, void *, __VA_ARGS__)
#define _calloc(...)                                            \
    zhpeu_call_null(zhpeu_err, calloc, void *, __VA_ARGS__)
#define _asprintf(...)                                          \
    zhpeu_syscall(zhpeu_err, zhpeu_asprintf, __VA_ARGS__)
#define _malloc_aligned(...)                                    \
    zhpeu_call_null(zhpeu_err, malloc_aligned, void *, __VA_ARGS__)
#define _malloc_cachealigned(...)                               \
    zhpeu_call_null(zhpeu_err, malloc_cachealigned, void *, __VA_ARGS__)
#define _calloc_aligned(...)                                    \
    zhpeu_call_null(zhpeu_err, calloc_aligned, void *, __VA_ARGS__)
#define _calloc_cachealigned(...)                               \
    zhpeu_call_null(zhpeu_err, calloc_cachealigned, void *, __VA_ARGS__)

#define _zhpeu_sockaddr_ntop(...)                               \
    zhpeu_call_null(zhpeu_sockaddr_ntop, char *, __VA_ARGS__)
#define _zhpeu_sockaddr_str(...)                                \
    zhpeu_call_null(zhpeu_err, zhpeu_sockaddr_str, char *, __VA_ARGS__)
#define _zhpeu_get_cpu_info_val(...)                            \
    zhpeu_call_null(zhpeu_err, zhpeu_get_cpuinfo_val, char *, __VA_ARGS__)
#define _zhpeu_parse_kb_uint64_t(...)                           \
    zhpeu_call_neg(zhpeu_err, zhpeu_parse_kb_uint64_t, int, __VA_ARGS__)
#define _zhpeu_sock_getaddrinfo(...)                            \
    zhpeu_call_neg(zhpeu_err, zhpeu_sock_getaddrinfo, int, __VA_ARGS__)
#define _zhpeu_sock_connect(...)                                \
    zhpeu_call_neg(zhpeu_err, zhpeu_sock_connect, int, __VA_ARGS__)
#define _zhpeu_sock_getsockname(...)                            \
    zhpeu_call_neg(zhpeu_err, zhpeu_sock_getsockname, int, __VA_ARGS__)
#define _zhpeu_sock_getpeername(...)                            \
    zhpeu_call_neg(zhpeu_err, zhpeu_sock_getpeername, int, __VA_ARGS__)
#define _zhpeu_sock_send_blob(...)                              \
    zhpeu_call_neg(zhpeu_err, zhpeu_sock_send_blob, int, __VA_ARGS__)
#define _zhpeu_sock_recv_fixed_blob(...)                        \
    zhpeu_call_neg(zhpeu_err, zhpeu_sock_recv_fixed_blob, int, __VA_ARGS__)
#define _zhpeu_sock_recv_var_blob(...)                          \
    zhpeu_call_neg(zhpeu_err, zhpeu_sock_recv_var_blob, int, __VA_ARGS__)
#define _zhpeu_sock_send_string(...)                            \
    zhpeu_call_neg(zhpeu_err, zhpeu_sock_send_string, int, __VA_ARGS__)
#define _zhpeu_sock_recv_string(...)                            \
    zhpeu_call_neg(zhpeu_err, zhpeu_sock_recv_string, int, __VA_ARGS__)
#define _zhpeu_munmap(...)                                      \
    zhpeu_call_neg(zhpeu_err, zhpeu_munmap, int, __VA_ARGS__)
#define _zhpeu_mmap(...)                                        \
    zhpeu_call_null(zhpeu_err, zhpeu_mmap, void *, __VA_ARGS__)
#define _zhpeu_get_cpuinfo_val(...)                             \
    zhpeu_call_null(zhpeu_err, zhpeu_get_cpuinfo_val, void *, __VA_ARGS__)

static inline uint64_t roundup64(uint64_t val, uint64_t round)
{
    return ((val + round - 1) / round * round);
}

static inline uint64_t roundup_pow_of_2(uint64_t val)
{
    if (!val || !(val & (val - 1)))
        return val;

    return ((uint64_t)1 << fls64(val));
}

static inline uint64_t mask2_off(uint64_t val, uint64_t size)
{
    uint64_t            mask = (size - 1);

    /* size must be power of 2. */
    assert(!(size & (size -1)));
    return (val & mask);
}

static inline uint64_t mask2_down(uint64_t val, uint64_t size)
{
    uint64_t            mask = ~(size - 1);

    /* size must be power of 2. */
    assert(!(size & (size -1)));
    return (val & mask);
}

static inline uint64_t mask2_up(uint64_t val, uint64_t size)
{
    uint64_t            mask = ~(size - 1);

    /* size must be power of 2. */
    assert(!(size & (size -1)));
    return ((val + size - 1) & mask);
}

static inline uint64_t page_off(uint64_t val)
{
    return mask2_off(val, zhpeu_init_time->pagesz);
}

static inline uint64_t page_down(uint64_t val)
{
    return mask2_down(val, zhpeu_init_time->pagesz);
}

static inline uint64_t page_up(uint64_t val)
{
    return mask2_up(val, zhpeu_init_time->pagesz);
}

static inline uint64_t l1_off(uint64_t val)
{
    return mask2_off(val, zhpeu_init_time->l1sz);
}

static inline uint64_t l1_down(uint64_t val)
{
    return mask2_down(val, zhpeu_init_time->l1sz);
}

static inline uint64_t l1_up(uint64_t val)
{
    return mask2_up(val, zhpeu_init_time->l1sz);
}

struct zhpeu_thr_wait {
    int32_t             state;
    pthread_mutex_t     mutex;
    pthread_cond_t      cond;
    bool                (*signal_fast)(struct zhpeu_thr_wait *thr_wait);
    void                (*signal_slow)(struct zhpeu_thr_wait *thr_wait,
                                       bool lock, bool unlock);
} CACHE_ALIGNED;

#define MS_PER_SEC      (1000UL)
#define US_PER_SEC      (1000000UL)
#define NS_PER_SEC      (1000000000UL)

#define KiB             ((size_t)1024)
#define MiB             (KiB * KiB)
#define GiB             (KiB * MiB)
#define TiB             (KiB * GiB)

enum {
    ZHPEU_THR_WAIT_IDLE,
    ZHPEU_THR_WAIT_SLEEP,
    ZHPEU_THR_WAIT_SIGNAL,
};

void zhpeu_thr_wait_init(struct zhpeu_thr_wait *thr_wait);
void zhpeu_thr_wait_signal_init(
    struct zhpeu_thr_wait *thr_wait,
    bool (*signal_fast)(struct zhpeu_thr_wait *thr_wait),
    void (*signal_slow)(struct zhpeu_thr_wait *thr_wait,
                        bool lock, bool unlock));
void zhpeu_thr_wait_destroy(struct zhpeu_thr_wait *thr_wait);

static inline void zhpeu_thr_wait_signal(struct zhpeu_thr_wait *thr_wait)
{
    if (thr_wait->signal_fast(thr_wait))
        thr_wait->signal_slow(thr_wait, true, true);
}

static inline bool zhpeu_thr_wait_sleep_fast(struct zhpeu_thr_wait *thr_wait)
{
    int32_t             old = ZHPEU_THR_WAIT_IDLE;
    int32_t             new = ZHPEU_THR_WAIT_SLEEP;

    /* One sleeper, many wakers. */
    if (atm_cmpxchg(&thr_wait->state, &old, new))
        /* Need to call slow. */
        return true;

    /* Reset SIGNAL to IDLE. */
    assert(old == ZHPEU_THR_WAIT_SIGNAL);
    new = ZHPEU_THR_WAIT_IDLE;
    atm_cmpxchg(&thr_wait->state, &old, new);

    /* Fast path succeeded. */
    return false;
}

int zhpeu_thr_wait_sleep_slow(struct zhpeu_thr_wait *thr_wait,
                              int64_t timeout_us, bool lock, bool unlock);

struct zhpeu_work_head {
    struct zhpeu_thr_wait thr_wait;
    STAILQ_HEAD(, zhpeu_work) work_list;
};

/* Worker returns true if it needs to be retried later. */
typedef bool (*zhpeu_worker)(struct zhpeu_work_head *head,
                             struct zhpeu_work *work);

struct zhpeu_work {
    STAILQ_ENTRY(zhpeu_work) lentry;
    zhpeu_worker        worker;
    void                *data;
    pthread_cond_t      cond;
    int                 status;
};

void zhpeu_work_head_init(struct zhpeu_work_head *head);
void zhpeu_work_head_signal_init(
    struct zhpeu_work_head *head,
    bool (*signal_fast)(struct zhpeu_thr_wait *thr_wait),
    void (*signal_slow)(struct zhpeu_thr_wait *thr_wait,
                        bool lock, bool unlock));
void zhpeu_work_head_destroy(struct zhpeu_work_head *head);

static inline void zhpeu_work_init(struct zhpeu_work *work)
{
    work->status = 0;
    work->worker = NULL;
    cond_init(&work->cond, NULL);
}

static inline void zhpeu_work_destroy(struct zhpeu_work *work)
{
    cond_destroy(&work->cond);
}

static inline void zhpeu_work_wait(struct zhpeu_work_head *head,
                                   struct zhpeu_work *work, bool lock,
                                   bool unlock)
{
    if (lock)
        mutex_lock(&head->thr_wait.mutex);
    while (work->worker)
        cond_wait(&work->cond, &head->thr_wait.mutex);
    if (unlock)
        mutex_unlock(&head->thr_wait.mutex);
}

static inline bool zhpeu_work_queued(struct zhpeu_work_head *head)
{
    return unlikely(!!STAILQ_FIRST(&head->work_list));
}

static inline void zhpeu_work_queue(struct zhpeu_work_head *head,
                                    struct zhpeu_work *work,
                                    zhpeu_worker worker, void *data,
                                    bool signal, bool lock, bool unlock)
{
    if (lock)
        mutex_lock(&head->thr_wait.mutex);
    work->worker = worker;
    work->data = data;
    STAILQ_INSERT_TAIL(&head->work_list, work, lentry);
    if (signal && head->thr_wait.signal_fast(&head->thr_wait))
        head->thr_wait.signal_slow(&head->thr_wait, false, unlock);
    else if (unlock)
        mutex_unlock(&head->thr_wait.mutex);
}

bool zhpeu_work_process(struct zhpeu_work_head *head, bool lock, bool unlock);

struct zhpeu_timing {
    uint64_t            tot;
    uint64_t            min;
    uint64_t            max;
    uint64_t            cnt;
    uint64_t            skw;
};

void zhpeu_timing_reset(struct zhpeu_timing *t);

void zhpeu_timing_update(struct zhpeu_timing *t, uint64_t cycles);

void zhpeu_timing_print(struct zhpeu_timing *t, const char *lbl,
                        uint64_t divisor);

struct zhpeu_debug_rec {
    uint                idx;
    uint                line;
    const char          *str;
    uint64_t            cycles;
    uint64_t            v[5];
};

struct zhpeu_debug_log {
    uint                idx;
    uint                mask;
    struct zhpeu_debug_rec ent[];
};

#define ZHPEU_DECLARE_DEBUG_LOG(_name, _order)                  \
struct {                                                        \
    uint                idx;                                    \
    uint                mask;                                   \
    struct zhpeu_debug_rec ent[1U << (_order)];                 \
} _name = { .mask = (1U << (_order)) - 1 }

void zhpeu_debug_log(void *vlog, const char *str, uint line,
                     uint64_t v0, uint64_t v1, uint64_t v2, uint64_t v3,
                     uint64_t v4, uint64_t cycles);

void zhpeu_assert_fail(const char *expr, const char *func, uint line);

/* Not affected by NDEBUG */
#define assert_always(_expr)                                    \
do {                                                            \
    if (unlikely(!(_expr)))                                     \
        zhpeu_assert_fail(#_expr, __func__, __LINE__);          \
} while (0)

#ifdef _ZHPEQ_TEST_COMPAT_

#define appname                 (zhpeu_appname)
#define page_size               (zhpeu_init_time->pagesz)

#define check_func_io           zhpeu_check_func_io
#define check_func_ion          zhpeu_check_func_ion
#define connect_sock            _zhpeu_sock_connect
#define do_getaddrinfo          zhpeu_sock_getaddrinfo
#define expected_saw            zhpeu_expected_saw
#define parse_kb_uint64_t(_callf, _line, ...)                   \
    _zhpeu_parse_kb_uint64_t(__VA_ARGS__)
#define print_dbg               zhpeu_print_dbg
#define print_err               zhpeu_print_err
#define print_func_err          zhpeu_print_func_err
#define print_func_errn         zhpeu_print_func_errn
#define print_info              zhpeu_print_info
#define print_range_err         zhpeu_print_range_err
#define print_usage             zhpeu_print_usage
#define print_usage             zhpeu_print_usage
#define random_array            zhpeu_random_array
#define random_range            zhpeu_random_range
#define random_seed             zhpeu_random_seed
#define sock_send_blob          _zhpeu_sock_send_blob
#define sock_recv_fixed_blob    _zhpeu_sock_recv_fixed_blob
#define sock_send_string        _zhpeu_sock_send_string
#define sock_recv_string        _zhpeu_sock_recv_string
#define sockaddr_dup            zhpeu_sockaddr_dup
#define sockaddr_valid          zhpeu_sockaddr_valid
#define zhpeq_util_init         zhpeu_util_init

#endif

#ifdef HAVE_ZHPE_SIM

#include <hpe_sim_api_linux64.h>

static inline bool zhpeu_is_sim(void)
{
    return !!sim_api_is_sim();
}

#else

static inline bool zhpeu_is_sim(void)
{
    return false;
}

#endif

_EXTERN_C_END

#endif /* _ZHPEQ_UTIL_H_ */
