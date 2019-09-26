/*
 * Copyright (C) 2017-2019 Hewlett Packard Enterprise Development LP.
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

/* Type checking container_of */
#ifdef container_of
#undef container_of
#endif
#define container_of(ptr, type, member)                         \
({                                                              \
    typeof( ((type *)0)->member ) *_ptr = (ptr);                \
    (type *)((char *)_ptr - offsetof(type, member));            \
})

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(_x)  (sizeof(_x) / sizeof(_x[0]))
#endif

#define TO_PTR(_int)    (void *)(uintptr_t)(_int)

#define FREE_IF(_ptr,_free)                                     \
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

#define arithcmp(_a, _b)        ((_a) < (_b) ? -1 : ((_a) > (_b) ? 1 : 0))

typedef long long       llong;
typedef unsigned long long ullong;
typedef unsigned char   uchar;

extern const char       *appname;

/* Borrow AF_APPLETALK since it should never be seen. */
#define AF_ZHPE         AF_APPLETALK
#define ZHPE_ADDRSTRLEN (37)
#define ZHPE_QUEUEINVAL (~(uint32_t)0)

#define ZHPE_SA_TYPE_SHIFT      (24)
#define ZHPE_SA_XID_MASK        ((1U << ZHPE_SA_TYPE_SHIFT) - 1)
#define ZHPE_SA_TYPE_MASK       (0xFFU << ZHPE_SA_TYPE_SHIFT)
#define ZHPE_SA_TYPE_FAM        (1U << ZHPE_SA_TYPE_SHIFT)

struct sockaddr_zhpe {
    sa_family_t         sz_family;
    uuid_t              sz_uuid;
    uint32_t            sz_queue;
};

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

int zhpeu_posix_memalign(void **memptr, size_t alignment, size_t size,
                         const char *callf, uint line);

#define posix_memalign(...) \
    zhpeu_posix_memalign(__VA_ARGS__, __func__, __LINE__)

void *zhpeu_malloc(size_t size, const char *callf, uint line);

#define malloc(...) \
    zhpeu_malloc(__VA_ARGS__, __func__, __LINE__)

void *zhpeu_realloc(void *ptr, size_t size, const char *callf, uint line);

#define realloc(...) \
    zhpeu_realloc(__VA_ARGS__, __func__, __LINE__)

void *zhpeu_calloc(size_t nmemb, size_t size, const char *callf, uint line);

#define calloc(...) \
    zhpeu_calloc(__VA_ARGS__, __func__, __LINE__)

void *zhpeu_malloc_aligned(size_t alignment, size_t size,
                           const char *callf, uint line);

#define malloc_aligned(...) \
    zhpeu_malloc_aligned(__VA_ARGS__, __func__, __LINE__)

#define malloc_cachealigned(...) \
    zhpeu_malloc_aligned(L1_CACHE_BYTES, __VA_ARGS__, __func__, __LINE__)

void *zhpeu_calloc_aligned(size_t alignment, size_t nmemb, size_t size,
                           const char *callf, uint line);

#define calloc_aligned(...) \
    zhpeu_calloc_aligned(__VA_ARGS__, __func__, __LINE__)

#define calloc_cachealigned(...) \
    zhpeu_calloc_aligned(L1_CACHE_BYTES, __VA_ARGS__, __func__, __LINE__)

void zhpeu_free(void *ptr, const char *callf, uint line);

#define free(...) \
    zhpeu_free(__VA_ARGS__, __func__, __LINE__)

/* Just a call to free for things that need a function pointer. */
void zhpeu_free_ptr(void *ptr);

/* Trying to rely on stdatomic.h with less verbosity.
 * I'm not at all convinced they do the right thing with fences, in general,
 * but on x86 atomic adds and cmpxchg are full barriers. So the only relaxed
 * thing I use are loads/stores.
 */

#define atm_load(_p) \
    atomic_load_explicit(_p, memory_order_acquire)
#define atm_load_rlx(_p) \
    atomic_load_explicit(_p, memory_order_relaxed)

#define atm_store(_p, _v)  \
    atomic_store_explicit(_p, _v, memory_order_release)
#define atm_store_rlx(_p, _v) \
    atomic_store_explicit(_p, _v, memory_order_relaxed)

#define atm_add(_p, _v) \
    atomic_fetch_add_explicit(_p, _v, memory_order_acq_rel)

#define atm_and(_p, _v) \
    atomic_fetch_and_explicit(_p, _v, memory_order_acq_rel)

#define atm_or(_p, _v) \
    atomic_fetch_or_explicit(_p, _v, memory_order_acq_rel)

#define atm_sub(_p, _v) \
    atomic_fetch_sub_explicit(_p, _v, memory_order_acq_rel)

#define atm_xchg(_p, _v) \
    atomic_exchange_explicit(_p, _v, memory_order_acq_rel)

#define atm_xor(_p, _v) \
    atomic_fetch_xor_explicit(_p, _v, memory_order_acq_rel)

#define atm_cmpxchg(_p, _oldp, _new) \
    atomic_compare_exchange_strong_explicit( \
        _p, _oldp, _new, memory_order_acq_rel, memory_order_acquire)

#define atm_inc(_p)     atm_add(_p, 1)
#define atm_dec(_p)     atm_sub(_p, 1)

#ifdef __GNUC__

#ifdef _BARRIER_DEFINED
#warning _BARRIER_DEFINED already defined
#undef _BARRIER_DEFINED
#endif

#if defined(__x86_32__) || defined( __x86_64__)

#define _BARRIER_DEFINED

/* But atomic_thread_fence() didn't generate the fences I wanted when I
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

#define L1_CACHE_BYTES  (64UL)

static inline void nop(void)
{
    asm volatile("nop");
}

#endif

#ifndef _BARRIER_DEFINED
#error No barrier support for this architecture
#endif

#undef _BARRIED_DEFINED

#define barrier()       __compiler_barrier()
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

/* Two simple atomic lists:
 * "lifo" for free lists and a "snatch" list with multiple-producers and
 * one consumer that snatches the entire list for processing at once: this
 * avoids most of the complexities with enqeue and dequeue around A-B-A, but
 * the tail must be handled carefully.
 */

struct zhpeu_atm_list_ptr {
    struct zhpeu_atm_list_next *ptr;
    uintptr_t            seq;
} INT128_ALIGNED;

struct zhpeu_atm_list_next {
    struct zhpeu_atm_list_next *next;
} INT64_ALIGNED;

struct zhpeu_atm_snatch_head {
    struct zhpeu_atm_list_next *head;
    struct zhpeu_atm_list_next *tail;
} INT128_ALIGNED;

#define ZHPEU_ATM_LIST_END      ((struct zhpeu_atm_list_next *)(intptr_t)-1)

static inline void zhpeu_atm_snatch_insert(struct zhpeu_atm_snatch_head *head,
                                           struct zhpeu_atm_list_next *new)
{
    struct zhpeu_atm_snatch_head oldh;
    struct zhpeu_atm_snatch_head newh;
    struct zhpeu_atm_list_next oldn;

    new->next = NULL;
    for (oldh = atm_load_rlx(head);;) {
        if (oldh.head) {
            newh.head = oldh.head;
            /* Try to link new into list. */
            oldn.next = NULL;
            if (!atm_cmpxchg(&oldh.tail->next, &oldn, new)) {
                /* Failed: advance the tail ourselves and retry. */
                newh.tail = oldn.next;
                if (atm_cmpxchg(head, &oldh, newh))
                    oldh = newh;
                continue;
            }
            /* Try to update the head; succeed or fail, we're done.
             * If we fail, it is up to the other threads to deal with it.
             */
            newh.tail = new;
            atm_cmpxchg(head, &oldh, newh);
            break;
        }
        /* List was empty. */
        newh.head = new;
        newh.tail = new;
        if (atm_cmpxchg(head, &oldh, newh))
            break;
    }
}

static inline void zhpeu_atm_snatch_list(struct zhpeu_atm_snatch_head *head,
                                         struct zhpeu_atm_snatch_head *oldh)
{
    struct zhpeu_atm_snatch_head newh;
    struct zhpeu_atm_list_next oldn;

    for (*oldh = atm_load_rlx(head);;) {
        if (!oldh->head)
            return;
        newh.head = NULL;
        newh.tail = NULL;
        if (atm_cmpxchg(head, oldh, newh))
            break;
    }
    /* Worst case: another thread has copied the head and went to sleep
     * before updating the next pointer and will wake up at some point far
     * in the future and do so. Or another thread could have successfully
     * updated next, but the tail update failed. We update the final next
     * pointer with ZHPEU_ATM_LIST_END to deal with some of this, but the
     * potential for a thread lurking demands a more structural
     * solution. The fifo list will also use ZHPEU_ATM_LIST_END, instead of
     * NULL and the assumption is that items will be bounced between
     * snatch lists and fifos as free lists; items will never be returned
     * to a general allocation pool unless some broader guarantee that
     * it is safe to do so.
     */
    for (;;) {
        oldn.next = NULL;
        if (atm_cmpxchg(&oldh->tail->next, &oldn, ZHPEU_ATM_LIST_END))
            break;
        oldh->tail = oldn.next;
    }
}

static inline void zhpeu_atm_fifo_init(struct zhpeu_atm_list_ptr *head)
{
    head->ptr = ZHPEU_ATM_LIST_END;
    head->seq = 0;
}

static inline void zhpeu_atm_fifo_push(struct zhpeu_atm_list_ptr *head,
                                       struct zhpeu_atm_list_next *new)
{
    struct zhpeu_atm_list_ptr oldh;
    struct zhpeu_atm_list_ptr newh;

    newh.ptr = new;
    for (oldh = atm_load_rlx(head);;) {
        new->next = oldh.ptr;
        newh.seq = oldh.seq + 1;
        if (atm_cmpxchg(head, &oldh, newh))
            break;
    }
}

static inline struct zhpeu_atm_list_next *
zhpeu_atm_fifo_pop(struct zhpeu_atm_list_ptr *head)
{
    struct zhpeu_atm_list_next *ret;
    struct zhpeu_atm_list_ptr oldh;
    struct zhpeu_atm_list_ptr newh;

    for (oldh = atm_load_rlx(head);;) {
        ret = oldh.ptr;
        if (ret == ZHPEU_ATM_LIST_END) {
            ret = NULL;
            break;
        }
        newh.ptr = ret->next;
        newh.seq = oldh.seq + 1;
        if (atm_cmpxchg(head, &oldh, newh))
            break;
    }

    return ret;
}

static inline sa_family_t sockaddr_family(const void *addr)
{
    const union sockaddr_in46 *sa = addr;

    return sa->sa_family;
}

static inline uint32_t sockaddr_porth(const void *addr)
{
    const union sockaddr_in46 *sa = addr;

    switch (sa->sa_family) {

    case AF_INET:
    case AF_INET6:
        return ntohs(sa->sin_port);

    case AF_ZHPE:
        return sa->zhpe.sz_queue;

    default:
        return 0;
    }
}

static inline size_t sockaddr_len(const void *addr)
{
    const union sockaddr_in46 *sa = addr;

    switch (sa->sa_family) {

    case AF_INET:
        return sizeof(struct sockaddr_in);

    case AF_INET6:
        return sizeof(struct sockaddr_in6);

    case AF_ZHPE:
        return sizeof(struct sockaddr_zhpe);

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

int sockaddr_cmpx(const union sockaddr_in46 *sa1,
                  const union sockaddr_in46 *sa2, bool noport);

static inline int sockaddr_portcmp(const void *addr1, const void *addr2)
{
    int                 ret;
    const union sockaddr_in46 *sa1 = addr1;
    const union sockaddr_in46 *sa2 = addr2;

    assert(sa1->sa_family == sa2->sa_family);

    /* Use memcmp for -1, 0, 1 behavior. */
    switch (sa1->sa_family) {

    case AF_INET:
    case AF_INET6:
        ret = memcmp(&sa1->sin_port, &sa2->sin_port, sizeof(sa1->sin_port));
        break;

    case AF_ZHPE:
        ret = memcmp(&sa1->zhpe.sz_queue, &sa2->zhpe.sz_queue,
                     sizeof(sa1->zhpe.sz_queue));
        break;

    default:
        ret = -1;
        break;
    }

    return ret;
}

static inline int sockaddr_cmp_noport(const void *addr1, const void *addr2)
{
    int                 ret;
    const union sockaddr_in46 *sa1 = addr1;
    const union sockaddr_in46 *sa2 = addr2;

    if (sa1->sa_family != sa2->sa_family) {
        ret = sockaddr_cmpx(sa1, sa2, true);
        goto done;
    }

    /* Use memcmp for -1, 0, 1 behavior. */
    switch (sa1->sa_family) {

    case AF_INET:
        ret = memcmp(&sa1->addr4.sin_addr, &sa2->addr4.sin_addr,
                     sizeof(sa1->addr4.sin_addr));
        break;

    case AF_INET6:
        ret = memcmp(&sa1->addr6.sin6_addr, &sa2->addr6.sin6_addr,
                     sizeof(sa1->addr6.sin6_addr));
        break;

    case AF_ZHPE:
        ret = uuid_compare(sa1->zhpe.sz_uuid, sa2->zhpe.sz_uuid);
        break;

    default:
        ret = -1;
        break;
    }

 done:
    return ret;
}

static inline int sockaddr_cmp(const void *addr1, const void *addr2)
{
    int                 ret;
    const union sockaddr_in46 *sa1 = addr1;
    const union sockaddr_in46 *sa2 = addr2;

    if (sa1->sa_family != sa2->sa_family) {
        ret = sockaddr_cmpx(sa1, sa2, false);
        goto done;
    }

    ret = sockaddr_cmp_noport(sa1, sa2);
    if (ret)
        goto done;
    ret = sockaddr_portcmp(sa1, sa2);

 done:
    return ret;
}

static inline bool sockaddr_wildcard6(const struct sockaddr_in6 *sa)
{
    return !memcmp(&sa->sin6_addr, &in6addr_any, sizeof(sa->sin6_addr));
}

static inline bool sockaddr_loopback6(const struct sockaddr_in6 *sa)
{
    return !memcmp(&sa->sin6_addr, &in6addr_loopback, sizeof(sa->sin6_addr));
}

static inline bool sockaddr_wildcard(const void *addr)
{
    bool                ret = false;
    const union sockaddr_in46 *sa = addr;

    switch (sa->sa_family) {

    case AF_INET:
        ret = (sa->addr4.sin_addr.s_addr == htonl(INADDR_ANY));
        break;

    case AF_INET6:
        ret = sockaddr_wildcard6(&sa->addr6);
        break;

    default:
        break;
    }

    return ret;
}

static inline bool sockaddr_loopback(const void *addr, bool loopany)
{
    bool                ret = false;
    const union sockaddr_in46 *sa = addr;
    uint32_t            netmask;

    switch (sa->sa_family) {

    case AF_INET:
        netmask = (loopany ? IN_CLASSA_NET : ~(uint32_t)0);
        ret = ((ntohl(sa->addr4.sin_addr.s_addr) & netmask) ==
               (INADDR_LOOPBACK & netmask));
        break;

    case AF_INET6:
        ret = sockaddr_loopback6(&sa->addr6);
        break;

    default:
        break;
    }

    return ret;
}

static inline void sockaddr_6to4(void *addr)
{
    union sockaddr_in46 *sa = addr;
    uint                i;
    uchar               *cp;

    if (sa->sa_family != AF_INET6)
        goto done;
    if (sockaddr_wildcard6(&sa->addr6))
        sa->addr4.sin_addr.s_addr = htonl(INADDR_ANY);
    else if (sockaddr_loopback6(&sa->addr6))
        sa->addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    else {
        /* IPV4 mapped: ten bytes of zero followed by 2 bytes of 0xFF? */
        for (i = 0, cp = sa->addr6.sin6_addr.s6_addr; i < 10; i++, cp++) {
            if (*cp)
                goto done;
        }
        for (i = 0; i < 2; i++, cp++) {
            if (*cp != 0xFF)
                goto done;
        }
        memmove(&sa->addr4.sin_addr, cp, sizeof(sa->addr4.sin_addr));
    }
    sa->sa_family = AF_INET;

 done:

    return;
}

static_assert(INET6_ADDRSTRLEN >= ZHPE_ADDRSTRLEN, "ZHPE_ADDRSTRLEN");

const char *sockaddr_ntop(const void *addr, char *buf, size_t len);

int zhpeu_asprintf(char **strp, const char *fmt, ...) PRINTF_ARGS(2, 3);

static inline char *sockaddr_str(const void *addr)
{
    char                *ret = NULL;
    const union sockaddr_in46 *sa = addr;
    const char          *family;
    char                ntop[INET6_ADDRSTRLEN];
    uint                port;

    if (!sockaddr_ntop(sa, ntop, sizeof(ntop)))
        return NULL;

    switch (sa->sa_family) {

    case AF_INET:
        family = "ipv4";
        port = ntohs(sa->sin_port);
        break;

    case AF_INET6:
        family = "ipv6";
        port = ntohs(sa->sin_port);
        break;

    case AF_ZHPE:
        family = "zhpe";
        port = htonl(sa->zhpe.sz_queue);
        break;

    default:
        break;
    }
    if (zhpeu_asprintf(&ret, "%s:%s:%u", family, ntop, port) == -1)
            ret = NULL;

    return ret;
}

void zhpeq_util_init(char *argv0, int default_log_level, bool use_syslog);

void print_dbg(const char *fmt, ...) PRINTF_ARGS(1, 2);

void print_info(const char *fmt, ...) PRINTF_ARGS(1, 2);

void print_err(const char *fmt, ...) PRINTF_ARGS(1, 2);

char *errf_str(const char *fmt, ...) PRINTF_ARGS(1, 2);

void print_usage(bool use_stdout, const char *fmt, ...) PRINTF_ARGS(2, 3);

void print_errs(const char *callf, uint line, char *errf_str,
                int err, const char *errs);

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

struct zhpeu_init_time {
    uint64_t            (*get_cycles)(volatile uint32_t *cpup);
    uint64_t            freq;
    void                (*clflush_range)(const void *p, size_t len, bool fence);
    void                (*clwb_range)(const void *p, size_t len, bool fence);
    uint64_t            pagesz;
    uint64_t            l1sz;
};

extern struct zhpeu_init_time *zhpeu_init_time;

#define page_size       (zhpeu_init_time->pagesz)

#define NSEC_PER_SEC    (1000000000UL)
#define NSEC_PER_USEC   (1000000UL)

static inline double cycles_to_usec(uint64_t delta, uint64_t loops)
{
    return (((double)delta * NSEC_PER_USEC) /
            ((double)zhpeu_init_time->freq * loops));
}

static inline uint64_t get_cycles(volatile uint32_t *cpup)
{
    return zhpeu_init_time->get_cycles(cpup);
}

static inline uint64_t get_tsc_freq(void)
{
    return zhpeu_init_time->freq;
}

static inline void clflush_range(const void *addr, size_t length, bool fence)
{
    zhpeu_init_time->clflush_range(addr, length, fence);
}

static inline void clwb_range(const void *addr, size_t length,  bool fence)
{
    zhpeu_init_time->clwb_range(addr, length, fence);
}

#define abort_syscall(_func, ...)                               \
do {                                                            \
    int                 __ret = _func(__VA_ARGS__);             \
                                                                \
    if (unlikely(__ret == -1)) {                                \
        __ret = errno;                                          \
        print_func_err(__func__, __LINE__,  #_func, "", __ret); \
        abort();                                                \
    }                                                           \
} while (0)

#define abort_posix(_func, ...)                                 \
do {                                                            \
    int                 __ret = _func(__VA_ARGS__);             \
                                                                \
    if (unlikely(__ret)) {                                      \
        print_func_err(__func__, __LINE__,  #_func, "", __ret); \
        abort();                                                \
    }                                                           \
} while (0)

#define abort_posix_errorok(_func, _err, ...)                   \
({                                                              \
    int                 __ret = _func(__VA_ARGS__);             \
    int                 __err = (_err);                         \
                                                                \
    if (unlikely(__ret)) {                                      \
        if (unlikely(__ret != __err || __ret < 0)) {            \
            print_func_err(__func__, __LINE__,  #_func, "",     \
                           __ret);                              \
            abort();                                            \
        }                                                       \
        __ret = -__ret;                                         \
    }                                                           \
    __ret;                                                      \
})

#define clock_gettime(...) \
    abort_syscall(clock_gettime, __VA_ARGS__)

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

bool _expected_saw(const char *callf, uint line,
                   const char *label, uintptr_t expected, uintptr_t saw);

#define expected_saw(...) \
    _expected_saw(__func__, __LINE__, __VA_ARGS__)

char *_sockaddr_port_str(const char *callf, uint line, const void *addr);

#define sockaddr_port_str(...) \
    _sockaddr_port_str(__func__, __LINE__, __VA_ARGS__)

char *_sockaddr_str(const char *callf, uint line, const void *addr);

#define sockaddr_str(...) \
    _sockaddr_str(__func__, __LINE__, __VA_ARGS__)

int _do_getsockname(const char *callf, uint line,
                    int fd, union sockaddr_in46 *sa);

#define do_getsockname(...) \
    _do_getsockname(__func__, __LINE__, __VA_ARGS__)

int _do_getpeername(const char *callf, uint line,
                    int fd, union sockaddr_in46 *da);

#define do_getpeername(...) \
    _do_getpeername(__func__, __LINE__, __VA_ARGS__)

int _sock_send_blob(const char *callf, uint line, int fd,
                    const void *blob, size_t blob_len);

#define sock_send_blob(...) \
    _sock_send_blob(__func__, __LINE__, __VA_ARGS__)

int _sock_recv_fixed_blob(const char *callf, uint line,
                          int fd, void *blob, size_t blob_len);

#define sock_recv_fixed_blob(...) \
    _sock_recv_fixed_blob(__func__, __LINE__, __VA_ARGS__)

int _sock_recv_var_blob(const char *callf, uint line,
                        int fd, size_t extra_len,
                        void **blob, size_t *blob_len);

#define sock_recv_var_blob(...) \
    _sock_recv_var_blob(__func__, __LINE__, __VA_ARGS__)

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
    _strdup_or_null(__func__, __LINE__, __VA_ARGS__)

#define cond_init(...) \
    abort_posix(pthread_cond_init, __VA_ARGS__)

#define cond_destroy(...) \
    abort_posix(pthread_cond_destroy, __VA_ARGS__)

#define cond_signal(...) \
    abort_posix(pthread_cond_signal, __VA_ARGS__)

#define cond_broadcast(...) \
    abort_posix(pthread_cond_broadcast, __VA_ARGS__)

#define cond_wait(...) \
    abort_posix(pthread_cond_wait, __VA_ARGS__)

#define cond_timedwait(...) \
    abort_posix_errorok(pthread_cond_timedwait, ETIMEDOUT, __VA_ARGS__)

#define mutexattr_settype(...) \
	abort_posix(pthread_mutexattr_settype, __VA_ARGS__)

#define mutexattr_init(...) \
	abort_posix(pthread_mutexattr_init, __VA_ARGS__)

#define mutexattr_destroy(...) \
	abort_posix(pthread_mutexattr_destroy, __VA_ARGS__)

#define mutex_init(...) \
    abort_posix(pthread_mutex_init, __VA_ARGS__)

#define mutex_destroy(...) \
    abort_posix(pthread_mutex_destroy, __VA_ARGS__)

#define mutex_lock(...) \
    abort_posix(pthread_mutex_lock, __VA_ARGS__)

#define mutex_trylock(...) \
    abort_posix_errorok(pthread_mutex_trylock, EBUSY, __VA_ARGS__)

#define mutex_unlock(...) \
    abort_posix(pthread_mutex_unlock, __VA_ARGS__)

#define spin_init(...) \
    abort_posix(pthread_spin_init, __VA_ARGS__)

#define spin_destroy(...) \
    abort_posix(pthread_spin_destroy, __VA_ARGS__)

#define spin_lock(...) \
    abort_posix(pthread_spin_lock, __VA_ARGS__)

#define spin_unlock(...) \
    abort_posix(pthread_spin_unlock, __VA_ARGS__)

void zhpeu_yield(void);

#define yield()         zhpeu_yield()

static inline int do_munmap(void *addr, size_t length,
                            const char *callf, uint line)
{
    int                 ret = 0;

    if (!addr)
        return 0;

    if (munmap(addr, length) == -1) {
        ret = -errno;
        print_func_err(callf, line, "munmap", "", ret);
    }

    return ret;
}

#define do_munmap(...) \
    do_munmap(__VA_ARGS__, __func__, __LINE__)

static inline void *do_mmap(void *addr, size_t length, int prot, int flags,
                            int fd, off_t offset, int *error,
                            const char *callf, uint line)
{
    void                *ret;
    int                 err = 0;

    ret = mmap(addr, length, prot, flags, fd, offset);
    if (ret == MAP_FAILED) {
        err = -errno;
        ret = NULL;
        print_func_err(callf, line, "mmap", "", err);
    }
    if (error)
        *error = err;

    return ret;
}

#define do_mmap(...) \
    do_mmap(__VA_ARGS__, __func__, __LINE__)

static inline int fls64(uint64_t v)
{
    int                 ret = -1;

    asm("bsrq %1,%q0" : "+r" (ret) : "r" (v));

    return ret;
}

static inline uint64_t roundup64(uint64_t val, uint64_t round)
{
    return ((val + round - 1) / round * round);
}

static inline uint64_t roundup_pow_of_2(uint64_t val)
{
    if (!val || !(val & (val - 1)))
        return val;

    return ((uint64_t)1 << (fls64(val) + 1));
}

static inline uint64_t page_off(uint64_t addr)
{
    uint64_t            page_off_mask = (uint64_t)(page_size - 1);

    return (addr & page_off_mask);
}

static inline uint64_t page_down(uint64_t addr)
{
    uint64_t            page_mask = ~(uint64_t)(page_size - 1);

    return (addr & page_mask);
}

static inline uint64_t page_up(uint64_t addr)
{
    uint64_t            page_mask = ~(uint64_t)(page_size - 1);

    return (((addr + page_size - 1) & page_mask));
}

struct zhpeu_thr_wait {
    int32_t             state;
    pthread_mutex_t     mutex;
    pthread_cond_t      cond;
} CACHE_ALIGNED;

#define MS_PER_SEC      (1000UL)
#define US_PER_SEC      (1000000UL)
#define NS_PER_SEC      (1000000000UL)

enum {
    ZHPEU_THR_WAIT_IDLE,
    ZHPEU_THR_WAIT_SLEEP,
    ZHPEU_THR_WAIT_SIGNAL,
};

static inline void zhpeu_thr_wait_init(struct zhpeu_thr_wait *thr_wait)
{
    memset(thr_wait, 0, sizeof(*thr_wait));
    mutex_init(&thr_wait->mutex, NULL);
    cond_init(&thr_wait->cond, NULL);
    atm_store_rlx(&thr_wait->state, ZHPEU_THR_WAIT_IDLE);
}

static inline void zhpeu_thr_wait_destroy(struct zhpeu_thr_wait *thr_wait)
{
    mutex_destroy(&thr_wait->mutex);
    cond_destroy(&thr_wait->cond);
}

static inline bool zhpeu_thr_wait_signal_fast(struct zhpeu_thr_wait *thr_wait)
{
    int32_t             old = ZHPEU_THR_WAIT_IDLE;
    int32_t             new = ZHPEU_THR_WAIT_SIGNAL;

    /* One sleeper, many wakers. */
    if (atm_cmpxchg(&thr_wait->state, &old, new) || old == new)
        /* Done! */
        return false;

    /* Need slow path. */
    assert(old == ZHPEU_THR_WAIT_SLEEP);

    return true;
}

static inline void zhpeu_thr_wait_signal_slow(struct zhpeu_thr_wait *thr_wait,
                                              bool lock, bool unlock)
{
    int32_t             old = ZHPEU_THR_WAIT_SLEEP;
    int32_t             new = ZHPEU_THR_WAIT_IDLE;

    /* One sleeper, many wakers. */
    assert(old == ZHPEU_THR_WAIT_SLEEP);

    if (lock)
            mutex_lock(&thr_wait->mutex);
    new = ZHPEU_THR_WAIT_IDLE;
    atm_cmpxchg(&thr_wait->state, &old, new);
    if (unlock)
            mutex_unlock(&thr_wait->mutex);
    cond_broadcast(&thr_wait->cond);
}

static inline void zhpeu_thr_wait_signal(struct zhpeu_thr_wait *thr_wait)
{
    if (zhpeu_thr_wait_signal_fast(thr_wait))
        zhpeu_thr_wait_signal_slow(thr_wait, true, true);
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

static inline int
zhpeu_thr_wait_sleep_slow(struct zhpeu_thr_wait *thr_wait, int64_t timeout_us,
                          bool lock, bool unlock)
{
    int                 ret = 0;
    int32_t             old = ZHPEU_THR_WAIT_SLEEP;
    int32_t             new = ZHPEU_THR_WAIT_IDLE;
    struct timespec     timeout;

    /* One sleeper, many wakers. */
    if (lock)
        mutex_lock(&thr_wait->mutex);
    if (timeout_us < 0) {
        while (atm_load_rlx(&thr_wait->state) == old)
            cond_wait(&thr_wait->cond, &thr_wait->mutex);
    } else {
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_nsec += timeout_us * US_PER_SEC;
        if (timeout.tv_nsec >= NS_PER_SEC) {
            timeout.tv_sec += timeout.tv_nsec / NS_PER_SEC;
            timeout.tv_nsec = timeout.tv_nsec % NS_PER_SEC;
        }
        while (atm_load_rlx(&thr_wait->state) == old) {
            ret = cond_timedwait(&thr_wait->cond, &thr_wait->mutex, &timeout);
            if (ret < 0) {
                atm_cmpxchg(&thr_wait->state, &old, new);
                break;
            }
        }
    }
    if (unlock)
        mutex_unlock(&thr_wait->mutex);

    return ret;
}

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

static inline void zhpeu_work_head_init(struct zhpeu_work_head *head)
{
    zhpeu_thr_wait_init(&head->thr_wait);
    STAILQ_INIT(&head->work_list);
}

static inline void zhpeu_work_head_destroy(struct zhpeu_work_head *head)
{
    zhpeu_thr_wait_destroy(&head->thr_wait);
}

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
    if (signal && zhpeu_thr_wait_signal_fast(&head->thr_wait))
        zhpeu_thr_wait_signal_slow(&head->thr_wait, false, unlock);
    else if (unlock)
        mutex_unlock(&head->thr_wait.mutex);
}

bool zhpeu_work_process(struct zhpeu_work_head *head, bool lock, bool unlock);

_EXTERN_C_END

#endif /* _ZHPEQ_UTIL_H_ */
