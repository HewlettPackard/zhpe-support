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

#ifndef _ZHPEQ_H_
#define _ZHPEQ_H_

#ifndef __KERNEL__

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#endif

/* Do extern "C" without goofing up emacs. */
#ifndef _EXTERN_C_BEG
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

struct zhpeq_timing_timer {
    const char          *name;
    volatile uint64_t   time;
    volatile uint64_t   min;
    volatile uint64_t   max;
    volatile uint64_t   count;
    volatile uint64_t   cpu_change;
};

struct zhpeq_timing_counter {
    const char          *name;
    volatile uint64_t   count;
};

struct zhpeq_timing_stamp {
    uint64_t            time;
    uint32_t		cpu;
} __attribute__ ((packed));

#ifndef __KERNEL__

extern struct zhpeq_timing_stamp zhpeq_timing_tx_start_stamp;
extern struct zhpeq_timing_stamp zhpeq_timing_tx_ibv_post_send_stamp;

static inline void zhpeq_timing_update_stamp(struct zhpeq_timing_stamp *stamp)
{
    uint32_t		lo;
    uint32_t		hi;
    uint32_t		cpu;

    asm volatile("rdtscp" : "=a" (lo), "=d" (hi), "=c" (cpu) : :);

    stamp->time = ((uint64_t)hi << 32 | lo);
    stamp->cpu = cpu;
}

static inline void
zhpeq_timing_update_count(struct zhpeq_timing_counter *counter)
{
    (void)__sync_fetch_and_add(&counter->count, 1);
}

#define ZHPEQ_TIMING_UPDATE_NEW_TIME   (1)
#define ZHPEQ_TIMING_UPDATE_OLD_CPU    (2)

static inline void
zhpeq_timing_update(struct zhpeq_timing_timer *timer,
                    struct zhpeq_timing_stamp *new,
                    struct zhpeq_timing_stamp *old, uint flags)
{
    int64_t             delta;
    uint64_t            oldv;
    uint64_t            newv;
    struct zhpeq_timing_stamp now;

    if (!old->time)
        return;
    if (!new) {
        zhpeq_timing_update_stamp(&now);
        new = &now;
    }
    delta = new->time - old->time;
    if (delta < 0)
        return;
    if (flags & ZHPEQ_TIMING_UPDATE_NEW_TIME)
        new->time = old->time;
    (void)__sync_fetch_and_add(&timer->time, delta);
    (void)__sync_fetch_and_add(&timer->count, 1);
    for (oldv = timer->min; delta < oldv; ) {
        newv = __sync_val_compare_and_swap(&timer->min, oldv, delta);
        if (newv == oldv)
            break;
        oldv = newv;
    }
    for (oldv = timer->max; delta > oldv; ) {
        newv = __sync_val_compare_and_swap(&timer->max, oldv, delta);
        if (newv == oldv)
            break;
        oldv = newv;
    }
    if (new->cpu != old->cpu) {
        __sync_fetch_and_add(&timer->cpu_change, 1);
        if (flags & ZHPEQ_TIMING_UPDATE_OLD_CPU)
            old->cpu = new->cpu;
    }
}

void zhpeq_timing_reset_timer(struct zhpeq_timing_timer *timer);
void zhpeq_timing_reset_counter(struct zhpeq_timing_counter *counter);
void *zhpeq_timing_reset_all(void);
void zhpeq_timing_print_timer(struct zhpeq_timing_timer *timer);
void zhpeq_timing_print_counter(struct zhpeq_timing_counter *counter);
void zhpeq_timing_print_all(void *saved);

#endif /* __KERNEL__ */

#ifdef ZHPEQ_TIMING

#define ZHPEQ_TIMING_TIMERS(_op)                \
    _op(tx_start)                               \
    _op(tx_commit)                              \
    _op(tx_cmdnew)                              \
    _op(tx_cmdpost)                             \
    _op(tx_cmddone)                             \
    _op(tx_cqread)                              \
    _op(rx_recv)                                \
    _op(rx_recv_done)                           \
    _op(ibv_reg_mr)                             \
    _op(ibv_dereg_mr)

#define ZHPEQ_TIMING_COUNTERS(_op)              \
    _op(tx_sleep)                               \
    _op(rx_sleep)                               \
    _op(rx_buffered)                            \
    _op(rx_multi)

#define ZHPEQ_TIMING_TIMER_EXTERN(_name)        \
    extern struct zhpeq_timing_timer zhpeq_timing_ ## _name;

#define ZHPEQ_TIMING_COUNTER_EXTERN(_name)      \
    extern struct zhpeq_timing_counter zhpeq_timing_ ## _name;

ZHPEQ_TIMING_TIMERS(ZHPEQ_TIMING_TIMER_EXTERN)
ZHPEQ_TIMING_COUNTERS(ZHPEQ_TIMING_COUNTER_EXTERN)

#define ZHPEQ_TIMING_TIMER_DECLARE(_name)       \
    struct zhpeq_timing_timer    zhpeq_timing_ ## _name = { # _name };

#define ZHPEQ_TIMING_COUNTER_DECLARE(_name)     \
    struct zhpeq_timing_counter  zhpeq_timing_ ## _name = { # _name };

#define ZHPEQ_TIMING_TABLE_ENTRY(_name)         \
    &zhpeq_timing_ ## _name,

#define ZHPEQ_TIMING_UPDATE_STAMP(_p)           \
    zhpeq_timing_update_stamp(_p)
#define ZHPEQ_TIMING_UPDATE_COUNT(_p)           \
    zhpeq_timing_update_count(_p)
#define ZHPEQ_TIMING_UPDATE(_t, _n, _o, _f)     \
    zhpeq_timing_update(_t, _n, _o, _f)

#define ZHPEQ_TIMING_DECLARATION(_c)   _c
#define ZHPEQ_TIMING_CODE(_c)   _c

#define ibv_reg_mr(_pd, _addr, _length, _access)                \
({                                                              \
    struct ibv_mr       *__ret_mr;                              \
    struct zhpeq_timing_stamp __start;                          \
                                                                \
    zhpeq_timing_update_stamp(&__start);                        \
    __ret_mr =  ibv_reg_mr(_pd, _addr, _length, _access);       \
    zhpeq_timing_update(&zhpeq_timing_ibv_reg_mr,               \
                        NULL, &__start, 0);                     \
    __ret_mr;                                                   \
})

#define ibv_dereg_mr(_mr)                                       \
({                                                              \
    int                 __ret;                                  \
    struct zhpeq_timing_stamp __start;                          \
                                                                \
    zhpeq_timing_update_stamp(&__start);                        \
    __ret =  ibv_dereg_mr(_mr);                                 \
    zhpeq_timing_update(&zhpeq_timing_ibv_dereg_mr,             \
                        NULL, &__start, 0);                     \
    __ret;                                                      \
})

#define ibv_post_send(_qp, _wr, _bad_wr)                        \
({                                                              \
    zhpeq_timing_update(&zhpeq_timing_tx_cmdpost, NULL,         \
                        &zhpeq_timing_tx_ibv_post_send_stamp,   \
                        0);                                     \
    ibv_post_send(_qp, _wr, _bad_wr);                           \
})

#else

#define ZHPEQ_TIMING_TIMERS(_op)
#define ZHPEQ_TIMING_COUNTERS(_op)
#define ZHPEQ_TIMING_TIMER_EXTERN(_name)
#define ZHPEQ_TIMING_COUNTER_EXTERN(_name)
#define ZHPEQ_TIMING_TIMER_DECLARE(_name)
#define ZHPEQ_TIMING_COUNTER_DECLARE(_name)
#define ZHPEQ_TIMING_TABLE_ENTRY(_name)
#define ZHPEQ_TIMING_UPDATE_STAMP(_p) do {} while (0)
#define ZHPEQ_TIMING_UPDATE_COUNT(_p) do {} while (0)
#define ZHPEQ_TIMING_UPDATE(_t, _n, _o, _f ) do {} while (0)
#define ZHPEQ_TIMING_CODE(_c)

#endif /* ZHPEQ_TIMING */

#define ZHPEQ_API_VERSION       (1)

#define ZHPEQ_IMM_MAX           (32)
#define ZHPEQ_ENQA_MAX          (52)

#define ZHPEQ_MR_GET            ((uint32_t)1 << 0)
#define ZHPEQ_MR_PUT            ((uint32_t)1 << 1)
#define ZHPEQ_MR_SEND           ZHPEQ_MR_PUT
#define ZHPEQ_MR_RECV           ZHPEQ_MR_GET
#define ZHPEQ_MR_GET_REMOTE     ((uint32_t)1 << 2)
#define ZHPEQ_MR_PUT_REMOTE     ((uint32_t)1 << 3)
#define ZHPEQ_MR_KEY_ONESHOT    ((uint32_t)1 << 7)
#define ZHPEQ_MR_KEY_VALID      ((uint32_t)1 << 31)

enum zhpeq_atomic_type {
    ZHPEQ_ATOMIC_SIZE32         = 0x80,
    ZHPEQ_ATOMIC_SIZE64
};

enum zhpeq_atomic_op {
    ZHPEQ_ATOMIC_SWAP           = 0x01,
    ZHPEQ_ATOMIC_ADD,
    ZHPEQ_ATOMIC_AND,
    ZHPEQ_ATOMIC_OR,
    ZHPEQ_ATOMIC_XOR,
    ZHPEQ_ATOMIC_SMIN,
    ZHPEQ_ATOMIC_SMAX,
    ZHPEQ_ATOMIC_UMIN,
    ZHPEQ_ATOMIC_UMAX,
    ZHPEQ_ATOMIC_CAS,
};

union zhpeq_atomic {
    int32_t             s32;
    int64_t             s64;
    uint32_t            u32;
    uint64_t            u64;
};

enum {
    ZHPEQ_CQ_STATUS_SUCCESS              = 0x00,
    ZHPEQ_CQ_STATUS_CMD_TRUNCATED        = 0x01,
    ZHPEQ_CQ_STATUS_BAD_CMD              = 0x02,
    ZHPEQ_CQ_STATUS_LOCAL_UNRECOVERABLE  = 0x11,
    ZHPEQ_CQ_STATUS_FABRIC_UNRECOVERABLE = 0x21,
    ZHPEQ_CQ_STATUS_FABRIC_NO_RESOURCES  = 0x22,
    ZHPEQ_CQ_STATUS_FABRIC_ACCESS        = 0x23,
};

struct zhpeq_result {
    char                data[ZHPEQ_IMM_MAX];
};

struct zhpeq_cq_entry {
    uint8_t             valid;
    uint8_t             status;
    uint16_t            index;
    uint8_t             filler1[4];
    void                *context;
    struct zhpeq_timing_stamp timestamp;
    uint8_t             filler2[4];
    struct zhpeq_result result;
};

enum zhpeq_backend {
    ZHPEQ_BACKEND_ZHPE = 1,
    ZHPEQ_BACKEND_LIBFABRIC,
    ZHPEQ_BACKEND_MAX,
};

struct zhpeq_backend_libfabric_params {
    enum zhpeq_backend  backend;
    const char          *provider_name;
    const char          *domain_name;
};

union zhpeq_backend_params {
    enum zhpeq_backend  backend;
    struct zhpeq_backend_libfabric_params libfabric;
};

struct zhpeq_attr {
    enum zhpeq_backend  backend;
    uint32_t            max_tx_queues;
    uint32_t            max_rx_queues;
    uint32_t            max_hw_qlen;
    uint32_t            max_sw_qlen;
    uint64_t            max_dma_len;
};

struct zhpeq_key_data {
    uint64_t            vaddr;
    uint64_t            zaddr;
    uint64_t            len;
    uint64_t            key;
    uint8_t             access;
};

/* Forward references to shut the compiler up. */
struct zhpeq;
struct zhpeq_dom;

static inline int zhpeq_rem_key_access(struct zhpeq_key_data *kdata,
                                       uint64_t start, uint64_t len,
                                       uint64_t access, uint64_t *zaddr)
{
    int                 ret = 0;

    if (kdata &&
        start >= kdata->vaddr && start + len <= kdata->vaddr + kdata->len &&
        (access & kdata->access) == access)
        *zaddr = (start - kdata->vaddr) + kdata->zaddr;
    else
        ret = -EINVAL;

    return ret;
}

static inline int zhpeq_lcl_key_access(struct zhpeq_key_data *kdata,
                                       void *buf, uint64_t len,
                                       uint64_t access, uint64_t *zaddr)
{
    return zhpeq_rem_key_access(kdata, (uintptr_t)buf, len, access, zaddr);
}

int zhpeq_register_backend(enum zhpeq_backend backend, void *ops);

int zhpeq_init(int api_version);

int zhpeq_query_attr(struct zhpeq_attr *attr);

int zhpeq_domain_alloc(const union zhpeq_backend_params *params,
                       struct zhpeq_dom **zdom_out);

int zhpeq_domain_free(struct zhpeq_dom *zdom);

int zhpeq_alloc(struct zhpeq_dom *zdom, int qlen, struct zhpeq **zq_out);

int zhpeq_free(struct zhpeq *zq);

int zhpeq_backend_open(struct zhpeq *zq, int sock_fd);

int zhpeq_backend_close(struct zhpeq *zq, int open_idx);

ssize_t zhpeq_cq_read(struct zhpeq *zq, struct zhpeq_cq_entry *entries,
                      size_t n_entries);

int zhpeq_mr_reg(struct zhpeq_dom *zdom, const void *buf, size_t len,
                     uint32_t access, uint64_t requested_key,
                     struct zhpeq_key_data **kdata_out);

int zhpeq_mr_free(struct zhpeq_dom *zdom, struct zhpeq_key_data *kdata);

int zhpeq_zmmu_export(struct zhpeq *zq, const struct zhpeq_key_data *kdata,
                      void **blob_out, size_t *blob_len);

int zhpeq_zmmu_import(struct zhpeq *zq, int open_idx,
                      const void *blob, size_t blob_len,
                      struct zhpeq_key_data **kdata_out);

int zhpeq_zmmu_free(struct zhpeq *zq, struct zhpeq_key_data *kdata);

int64_t zhpeq_reserve(struct zhpeq *zq, uint32_t n_entries);

int zhpeq_commit(struct zhpeq *zq, uint32_t qindex, uint32_t n_entries);

int zhpeq_check_stopped(struct zhpeq *zq);

int zhpeq_restart(struct zhpeq *zq, uint32_t head_idx, uint32_t tail_idx);

int zhpeq_put(struct zhpeq *zq, uint32_t qindex, bool fence,
              uint64_t local_addr, size_t len, uint64_t remote_addr,
              void *context);

int zhpeq_puti(struct zhpeq *zq, uint32_t qindex, bool fence,
               const void *buf, size_t len, uint64_t remote_addr,
               void *context);

int zhpeq_get(struct zhpeq *zq, uint32_t qindex, bool fence,
              uint64_t local_addr, size_t len, uint64_t remote_addr,
              void *context);

int zhpeq_geti(struct zhpeq *zq, uint32_t qindex, bool fence,
               uint64_t remote_addr, size_t len, void *context);

int zhpeq_nop(struct zhpeq *zq, uint32_t qindex, bool fence,
              void *context);

int zhpeq_atomic(struct zhpeq *zq, uint32_t qindex, bool fence, bool retval,
                 enum zhpeq_atomic_type datatype, enum zhpeq_atomic_op op,
                 uint64_t remote_addr, const union zhpeq_atomic *operands,
                 void *context);

void zhpeq_print_info(struct zhpeq *zq);

int zhpeq_active(struct zhpeq *zq);

_EXTERN_C_END

#ifdef _EXTERN_C_SET
#undef _EXTERN_C_SET
#undef _EXTERN_C_BEGIN
#undef _EXTERN_C_END
#endif

#endif /* _ZHPEQ_H_ */
