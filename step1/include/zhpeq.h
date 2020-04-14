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

#ifndef _ZHPEQ_H_
#define _ZHPEQ_H_

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/epoll.h>

#include <zhpeq_util.h>

#include <zhpe_uapi.h>

_EXTERN_C_BEG

#define ZHPEQ_API_VERSION       (1)

#define __IMPORT(_x)            ZHPEQ_##_x = ZHPE_##_x

enum {
    __IMPORT(MR_GET),
    __IMPORT(MR_PUT),
    __IMPORT(MR_GET_REMOTE),
    __IMPORT(MR_PUT_REMOTE),
    __IMPORT(MR_SEND),
    __IMPORT(MR_RECV),
    __IMPORT(MR_FLAG0),
    __IMPORT(MR_FLAG1),
    __IMPORT(MR_FLAG2),
    __IMPORT(MR_REQ_CPU),
    __IMPORT(MR_REQ_CPU_CACHE),
    __IMPORT(MR_REQ_CPU_WB),
    __IMPORT(MR_REQ_CPU_WC),
    __IMPORT(MR_REQ_CPU_WT),
    __IMPORT(MR_REQ_CPU_UC),
};

#undef __IMPORT

enum zhpeq_atomic_size {
    ZHPEQ_ATOMIC_SIZE_NONE      = ZHPE_HW_ATOMIC_RETURN,
    ZHPEQ_ATOMIC_SIZE32         = (ZHPE_HW_ATOMIC_SIZE_32 |
                                   ZHPE_HW_ATOMIC_RETURN),
    ZHPEQ_ATOMIC_SIZE64         = (ZHPE_HW_ATOMIC_SIZE_64 |
                                   ZHPE_HW_ATOMIC_RETURN),
};

#define __IMPORT(_x)            ZHPEQ_ATOMIC_##_x = ZHPE_HW_OPCODE_ATM_##_x

enum zhpeq_atomic_op {
    ZHPEQ_ATOMIC_NONE           = ZHPE_HW_OPCODE_NOP,
    __IMPORT(SWAP),
    __IMPORT(ADD),
    __IMPORT(AND),
    __IMPORT(OR),
    __IMPORT(XOR),
    __IMPORT(SMIN),
    __IMPORT(SMAX),
    __IMPORT(UMIN),
    __IMPORT(UMAX),
    __IMPORT(CAS),
};

#undef __IMPORT

#define	ZHPEQ_HOSTS_FILE	"/etc/hosts.zhpeq"
#define	ZHPEQ_HOSTS_ENV         "ZHPEQ_HOSTS"

enum zhpeq_backend {
    ZHPEQ_BACKEND_NONE,
    ZHPEQ_BACKEND_ZHPE,
    ZHPEQ_BACKEND_LIBFABRIC,
    ZHPEQ_BACKEND_MAX,
};

enum {
    ZHPEQ_PRIO_LO               = ZHPE_PRIO_LO,
    ZHPEQ_PRIO_HI               = ZHPE_PRIO_HI,
    ZHPEQ_MAX_PRIO              = ZHPE_MAX_PRIO,
    ZHPEQ_MAX_TC                = ZHPE_MAX_TC,
    ZHPEQ_MAX_IMM               = ZHPE_MAX_IMM,
    ZHPEQ_MAX_KEY_BLOB          = 32,
};

struct zhpeq_attr {
    enum zhpeq_backend  backend;
    struct zhpe_attr    z;
};

struct zhpeq_key_data {
    struct zhpe_key_data z;
    struct zhpeq_dom    *zqdom;
    void                *cache_entry;
#ifdef NOT_YET
    /* ZZZ: registration thread. */
    void                (*ready)(struct zhpeq_key_data *qkdata,
                                 void *ready_data);
    void                *ready_data;
#endif
};

/* Public portions of structures. */
struct zhpeq_mmap_desc {
    struct zhpeq_key_data *qkdata;
    void                *addr;
};

struct zhpeq_dom {
    void                *dummy;
};

struct zhpeq_rq_epoll {
    void                *dummy;
};

#define ZHPEQ_BITMAP_BITS       (64U)
#define ZHPEQ_BITMAP_SHIFT      (6U)

struct zhpeq_tq;

typedef void (*zhpeq_tq_entry_insert_fn)(struct zhpeq_tq *ztq,
                                         uint16_t reservation16);

extern zhpeq_tq_entry_insert_fn zhpeq_insert_fn[];

enum {
    ZHPEQ_INSERT_CMD    = 0,
    ZHPEQ_INSERT_MEM,
    ZHPEQ_INSERT_NONE,
    ZHPEQ_INSERT_LEN,
    ZHPEQ_INSERT_SHIFT  = 16,
};

struct zhpeq_tq {
    struct zhpeq_dom    *zqdom;
    struct zhpe_xqinfo  tqinfo;
    void                *qcm;
    union zhpe_hw_wq_entry *cmd;
    union zhpe_hw_wq_entry *wq;
    union zhpe_hw_cq_entry *cq;
    uint64_t            *free_bitmap;
    void                **ctx;
    union zhpe_hw_wq_entry *mem;
    uint32_t            wq_tail;
    uint32_t            wq_tail_commit;
    uint32_t            cq_head;
    uint32_t            cmd_queued;
};

#define ZHPEQ_TQ_RESERVATION_MASK ((1U << ZHPEQ_INSERT_SHIFT) - 1)

struct zhpeq_rq {
    struct zhpeq_dom    *zqdom;
    struct zhpe_rqinfo  rqinfo;
    volatile void       *qcm;
    union zhpe_hw_rdm_entry *rq;
    int64_t             epoll_threshold_cycles;
    uint64_t            rx_last_time;
    uint32_t            rx_last_head;
    uint32_t            head;
    uint32_t            head_commit;
};

struct zhpeq_rx_oos {
    struct zhpeq_rx_oos *next;
    uint64_t            valid_bits;
    uint32_t            base_off;
    struct zhpe_enqa_payload msgs[64];
};

struct zhpeq_rx_seq {
    struct zhpeq_rx_oos *rx_oos_list;
    struct zhpeq_rx_oos *(*alloc)(struct zhpeq_rx_seq *zseq);
    void                (*free)(struct zhpeq_rx_seq *zseq,
                                struct zhpeq_rx_oos *rx_oos);
    uint64_t            rx_oos_cnt;
    uint32_t            rx_oos_base_seq;
    uint32_t            rx_oos_max;
    uint32_t            seq;
};

static inline int zhpeq_rem_key_access(const struct zhpeq_key_data *qkdata,
                                       uint64_t start, uint64_t len,
                                       uint32_t qaccess, uint64_t *zaddr)
{
    const struct zhpe_key_data *kdata = &qkdata->z;

    if (unlikely((qaccess & kdata->access) != qaccess || start < kdata->vaddr ||
                 start + len > kdata->vaddr + kdata->len))
        return -EINVAL;
    *zaddr = (start - kdata->vaddr) + kdata->zaddr;

    return 0;
}

static inline int zhpeq_lcl_key_access(const struct zhpeq_key_data *qkdata,
                                       const void *buf, uint64_t len,
                                       uint32_t qaccess)
{
    uintptr_t           start = (uintptr_t)buf;
    const struct zhpe_key_data *kdata = &qkdata->z;

    if (unlikely((qaccess & kdata->access) != qaccess || start < kdata->vaddr ||
                 start + len > kdata->vaddr + kdata->len))
        return -EINVAL;

    return 0;
}

int zhpeq_init(int api_version, struct zhpeq_attr *attr);

int zhpeq_query_attr(struct zhpeq_attr *attr);

int zhpeq_domain_alloc(struct zhpeq_dom **zqdom_out);

int zhpeq_domain_free(struct zhpeq_dom *zqdom);

int zhpeq_domain_insert_addr(struct zhpeq_dom *zqdom, void *sa,
                             void **addr_cookie);

int zhpeq_domain_remove_addr(struct zhpeq_dom *zqdom, void *addr_cookie);

int zhpeq_tq_alloc(struct zhpeq_dom *zqdom, int cmd_qlen, int cmp_qlen,
                   int traffic_class, int priority, int slice_mask,
                   struct zhpeq_tq **ztq_out);

int zhpeq_tq_free(struct zhpeq_tq *ztq);

static inline uint64_t ioread64(const volatile void *addr)
{
    return le64toh(*(const volatile uint64_t *)addr);
}

static inline void iowrite64(uint64_t value, volatile void *addr)
{
    *(volatile uint64_t *)addr = htole64(value);
}

static inline uint64_t qcmread64(const volatile void *qcm, size_t off)
{
    return ioread64((char *)qcm + off);
}

static inline void qcmwrite64(uint64_t value, volatile void *qcm, size_t off)
{
    iowrite64(value, (char *)qcm + off);
}

#define ZHPEQ_TQ_RESERVE_CMD_OK         (~(uint64_t)0)
#define ZHPEQ_TQ_RESERVE_MEM_ONLY                                       \
    (~(uint64_t)((1UL << ZHPE_XDM_QCM_CMD_BUF_COUNT) - 1))

int32_t zhpeq_tq_reserve_type(struct zhpeq_tq *ztq, uint64_t type_mask);

static inline int32_t zhpeq_tq_reserve(struct zhpeq_tq *ztq)
{
    /*
     * Fence operations only work on memory queue ops, so call
     * zhpeq_tq_reserve_type(ztq, ZHPEQ_TQ_RESERVE_MEM_ONLY) when using hardware
     * fence.
     */
    return zhpeq_tq_reserve_type(ztq, ZHPEQ_TQ_RESERVE_CMD_OK);
}

static inline void zhpeq_tq_unreserve(struct zhpeq_tq *ztq, uint16_t index)
{
    barrier();
    ztq->free_bitmap[index >> ZHPEQ_BITMAP_SHIFT] |=
        ((uint64_t)1 << (index & (ZHPEQ_BITMAP_BITS - 1)));
}

void zhpeq_tq_commit(struct zhpeq_tq *ztq);

static inline void zhpeq_tq_insert(struct zhpeq_tq *ztq, int32_t reservation)
{
    zhpeq_insert_fn[reservation >> ZHPEQ_INSERT_SHIFT](ztq, reservation);
}

static inline void zhpeq_tq_set_context(struct zhpeq_tq *ztq,
                                        int32_t reservation, void *context)
{
    ztq->ctx[(uint16_t)reservation] = context;
}

static inline union zhpe_hw_wq_entry *zhpeq_tq_get_wqe(struct zhpeq_tq *ztq,
                                                       int32_t reservation)
{
    return &ztq->mem[(uint16_t)reservation];
}

static inline void zhpeq_tq_nop(union zhpe_hw_wq_entry *wqe,
                                uint16_t op_flags)
{
    wqe->hdr.opcode = ZHPE_HW_OPCODE_NOP | op_flags;
}

static inline void zhpeq_tq_sync(union zhpe_hw_wq_entry *wqe,
                                 uint16_t op_flags)
{
    wqe->hdr.opcode = ZHPE_HW_OPCODE_SYNC | ZHPE_HW_OPCODE_FENCE | op_flags;
}

static inline void zhpeq_tq_rw(union zhpe_hw_wq_entry *wqe,
                               uint16_t opcode, uint64_t rd_addr, size_t len,
                               uint64_t wr_addr)
{
    wqe->hdr.opcode = opcode;
    wqe->dma.len = len;
    wqe->dma.rd_addr = rd_addr;
    wqe->dma.wr_addr = wr_addr;
}

static inline void zhpeq_tq_put(union zhpe_hw_wq_entry *wqe,
                                uint16_t op_flags, uint64_t lcl_addr,
                                size_t len, uint64_t rem_addr)
{
    zhpeq_tq_rw(wqe, (ZHPE_HW_OPCODE_PUT | op_flags), lcl_addr, len, rem_addr);
}

static inline void *zhpeq_tq_puti(union zhpe_hw_wq_entry *wqe,
                                  uint16_t op_flags, size_t len,
                                  uint64_t rem_addr)
{
    wqe->hdr.opcode = ZHPE_HW_OPCODE_PUTIMM | op_flags;
    wqe->imm.len = len;
    wqe->imm.rem_addr = rem_addr;

    return wqe->imm.data;
}

static inline void zhpeq_tq_get(union zhpe_hw_wq_entry *wqe,
                                uint16_t op_flags, uint64_t lcl_addr,
                                size_t len, uint64_t rem_addr)
{
    zhpeq_tq_rw(wqe, (ZHPE_HW_OPCODE_GET | op_flags), rem_addr, len, lcl_addr);
}

static inline void zhpeq_tq_geti(union zhpe_hw_wq_entry *wqe,
                                 uint16_t op_flags, size_t len,
                                 uint64_t rem_addr)
{
    wqe->hdr.opcode = ZHPE_HW_OPCODE_GETIMM | op_flags;
    wqe->imm.len = len;
    wqe->imm.rem_addr = rem_addr;
}

static inline void *
zhpeq_tq_enqa(union zhpe_hw_wq_entry *wqe, uint16_t op_flags,
              uint32_t dgcid, uint32_t rspctxid)
{
    wqe->hdr.opcode = ZHPE_HW_OPCODE_ENQA | op_flags;
    wqe->enqa.dgcid = dgcid;
    wqe->enqa.rspctxid = rspctxid;

    return &wqe->enqa.payload;
}

static inline struct zhpe_hw_wq_atomic *
zhpeq_tq_atomic(union zhpe_hw_wq_entry *wqe,
                uint16_t op_flags, enum zhpeq_atomic_size datasize,
                enum zhpeq_atomic_op op, uint64_t rem_addr)
{
    wqe->hdr.opcode = op | op_flags;
    wqe->atm.rem_addr = rem_addr;
    wqe->atm.size = datasize;

    return &wqe->atm;
}

int zhpeq_tq_restart(struct zhpeq_tq *ztq);

static inline void *zhpeq_q_entry(void *entries, uint32_t qindex,
                                  uint32_t qmask)
{
    return VPTR(entries, ZHPE_HW_ENTRY_LEN * (qindex & qmask));
}

static inline bool zhpeq_cmp_valid(volatile void *qent, uint32_t qindex,
                                   uint32_t qmask)
{
    uint                valid = atm_load_rlx((uint8_t *)qent);
    uint                shift = fls32(qmask);

    return ((valid ^ (qindex >> shift)) & ZHPE_CMP_ENT_VALID_MASK);
}

static inline struct zhpe_cq_entry *zhpeq_tq_cq_entry(struct zhpeq_tq *ztq)
{
    uint32_t            qmask = ztq->tqinfo.cmplq.ent - 1;
    uint32_t            qindex = ztq->cq_head;
    struct zhpe_cq_entry *cqe = zhpeq_q_entry(ztq->cq, qindex, qmask);

    /* likely() to optimize the success case. */
    if (likely(zhpeq_cmp_valid(cqe, qindex, qmask)))
        return cqe;

    return NULL;
}

static inline void *zhpeq_tq_cq_context(struct zhpeq_tq *ztq,
                                        struct zhpe_cq_entry *cqe)
{
    return ztq->ctx[cqe->index];
}

static inline void zhpeq_tq_cq_entry_done(struct zhpeq_tq *ztq,
                                          struct zhpe_cq_entry *cqe)
{
    /*
     * Simple rule: do not access the cqe or the backup copy of the
     * XDM command after this call.
     */
    zhpeq_tq_unreserve(ztq, cqe->index);
    ztq->cq_head++;
}

int zhpeq_rq_free(struct zhpeq_rq *zrq);

int zhpeq_rq_alloc(struct zhpeq_dom *zqdom, int rx_qlen, int slice_mask,
                   struct zhpeq_rq **zrq_out);

int zhpeq_rq_alloc_specific(struct zhpeq_dom *zqdom, int rx_qlen,
                            int qspecific, struct zhpeq_rq **zrq_out);

static inline void __zhpeq_rq_head_update(struct zhpeq_rq *zrq, uint32_t qhead,
                                          bool check)
{
    uint32_t            qmask = zrq->rqinfo.cmplq.ent - 1;

    if (check && zrq->head_commit == qhead)
        return;
    zrq->head_commit = qhead;
    qcmwrite64(qhead & qmask, zrq->qcm, ZHPE_RDM_QCM_RCV_QUEUE_HEAD_OFFSET);
}

static inline void zhpeq_rq_head_update(struct zhpeq_rq *zrq,
                                        uint32_t threshold)
{
    if (!threshold)
        threshold = zrq->rqinfo.cmplq.ent / 4;
    if (unlikely(zrq->head - zrq->head_commit > threshold)) {
        /*
         * Update qcm head: try to manage unnecessary interrupts by
         * keeping head 1 behind.
         */
        __zhpeq_rq_head_update(zrq, zrq->head - 1, false);
    }
}

static inline struct zhpe_rdm_entry *zhpeq_rq_entry(struct zhpeq_rq *zrq)
{
    uint32_t            qmask = zrq->rqinfo.cmplq.ent - 1;
    uint32_t            qindex = zrq->head;
    struct zhpe_rdm_entry *rqe = zhpeq_q_entry(zrq->rq, qindex, qmask);

    /* May not actually be likely, but we want to optimize success. */
    if (likely(zhpeq_cmp_valid(rqe, qindex, qmask)))
        return rqe;

    return NULL;
}

static inline void zhpeq_rq_entry_done(struct zhpeq_rq *zrq,
                                       struct zhpe_rdm_entry *rqe)
{
    uint32_t            new;

    /* Simple rule: do not access the rqe after this call. */
    barrier();
    new = zrq->head + 1;
    /* Not concerned about order, but are about read/write tearing. */
    atm_store_rlx(&zrq->head, new);
}

int zhpeq_rq_epoll_alloc(struct zhpeq_rq_epoll **zepoll_out);

int zhpeq_rq_epoll_free(struct zhpeq_rq_epoll *zepoll);

int zhpeq_rq_epoll_add(struct zhpeq_rq_epoll *zepoll, struct zhpeq_rq *zrq,
                       void (*epoll_handler)(struct zhpeq_rq *zrq,
                                             void *epoll_handler_data),
                       void *epoll_handler_data, uint32_t epoll_threshold_us,
                       bool disabled);

int zhpeq_rq_epoll_del(struct zhpeq_rq *zrq);

int zhpeq_rq_epoll(struct zhpeq_rq_epoll *zepoll,
                   int timeout_ms, const sigset_t *sigmask, bool entr_ok);

int zhpeq_rq_epoll_signal(struct zhpeq_rq_epoll *zepoll);

bool zhpeq_rq_epoll_enable(struct zhpeq_rq *zrq);

static inline bool zhpeq_rq_epoll_check(struct zhpeq_rq *zrq, uint64_t now)
{
    uint32_t            qhead;

    /*
     * Racy, lock-free, lightweight check to see of see should try to enable
     * epoll. Not perfect, doesn't have to be. It is assumed that zrq->head
     * may be updated in another thread, but rx_last_xxx will only be done in
     * this thread.
     *
     * Usage:
     * now = get_cycles_approx();
     * epoll_enabled = false;
     * if (unlikely(zhpeq_rq_epoll_check(zrq, now))) {
     *     lock(); // Locking needed if there are other threads.
     *     epoll_enabled = zhpeq_rq_epoll_enable(zrq);
     *     unlock();
     * }
     * If epoll_enabled is true at this point, it should be safe to rely on
     * epoll, if not, then continue using zhpeq_rq_entry(). Note that
     * spurious epoll_events are possible, especially after
     * zhpeq_rq_epoll_enable() is called.
     */
    qhead = atm_load_rlx(&zrq->head);
    if (likely(qhead != zrq->rx_last_head)) {
        zrq->rx_last_head = qhead;
        zrq->rx_last_time = now;

        return false;
    }

    return ((int64_t)(now - zrq->rx_last_time) > zrq->epoll_threshold_cycles);
}

int zhpeq_rq_get_addr(struct zhpeq_rq *zrq, void *sa, size_t *sa_len);

int zhpeq_rq_xchg_addr(struct zhpeq_rq *zrq, int sock_fd,
                       void *sa, size_t *sa_len);

int zhpeq_rx_oos_insert(struct zhpeq_rx_seq *zseq, void *msg, uint32_t seen);

bool zhpeq_rx_oos_spill(struct zhpeq_rx_seq *zseq, uint32_t msgs,
                        void (*handler)(void *handler_data,
                                        struct zhpe_enqa_payload *msg),
                        void *handler_data);

#ifdef NDEBUG

static inline
void zhpeq_rx_oos_log(const char *func, uint line,
                      uint64_t v0, uint64_t v1, uint64_t v2, uint64_t v3,
                      uint64_t v4)
{
}

#else

void zhpeq_rx_oos_log(const char *func, uint line,
                      uint64_t v0, uint64_t v1, uint64_t v2, uint64_t v3,
                      uint64_t v4);

#endif

int zhpeq_mr_reg(struct zhpeq_dom *zqdom, const void *buf, size_t len,
                 uint32_t access, struct zhpeq_key_data **qkdata_out);

int zhpeq_qkdata_free(struct zhpeq_key_data *qkdata);

int zhpeq_qkdata_export(const struct zhpeq_key_data *qkdata, uint32_t qaccmask,
                        void *blob, size_t *blob_len);

int zhpeq_qkdata_import(struct zhpeq_dom *zqdom, void *addr_cookie,
                        const void *blob, size_t blob_len,
                        struct zhpeq_key_data **qkdata_out);

int zhpeq_fam_qkdata(struct zhpeq_dom *zqdom, void *addr_cookie,
                     struct zhpeq_key_data **qkdata_out, size_t *n_qkdata);

int zhpeq_zmmu_reg(struct zhpeq_key_data *qkdata);

int zhpeq_mmap(const struct zhpeq_key_data *qkdata,
               uint32_t cache_mode, void *addr, size_t length, int prot,
               int flags, off_t offset, struct zhpeq_mmap_desc **zmdesc);

int zhpeq_mmap_unmap(struct zhpeq_mmap_desc *zmdesc);

int zhpeq_mmap_commit(struct zhpeq_mmap_desc *zmdesc,
                      const void *addr, size_t length, bool fence,
                      bool invalidate, bool wait);

static inline bool zhpeq_is_asic(void)
{
    return true;
}

int zhpeq_get_zaddr(const char *node, const char *service,
                    bool source, struct sockaddr_zhpe *sz);

/* Info/debugging */

void zhpeq_print_tq_info(struct zhpeq_tq *ztq);

void zhpeq_print_qkdata(const char *func, uint line,
                        const struct zhpeq_key_data *qkdata);

void zhpeq_print_tq_qcm(const char *func, uint line,
                        const struct zhpeq_tq *ztq);

void zhpeq_print_tq_wq(struct zhpeq_tq *ztq, int cnt);

void zhpeq_print_tq_cq(struct zhpeq_tq *ztq, int cnt);

void zhpeq_print_rq_qcm(const char *func, uint line,
                        const struct zhpeq_rq *zrq);

_EXTERN_C_END

#endif /* _ZHPEQ_H_ */
