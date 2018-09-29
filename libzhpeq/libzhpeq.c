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

#include <internal.h>

#include <dlfcn.h>
#include <limits.h>

/* Set to 1 to dump qkdata when registered/exported/imported/freed. */
#define QKDATA_DUMP     (0)

#define LIBNAME         "libzhpeq"
#define BACKNAME        "libzhpeq_backend.so"

static pthread_mutex_t  init_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct backend_ops *b_ops;
static struct zhpeq_attr b_attr;

uuid_t                  zhpeq_uuid;

ZHPEQ_TIMING_TIMERS(ZHPEQ_TIMING_TIMER_DECLARE)
ZHPEQ_TIMING_COUNTERS(ZHPEQ_TIMING_COUNTER_DECLARE)

static struct zhpeq_timing_timer *timer_table[] = {
    ZHPEQ_TIMING_TIMERS(ZHPEQ_TIMING_TABLE_ENTRY)
    NULL
};

static struct zhpeq_timing_counter *counter_table[] = {
    ZHPEQ_TIMING_COUNTERS(ZHPEQ_TIMING_TABLE_ENTRY)
    NULL
};

struct zhpe_timing_stamp zhpeq_timing_tx_start_stamp;
struct zhpe_timing_stamp zhpeq_timing_tx_ibv_post_send_stamp;

void zhpeq_timing_reset_timer(struct zhpeq_timing_timer *timer)
{
    timer->time = 0;
    timer->min = UINT64_MAX;
    timer->max = 0;
    timer->count = 0;
    timer->cpu_change = 0;
}

void zhpeq_timing_reset_counter(struct zhpeq_timing_counter *counter)
{
    counter->count = 0;
}

void *zhpeq_timing_reset_all(void)
{
    void                *ret = NULL;
    size_t              i;
    size_t              req;
    struct zhpeq_timing_timer *timer;
    struct zhpeq_timing_counter *counter;

    /* This is not atomic. */
    for (i = 0; timer_table[i]; i++);
    req = (i + 1) * sizeof(*timer);
    for (i = 0; counter_table[i]; i++);
    req += (i + 1) * sizeof(*counter);
    ret = malloc(req);
    if (ret) {
        memset(ret, 0, req);
        for (i = 0, timer = ret; timer_table[i]; i++, timer++)
            *timer = *timer_table[i];
        timer++;
        for (i = 0, counter = (void *)timer; counter_table[i]; i++, counter++)
            *counter = *counter_table[i];
    }

    for (i = 0; timer_table[i]; i++)
        zhpeq_timing_reset_timer(timer_table[i]);
    for (i = 0; counter_table[i]; i++)
        zhpeq_timing_reset_counter(counter_table[i]);

    return ret;
}

void zhpeq_timing_print_timer(struct zhpeq_timing_timer *timer)
{
    if (timer->count)
        printf("    %s %.3lf/%.3lf/%.3lf/%Lu/%Lu\n", timer->name,
               cycles_to_usec(timer->time, timer->count),
               cycles_to_usec(timer->min, 1), cycles_to_usec(timer->max, 1),
               (ullong)timer->count, (ullong)timer->cpu_change);
    else
        printf("    %s 0/0/0/0/0\n", timer->name);
}

void zhpeq_timing_print_counter(struct zhpeq_timing_counter *counter)
{
    printf("    %s %Lu\n", counter->name, (ullong)counter->count);
}

void zhpeq_timing_print_all(void *saved)
{
    struct zhpeq_timing_timer *timer;
    struct zhpeq_timing_counter *counter;

    if (!saved)
        return;

    for (timer = saved; timer->name; timer++)
        zhpeq_timing_print_timer(timer);
    timer++;
    for (counter = (void *)timer ; counter->name; counter++)
        zhpeq_timing_print_counter(counter);
}

#ifdef ZHPEQ_TIMING

/* Save timestamp in work-queue-entry memory. */
static inline void zhpeq_timing_reserve(struct zhpeq *zq, uint32_t qindex,
                                        uint32_t n_entries)
{
    uint32_t            i;
    uint32_t            qmask = zq->xqinfo.cmdq.ent - 1;
    struct zhpe_timing_stamp now;
    union zhpe_hw_wq_entry *wqe;

    if (likely(zhpeq_timing_tx_start_stamp.time != 0)) {
        zhpeq_timing_update_stamp(&now);
        now.time = zhpeq_timing_tx_start_stamp.time;
        zhpeq_timing_tx_start_stamp.time = 0;
    } else
        now.time = 0;

    /* Save timestamp in entries. */
    for (i = 0; i < n_entries; i++) {
        wqe = zq->wq + ((qindex + i) & qmask);
        wqe->nop.timestamp = now;
    };
}

/* Move timestamp to safe place when operation formatted. */
static inline void zhpeq_timing_nop(union zhpe_hw_wq_entry *wqe)
{
    /* Nothing to do. */
}

static inline void zhpeq_timing_dma(union zhpe_hw_wq_entry *wqe)
{
    wqe->dma.timestamp = wqe->nop.timestamp;
}

static inline void zhpeq_timing_imm(union zhpe_hw_wq_entry *wqe)
{
    wqe->imm.timestamp = wqe->nop.timestamp;
}

static inline void zhpeq_timing_atm(union zhpe_hw_wq_entry *wqe)
{
    wqe->atm.timestamp = wqe->nop.timestamp;
}

/* Count time from reserve to commit, update timestamp. */
static inline void zhpeq_timing_commit(struct zhpeq *zq, uint32_t qindex,
                                       uint32_t n_entries)
{
    uint32_t            i;
    uint32_t            qmask = zq->xqinfo.cmdq.ent - 1;
    struct zhpe_timing_stamp now;
    struct zhpe_timing_stamp then;
    union zhpe_hw_wq_entry *wqe;

    zhpeq_timing_update_stamp(&now);
    for (i = 0; i < n_entries; i++) {
        wqe = zq->wq + ((qindex + i) & qmask);

        switch (wqe->hdr.opcode & ~ZHPE_HW_OPCODE_FENCE) {

        case ZHPE_HW_OPCODE_NOP:
            then = wqe->nop.timestamp;
            wqe->nop.timestamp.cpu = now.cpu;
            break;

        case ZHPE_HW_OPCODE_PUT:
        case ZHPE_HW_OPCODE_GET:
            then = wqe->dma.timestamp;
            wqe->dma.timestamp.cpu = now.cpu;
            break;

        case ZHPE_HW_OPCODE_PUTIMM:
        case ZHPE_HW_OPCODE_GETIMM:
            then = wqe->imm.timestamp;
            wqe->imm.timestamp.cpu = now.cpu;
            break;

        case ZHPE_HW_OPCODE_ATM_ADD:
        case ZHPE_HW_OPCODE_ATM_CAS:
            then = wqe->atm.timestamp;
            wqe->atm.timestamp.cpu = now.cpu;
            break;

        default:
            print_err("%s,%u:Unexpected opcode 0x%02x\n",
                      __FUNCTION__, __LINE__, wqe->hdr.opcode);
            return;
        }
        zhpeq_timing_update(&zhpeq_timing_tx_commit, &now, &then, 0);
    }
}

#else

static inline void zhpeq_timing_reserve(struct zhpeq *zq, uint32_t qindex,
                                        uint32_t n_entries)
{
}

static inline void zhpeq_timing_nop(union zhpe_hw_wq_entry *wqe)
{
}

static inline void zhpeq_timing_dma(union zhpe_hw_wq_entry *wqe)
{
}

static inline void zhpeq_timing_imm(union zhpe_hw_wq_entry *wqe)
{
}

static inline void zhpeq_timing_atm(union zhpe_hw_wq_entry *wqe)
{
}

/* Count time from reserve to commit, update timestamp. */
static inline void zhpeq_timing_commit(struct zhpeq *zq, uint32_t qindex,
                                       uint32_t n_entries)
{
}

#endif

static void __attribute__((constructor)) lib_init(void)
{
    void                *dlhandle = dlopen(BACKNAME, RTLD_NOW);

    if (!dlhandle) {
        print_err("Failed to load %s:%s\n", BACKNAME, dlerror());
        abort();
    }
}

void zhpeq_register_backend(enum zhpe_backend backend, struct backend_ops *ops)
{
    /* For the moment, the zhpe backend will only register if the zhpe device
     * can be opened and the libfabric backend will only register if the zhpe
     * device can't be opened.
     */

    switch (backend) {

    case ZHPEQ_BACKEND_LIBFABRIC:
    case ZHPEQ_BACKEND_ZHPE:
        b_ops = ops;
        break;

    default:
        print_err("Unexpected backed %d\n", backend);
        break;
    }
}

int zhpeq_init(int api_version)
{
    int                 ret = -EINVAL;
    static int          init_status = 1;

    if (init_status > 0) {
        if (!expected_saw("api_version", ZHPEQ_API_VERSION, api_version))
            goto done;
        if (!expected_saw("sizeof(zhpe_hw_wq_entry)",
                          ZHPE_ENTRY_LEN, sizeof(union zhpe_hw_wq_entry)))
            goto done;
        if (!expected_saw("sizeof(zhpeq_cq_entry)",
                          ZHPE_ENTRY_LEN, sizeof(struct zhpeq_cq_entry)))
        goto done;
        mutex_lock(&init_mutex);
        if (b_ops->lib_init)
            ret = b_ops->lib_init(&b_attr);
        init_status = (ret <= 0 ? ret : 0);
        mutex_unlock(&init_mutex);
    }
    ret = init_status;
 done:

    return ret;
}

int zhpeq_query_attr(struct zhpeq_attr *attr)
{
    int                 ret = -EINVAL;

    /* Compatibility handling is left for another day. */
    if (!attr)
        goto done;

    *attr = b_attr;
    ret = 0;

 done:

    return ret;
}

int zhpeq_domain_free(struct zhpeq_dom *zdom)
{
    int                 ret = -EINVAL;

    if (!zdom)
        goto done;

    ret = 0;
    if (b_ops->domain_free)
        ret = b_ops->domain_free(zdom);
    free(zdom);

 done:
    return ret;
}

int zhpeq_domain_alloc(struct zhpeq_dom **zdom_out)
{
    int                 ret = -EINVAL;
    struct zhpeq_dom    *zdom = NULL;

    if (!zdom_out)
        goto done;
    *zdom_out = NULL;

    ret = -ENOMEM;
    zdom = calloc(1, sizeof(*zdom));
    if (!zdom)
        goto done;

    ret = 0;
    if (b_ops->domain)
        ret = b_ops->domain(zdom);

 done:
    if (ret >= 0)
        *zdom_out = zdom;
    else
        (void)zhpeq_domain_free(zdom);

    return ret;
}

int zhpeq_free(struct zhpeq *zq)
{
    int                 ret = -EINVAL;
    int                 rc;
    union xdm_active    active;

    if (!zq)
        goto done;
    /* Stop the queue. */
    iowrite64(1, zq->qcm + ZHPE_XDM_QCM_STOP_OFFSET);
    for (;;) {
        active.u64 =
            ioread64(zq->qcm + ZHPE_XDM_QCM_ACTIVE_STATUS_ERROR_OFFSET);
        if (!active.bits.active)
            break;
        sched_yield();
    }
    if (b_ops->qfree_pre)
        rc = b_ops->qfree_pre(zq);

    ret = 0;
    /* Unmap qcm, wq, and cq. */
    rc = do_munmap((void *)zq->qcm, zq->xqinfo.qcm.size);
    if (ret >= 0 && rc < 0)
        ret = rc;
    rc = do_munmap(zq->wq, zq->xqinfo.cmdq.size);
    if (ret >= 0 && rc < 0)
        ret = rc;
    rc = do_munmap(zq->cq, zq->xqinfo.cmplq.size);
    if (ret >= 0 && rc < 0)
        ret = rc;
    /* Call the driver to free the queue. */
    rc = b_ops->qfree(zq);
    if (ret >= 0 && rc < 0)
        ret = rc;
    if (zq->tail_lock_init)
        spin_destroy(&zq->tail_lock);
    /* Free queue memory. */
    free(zq->context);
    free(zq);

 done:
    return ret;
}

int zhpeq_alloc(struct zhpeq_dom *zdom, int cmd_qlen, int cmp_qlen,
                int traffic_class, int priority, int slice_mask,
                struct zhpeq **zq_out)
{
    int                 ret = -EINVAL;
    struct zhpeq        *zq = NULL;
    union xdm_cmp_tail  tail = {
        .bits.toggle_valid = 1,
    };
    int                 flags;

    if (!zq_out)
        goto done;
    *zq_out = NULL;
    if (!zdom ||
        cmd_qlen < 2 || cmd_qlen > b_attr.z.max_hw_qlen ||
        cmp_qlen < 2 || cmp_qlen > b_attr.z.max_hw_qlen ||
        traffic_class < 0 || traffic_class > ZHPEQ_TC_MAX ||
        priority < 0 || priority > ZHPEQ_PRI_MAX ||
        (slice_mask & ~(ALL_SLICES | SLICE_DEMAND)))
        goto done;

    ret = -ENOMEM;
    zq = calloc(1, sizeof(*zq));
    if (!zq)
        goto done;
    zq->zdom = zdom;
    spin_init(&zq->tail_lock, PTHREAD_PROCESS_PRIVATE);
    zq->tail_lock_init = true;

    if (cmd_qlen < cmp_qlen)
        cmd_qlen = cmp_qlen;

    cmd_qlen = roundup_pow_of_2(cmd_qlen);
    cmp_qlen = roundup_pow_of_2(cmp_qlen);

    ret = b_ops->qalloc(zq, cmd_qlen, cmp_qlen, traffic_class,
                        priority, slice_mask);
    if (ret < 0)
        goto done;

    zq->context = calloc(zq->xqinfo.cmdq.ent, sizeof(*zq->context));
    if (!zq->context)
        goto done;

    /* zq->fd == -1 means we're faking things out. */
    flags = (zq->fd == -1 ? MAP_ANONYMOUS | MAP_PRIVATE : MAP_SHARED);
    /* Map registers, wq, and cq. */
    zq->qcm = do_mmap(NULL, zq->xqinfo.qcm.size, PROT_READ | PROT_WRITE,
                      flags, zq->fd, zq->xqinfo.qcm.off, &ret);
    if (!zq->qcm)
        goto done;
    zq->wq = do_mmap(NULL, zq->xqinfo.cmdq.size, PROT_READ | PROT_WRITE,
                     flags, zq->fd, zq->xqinfo.cmdq.off, &ret);
    if (!zq->wq)
        goto done;
    zq->cq = do_mmap(NULL, zq->xqinfo.cmplq.size, PROT_READ | PROT_WRITE,
                     flags, zq->fd, zq->xqinfo.cmplq.off, &ret);
    if (!zq->cq)
        goto done;
    if (b_ops->qalloc_post) {
        ret = b_ops->qalloc_post(zq);
        if (ret < 0)
            goto done;
    }

    /* Initialize completion tail to zero and set toggle bit. */
    iowrite64(tail.u64, zq->qcm + ZHPE_XDM_QCM_CMPL_QUEUE_TAIL_TOGGLE_OFFSET);
    /* Intialize command head and tail to zero. */
    iowrite64(0, zq->qcm + ZHPE_XDM_QCM_CMD_QUEUE_HEAD_OFFSET);
    iowrite64(0, zq->qcm + ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
    /* Start the queue. */
    iowrite64(0, zq->qcm + ZHPE_XDM_QCM_STOP_OFFSET);
    ret = 0;

 done:
    if (ret >= 0)
        *zq_out = zq;
    else
        (void)zhpeq_free(zq);

    return ret;
}

int zhpeq_backend_open(struct zhpeq *zq, int sock_fd)
{
    int                 ret = -EINVAL;

    if (!zq)
        goto done;

    ret = 0;
    if (b_ops->open)
        ret = b_ops->open(zq, sock_fd);
 done:

    return ret;
}

int zhpeq_backend_close(struct zhpeq *zq, int open_idx)
{
    int                 ret = -EINVAL;

    if (!zq)
        goto done;

    ret = 0;
    if (b_ops->close)
        ret = b_ops->close(zq, open_idx);
 done:

    return ret;
}

int64_t zhpeq_reserve(struct zhpeq *zq, uint32_t n_entries)
{
    int64_t             ret = -EINVAL;
    uint32_t            qmask;
    uint32_t            avail;

    if (!zq)
        goto done;
    qmask = zq->xqinfo.cmdq.ent - 1;
    if (!zq || n_entries < 1 || n_entries > qmask)
        goto done;

    /* While I can use compare-and-swap for reserve, it won't work
     * for commit.
     */
    ret = 0;
    spin_lock(&zq->tail_lock);
    avail = qmask - ((zq->tail_reserved - zq->q_head) & qmask);
    if (avail >= n_entries) {
        ret = zq->tail_reserved;
        zq->tail_reserved += n_entries;
        zhpeq_timing_reserve(zq, ret, n_entries);
    } else
        ret = -EAGAIN;
    spin_unlock(&zq->tail_lock);

 done:
    return ret;
}

int zhpeq_commit(struct zhpeq *zq, uint32_t qindex, uint32_t n_entries)
{
    int                 ret = -EINVAL;
    bool                set = false;
    uint32_t            qmask;

    if (!zq)
        goto done;

    qmask = zq->xqinfo.cmdq.ent - 1;
    /* We need a lock to guarantee writes to tail register are ordered. */
    ret = 0;
    for (;;) {
        spin_lock(&zq->tail_lock);
        if (qindex == zq->tail_commit) {
            smp_wmb();
            zhpeq_timing_commit(zq, qindex, n_entries);
            zq->tail_commit += n_entries;
            iowrite64(zq->tail_commit & qmask,
                      zq->qcm + ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
            set = true;
        }
        spin_unlock(&zq->tail_lock);
        if (set) {
            if (b_ops->wq_signal)
                ret = b_ops->wq_signal(zq);
            break;
        }
        /* FIXME: Yes? No? */
        sched_yield();
    }
    ZHPEQ_TIMING_UPDATE(&zhpeq_timing_tx_commit, NULL,
                        &zhpeq_timing_tx_start_stamp,
                        ZHPEQ_TIMING_UPDATE_OLD_CPU);

 done:
    return ret;
}

int zhpeq_nop(struct zhpeq *zq, uint32_t qindex, bool fence,
              void *context)
{
    int                 ret = -EINVAL;
    union zhpe_hw_wq_entry *wqe;

    if (!zq)
        goto done;
    if (!context)
        goto done;

    qindex = qindex & (zq->xqinfo.cmdq.ent - 1);
    zq->context[qindex] = context;
    wqe = zq->wq + qindex;
    zhpeq_timing_nop(wqe);

    wqe->hdr.opcode = ZHPE_HW_OPCODE_NOP;
    wqe->hdr.cmp_index = qindex;

    ret = 0;

 done:
    return ret;
}

static inline int zhpeq_rw(struct zhpeq *zq, uint32_t qindex, bool fence,
                           uint64_t rd_addr, size_t len, uint64_t wr_addr,
                           void *context, uint16_t opcode)
{
    int                 ret = -EINVAL;
    union zhpe_hw_wq_entry *wqe;

    if (!zq)
        goto done;
    if (len > b_attr.z.max_dma_len)
        goto done;

    qindex = qindex & (zq->xqinfo.cmdq.ent - 1);
    zq->context[qindex] = context;
    wqe = zq->wq + qindex;
    zhpeq_timing_dma(wqe);

    opcode |= (fence ? ZHPE_HW_OPCODE_FENCE : 0);
    wqe->hdr.opcode = opcode;
    wqe->hdr.cmp_index = qindex;
    wqe->dma.len = len;
    wqe->dma.rd_addr = rd_addr;
    wqe->dma.wr_addr = wr_addr;
    ret = 0;

 done:
    return ret;
}

int zhpeq_put(struct zhpeq *zq, uint32_t qindex, bool fence,
              uint64_t lcl_addr, size_t len, uint64_t rem_addr,
              void *context)
{
    return zhpeq_rw(zq, qindex, fence, lcl_addr, len, rem_addr, context,
                    ZHPE_HW_OPCODE_PUT);
}

int zhpeq_puti(struct zhpeq *zq, uint32_t qindex, bool fence,
               const void *buf, size_t len, uint64_t remote_addr,
               void *context)
{
    int                 ret = -EINVAL;
    union zhpe_hw_wq_entry *wqe;

    if (!zq)
        goto done;
    if (!buf || !len || len > sizeof(wqe->imm.data))
        goto done;

    qindex = qindex & (zq->xqinfo.cmdq.ent - 1);
    zq->context[qindex] = context;
    wqe = zq->wq + qindex;
    zhpeq_timing_imm(wqe);

    wqe->hdr.opcode = ZHPE_HW_OPCODE_PUTIMM;
    wqe->hdr.opcode |= (fence ? ZHPE_HW_OPCODE_FENCE : 0);
    wqe->hdr.cmp_index = qindex;
    wqe->imm.len = len;
    wqe->imm.rem_addr = remote_addr;
    memcpy(wqe->imm.data, buf, len);

    ret = 0;

 done:
    return ret;
}

int zhpeq_get(struct zhpeq *zq, uint32_t qindex, bool fence,
              uint64_t lcl_addr, size_t len, uint64_t rem_addr,
              void *context)
{
    return zhpeq_rw(zq, qindex, fence, rem_addr, len, lcl_addr, context,
                    ZHPE_HW_OPCODE_GET);
}

int zhpeq_geti(struct zhpeq *zq, uint32_t qindex, bool fence,
               size_t len, uint64_t remote_addr, void *context)
{
    int                 ret = -EINVAL;
    union zhpe_hw_wq_entry *wqe;

    if (!zq)
        goto done;
    if (!len || len > sizeof(wqe->imm.data))
        goto done;

    qindex = qindex & (zq->xqinfo.cmdq.ent - 1);
    zq->context[qindex] = context;
    wqe = zq->wq + qindex;
    zhpeq_timing_imm(wqe);

    wqe->hdr.opcode = ZHPE_HW_OPCODE_GETIMM;
    wqe->hdr.opcode |= (fence ? ZHPE_HW_OPCODE_FENCE : 0);
    wqe->hdr.cmp_index = qindex;
    wqe->imm.len = len;
    wqe->imm.rem_addr = remote_addr;

    ret = 0;
 done:
    return ret;
}

int zhpeq_atomic(struct zhpeq *zq, uint32_t qindex, bool fence, bool retval,
                 enum zhpeq_atomic_size datasize, enum zhpeq_atomic_op op,
                 uint64_t remote_addr, const union zhpeq_atomic *operands,
                 void *context)
{
    int                 ret = -EINVAL;
    union zhpe_hw_wq_entry *wqe;
    size_t              n_operands;

    if (!zq)
        goto done;
    if (!operands)
        goto done;

    qindex = qindex & (zq->xqinfo.cmdq.ent - 1);
    zq->context[qindex] = context;
    wqe = zq->wq + qindex;
    zhpeq_timing_atm(wqe);

    wqe->hdr.opcode = (fence ? ZHPE_HW_OPCODE_FENCE : 0);
    switch (op) {

    case ZHPEQ_ATOMIC_ADD:
        wqe->hdr.opcode |= ZHPE_HW_OPCODE_ATM_ADD;
        n_operands = 1;
        break;

    case ZHPEQ_ATOMIC_CAS:
        wqe->hdr.opcode |= ZHPE_HW_OPCODE_ATM_CAS;
        n_operands = 2;
        break;

    case ZHPEQ_ATOMIC_SWAP:
        wqe->hdr.opcode |= ZHPE_HW_OPCODE_ATM_SWAP;
        n_operands = 1;
        break;

    default:
        goto done;
    }

    wqe->atm.size = (retval ? ZHPE_HW_ATOMIC_RETURN : 0);

    switch (datasize) {

    case ZHPEQ_ATOMIC_SIZE32:
        wqe->atm.size |= ZHPE_HW_ATOMIC_SIZE_32;
        break;

    case ZHPEQ_ATOMIC_SIZE64:
        wqe->atm.size |= ZHPE_HW_ATOMIC_SIZE_64;
        break;

    default:
        goto done;
    }

    wqe->hdr.cmp_index = qindex;
    wqe->atm.rem_addr = remote_addr;
    while (n_operands-- > 0)
        wqe->atm.operands[n_operands] = operands[n_operands].z;

    ret = 0;

 done:
    return ret;
}

int zhpeq_mr_reg(struct zhpeq_dom *zdom, const void *buf, size_t len,
                 uint32_t access, struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -EINVAL;

    if (!qkdata_out)
        goto done;
    *qkdata_out = NULL;
    if (!zdom)
         goto done;

    ret = b_ops->mr_reg(zdom, buf, len, access, qkdata_out);
#if QKDATA_DUMP
    if (ret >= 0)
        zhpeq_print_qkdata(__FUNCTION__, __LINE__, zdom, *qkdata_out);
#endif

 done:
    return ret;
}

int zhpeq_mr_free(struct zhpeq_dom *zdom, struct zhpeq_key_data *qkdata)
{
    int                 ret = 0;

    if (!qkdata)
        goto done;
    ret = -EINVAL;
    if (!zdom)
        goto done;

#if QKDATA_DUMP
    zhpeq_print_qkdata(__FUNCTION__, __LINE__, zdom, qkdata);
#endif
    ret = b_ops->mr_free(zdom, qkdata);

 done:
    return ret;
}

int zhpeq_zmmu_import(struct zhpeq_dom *zdom, int open_idx, const void *blob,
                      size_t blob_len, bool cpu_visible,
                      struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -EINVAL;

    if (!qkdata_out)
        goto done;
    *qkdata_out = NULL;
    if (!zdom || !blob)
        goto done;

    ret = b_ops->zmmu_import(zdom, open_idx, blob, blob_len, cpu_visible,
                             qkdata_out);
#if QKDATA_DUMP
    if (ret >= 0)
        zhpeq_print_qkdata(__FUNCTION__, __LINE__, zdom, *qkdata_out);
#endif

 done:
    return ret;
}

int zhpeq_zmmu_export(struct zhpeq_dom *zdom,
                      const struct zhpeq_key_data *qkdata,
                      void *blob, size_t *blob_len)
{
    int                 ret = -EINVAL;
    struct zhpeq_mr_desc_v1 *desc = container_of(qkdata,
                                                 struct zhpeq_mr_desc_v1,
                                                 qkdata);

    if (!zdom || !qkdata || !blob || !blob_len ||
        desc->hdr.magic != ZHPE_MAGIC || desc->hdr.version != ZHPEQ_MR_V1)
        goto done;

#if QKDATA_DUMP
    zhpeq_print_qkdata(__FUNCTION__, __LINE__, zdom, qkdata);
#endif
    ret = b_ops->zmmu_export(zdom, qkdata, blob, blob_len);

 done:
    return ret;
}

int zhpeq_zmmu_free(struct zhpeq_dom *zdom, struct zhpeq_key_data *qkdata)
{
    int                 ret = 0;

    if (!qkdata)
        goto done;
    ret = -EINVAL;
    if (!zdom)
        goto done;

#if 0
    zhpeq_print_qkdata(__FUNCTION__, __LINE__, zdom, qkdata);
#endif
    ret = b_ops->zmmu_free(zdom, qkdata);

 done:
    return ret;
}

ssize_t zhpeq_cq_read(struct zhpeq *zq, struct zhpeq_cq_entry *entries,
                      size_t n_entries)
{
    ssize_t             ret = -EINVAL;
    bool                polled = false;
    uint16_t            qmask;
    union zhpe_hw_cq_entry *cqe;
    volatile uint8_t    *validp;
    ssize_t             i;
    uint32_t            idx;

    if (!zq || !entries || n_entries > SSIZE_MAX)
        goto done;

    /* This is currently not thread safe for multiple readers on a single zq;
     * I don't see a use for it, at the moment.
     */
    qmask = zq->xqinfo.cmplq.ent - 1;

    /* Lets try to optimize our read-barriers. */
    for (i = 0; i < n_entries;) {
        idx = ((zq->q_head + i) & qmask);
        cqe = zq->cq + idx;
        validp = (void *)cqe;
        if ((*validp & ZHPE_HW_CQ_VALID) != cq_valid(zq->q_head + i, qmask)) {
            if (i > 0 || !b_ops->cq_poll || polled)
                break;
            ret = b_ops->cq_poll(zq, n_entries);
            if (ret < 0)
                goto done;
            polled = true;
            continue;
        }
        i++;
    }
    ret = i;
    /* Just the one. */
    smp_rmb();
    /* Transfer entries to the caller's buffer and reset valid.
     */
    for (i = 0; i < ret; i++) {
        idx = ((zq->q_head + i) & qmask);
        cqe = zq->cq + idx;
        entries[i].z = cqe->entry;
        entries[i].z.context = zq->context[cqe->entry.index];
        ZHPEQ_TIMING_UPDATE(&zhpeq_timing_tx_cqread,
                            NULL, &cqe->entry.timestamp, 0);
    }
    smp_wmb();
    zq->q_head += ret;

 done:
    return ret;
}

void zhpeq_print_info(struct zhpeq *zq)
{
    const char          *b_str = "unknown";
    struct zhpe_attr    *attr = &b_attr.z;

    switch (b_attr.backend) {

    case ZHPEQ_BACKEND_ZHPE:
        b_str = "zhpe";
        break;

    case ZHPEQ_BACKEND_LIBFABRIC:
        b_str = "libfabric";
        break;

    default:
        break;
    }

    printf("%s:attributes\n", LIBNAME);
    printf("backend       : %s\n", b_str);
    printf("max_tx_queues : %u\n", attr->max_tx_queues);
    printf("max_rx_queues : %u\n", attr->max_rx_queues);
    printf("max_hw_qlen   : %u\n", attr->max_hw_qlen);
    printf("max_sw_qlen   : %u\n", attr->max_sw_qlen);
    printf("max_dma_len   : %Lu\n", (ullong)attr->max_dma_len);

    if (b_ops->print_info) {
        printf("\n");
        b_ops->print_info(zq);
    }
}

struct zhpeq_dom *zhpeq_dom(struct zhpeq *zq)
{
    return zq->zdom;
}

int zhpeq_getaddr(struct zhpeq *zq, union sockaddr_in46 *sa)
{
    ssize_t             ret = -EINVAL;

    if (!zq || !sa)
        goto done;

    ret = b_ops->getaddr(zq, sa);
 done:

    return ret;
}

void zhpeq_print_qkdata(const char *func, uint line, struct zhpeq_dom *zdom,
                        const struct zhpeq_key_data *qkdata)
{
    char                *id_str = NULL;

    if (b_ops->qkdata_id_str)
        id_str = b_ops->qkdata_id_str(zdom, qkdata);
    printf("%s,%u:%p %s\n", func, line, qkdata, (id_str ?: ""));
    printf("%s,%u:v/z/l 0x%Lx 0x%Lx 0x%Lx\n", func, line,
           (ullong)qkdata->z.vaddr, (ullong)qkdata->z.zaddr,
           (ullong)qkdata->z.len);
    printf("%s,%u:a/l 0x%Lx 0x%Lx\n", func, line,
           (ullong)qkdata->z.access, (ullong)qkdata->laddr);
}

static void print_qcm1(const char *func, uint line, const volatile void *qcm,
                      uint offset)
{
        printf("%s,%u:qcm[0x%03x] = 0x%lx\n",
               func, line, offset, ioread64(qcm + offset));
}

void zhpeq_print_qcm(const char *func, uint line, const struct zhpeq *zq)
{
        uint            i;

        printf("%s,%u:%s %p\n", func, line, __FUNCTION__, zq->qcm);
        for (i = 0x00; i < 0x30; i += 0x08)
            print_qcm1(func, line, zq->qcm, i);
        for (i = 0x40; i < 0x108; i += 0x40)
            print_qcm1(func, line, zq->qcm, i);
}
