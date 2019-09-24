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

#include <internal.h>

#include <dlfcn.h>
#include <limits.h>

static_assert(sizeof(union zhpe_hw_wq_entry) ==  ZHPE_ENTRY_LEN,
              "zhpe_hw_wq_entry");
static_assert(sizeof(union zhpe_hw_cq_entry) ==  ZHPE_ENTRY_LEN,
              "zhpe_hw_cq_entry");

/* Set to 1 to dump qkdata when registered/exported/imported/freed. */
#define QKDATA_DUMP     (0)

#define LIBNAME         "libzhpeq"
#define BACKNAME        "libzhpeq_backend.so"

static pthread_mutex_t  init_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool             b_zhpe;
static struct backend_ops *b_ops;
static struct zhpeq_attr b_attr;

uuid_t                  zhpeq_uuid;

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
        b_ops = ops;
        break;

    case ZHPEQ_BACKEND_ZHPE:
        b_zhpe = true;
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

        mutex_lock(&init_mutex);
        if (b_ops && b_ops->lib_init)
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
    zdom = calloc_cachealigned(1, sizeof(*zdom));
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
    if (zq->qcm) {
        iowrite64(1, zq->qcm + ZHPE_XDM_QCM_STOP_OFFSET);
        for (;;) {
            active.u64 =
                ioread64(zq->qcm + ZHPE_XDM_QCM_ACTIVE_STATUS_ERROR_OFFSET);
            if (!active.bits.active)
                break;
            sched_yield();
        }
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
    if (zq->xqinfo.qcm.size) {
        rc = b_ops->qfree(zq);
        if (ret >= 0 && rc < 0)
            ret = rc;
    }

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
    size_t              i;
    size_t              req;

    if (!zq_out)
        goto done;
    *zq_out = NULL;
    if (!zdom ||
        cmd_qlen < 2 || cmd_qlen > b_attr.z.max_tx_qlen ||
        cmp_qlen < 2 || cmp_qlen > b_attr.z.max_tx_qlen ||
        traffic_class < 0 || traffic_class > ZHPEQ_TC_MAX ||
        priority < 0 || priority > ZHPEQ_PRI_MAX ||
        (slice_mask & ~(ALL_SLICES | SLICE_DEMAND)))
        goto done;

    ret = -ENOMEM;
    req = sizeof(*zq);
#if ZHPEQ_RECORD
    req += sizeof(zq->hist[0]) * cmd_qlen;
#endif
    zq = calloc_cachealigned(1, req);
    if (!zq)
        goto done;
    zq->zdom = zdom;

    cmd_qlen = roundup_pow_of_2(cmd_qlen);
    cmp_qlen = roundup_pow_of_2(cmp_qlen);

    ret = b_ops->qalloc(zq, cmd_qlen, cmp_qlen, traffic_class,
                        priority, slice_mask);
    if (ret < 0)
        goto done;

    zq->context = calloc_cachealigned(zq->xqinfo.cmplq.ent,
                                      sizeof(*zq->context));
    if (!zq->context)
        goto done;

    /* Initialize context storage free list. */
    for (i = 0; i < zq->xqinfo.cmplq.ent - 1; i++)
        zq->context[i] = TO_PTR(i + 1);
    zq->context[i] = TO_PTR(FREE_END);
    /* context_free is zeroed. */

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

int zhpeq_backend_exchange(struct zhpeq *zq, int sock_fd,
                           void *sa, size_t *sa_len)
{
    int                 ret = -EINVAL;

    if (!zq || !sa || !sa_len)
        goto done;

    ret = b_ops->exchange(zq, sock_fd, sa, sa_len);

 done:
    return ret;
}

int zhpeq_backend_open(struct zhpeq *zq, void *sa)
{
    int                 ret = -EINVAL;

    if (!zq)
        goto done;

    ret = b_ops->open(zq, sa);
 done:

    return ret;
}

int zhpeq_backend_close(struct zhpeq *zq, int open_idx)
{
    int                 ret = -EINVAL;

    if (!zq)
        goto done;

    ret = b_ops->close(zq, open_idx);
 done:

    return ret;
}

int64_t zhpeq_reserve(struct zhpeq *zq, uint32_t n_entries)
{
    int64_t             ret = -EINVAL;
    uint32_t            qmask;
    uint32_t            avail;
    struct zhpeq_ht     old;
    struct zhpeq_ht     new;

    if (!zq)
        goto done;
    qmask = zq->xqinfo.cmdq.ent - 1;
    if (n_entries < 1 || n_entries > qmask)
        goto done;

    ret = 0;
    for (old = atm_load_rlx(&zq->head_tail) ;;) {
        avail = qmask - (old.tail - old.head);
        if (avail < n_entries) {
            ret = -EAGAIN;
            break;
        }
        new.head = old.head;
        ret = old.tail;
        new.tail = old.tail + n_entries;
        if (atm_cmpxchg(&zq->head_tail, &old, new))
            break;
    }

 done:
    return ret;
}

int64_t zhpeq_reserve_next(struct zhpeq *zq, int64_t last)
{
    int64_t             ret = -EINVAL;
    uint32_t            qmask;
    uint32_t            avail;
    struct zhpeq_ht     old;
    struct zhpeq_ht     new;

    if (!zq)
        goto done;
    qmask = zq->xqinfo.cmdq.ent - 1;

    ret = 0;
    for (old = atm_load_rlx(&zq->head_tail) ;;) {
        avail = qmask - (old.tail - old.head);
        if (avail < 1 || last != old.tail - 1) {
            ret = -EAGAIN;
            break;
        }
        new.head = old.head;
        ret = old.tail;
        new.tail = old.tail + 1;
        if (atm_cmpxchg(&zq->head_tail, &old, new))
            break;
    }

 done:
    return ret;
}

int zhpeq_commit(struct zhpeq *zq, uint32_t qindex, uint32_t n_entries)
{
    int                 ret = -EINVAL;
    uint32_t            qmask;
    uint32_t            old;
    uint32_t            new;
    uint32_t            i MAYBE_UNUSED;

    if (!zq)
        goto done;

    qmask = zq->xqinfo.cmdq.ent - 1;

#ifdef HAVE_ZHPE_STATS
    zhpe_stats_pause_all();
    union zhpe_hw_wq_entry *wqe;

    for (i = 0; i < n_entries; i++) {
        wqe = zq->wq + ((qindex + i) & qmask);
        zhpe_stats_stamp(zhpe_stats_subid(ZHPQ, 60), (uintptr_t)zq,
                         wqe->hdr.cmp_index,
                         (uintptr_t)zq->context[wqe->hdr.cmp_index]);
    }
    zhpe_stats_restart_all();
#endif

    old = atm_load_rlx(&zq->tail_commit);
    if (old != qindex) {
        ret = -EAGAIN;
        goto done;
    }
    new = old + n_entries;
#if ZHPEQ_RECORD
    i = atm_inc(&zq->hist_idx) & qmask;
    zq->hist[i].qhead = zq->head_tail.head;
    zq->hist[i].qtail = old;
    zq->hist[i].qnew = new;
    zq->hist[i].xhead = ioread64(zq->qcm + ZHPE_XDM_QCM_CMD_QUEUE_HEAD_OFFSET);
    zq->hist[i].xtail = ioread64(zq->qcm + ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
#endif
    io_wmb();
    iowrite64(new & qmask,
              zq->qcm + ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
    io_wmb();
    atm_store_rlx(&zq->tail_commit, new);
    ret = 0;

 done:
    return ret;
}

int zhpeq_signal(struct zhpeq *zq)
{
    return b_ops->wq_signal(zq);
}

static inline void set_context(struct zhpeq *zq, union zhpe_hw_wq_entry *wqe,
                               void *context)
{
    struct free_index   old;
    struct free_index   new;

    for (old = atm_load_rlx(&zq->context_free);;) {
        if (unlikely(old.index == FREE_END)) {
            /* Tiny race between head moving and context slot freed. */
            sched_yield();
            old = atm_load_rlx(&zq->context_free);
            continue;
        }
        new.index = (int32_t)(uintptr_t)zq->context[old.index];
        new.seq = old.seq + 1;
        if (atm_cmpxchg(&zq->context_free, &old, new))
            break;
    }
    zq->context[old.index] = context;
    wqe->hdr.cmp_index = old.index;
}

static inline void *get_context(struct zhpeq *zq, struct zhpe_cq_entry *cqe)
{
    void                *ret = zq->context[cqe->index];
    struct free_index   old;
    struct free_index   new;

    for (old = atm_load_rlx(&zq->context_free) ;;) {
        zq->context[cqe->index] = TO_PTR(old.index);
        new.index = cqe->index;
        new.seq = old.seq + 1;
        if (atm_cmpxchg(&zq->context_free, &old, new))
            break;
    }

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
    wqe = zq->wq + qindex;

    wqe->hdr.opcode = ZHPE_HW_OPCODE_NOP;
    set_context(zq, wqe, context);

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

    qindex &= (zq->xqinfo.cmdq.ent - 1);
    wqe = zq->wq + qindex;

    opcode |= (fence ? ZHPE_HW_OPCODE_FENCE : 0);
    wqe->hdr.opcode = opcode;
    set_context(zq, wqe, context);
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

    qindex &= (zq->xqinfo.cmdq.ent - 1);
    wqe = zq->wq + qindex;

    wqe->hdr.opcode = ZHPE_HW_OPCODE_PUTIMM;
    wqe->hdr.opcode |= (fence ? ZHPE_HW_OPCODE_FENCE : 0);
    set_context(zq, wqe, context);
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
    wqe = zq->wq + qindex;

    wqe->hdr.opcode = ZHPE_HW_OPCODE_GETIMM;
    wqe->hdr.opcode |= (fence ? ZHPE_HW_OPCODE_FENCE : 0);
    set_context(zq, wqe, context);
    wqe->imm.len = len;
    wqe->imm.rem_addr = remote_addr;

    ret = 0;
 done:
    return ret;
}

static int set_atomic_operands(union zhpe_hw_wq_entry *wqe,
                               enum zhpeq_atomic_size datasize,
                               uint64_t op1, uint64_t op2)
{
    switch (datasize) {

    case ZHPEQ_ATOMIC_SIZE32:
        wqe->atm.size |= ZHPE_HW_ATOMIC_SIZE_32;
        wqe->atm.operands32[0] = op1;
        wqe->atm.operands32[1] = op2;
        return 0;

    case ZHPEQ_ATOMIC_SIZE64:
        wqe->atm.size |= ZHPE_HW_ATOMIC_SIZE_64;
        wqe->atm.operands64[0] = op1;
        wqe->atm.operands64[1] = op2;
        return 0;

    default:
        return -EINVAL;
    }
}

int zhpeq_atomic(struct zhpeq *zq, uint32_t qindex, bool fence, bool retval,
                 enum zhpeq_atomic_size datasize, enum zhpeq_atomic_op op,
                 uint64_t remote_addr, const uint64_t *operands, void *context)
{
    int                 ret = 0;
    union zhpe_hw_wq_entry *wqe;

    if (!zq) {
        ret = -EINVAL;
        goto done;
    }

    qindex = qindex & (zq->xqinfo.cmdq.ent - 1);
    wqe = zq->wq + qindex;

    wqe->hdr.opcode = (fence ? ZHPE_HW_OPCODE_FENCE : 0);
    set_context(zq, wqe, context);
    wqe->atm.size = (retval ? ZHPE_HW_ATOMIC_RETURN : 0);
    wqe->atm.rem_addr = remote_addr;

    switch (op) {

    case ZHPEQ_ATOMIC_ADD:
        wqe->hdr.opcode |= ZHPE_HW_OPCODE_ATM_ADD;
        ret = set_atomic_operands(wqe, datasize, operands[0], 0);
        break;

    case ZHPEQ_ATOMIC_CAS:
        ret = wqe->hdr.opcode |= ZHPE_HW_OPCODE_ATM_CAS;
        set_atomic_operands(wqe, datasize, operands[1], operands[0]);
        break;

    case ZHPEQ_ATOMIC_SWAP:
        wqe->hdr.opcode |= ZHPE_HW_OPCODE_ATM_SWAP;
        ret = set_atomic_operands(wqe, datasize, operands[0], 0);
        break;

    default:
        ret = -EINVAL;
        break;
    }

 done:
    return ret;
}

int zhpeq_mr_reg(struct zhpeq_dom *zdom, const void *buf, size_t len,
                 uint32_t access, struct zhpeq_key_data **qkdata_out)
{
    zhpe_stats_start(zhpe_stats_subid(ZHPQ, 0));

    int                 ret = -EINVAL;

    if (!qkdata_out)
        goto done;
    *qkdata_out = NULL;
    if (!zdom || !len || page_up((uintptr_t)buf + len)  <= (uintptr_t)buf ||
        (access & ~ZHPEQ_MR_VALID_MASK))
        goto done;

    ret = b_ops->mr_reg(zdom, buf, len, access, qkdata_out);
#if QKDATA_DUMP
    if (ret >= 0)
        zhpeq_print_qkdata(__func__, __LINE__, *qkdata_out);
#endif

 done:
    zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 0));

    return ret;
}

int zhpeq_qkdata_free(struct zhpeq_key_data *qkdata)
{
    int                 ret = 0;
    struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, struct zhpeq_mr_desc_v1, qkdata);

    if (!qkdata)
        goto done;
    ret = -EINVAL;
    if (desc->hdr.magic != ZHPE_MAGIC ||
        (desc->hdr.version & ~ZHPEQ_MR_REMOTE) != ZHPEQ_MR_V1)
        goto done;
#if QKDATA_DUMP
    zhpeq_print_qkdata(__func__, __LINE__, qkdata);
#endif
    if (desc->qkdata.z.zaddr) {
        if (desc->hdr.version & ZHPEQ_MR_REMOTE) {
            zhpe_stats_start(zhpe_stats_subid(ZHPQ, 50));
            ret = b_ops->zmmu_free(qkdata);
            zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 50));
        } else {
            zhpe_stats_start(zhpe_stats_subid(ZHPQ, 10));
            ret = b_ops->mr_free(qkdata);
            zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 10));
        }
    }
    free(desc);

 done:

    return ret;
}

int zhpeq_zmmu_reg(struct zhpeq_key_data *qkdata)
{
    zhpe_stats_start(zhpe_stats_subid(ZHPQ, 40));

    int                 ret = -EINVAL;
    struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, struct zhpeq_mr_desc_v1, qkdata);

    if (!qkdata || desc->hdr.magic != ZHPE_MAGIC ||
        desc->hdr.version != (ZHPEQ_MR_V1 | ZHPEQ_MR_REMOTE))
        goto done;

#if QKDATA_DUMP
    zhpeq_print_qkdata(__func__, __LINE__, qkdata);
#endif
    ret = b_ops->zmmu_reg(qkdata);

 done:
    zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 40));

    return ret;
}

int zhpeq_fam_qkdata(struct zhpeq_dom *zdom, int open_idx,
                     struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -EINVAL;

    zhpe_stats_start(zhpe_stats_subid(ZHPQ, 20));

    if (!qkdata_out)
        goto done;
    *qkdata_out = NULL;
    if (!zdom)
        goto done;

    if (b_ops->fam_qkdata)
        ret = b_ops->fam_qkdata(zdom, open_idx, qkdata_out);
    else
        ret = -ENOSYS;

#if QKDATA_DUMP
    if (ret >= 0)
        zhpeq_print_qkdata(__func__, __LINE__, *qkdata_out);
#endif

 done:
    zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 20));

    return ret;
}

int zhpeq_qkdata_export(const struct zhpeq_key_data *qkdata,
                        void *blob, size_t *blob_len)
{
    zhpe_stats_start(zhpe_stats_subid(ZHPQ, 30));

    int                 ret = -EINVAL;
    const struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, const struct zhpeq_mr_desc_v1, qkdata);

    if (!qkdata || !blob || !blob_len ||
        *blob_len < sizeof(struct key_data_packed) ||
        desc->hdr.magic != ZHPE_MAGIC || desc->hdr.version != ZHPEQ_MR_V1)
        goto done;

#if QKDATA_DUMP
    zhpeq_print_qkdata(__func__, __LINE__, qkdata);
#endif
    *blob_len = sizeof(struct key_data_packed);
    ret = b_ops->qkdata_export(qkdata, blob);

 done:
    zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 30));

    return ret;
}

int zhpeq_qkdata_import(struct zhpeq_dom *zdom, int open_idx,
                        const void *blob, size_t blob_len,
                        struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -EINVAL;
    const struct key_data_packed *pdata = blob;
    struct zhpeq_mr_desc_v1 *desc = NULL;
    struct zhpeq_key_data *qkdata;

    if (!qkdata_out)
        goto done;
    *qkdata_out = NULL;
    if (!blob || blob_len != sizeof(*pdata))
        goto done;

    desc = malloc(sizeof(*desc));
    if (!desc) {
        ret = -ENOMEM;
        goto done;
    }
    qkdata = &desc->qkdata;

    desc->hdr.magic = ZHPE_MAGIC;
    desc->hdr.version = ZHPEQ_MR_V1 | ZHPEQ_MR_REMOTE;
    desc->hdr.zdom = zdom;
    desc->open_idx = open_idx;
    unpack_kdata(pdata, qkdata);
    qkdata->rsp_zaddr = qkdata->z.zaddr;
    qkdata->z.zaddr = 0;
    *qkdata_out = qkdata;
    ret = 0;

 done:
    return ret;
}

int zhpeq_mmap(const struct zhpeq_key_data *qkdata,
               uint32_t cache_mode, void *addr, size_t length, int prot,
               int flags, off_t offset, struct zhpeq_mmap_desc **zmdesc)
{
    int                 ret = -EINVAL;
    const struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, const struct zhpeq_mr_desc_v1, qkdata);

    if (zmdesc)
        *zmdesc = NULL;
    if (!qkdata || !zmdesc || (cache_mode & ~ZHPEQ_MR_REQ_CPU_CACHE) ||
        desc->hdr.magic != ZHPE_MAGIC ||
        desc->hdr.version != (ZHPEQ_MR_V1 | ZHPEQ_MR_REMOTE) ||
        !length || page_off(offset) ||
        page_off(qkdata->z.vaddr) || page_off(qkdata->z.len) ||
        offset + length > desc->qkdata.z.len || (prot & PROT_EXEC) ||
        ((prot & PROT_READ) && !(qkdata->z.access & ZHPEQ_MR_GET_REMOTE)) ||
        ((prot & PROT_WRITE) && !(qkdata->z.access & ZHPEQ_MR_PUT_REMOTE)))
        goto done;
    cache_mode |= ZHPEQ_MR_REQ_CPU;

    if (b_ops->mmap)
        ret = b_ops->mmap(qkdata, cache_mode, addr, length, prot,
                          flags, offset, zmdesc);
    else
        ret = -ENOSYS;
#if QKDATA_DUMP
    if (ret >= 0)
        zhpeq_print_qkdata(__func__, __LINE__, qkdata);
#endif

 done:
    return ret;
}

int zhpeq_mmap_unmap(struct zhpeq_mmap_desc *zmdesc)
{
    int                 ret = -EINVAL;

    if (!zmdesc)
        goto done;

#if QKDATA_DUMP
    zhpeq_print_qkdata(__func__, __LINE__, zmdesc->qkdata);
#endif
    if (b_ops->mmap_unmap)
        ret = b_ops->mmap_unmap(zmdesc);
    else
        ret = -ENOSYS;

 done:
    return ret;
}

int zhpeq_mmap_commit(struct zhpeq_mmap_desc *zmdesc,
                      const void *addr, size_t length, bool fence,
                      bool invalidate, bool wait)
{
    int                 ret;

    if (b_ops->mmap_commit)
        ret = b_ops->mmap_commit(zmdesc, addr, length, fence, invalidate, wait);
    else
        ret = -ENOSYS;

    return ret;
}

ssize_t zhpeq_cq_read(struct zhpeq *zq, struct zhpeq_cq_entry *entries,
                      size_t n_entries)
{
    ssize_t             ret = -EINVAL;
    bool                polled = false;
    union zhpe_hw_cq_entry *cqe;
    ssize_t             i;
    uint32_t            qmask;
    uint32_t            old;
    uint32_t            new;

    if (!zq || !entries || n_entries > SSIZE_MAX)
        goto done;

    qmask = zq->xqinfo.cmplq.ent - 1;

    for (i = 0, old = atm_load_rlx(&zq->head_tail.head) ; i < n_entries ;) {
        cqe = zq->cq + (old & qmask);
        if ((atm_load_rlx((uint8_t *)cqe) & ZHPE_HW_CQ_VALID) !=
             cq_valid(old, qmask)) {
            if (i > 0 || !b_ops->cq_poll || polled) {
                if (i == 0)
                    zhpe_stats_stamp(zhpe_stats_subid(ZHPQ, 70), (uintptr_t)zq);
                break;
            }
            ret = b_ops->cq_poll(zq, n_entries);
            if (ret < 0)
                goto done;
            polled = true;
            continue;
        }
        entries[i].z = cqe->entry;
        new = old + 1;
        if (!atm_cmpxchg(&zq->head_tail.head, &old, new))
            continue;
        entries[i].z.context = get_context(zq, &entries[i].z);
        zhpe_stats_stamp(zhpe_stats_subid(ZHPQ, 80), (uintptr_t)zq,
                         entries[i].z.index, (uintptr_t)entries[i].z.context);
        if (entries[i].z.status != ZHPEQ_CQ_STATUS_SUCCESS)
            print_err("%s,%u:head 0x%x index 0x%x status 0x%x\n",
                      __func__, __LINE__, old, entries[i].z.index,
                      entries[i].z.status);
        old = new;
        i++;
    }
    ret = i;

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
    printf("max_tx_qlen   : %u\n", attr->max_tx_qlen);
    printf("max_rx_qlen   : %u\n", attr->max_rx_qlen);
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

int zhpeq_getaddr(struct zhpeq *zq, void *sa, size_t *sa_len)
{
    ssize_t             ret = -EINVAL;

    if (!zq || !sa || !sa_len)
        goto done;

    ret = b_ops->getaddr(zq, sa, sa_len);
 done:

    return ret;
}

void zhpeq_print_qkdata(const char *func, uint line,
                        const struct zhpeq_key_data *qkdata)
{
    char                *id_str = NULL;

    if (b_ops->qkdata_id_str)
        id_str = b_ops->qkdata_id_str(qkdata);
    fprintf(stderr, "%s,%u:%p %s\n", func, line, qkdata, (id_str ?: ""));
    fprintf(stderr, "%s,%u:v/z/l 0x%Lx 0x%Lx 0x%Lx\n", func, line,
            (ullong)qkdata->z.vaddr, (ullong)qkdata->z.zaddr,
            (ullong)qkdata->z.len);
    fprintf(stderr, "%s,%u:a/l 0x%Lx 0x%Lx\n", func, line,
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
    uint                i;

    printf("%s,%u:%s %p\n", func, line, __func__, zq->qcm);
    for (i = 0x00; i < 0x30; i += 0x08)
        print_qcm1(func, line, zq->qcm, i);
    for (i = 0x40; i < 0x108; i += 0x40)
        print_qcm1(func, line, zq->qcm, i);
}

bool zhpeq_is_asic(void)
{
    return b_zhpe;
}

static uint wq_opcode(union zhpe_hw_wq_entry *wqe)
{
    return le16toh(wqe->hdr.opcode & ZHPE_HW_OPCODE_MASK);
}

static uint wq_fence(union zhpe_hw_wq_entry *wqe)
{
    return !!(le16toh(wqe->hdr.opcode & ZHPE_HW_OPCODE_FENCE));
}

static uint wq_index(union zhpe_hw_wq_entry *wqe)
{
    return le16toh(wqe->hdr.cmp_index);
}

static void wq_print_imm(union zhpe_hw_wq_entry *wqe, uint i, const char *opstr)
{
    struct zhpe_hw_wq_imm *imm = &wqe->imm;

    fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x len 0x%x rem 0x%lx\n",
            i, opstr, wq_fence(wqe), wq_index(wqe),
            imm->len, le64toh(imm->rem_addr));
}

static void wq_print_dma(union zhpe_hw_wq_entry *wqe, uint i, const char *opstr)
{
    struct zhpe_hw_wq_dma *dma = &wqe->dma;

    fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x len 0x%x rd 0x%lx wr 0x%lx\n",
            i, opstr, wq_fence(wqe), wq_index(wqe),
            le32toh(dma->len), le64toh(dma->rd_addr), le64toh(dma->wr_addr));
}

static void wq_print_atm(union zhpe_hw_wq_entry *wqe, uint i, const char *opstr)
{
    struct zhpe_hw_wq_atomic *atm = &wqe->atm;
    uint64_t            operands[2];

    if ((atm->size & ZHPE_HW_ATOMIC_SIZE_MASK) == ZHPE_HW_ATOMIC_SIZE_32) {
        operands[0] = le32toh(atm->operands32[0]);
        operands[1] = le32toh(atm->operands32[1]);
    } else {
        operands[0] = le64toh(atm->operands64[0]);
        operands[1] = le64toh(atm->operands64[1]);
    }
    fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x size 0x%x rem 0x%lx"
            " operands 0x%lx 0x%lx\n",
            i, opstr, wq_fence(wqe), wq_index(wqe),
            atm->size, le64toh(atm->rem_addr), operands[0], operands[1]);
}

void zhpeq_print_wq(struct zhpeq *zq, int offset, int cnt)
{
    struct zhpeq_ht     old = atm_load_rlx(&zq->head_tail);
    uint32_t            qmask = zq->xqinfo.cmdq.ent - 1;
    uint                i;
    union zhpe_hw_wq_entry *wqe;

    if (offset < 0 && (uint)(-offset) > old.tail)
        offset = -(int)old.tail;
    for (i = old.tail + (int32_t)offset; i < old.tail && cnt > 0; i++, cnt--) {
        wqe = &zq->wq[i & qmask];
        switch (wq_opcode(wqe)) {

        case ZHPE_HW_OPCODE_NOP:
            fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x\n",
                    i, "NOP", wq_fence(wqe), wq_index(wqe));
            break;

        case ZHPE_HW_OPCODE_GETIMM:
            wq_print_imm(wqe, i, "GETIMM");
            break;

        case ZHPE_HW_OPCODE_PUTIMM:
            wq_print_imm(wqe, i, "PUTIMM");
            break;

        case ZHPE_HW_OPCODE_GET:
            wq_print_dma(wqe, i, "GET");
            break;

        case ZHPE_HW_OPCODE_PUT:
            wq_print_dma(wqe, i, "PUT");
            break;

        case ZHPE_HW_OPCODE_ATM_ADD:
            wq_print_atm(wqe, i, "ATMADD");
            break;

        case ZHPE_HW_OPCODE_ATM_CAS:
            wq_print_atm(wqe, i, "ATMCAS");
            break;

        case ZHPE_HW_OPCODE_ATM_SWAP:
            wq_print_atm(wqe, i, "ATMSWAP");
            break;

        default:
            fprintf(stderr, "%7d:OP 0x%02x:f %u idx %0x04x\n",
                    i, wq_opcode(wqe), wq_fence(wqe), wq_index(wqe));
            break;
        }
    }
}

void zhpeq_print_cq(struct zhpeq *zq, int offset, int cnt)
{
    struct zhpeq_ht     old = atm_load_rlx(&zq->head_tail);
    uint32_t            qmask = zq->xqinfo.cmplq.ent - 1;
    uint                i;
    union zhpe_hw_cq_entry *cqe;
    char                *d;

    if (offset < 0 && (uint)(-offset) > old.head)
        offset = -(int)old.head;
    for (i = old.tail + (int32_t)offset; i < old.head && cnt > 0; i++, cnt--) {
        cqe = &zq->cq[i & qmask];
        /* Print the first 8 bytes of the result */
        d = cqe->entry.result.data;
        fprintf(stderr, "%7d:v %u idx 0x%04x status 0x%02x"
                " data %02x%02x%x02%02x%02x%02x%02x%02x\n",
                i, cqe->entry.valid, le16toh(cqe->entry.index),
                cqe->entry.status,
                d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
    }
}
