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

#include <zhpeq_util_fab.h>

#include <sys/queue.h>

#define FIVERSION       FI_VERSION(1, 5)

#define SLEEP_THRESHOLD_NS (20000)

#define AV_MAX          (16383)

#define KEY_SHIFT       47
#define KEY_MASK_ADDR   (((uint64_t)1 << KEY_SHIFT) - 1)
#define KEYTAB_SHIFT    (64 - KEY_SHIFT)
#define KEYTAB_SIZE     ((size_t)1 << KEYTAB_SHIFT)

#define TO_KEYIDX(_addr) ((_addr) >> KEY_SHIFT)
#define TO_ADDR(_addr)  ((_addr) & KEY_MASK_ADDR)

struct zdom_data {
    struct fab_dom      fab_dom;
    struct fid_mr       **lcl_mr;
    union free_index    lcl_mr_free;
};

enum engine_init {
    ENGINE_INIT,
    ENGINE_WQ_MUTEX_INIT,
    ENGINE_WQ_COND_INIT,
    ENGINE_WQ_THREAD_INIT,
};

struct key_data_packed {
    uint64_t            key;
    uint64_t            vaddr;
    uint64_t            zaddr;
    uint64_t            len;
    uint8_t             access;
} __attribute__((packed));

static inline void pack_kdata(const struct zhpeq_key_data *kdata,
                              struct key_data_packed *pdata,
                              uint64_t backend_key)
{
    pdata->key = be64toh(kdata->key);
    pdata->vaddr = be64toh(kdata->vaddr);
    pdata->zaddr = be64toh(backend_key);
    pdata->len = be64toh(kdata->len);
    pdata->access = kdata->access;
}

static inline void unpack_kdata(const struct key_data_packed *pdata,
                                struct zhpeq_key_data *kdata)
{
    kdata->key = htobe64(pdata->key);
    kdata->vaddr = htobe64(pdata->vaddr);
    kdata->zaddr = htobe64(pdata->zaddr);
    kdata->len = htobe64(pdata->len);
    kdata->access = pdata->access;
}

/*
 * The sockets provider gets annoyed if you delete the listener before
 * deleting all the sockets derived from it. Seems stupid.
 */

struct rkey {
    uint64_t            rkey;
    uint64_t            av_idx;
};

struct context {
    struct fi_context2  opaque;
    struct zhpeq_result *result;
    ZHPEQ_TIMING_CODE(struct zhpeq_timing_stamp timestamp);
    uint16_t            cmp_index;
    uint8_t             result_len;
};

#ifdef ZHPEQ_TIMING

#define lfabt_cmdpost(_data, _wqe, _ctxt)                               \
do {                                                                    \
    zhpeq_timing_update(&zhpeq_timing_tx_cmdnew, &lfabt_new,            \
                        &(_wqe)->_data.timestamp, 0);                   \
    zhpeq_timing_update_stamp(&(_ctxt)->timestamp);                     \
    (_ctxt)->timestamp.time = (_wqe)->_data.timestamp.time;             \
    zhpeq_timing_tx_ibv_post_send_stamp.time =                          \
        (_wqe)->_data.timestamp.time;                                   \
    zhpeq_timing_tx_ibv_post_send_stamp.cpu = (_ctxt)->timestamp.cpu;   \
} while (0)

#define lfabt_cmddone(_ctxt, _cqe)                                      \
do {                                                                    \
    zhpeq_timing_update_stamp(&(_cqe)->entry.timestamp);                \
    zhpeq_timing_update(&zhpeq_timing_tx_cmddone,                       \
                        &(_cqe)->entry.timestamp,                       \
                        &(_ctxt)->timestamp, 0);                        \
} while (0)

#else

#define lfabt_cmdpost(_data, _wqe, _ctxt)       \
    do {} while (0)

#define lfabt_cmddone(_ctxt, _cqe)              \
    do {} while (0)

#endif

#define AV_OP_INSERT_INIT (4)
#define AV_OP_REMOVE_INIT (AV_OP_INSERT_INIT + 1)

struct av_op {
    struct av_op        *next;
    struct av_op        *prev;
    union sockaddr_in46 ep_addr;
    fi_addr_t           fi_addr;
    pthread_cond_t      cond;
    int                 status;
};

struct stuff {
    struct fab_conn     fab_conn;
    struct fab_conn     fab_listener;
    union free_index    rkey_free;
    struct rkey         *rkey;
    pthread_mutex_t     wq_mutex;
    pthread_cond_t      wq_cond;
    uint64_t            wq_signal;
    uint64_t            wq_signal_seen;
    pthread_t           wq_thread;
    struct context      *context;
    struct context      *context_free;
    struct zhpeq_result *results;
    struct fid_mr       *results_mr;
    void                *results_desc;
    struct av_op        *av_cur;
    uint32_t            cq_tail;
    enum engine_init    engine_init;
    volatile bool       halt;
    bool                allocated;
};

static inline void av_list_insert(struct stuff *conn, struct av_op *av_op)
{
    struct av_op        *cur;

    if (!(cur = conn->av_cur)) {
        av_op->next = av_op;
        av_op->prev = av_op;
        conn->av_cur = av_op;
    } else {
        av_op->next = cur;
        av_op->prev = cur->prev;
        cur->prev->next = av_op;
        cur->prev = av_op;
    }
}

static inline void av_list_remove(struct stuff *conn, struct av_op *av_op)
{
    if (av_op == conn->av_cur) {
        if (av_op->next == av_op) {
            conn->av_cur = NULL;
            return;
        }
        conn->av_cur = av_op->next;
    }
    av_op->prev->next = av_op->next;
    av_op->next->prev = av_op->prev;
}

static int engine_start(struct zhpeq *zq);

static inline void conn_wq_signal(struct stuff *conn, bool locked)
{
    /* Heavy as hell. */
    if (!locked)
        mutex_lock(&conn->wq_mutex);
    if (conn->wq_signal == conn->wq_signal_seen) {
        conn->wq_signal++;
        cond_broadcast(&conn->wq_cond);
    }
    if (!locked)
        mutex_unlock(&conn->wq_mutex);
}

static int stuff_free(struct stuff *stuff)
{
    int                 ret = 0;
    int                 rc;

    if (!stuff)
        goto done;

    switch (stuff->engine_init) {

    case ENGINE_WQ_THREAD_INIT:
        stuff->halt = true;
        conn_wq_signal(stuff, false);

        rc = -pthread_join(stuff->wq_thread, NULL);
        if (rc < 0) {
            print_func_err(__FUNCTION__, __LINE__, "pthread_join", "wq", rc);
            if (ret >= 0)
                ret = rc;
        }
        /* FALLTHROUGH */

    case ENGINE_WQ_COND_INIT:
        cond_destroy(&stuff->wq_cond);
        /* FALLTHROUGH */

    case ENGINE_WQ_MUTEX_INIT:
        mutex_destroy(&stuff->wq_mutex);
        /* FALLTHROUGH */

    default:
        break;
    }

    do_free(stuff->context);
    if (stuff->results_mr)
        fi_close(&stuff->results_mr->fid);
    do_free(stuff->results);
    fab_conn_free(&stuff->fab_conn);
    fab_conn_free(&stuff->fab_listener);

    if (stuff->allocated)
        free(stuff);

 done:
    return ret;
}

static int lfab_domain_free(struct zhpeq_dom *zdom)
{
    int                 ret = 0;
    struct zdom_data    *bdom = zdom->backend_data;

    if (!bdom)
        goto done;

    free(bdom->lcl_mr);
    ret = fab_conn_free(&bdom->fab_dom.fab_conn);
    free(bdom);
    zdom->backend_data = NULL;

 done:
    return ret;
}

static int lfab_domain(const union zhpeq_backend_params *params,
                       struct zhpeq_dom *zdom)
{
    int                 ret = -ENOMEM;
    const char          *provider = NULL;
    const char          *domain = NULL;
    struct zdom_data    *bdom;
    size_t              i;

    if (params) {
        provider = params->libfabric.provider_name;
        domain = params->libfabric.domain_name;
    }

    bdom = zdom->backend_data = do_calloc(1, sizeof(*bdom));
    if (!bdom)
        goto done;
    fab_dom_init(&bdom->fab_dom);
    bdom->lcl_mr = do_calloc(KEYTAB_SIZE, sizeof(*bdom->lcl_mr));
    if (!bdom->lcl_mr)
        goto done;
    bdom->lcl_mr_free.index = 1;
    for (i = 0; i < KEYTAB_SIZE - 1; i++)
        bdom->lcl_mr[i] = TO_PTR(((i + 1) << 1) | 1);
    bdom->lcl_mr[i] = TO_PTR(-1);

    ret = fab_av_domain(provider, domain, &bdom->fab_dom);
    if (ret < 0)
        goto done;

 done:

    return ret;
}

static struct stuff *stuff_alloc(struct fab_dom *dom)
{
    struct stuff        *ret = NULL;
    int                 err = 0;
    size_t              req;
    size_t              i;

    req = sizeof(*ret) + sizeof(*ret->rkey) * KEYTAB_SIZE;
    ret = do_calloc(1, req);
    if (!ret)
        goto done;
    ret->allocated = true;
    ret->rkey = (void *)ret + sizeof(*ret);
    ret->rkey_free.index = 0;
    for (i = 0; i < KEYTAB_SIZE - 1; i++)
        ret->rkey[i].rkey = i + 1;
    ret->rkey[i].rkey = FI_KEY_NOTAVAIL;
    fab_conn_init(dom, &ret->fab_conn);
    fab_conn_init(dom, &ret->fab_listener);

    /* Initalize pthreads structures. */
    mutex_init(&ret->wq_mutex, NULL);
    ret->engine_init = ENGINE_WQ_MUTEX_INIT;

    cond_init(&ret->wq_cond, NULL);
    ret->engine_init = ENGINE_WQ_COND_INIT;

 done:
    if (err < 0) {
        stuff_free(ret);
        ret = NULL;
        errno = -err;
    }

    return ret;
}

static int lfab_qalloc(struct zhpeq_dom *zdom, struct zhpeq *zq)
{
    int                 ret = -ENOMEM;
    struct zdom_data    *bdom = zdom->backend_data;
    struct stuff        *conn;
    struct fab_conn     *fab_conn;
    size_t              req;

    conn = stuff_alloc(&bdom->fab_dom);
    if (!conn)
        goto done;
    zq->backend_data = conn;
    fab_conn = &conn->fab_conn;

    ret = fab_ep_setup(fab_conn, NULL, 0, 0);
    if (ret < 0)
        goto done;

    ret = -ENOMEM;
    /* Build free list of context structures big enough for all I/Os. */
#if 0
    req = fab_conn->info->tx_attr->size;
    if (req > zq->info.qlen)
        req = zq->info.qlen;
#else
    /* FIXME: Looks like per-AV limit of 7. Need to handle this. */
    req = 7;
#endif
    conn->context = do_malloc(req * sizeof(*conn->context));
    if (!conn->context)
        goto done;
    while (req > 0) {
        req--;
        conn->context[req].opaque.internal[0] = conn->context_free;
        conn->context_free = &conn->context[req];
    }
    req = zq->info.qlen * sizeof(*conn->results);
    conn->results = do_malloc(req);
    if (!conn->results)
        goto done;
    ret = fi_mr_reg(fab_conn->domain, conn->results, req,
                    FI_READ | FI_WRITE, 0, 0, 0, &conn->results_mr, NULL);
    if (ret < 0) {
        conn->results_mr = NULL;
        print_func_fi_err(__FUNCTION__, __LINE__, "fi_mr_req", "", ret);
        goto done;
    }
    conn->results_desc = fi_mr_desc(conn->results_mr);

    ret = engine_start(zq);
    if (ret < 0)
        goto done;

 done:

    return ret;
}

static inline int do_av_op(struct stuff *conn, struct av_op *av_op)
{
    /* Do the work on the engine thread so it is single-threaded. */
    cond_init(&av_op->cond, NULL);
    mutex_lock(&conn->wq_mutex);
    av_list_insert(conn, av_op);
    conn_wq_signal(conn, true);
    cond_wait(&av_op->cond,  &conn->wq_mutex);
    mutex_unlock(&conn->wq_mutex);
    cond_destroy(&av_op->cond);

    return av_op->status;
}

static int lfab_open(struct zhpeq *zq, int sock_fd)
{
    int                 ret;
    struct stuff        *conn = zq->backend_data;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    struct av_op        av_op = {
        .status         = AV_OP_INSERT_INIT,
        .fi_addr        = FI_ADDR_UNSPEC,
    };

    ret = fab_av_xchg_addr(fab_conn, sock_fd, &av_op.ep_addr);
    if (ret < 0)
        goto done;
    ret = do_av_op(conn, &av_op);
    if (ret >= 0) {
        ret = av_op.fi_addr;
        if (av_op.fi_addr > AV_MAX) {
            print_err("%s,%u:av %lu exceeds AV_MAX %u\n",
                      __FUNCTION__, __LINE__, av_op.fi_addr, AV_MAX);
            ret = -FI_EINVAL;
        }
    }
 done:
    if (ret < 0 && av_op.fi_addr != FI_ADDR_UNSPEC) {
        av_op.status = AV_OP_REMOVE_INIT;
        (void)do_av_op(conn, &av_op);
    }

    return ret;
}

static int lfab_close(struct zhpeq *zq, int open_idx)
{
    struct stuff        *conn = zq->backend_data;
    struct av_op        av_op = {
        .status         = AV_OP_REMOVE_INIT,
        .fi_addr        = open_idx,
    };

    return do_av_op(conn, &av_op);
}

static inline void cq_write(struct zhpeq *zq, void *vcontext, int status)
{
    struct zhpe_hw_reg *reg = zq->reg;
    struct stuff        *conn = zq->backend_data;
    struct context      *context = vcontext;
    uint32_t            qmask = zq->info.qlen - 1;
    union zhpe_hw_cq_entry *cqe = zq->cq + (conn->cq_tail & qmask);

    lfabt_cmddone(context, cqe);

    cqe->entry.index = context->cmp_index;
    cqe->entry.status = (status < 0 ? ZHPEQ_CQ_STATUS_FABRIC_UNRECOVERABLE :
                         ZHPEQ_CQ_STATUS_SUCCESS);
    if (context->result)
        memcpy(cqe->entry.result.data, context->result->data,
               context->result_len);
    smp_wmb();
    /* The following two events can be seen out of order: don't care. */
    cqe->entry.valid = cq_valid(conn->cq_tail, qmask);
    conn->cq_tail++;
    reg->cq_tail  = (conn->cq_tail & qmask);
    /* Place context on free list. */
    context->opaque.internal[0] = conn->context_free;
    conn->context_free = context;
}

static void cq_update(void *arg, void *vcqe, bool err)
{
    struct fi_cq_entry  *cqe;
    struct fi_cq_err_entry *cqerr;

    if (err) {
        cqerr = vcqe;
        cq_write(arg, cqerr->op_context, -cqerr->err);
    } else {
        cqe = vcqe;
        cq_write(arg, cqe->op_context, 0);
    }
}

static int retry_none(void *args)
{
    /* No retry, will be returned to av_wait caller. */
    return 1;
}

static void *lfab_wq_start(void *voidzq)
{
    struct zhpeq        *zq = voidzq;
    struct zhpe_hw_reg  *reg = zq->reg;
    struct stuff        *conn = zq->backend_data;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    struct zdom_data    *bdom = zq->zdom->backend_data;
    struct fid_mr       **lcl_mr = bdom->lcl_mr;
    uint16_t            qmask = zq->info.qlen - 1;
    uint64_t            tx_queued = 0;
    uint64_t            tx_completed = 0;
    struct timespec     ts_beg = { 0, 0 };
    struct iovec        msg_iov;
    struct fi_rma_iov   rma_iov;
    void                *ldsc;
    struct fi_msg_rma   msg = {
        .msg_iov = &msg_iov,
        .desc = &ldsc,
        .iov_count = 1,
        .rma_iov = &rma_iov,
        .rma_iov_count = 1,
    };
    struct timespec     ts_end;
    uint64_t            queued;
    uint16_t            wq_head;
    uint16_t            wq_tail;
    union zhpe_hw_wq_entry *wqe;
    ssize_t             rc;
    uint64_t            laddr;
    uint64_t            raddr;
    struct fid_mr       *mr;
    uint64_t            flags;
    struct fi_ioc       atm_op_ioc = { .count = 1 };
    struct fi_ioc       atm_cmp_ioc = { .count = 1 };
    struct fi_ioc       atm_res_ioc = { .count = 1 };
    struct fi_rma_ioc   atm_rma_ioc = { .count = 1 };
    struct fi_msg_atomic atm_msg = {
        .msg_iov = &atm_op_ioc,
        .desc = &ldsc,
        .iov_count = 1,
        .rma_iov = &atm_rma_ioc,
        .rma_iov_count = 1,
    };
    struct context      *context;
    char                *sendbuf;
    struct av_op        *av_op;
    ZHPEQ_TIMING_CODE(struct zhpeq_timing_stamp lfabt_new);

    for (wq_head = reg->wq_head;;) {
        if (conn->halt)
            break;

        smp_rmb();
        /* We will process one entry's state each pass. */
        if ((av_op = atomic_load_lazy_ptr((void **)&conn->av_cur))) {

            switch (av_op->status) {

            case AV_OP_REMOVE_INIT:
                rc = fab_av_remove(fab_conn, av_op->fi_addr);
                av_op->status = 1;
                break;

            case AV_OP_INSERT_INIT:
                rc = fab_av_insert(fab_conn, &av_op->ep_addr, &av_op->fi_addr);
                if (rc < 0)
                    break;
                av_op->status--;
                /* FALLTHROUGH */
            case AV_OP_INSERT_INIT - 1:
                rc = fab_av_wait_send(fab_conn, av_op->fi_addr,
                                      retry_none, NULL);
                if (rc == 1 || rc < 0)
                    break;
                av_op->status--;
                /* FALLTHROUGH */
            case AV_OP_INSERT_INIT - 2:
                rc = fab_av_wait_recv(fab_conn, av_op->fi_addr,
                                      retry_none, NULL);
                if (rc == 1 || rc < 0)
                    break;
                av_op->status--;
                assert(av_op->status == 1);
                break;

            default:
                print_err("%s,%u:Invalid status %d\n",
                          __FUNCTION__, __LINE__, av_op->status);
                rc = -FI_EINVAL;
                break;

            }
            /* Complete the operation and/or rotate to the next entry. */
            mutex_lock(&conn->wq_mutex);
            if (rc < 0 || av_op->status == 1) {
                av_list_remove(conn, av_op);
                if (rc < 0)
                    av_op->status = rc;
                else
                    av_op->status = 0;
                cond_signal(&av_op->cond);
            } else
                conn->av_cur = av_op->next;
            mutex_unlock(&conn->wq_mutex);
        }

        for (queued = tx_queued, wq_tail = reg->wq_tail;
             (context = conn->context_free) && wq_head != wq_tail;
             wq_head = (wq_head + 1) & qmask) {

            ZHPEQ_TIMING_UPDATE_STAMP(&lfabt_new);

            conn->context_free = context ->opaque.internal[0];
            wqe = zq->wq + wq_head;
            context->result = NULL;
            context->cmp_index = wqe->hdr.cmp_index;

            /* Fences are now more compatible with libfabric: a fence bit
             * on an operation means it is not dispatched until all previous
             * operations are complete; however, we can't just rely on
             * the libfabric fence, since that is per endpoint and ours
             * are not. So, we must wait for all operations to complete.
             *
             * Completion does not guarantee delivery, but if the fence
             * works as advertised on a per-endpoint basis, we don't
             * care.
             */
            flags = 0;
            if (wqe->hdr.opcode & ZHPE_HW_OPCODE_FENCE) {
                flags = FI_FENCE;
                /* Wait for all outstanding operations to complete. */
                for (;;) {
                    rc = fab_completions(fab_conn->tx_cq, 0, cq_update, zq);
                    if (rc < 0)
                        goto done;
                    tx_completed += rc;
                    if (tx_queued == tx_completed)
                        break;
                    sched_yield();
                }
            }

            rc = 0;

            switch (wqe->hdr.opcode & ~ZHPE_HW_OPCODE_FENCE) {

            case ZHPE_HW_OPCODE_NOP:
                lfabt_cmdpost(nop, wqe, context);
                cq_write(zq, context, 0);
                break;

            case ZHPE_HW_OPCODE_PUT:
                msg.context = context;
                laddr = wqe->dma.lcl_addr;
                mr = lcl_mr[TO_KEYIDX(laddr)];
                /* Check if key unregistered. (Race handling.) */
                if ((uintptr_t)mr & 1) {
                    cq_write(zq, msg.context, -EINVAL);
                    break;
                }
                ldsc = fi_mr_desc(mr);
                msg_iov.iov_base = TO_PTR(TO_ADDR(laddr));
                msg_iov.iov_len = wqe->dma.len;
                rma_iov.len = wqe->dma.len;
                raddr = wqe->dma.rem_addr;
                rma_iov.addr = TO_ADDR(raddr);
                rma_iov.key = conn->rkey[TO_KEYIDX(raddr)].rkey;
                msg.addr = conn->rkey[TO_KEYIDX(raddr)].av_idx;
                lfabt_cmdpost(dma, wqe, context);
                rc = fi_writemsg(fab_conn->ep, &msg, flags);
                if (rc < 0) {
                    if (rc == -FI_EAGAIN)
                        break;
                    print_func_fi_err(__FUNCTION__, __LINE__,
                                      "fi_writemsg", "", rc);
                    cq_write(zq, context, rc);
                    break;
                }
                tx_queued++;
                break;

            case ZHPE_HW_OPCODE_GET:
                msg.context = context;
                laddr = wqe->dma.lcl_addr;
                mr = lcl_mr[TO_KEYIDX(laddr)];
                /* Check if key unregistered. (Race handling.) */
                if ((uintptr_t)mr & 1) {
                    cq_write(zq, context, -EINVAL);
                    break;
                }
                ldsc = fi_mr_desc(mr);
                msg_iov.iov_base = TO_PTR(TO_ADDR(laddr));
                msg_iov.iov_len = wqe->dma.len;
                rma_iov.len = wqe->dma.len;
                raddr = wqe->dma.rem_addr;
                rma_iov.addr = TO_ADDR(raddr);
                rma_iov.key = conn->rkey[TO_KEYIDX(raddr)].rkey;
                msg.addr = conn->rkey[TO_KEYIDX(raddr)].av_idx;
                lfabt_cmdpost(dma, wqe, context);
                rc = fi_readmsg(fab_conn->ep, &msg, flags);
                if (rc < 0) {
                    if (rc == -FI_EAGAIN)
                        break;
                    print_func_fi_err(__FUNCTION__, __LINE__,
                                      "fi_readmsg", "", rc);
                    cq_write(zq, context, rc);
                    break;
                }
                tx_queued++;
                break;

            case ZHPE_HW_OPCODE_PUTIMM:
                msg.context = context;
                /* No NULL descriptors! Use results buffer for sent data. */
                sendbuf = conn->results[context->cmp_index].data;
                memcpy(sendbuf, wqe->imm.data, wqe->imm.len);
                laddr = (uintptr_t)sendbuf;
                ldsc = conn->results_desc;
                msg_iov.iov_base = TO_PTR(TO_ADDR(laddr));
                msg_iov.iov_len = wqe->imm.len;
                rma_iov.len = wqe->imm.len;
                raddr = wqe->imm.rem_addr;
                rma_iov.addr = TO_ADDR(raddr);
                rma_iov.key = conn->rkey[TO_KEYIDX(raddr)].rkey;
                msg.addr = conn->rkey[TO_KEYIDX(raddr)].av_idx;
                lfabt_cmdpost(imm, wqe, context);
                rc = fi_writemsg(fab_conn->ep, &msg, flags);
                if (rc < 0) {
                    if (rc == -FI_EAGAIN)
                        break;
                    print_func_fi_err(__FUNCTION__, __LINE__,
                                      "fi_writemsg", "", rc);
                    cq_write(zq, context, rc);
                    break;
                }
                tx_queued++;
                break;

            case ZHPE_HW_OPCODE_GETIMM:
                msg.context = context;
                /* Return data in local results buffer. */
                context->result = &conn->results[context->cmp_index];
                context->result_len = wqe->imm.len;
                laddr = (uintptr_t)context->result->data;
                ldsc = conn->results_desc;
                msg_iov.iov_base = TO_PTR(TO_ADDR(laddr));
                msg_iov.iov_len = wqe->imm.len;
                rma_iov.len = wqe->imm.len;
                raddr = wqe->imm.rem_addr;
                rma_iov.addr = TO_ADDR(raddr);
                rma_iov.key = conn->rkey[TO_KEYIDX(raddr)].rkey;
                msg.addr = conn->rkey[TO_KEYIDX(raddr)].av_idx;
                lfabt_cmdpost(imm, wqe, context);
                rc = fi_readmsg(fab_conn->ep, &msg, flags);
                if (rc < 0) {
                    if (rc == -FI_EAGAIN)
                        break;
                    print_func_fi_err(__FUNCTION__, __LINE__,
                                      "fi_readmsg", "", rc);
                    cq_write(zq, context, rc);
                    break;
                }
                tx_queued++;
                break;

            case ZHPE_HW_OPCODE_ATM_ADD:
            case ZHPE_HW_OPCODE_ATM_CAS:
                atm_msg.context = context;
                /* Return data in local results buffer.
                 * No NULL descriptors! Use results buffer for sent data, too.
                 */
                context->result = &conn->results[context->cmp_index];
                sendbuf = context->result->data;
                if ((wqe->atm.size & ZHPE_HW_ATOMIC_SIZE_MASK) ==
                    ZHPE_HW_ATOMIC_SIZE_64) {
                    atm_msg.datatype = FI_UINT64;
                    context->result_len = sizeof(uint64_t);
                } else {
                    atm_msg.datatype = FI_UINT32;
                    context->result_len = sizeof(uint32_t);
                }
                memcpy(sendbuf, wqe->atm.operands, sizeof(wqe->atm.operands));
                laddr = (uintptr_t)sendbuf;
                ldsc = conn->results_desc;
                atm_op_ioc.addr = TO_PTR(TO_ADDR(laddr));
                atm_res_ioc.addr = atm_op_ioc.addr;
                atm_cmp_ioc.addr =
                    atm_op_ioc.addr + sizeof(wqe->atm.operands[0]);
                raddr = wqe->atm.rem_addr;
                atm_rma_ioc.addr = TO_ADDR(raddr);
                atm_rma_ioc.key = conn->rkey[TO_KEYIDX(raddr)].rkey;
                atm_msg.addr = conn->rkey[TO_KEYIDX(raddr)].av_idx;
                lfabt_cmdpost(atm, wqe, context);
                if ((wqe->hdr.opcode & ~ZHPE_HW_OPCODE_FENCE) !=
                    ZHPE_HW_OPCODE_ATM_ADD) {
                    atm_msg.op = FI_CSWAP;
                    rc = fi_compare_atomicmsg(
                        fab_conn->ep, &atm_msg, &atm_cmp_ioc, &ldsc, 1,
                        &atm_res_ioc, &conn->results_desc, 1, flags);
                } else {
                    atm_msg.op = FI_SUM;
                    rc = fi_fetch_atomicmsg(
                        fab_conn->ep, &atm_msg,
                        &atm_res_ioc, &conn->results_desc, 1, flags);
                }
                if (rc < 0) {
                    if (rc == -FI_EAGAIN)
                        break;
                    print_func_fi_errn(__FUNCTION__, __LINE__,
                                       "fi_atomicmsg", atm_msg.op, true, rc);
                    cq_write(zq, context, rc);
                    break;
                }
                tx_queued++;
                break;

            default:
                print_err("%s,%u:Unexpected opcode 0x%02x\n",
                          __FUNCTION__, __LINE__, wqe->hdr.opcode);
                goto done;
            }
            /* Get completions before retrying. */
            if (rc == -FI_EAGAIN)
                break;
        }
        /* Don't sleep while there are I/Os outstanding. */
        if (tx_queued != tx_completed) {
            rc = fab_completions(fab_conn->tx_cq, 0, cq_update, zq);
            if (rc < 0)
                goto done;
            tx_completed += rc;
            continue;
        }
        /* Time to sleep? */
        rc = gettime_raw(&ts_end);
        if (rc < 0)
            goto done;
        /* Reset the sleep clock if operations were started. */
        if (tx_queued != queued)
            ts_beg = ts_end;
        if (ts_delta(&ts_beg, &ts_end) < SLEEP_THRESHOLD_NS)
            continue;

        /* XXX: error handling? */
        reg->wq_head = wq_head;

        /* Go to sleep on the cond/mutex. */
        mutex_lock(&conn->wq_mutex);
        while (conn->wq_signal == conn->wq_signal_seen && !conn->av_cur) {
            ZHPEQ_TIMING_UPDATE_COUNT(&zhpeq_timing_tx_sleep);
            cond_wait(&conn->wq_cond,  &conn->wq_mutex);
        }
        conn->wq_signal_seen = conn->wq_signal;
        mutex_unlock(&conn->wq_mutex);
        /* Reset the sleep clock. */
        rc = gettime_raw(&ts_beg);
        if (rc < 0)
            goto done;
    }

done:
    /* FIXME: Problematic: orderly shutdown handshake needed in libfabric.
     * Key revocation needs to be skipped. Must deal with outstanding
     * av processing.
     */
#if 0
    /* Wait for all outstanding operations to complete. */
    for (;;) {
        rc = fab_completions(fab_conn->tx_cq, 0, cq_update, zq);
        if (rc < 0)
            goto done;
        tx_completed += rc;
        if (tx_queued == tx_completed)
            break;
        sched_yield();
    }
#endif

    return NULL;
}

static int engine_start(struct zhpeq *zq)
{
    int                 ret;
    struct stuff        *conn = zq->backend_data;

    ret = -pthread_create(&conn->wq_thread, NULL, lfab_wq_start, zq);
    if (ret < 0) {
        print_func_err(__FUNCTION__, __LINE__, "pthread_mutex_init",
                       "wq", ret);
        goto done;
    }
    conn->engine_init = ENGINE_WQ_THREAD_INIT;

 done:
    return ret;
}

static int lfab_lib_init(void)
{
    return 0;
}

static int lfab_qfree(struct zhpeq *zq)
{
    int                 ret = 0;

    if (zq)
        ret = stuff_free(zq->backend_data);

    return ret;
}

static int lfab_wq_signal(struct zhpeq *zq)
{
    struct stuff        *conn = zq->backend_data;

    conn_wq_signal(conn, false);

    return 0;
}

static ssize_t lfab_cq_poll(struct zhpeq *zq, size_t hint)
{
    return lfab_wq_signal(zq);
}

static void free_lcl_mr(struct zdom_data *bdom, uint32_t index)
{
    union free_index    old;
    union free_index    new;

    for (old.blob = bdom->lcl_mr_free.blob;;) {
        bdom->lcl_mr[index] = TO_PTR(old.index);
        new.index = (index << 1) | 1;
        new.seq = old.seq + 1;
        new.blob = __sync_val_compare_and_swap(&bdom->lcl_mr_free.blob,
                                               old.blob, new.blob);
        if (old.blob == new.blob)
            break;
        old.blob = new.blob;
    }
}

static int lfab_mr_reg(struct zhpeq_dom *zdom,
                       const void *buf, size_t len,
                       uint32_t access, struct zhpeq_key_data **kdata_out)
{
    int                 ret = -ENOMEM;
    struct zdom_data    *bdom = zdom->backend_data;
    struct fab_conn     *fab_conn = &bdom->fab_dom.fab_conn;
    struct zhpe_mr_desc_v1 *desc = NULL;
    uint64_t            fi_access = 0;
    struct fid_mr       *mr = NULL;
    union free_index    old;
    union free_index    new;
    uint32_t            index;

    desc = do_malloc(sizeof(*desc));
    if (!desc)
        goto done;
    if (access & ZHPEQ_MR_GET)
        fi_access |= FI_READ;
    if (access & ZHPEQ_MR_PUT)
        fi_access |= FI_WRITE;
    if (access & ZHPEQ_MR_GET_REMOTE)
        fi_access |= FI_REMOTE_READ;
    if (access & ZHPEQ_MR_PUT_REMOTE)
        fi_access |= FI_REMOTE_WRITE;
    ret = fi_mr_reg(fab_conn->domain, buf, len, fi_access, 0, 0, 0, &mr, NULL);
    if (ret < 0) {
        mr = NULL;
        goto done;
    }
    ret = -ENOSPC;
    for (old.blob = bdom->lcl_mr_free.blob;;) {
        if (old.index == FREE_END)
            goto done;
        index = old.index >> 1;
        new.index = (uintptr_t)bdom->lcl_mr[index];
        new.seq = old.seq + 1;
        new.blob = __sync_val_compare_and_swap(&bdom->lcl_mr_free.blob,
                                               old.blob, new.blob);
        if (old.blob == new.blob)
            break;
        old.blob = new.blob;
    }
    bdom->lcl_mr[index] = mr;
    desc->hdr.magic = ZHPE_MAGIC;
    desc->hdr.version = ZHPE_MR_V1;
    desc->kdata.vaddr = (uintptr_t)buf;
    desc->kdata.len = len;
    desc->kdata.zaddr = (((uint64_t)index << KEY_SHIFT) +
                         TO_ADDR(desc->kdata.vaddr));
    desc->kdata.access = access;
    desc->kdata.key = fi_mr_key(mr);
    *kdata_out = &desc->kdata;

    ret = 0;

 done:
    if (ret < 0) {
        if (mr)
            fi_close(&mr->fid);
        free(desc);
    }

    return ret;
}

static int lfab_mr_free(struct zhpeq_dom *zdom, struct zhpeq_key_data *kdata)
{
    int                 ret = -EINVAL;
    struct zdom_data    *bdom = zdom->backend_data;
    struct zhpe_mr_desc_v1 *desc = container_of(kdata, struct zhpe_mr_desc_v1,
                                                kdata);
    uint32_t            index = TO_KEYIDX(kdata->zaddr);

    if (desc->hdr.magic != ZHPE_MAGIC || desc->hdr.version != ZHPE_MR_V1)
        goto done;

    ret = fi_close(&bdom->lcl_mr[index]->fid);
    free_lcl_mr(bdom, index);
    do_free(desc);
    ret = 0;

 done:
    return ret;
}

static void free_conn_rkey(struct stuff *conn, uint32_t index)
{
    union free_index    old;
    union free_index    new;

    for (old.blob = conn->rkey_free.blob;;) {
        conn->rkey[index].rkey = old.index;
        new.index = index;
        new.seq = old.seq + 1;
        new.blob = __sync_val_compare_and_swap(&conn->rkey_free.blob, old.blob,
                                               new.blob);
        if (old.blob == new.blob)
            break;
        old.blob = new.blob;
    }
}

static int lfab_zmmu_import(struct zhpeq *zq, int open_idx,
                            const void *blob, size_t blob_len,
                            struct zhpeq_key_data **kdata_out)
{
    int                 ret = -EINVAL;
    struct stuff        *conn = zq->backend_data;
    const struct key_data_packed *pdata = blob;
    struct zhpe_mr_desc_v1 *desc = NULL;
    union free_index    old;
    union free_index    new;

    if (blob_len != sizeof(*pdata))
        goto done;

    ret = -ENOMEM;
    desc = do_malloc(sizeof(*desc));
    if (!desc)
        goto done;
    desc->hdr.magic = ZHPE_MAGIC;
    desc->hdr.version = ZHPE_MR_V1 | ZHPE_MR_REMOTE;
    unpack_kdata(pdata, &desc->kdata);

    ret = -ENOSPC;
    for (old.blob = conn->rkey_free.blob;;) {
        if (old.index == FREE_END)
            goto done;
        new.index = conn->rkey[old.index].rkey;
        new.seq = old.seq + 1;
        new.blob = __sync_val_compare_and_swap(&conn->rkey_free.blob, old.blob,
                                               new.blob);
        if (old.blob == new.blob)
            break;
        old.blob = new.blob;
    }
    conn->rkey[old.index].rkey = desc->kdata.zaddr;
    conn->rkey[old.index].av_idx = open_idx;
    desc->kdata.zaddr = (((uint64_t)old.index << KEY_SHIFT) +
                         TO_ADDR(desc->kdata.vaddr));
    *kdata_out = &desc->kdata;

    ret = 0;

 done:
    if (ret < 0)
        free(desc);

    return ret;
}

static int lfab_zmmu_free(struct zhpeq *zq, struct zhpeq_key_data *kdata)
{
    int                 ret = -EINVAL;
    struct stuff        *conn = zq->backend_data;
    struct zhpe_mr_desc_v1 *desc = container_of(kdata, struct zhpe_mr_desc_v1,
                                                kdata);
    uint32_t            index = TO_KEYIDX(kdata->zaddr);

    if (desc->hdr.magic != ZHPE_MAGIC ||
        desc->hdr.version != (ZHPE_MR_V1 | ZHPE_MR_REMOTE))
        goto done;

    free_conn_rkey(conn, index);
    do_free(desc);
    ret = 0;

 done:
    return ret;
}

static int lfab_zmmu_export(struct zhpeq *zq,
                            const struct zhpeq_key_data *kdata,
                            void **blob_out, size_t *blob_len)
{
    int                 ret = -EINVAL;
    struct zdom_data    *bdom = zq->zdom->backend_data;
    struct zhpe_mr_desc_v1 *desc = container_of(kdata, struct zhpe_mr_desc_v1,
                                                kdata);
    struct key_data_packed *blob = NULL;

    if (desc->hdr.magic != ZHPE_MAGIC || desc->hdr.version != ZHPE_MR_V1)
        goto done;

    ret = -ENOMEM;
    *blob_len = sizeof(*blob);
    blob = do_malloc(*blob_len);
    if (!blob)
        goto done;

    pack_kdata(&desc->kdata, blob,
               fi_mr_key(bdom->lcl_mr[TO_KEYIDX(kdata->zaddr)]));
    *blob_out = blob;

    ret = 0;

 done:
    return ret;
}

static void lfab_print_info(struct zhpeq *zq)
{
    struct fab_conn     *fab_conn = NULL;
    struct stuff        *conn;

    if (zq) {
        conn = zq->backend_data;
        fab_conn = &conn->fab_conn;
    }
    fab_print_info(fab_conn);
}

struct backend_ops libfabric_ops = {
    .lib_init           = lfab_lib_init,
    .domain             = lfab_domain,
    .domain_free        = lfab_domain_free,
    .qalloc             = lfab_qalloc,
    .qfree              = lfab_qfree,
    .open               = lfab_open,
    .close              = lfab_close,
    .wq_signal          = lfab_wq_signal,
    .cq_poll            = lfab_cq_poll,
    .mr_reg             = lfab_mr_reg,
    .mr_free            = lfab_mr_free,
    .zmmu_import        = lfab_zmmu_import,
    .zmmu_free          = lfab_zmmu_free,
    .zmmu_export        = lfab_zmmu_export,
    .print_info         = lfab_print_info,
};
