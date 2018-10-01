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

#define SLEEP_THRESHOLD_NS ((uint64_t)100000)
#define QFREE_THRESHOLD_NS ((uint64_t)1000000000)

#define AV_MAX          (16383)

#define KEY_SHIFT       47
#define KEY_MASK_ADDR   (((uint64_t)1 << KEY_SHIFT) - 1)
#define KEYTAB_SHIFT    (64 - KEY_SHIFT)
#define KEYTAB_SIZE     ((size_t)1 << KEYTAB_SHIFT)

#define TO_KEYIDX(_addr) ((_addr) >> KEY_SHIFT)
#define TO_ADDR(_addr)  ((_addr) & KEY_MASK_ADDR)

static const char       *backend_prov = NULL;
static const char       *backend_dom = NULL;

struct rkey {
    uint64_t            rkey;
    uint64_t            av_idx;
};

struct zdom_data {
    struct fab_dom      *fab_dom;
    struct fid_mr       **lcl_mr;
    union free_index    lcl_mr_free;
    struct rkey         *rkey;
    union free_index    rkey_free;
};

enum engine_state {
    ENGINE_STOPPED,
    ENGINE_RUNNING,
};

/*
 * The sockets provider gets annoyed if you delete the listener before
 * deleting all the sockets derived from it. Seems stupid.
 */

struct context {
    struct fi_context2  opaque;
    struct zhpeq        *zq;
    struct zhpe_result  *result;
    ZHPEQ_TIMING_CODE(struct zhpe_timing_stamp timestamp);
    uint16_t            cmp_index;
    uint8_t             result_len;
};

static inline void cq_write(void *vcontext, int status);

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

STAILQ_HEAD(stailq_head, stailq_entry);

struct stailq_entry {
    STAILQ_ENTRY(stailq_entry) ptrs;
};

CIRCLEQ_HEAD(circleq_head, circleq_entry);

struct circleq_entry {
    CIRCLEQ_ENTRY(circleq_entry) ptrs;
};

struct lfab_work_av_op {
    struct stuff        *conn;
    fi_addr_t           fi_addr;
    union sockaddr_in46 ep_addr;
};

struct lfab_work_fi_mr_reg {
    struct fid_domain   *domain;
    const void          *buf;
    size_t              len;
    uint64_t            access;
    struct fid_mr       **mr_out;
};

struct lfab_work_fi_getname {
    struct fid          *fid;
    void                *buf;
    size_t              *len_inout;
};

struct lfab_work_qfree_pre {
    struct stuff        *conn;
    uint64_t            tx_queued;
    uint64_t            tx_completed;
    struct timespec     ts_last;
};

struct stuff {
    struct zhpeq        *zq;
    struct circleq_entry lentry;
    struct fab_conn     *fab_conn;
    struct context      *context;
    struct context      *context_free;
    size_t              context_entries;
    struct zhpe_result  *results;
    struct fid_mr       *results_mr;
    void                *results_desc;
    uint64_t            tx_queued;
    uint64_t            tx_completed;
    struct iovec        msg_iov;
    struct fi_rma_iov   rma_iov;
    void                *ldsc;
    struct fi_msg_rma   msg;
    struct fi_ioc       atm_op_ioc;
    struct fi_ioc       atm_cmp_ioc;
    struct fi_ioc       atm_res_ioc;
    struct fi_rma_ioc   atm_rma_ioc;
    struct fi_msg_atomic atm_msg;
    uint32_t            cq_tail;
    bool                allocated;
};

struct engine {
    struct zhpeu_work_head  work_head;
    pthread_t           thread;
    struct circleq_head zq_head;
    enum engine_state   state;
};

/* A single engine thread, a single endpoint, and a single domain. */

static struct engine    eng;
static struct fab_dom   *one_dom;
static struct fab_conn  *one_conn;

static void *lfab_eng_thread(void *veng);
static void cq_update(void *arg, void *vcqe, bool err);
static int stuff_free(struct stuff *stuff);

static int lfab_eng_work_queue(struct engine *eng, zhpeu_worker worker,
                               void *data)
{
    int                 ret;
    struct zhpeu_work   work;

    zhpeu_work_init(&work);

    mutex_lock(&eng->work_head.thr_wait.mutex);

    switch (eng->state) {

    case ENGINE_STOPPED:
        ret = -pthread_create(&eng->thread, NULL, lfab_eng_thread, eng);
        if (ret >= 0)
            eng->state = ENGINE_RUNNING;
        else
            print_func_err(__FUNCTION__, __LINE__, "pthread_create",
                           "eng", ret);
        break;

    default:
        ret = 0;
        break;

    }
    if (likely(ret >= 0)) {
        zhpeu_work_queue(&eng->work_head, &work, worker, data,
                        true, false, false);
        zhpeu_work_wait(&eng->work_head, &work, false, false);
        ret = work.status;
    }
    mutex_unlock(&eng->work_head.thr_wait.mutex);

    zhpeu_work_destroy(&work);

    return ret;
}

static bool worker_qfree_pre(struct zhpeu_work_head *head,
                             struct zhpeu_work *work)
{
    struct lfab_work_qfree_pre *data = work->data;
    struct stuff        *conn = work->data;
    struct engine       *eng = container_of(head, struct engine, work_head);
    struct timespec     ts_now;
    struct context      *context;
    size_t              i;

    /* All operations done? */
    if (conn->tx_queued == conn->tx_completed)
        goto remove;
    /* First time? */
    clock_gettime_monotonic(&ts_now);
    if (!work->status) {
        /* Yes: snapshot initial state. */
        data->tx_queued = conn->tx_queued;
        data->tx_completed = conn->tx_completed;
        data->ts_last = ts_now;
        work->status = 1;
        return true;
    }
    /* Making progress? */
    if (data->tx_completed != conn->tx_completed) {
        /* Yes: are new I/Os being started? */
        if (conn->tx_queued == data->tx_queued) {
            /* No: update state. */
            data->tx_completed = conn->tx_completed;
            data->ts_last = ts_now;
            return true;
        }
        /* Yes, someone is breaking the rules: give up. */
    }
    /* No progress: 2ms timer expired? */
    else if (ts_delta(&data->ts_last, &ts_now) < 2 * NS_PER_SEC / MS_PER_SEC)
        /* No: keep trying. */
        return true;

    /* Give up and somewhat painfully clean up outstanding I/Os:
     * mark all contexts in the free list and then march through the
     * array and error out all the outstanding contexts.
     */
    for (context = conn->context_free; context;
         context = context->opaque.internal[0])
        context->zq = NULL;
    for (i = 0, context = conn->context; i < conn->context_entries;
         i++, context++) {
        if (context->zq) {
            cq_write(context, -EIO);
            context->zq = NULL;
            if (conn->tx_completed == conn->tx_queued)
                break;
        }
    }

 remove:
    /* Remove the conn from the engine thread. */
    CIRCLEQ_REMOVE(&eng->zq_head, &conn->lentry, ptrs);
    work->status = stuff_free(conn);

    return false;
}

static int retry_none(void *args)
{
    /* No retry, will be returned to av_wait caller. */
    return 1;
}

static bool worker_av_op_remove(struct zhpeu_work_head *head,
                                struct zhpeu_work *work)
{
    struct lfab_work_av_op *data = work->data;
    struct stuff        *conn = data->conn;

    work->status = fab_av_remove(conn->fab_conn->dom, data->fi_addr);

    return false;
}

static bool worker_av_op_recv(struct zhpeu_work_head *head,
                              struct zhpeu_work *work)
{
    struct lfab_work_av_op *data = work->data;
    struct stuff        *conn = data->conn;
    int                 rc;

    rc = fab_av_wait_recv(conn->fab_conn, data->fi_addr, retry_none, NULL);
    if (rc <= 0) {
        work->status = rc;
        return false;
    }

    return true;
}

static bool worker_av_op_send(struct zhpeu_work_head *head,
                              struct zhpeu_work *work)
{
    struct lfab_work_av_op *data = work->data;
    struct stuff        *conn = data->conn;
    int                 rc;

    rc = fab_av_wait_send(conn->fab_conn, data->fi_addr, retry_none, NULL);
    if (rc < 0) {
        work->status = rc;
        return false;
    }
    if (!rc)
        work->worker = worker_av_op_recv;

    return true;
}

static bool worker_av_op_insert(struct zhpeu_work_head *head,
                                struct zhpeu_work *work)
{
    struct lfab_work_av_op *data = work->data;
    struct stuff        *conn = data->conn;
    int                 rc;

    rc = fab_av_insert(conn->fab_conn->dom, &data->ep_addr, &data->fi_addr);
    if (rc) {
        work->status = (rc > 0 ? 0 : rc);
        return false;
    }
    work->worker = worker_av_op_send;

    return true;
}

static int stuff_free(struct stuff *stuff)
{
    int                 ret = 0;
    int                 rc;

    if (!stuff)
        goto done;

    rc = FI_CLOSE(stuff->results_mr);
    ret = (ret >= 0 ? rc : ret);
    rc = fab_conn_free(stuff->fab_conn);
    ret = (ret >= 0 ? rc : ret);
    free(stuff->context);
    free(stuff->results);

    if (stuff->allocated)
        free(stuff);

 done:
    return ret;
}

static bool worker_domain_free(struct zhpeu_work_head *head,
                               struct zhpeu_work *work)
{
    struct zdom_data    *bdom = work->data;

    work->status = fab_dom_free(bdom->fab_dom);
    free(bdom->lcl_mr);
    free(bdom->rkey);
    free(bdom);

    return false;
}

static int lfab_domain_free(struct zhpeq_dom *zdom)
{
    int                 ret = 0;
    struct zdom_data    *bdom = zdom->backend_data;

    if (zdom->backend_data) {
        zdom->backend_data = NULL;
        ret = lfab_eng_work_queue(&eng, worker_domain_free, bdom);
    }

    return ret;
}

static void onfree_one_dom(struct fab_dom *dom, void *data)
{
    *(void **)data = NULL;
    free(dom);
}

static void onfree_one_conn(struct fab_conn *conn, void *data)
{
    *(void **)data = NULL;
    free(conn);
}

static bool worker_domain(struct zhpeu_work_head *head,
                          struct zhpeu_work *work)
{
    int                 ret = -ENOMEM;
    struct zhpeq_dom    *zdom = work->data;
    struct zdom_data    *bdom;
    size_t              i;

    bdom = zdom->backend_data = calloc_cachealigned(1, sizeof(*bdom));
    if (!bdom)
        goto done;

    bdom->lcl_mr = calloc_cachealigned(KEYTAB_SIZE, sizeof(*bdom->lcl_mr));
    if (!bdom->lcl_mr)
        goto done;
    bdom->lcl_mr_free.index = 1;
    for (i = 0; i < KEYTAB_SIZE - 1; i++)
        bdom->lcl_mr[i] = TO_PTR(((i + 1) << 1) | 1);
    bdom->lcl_mr[i] = TO_PTR(-1);

    bdom->rkey = calloc_cachealigned(KEYTAB_SIZE, sizeof(*bdom->rkey));
    if (!bdom->rkey)
        goto done;
    bdom->rkey_free.index = 0;
    for (i = 0; i < KEYTAB_SIZE - 1; i++)
        bdom->rkey[i].rkey = i + 1;
    bdom->rkey[i].rkey = FI_KEY_NOTAVAIL;

    if (one_dom) {
        atomic_fetch_add(&one_dom->use_count, 1);
        ret = 0;
    } else {
        one_dom = fab_dom_alloc(onfree_one_dom, &one_dom);
        if (!one_dom)
            goto done;
        ret = fab_dom_setup(NULL, NULL, false, backend_prov, backend_dom,
                            FI_EP_RDM, one_dom);
        if (ret < 0)
            goto done;
    }
    bdom->fab_dom = one_dom;

 done:
    work->status = ret;

    return false;
}

static int lfab_domain(struct zhpeq_dom *zdom)
{
    return lfab_eng_work_queue(&eng, worker_domain, zdom);
}

static struct stuff *stuff_alloc(void)
{
    struct stuff        *ret = NULL;
    int                 err = 0;

    ret = calloc_cachealigned(1, sizeof(*ret));
    if (!ret)
        goto done;
    ret->allocated = true;

    ret->msg.msg_iov = &ret->msg_iov;
    ret->msg.desc = &ret->ldsc;
    ret->msg.iov_count = 1;
    ret->msg.rma_iov = &ret->rma_iov;
    ret->msg.rma_iov_count = 1;
    ret->atm_op_ioc.count = 1;
    ret->atm_cmp_ioc.count = 1;
    ret->atm_res_ioc.count = 1;
    ret->atm_rma_ioc.count = 1;
    ret->atm_msg.msg_iov = &ret->atm_op_ioc;
    ret->atm_msg.desc = &ret->ldsc;
    ret->atm_msg.iov_count = 1;
    ret->atm_msg.rma_iov = &ret->atm_rma_ioc;
    ret->atm_msg.rma_iov_count = 1;

 done:
    if (err < 0) {
        stuff_free(ret);
        ret = NULL;
        errno = -err;
    }

    return ret;
}

static int lfab_qalloc(struct zhpeq *zq, int cmd_qlen, int cmp_qlen,
                       int traffic_class, int priority, int slice_mask)
{
    /* Tell caller we don't have a driver. */
    zq->fd = -1;
    /* Use xqinfo for compatiblity with asic code. */
    zq->xqinfo.qcm.size =
        roundup64(ZHPE_XDM_QCM_CMPL_QUEUE_TAIL_TOGGLE_OFFSET + 8, page_size);
    zq->xqinfo.qcm.off = 0;
    zq->xqinfo.cmdq.ent = cmd_qlen;
    zq->xqinfo.cmdq.size = roundup64(cmd_qlen * ZHPE_ENTRY_LEN, page_size);
    zq->xqinfo.cmdq.off = 0;
    zq->xqinfo.cmplq.ent = cmp_qlen;
    zq->xqinfo.cmplq.size = roundup64(cmp_qlen * ZHPE_ENTRY_LEN, page_size);
    zq->xqinfo.cmplq.off = 0;

    return 0;
}

static bool worker_qalloc_post(struct zhpeu_work_head *head,
                               struct zhpeu_work *work)
{
    int                 ret = -ENOMEM;
    struct zhpeq        *zq = work->data;
    struct zhpeq_dom    *zdom = zq->zdom;
    struct zdom_data    *bdom = zdom->backend_data;
    struct engine       *eng = container_of(head, struct engine, work_head);
    struct stuff        *conn;
    struct fab_conn     *fab_conn;
    size_t              req;
    struct context      *context;

    conn = stuff_alloc();
    if (!conn)
        goto done;
    zq->backend_data = conn;
    conn->zq = zq;

    if (one_conn) {
        conn->fab_conn = one_conn;
        atomic_fetch_add(&one_conn->use_count, 1);
    } else {
        one_conn = fab_conn_alloc(bdom->fab_dom, onfree_one_conn, &one_conn);
        ret = fab_ep_setup(one_conn, NULL, 0, 0);
        if (ret < 0)
            goto done;
        ret = -ENOMEM;
    }
    fab_conn = conn->fab_conn = one_conn;

    /* Build free list of context structures big enough for all I/Os. */
    req = fab_conn->dom->finfo.info->tx_attr->size;
    if (req > zq->xqinfo.cmdq.ent)
        req = zq->xqinfo.cmdq.ent;
    conn->context_entries = req;

    req = conn->context_entries * sizeof(*conn->results);
    conn->results = malloc_cachealigned(req);
    if (!conn->results)
        goto done;
    ret = fi_mr_reg(fab_conn->dom->domain, conn->results, req,
                    FI_READ | FI_WRITE, 0, 0, 0, &conn->results_mr, NULL);
    if (ret < 0) {
        conn->results_mr = NULL;
        print_func_fi_err(__FUNCTION__, __LINE__, "fi_mr_req", "", ret);
        goto done;
    }
    conn->results_desc = fi_mr_desc(conn->results_mr);

    req = conn->context_entries * sizeof(*conn->context);
    conn->context = malloc_cachealigned(req);
    if (!conn->context)
        goto done;
    for (req = conn->context_entries; req > 0;) {
        req--;
        context = &conn->context[req];
        context->zq = zq;
        context->result = &conn->results[req];
        context->result_len = 0;
        context->opaque.internal[0] = conn->context_free;
        conn->context_free = context;
    }

    CIRCLEQ_INSERT_TAIL(&eng->zq_head, &conn->lentry, ptrs);

 done:
    if (ret < 0) {
        stuff_free(conn);
        zq->backend_data = NULL;
    }
    work->status = ret;

    return false;
}

static int lfab_qalloc_post(struct zhpeq *zq)
{
    return lfab_eng_work_queue(&eng, worker_qalloc_post, zq);
}


static int lfab_open(struct zhpeq *zq, int sock_fd)
{
    int                 ret;
    struct stuff        *conn = zq->backend_data;
    struct fab_conn     *fab_conn = conn->fab_conn;
    struct lfab_work_av_op data = {
        .conn           = conn,
        .fi_addr        = FI_ADDR_UNSPEC,
    };

    ret = fab_av_xchg_addr(fab_conn, sock_fd, &data.ep_addr);
    if (ret < 0)
        goto done;
    ret = lfab_eng_work_queue(&eng, worker_av_op_insert, &data);
    if (ret < 0)
        goto done;
    ret = data.fi_addr;
    if (data.fi_addr > AV_MAX) {
        print_err("%s,%u:av %lu exceeds AV_MAX %u\n",
                  __FUNCTION__, __LINE__, data.fi_addr, AV_MAX);
        (void)lfab_eng_work_queue(&eng, worker_av_op_remove, &data);
        ret = -ENOSPC;
    }

 done:

    return ret;
}

static int lfab_close(struct zhpeq *zq, int open_idx)
{
    struct stuff        *conn = zq->backend_data;
    struct lfab_work_av_op data = {
        .conn           = conn,
        .fi_addr        = open_idx,
    };

    return lfab_eng_work_queue(&eng, worker_av_op_remove, &data);
}

static inline void cq_write(void *vcontext, int status)
{
    struct context      *context = vcontext;
    struct zhpeq        *zq;
    struct stuff        *conn;
    uint32_t            qmask;
    union zhpe_hw_cq_entry *cqe;

    zq = context->zq;
    if (!zq)
        return;

    conn = zq->backend_data;
    qmask = zq->xqinfo.cmplq.ent - 1;
    cqe = zq->cq + (conn->cq_tail & qmask);

    conn->tx_completed++;
    lfabt_cmddone(context, cqe);

    cqe->entry.index = context->cmp_index;
    cqe->entry.status = (status < 0 ? ZHPEQ_CQ_STATUS_FABRIC_UNRECOVERABLE :
                         ZHPEQ_CQ_STATUS_SUCCESS);
    if (context->result_len) {
        memcpy(cqe->entry.result.data, context->result->data,
               context->result_len);
        context->result_len = 0;
    }
    smp_wmb();
    /* The following two events can be seen out of order: don't care. */
    cqe->entry.valid = cq_valid(conn->cq_tail, qmask);
    conn->cq_tail++;
    iowrite64(conn->cq_tail & qmask,
              zq->qcm + ZHPE_XDM_QCM_CMPL_QUEUE_TAIL_TOGGLE_OFFSET);
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
        cq_write(cqerr->op_context, -cqerr->err);
    } else {
        cqe = vcqe;
        cq_write(cqe->op_context, 0);
    }
}

static inline void cleanup_eagain(struct stuff *conn, struct context *context,
                                  uint64_t *tx_queued)
{
    /* Nothing got queued, but we don't want the engine to sleep. */
    conn->tx_queued--;
    if (conn->tx_queued == *tx_queued)
        (*tx_queued)--;
    /* Return context to free list. */
    context->opaque.internal[0] = conn->context_free;
    conn->context_free = context;
}

static bool lfab_zq(struct stuff *conn)
{
    struct zhpeq        *zq = conn->zq;
    struct fab_conn     *fab_conn = conn->fab_conn;
    struct zdom_data    *bdom = zq->zdom->backend_data;
    struct fid_mr       **lcl_mr = bdom->lcl_mr;
    uint64_t            tx_queued = conn->tx_queued;
    uint16_t            qmask = zq->xqinfo.cmdq.ent - 1;
    uint16_t            wq_head;
    uint16_t            wq_tail;
    union zhpe_hw_wq_entry *wqe;
    ssize_t             rc;
    uint64_t            laddr;
    uint64_t            raddr;
    struct fid_mr       *mr;
    uint64_t            flags;
    struct context      *context;
    char                *sendbuf;
    ZHPEQ_TIMING_CODE(struct zhpe_timing_stamp lfabt_new);

    wq_head = ioread64(zq->qcm + ZHPE_XDM_QCM_CMD_QUEUE_HEAD_OFFSET) & qmask;
    smp_rmb();
    wq_tail = ioread64(zq->qcm + ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET) & qmask;
    for (; (context = conn->context_free) && wq_head != wq_tail;
         wq_head = (wq_head + 1) & qmask) {

        /* We never expect to timestamp a fence. */
        ZHPEQ_TIMING_UPDATE_STAMP(&lfabt_new);

        wqe = zq->wq + wq_head;

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
            if (conn->tx_queued != conn->tx_completed) {
                (void)fab_completions(fab_conn->tx_cq, 0, cq_update, NULL);
                if (conn->tx_queued != conn->tx_completed)
                    goto done;
            }
        }

        conn->context_free = context->opaque.internal[0];
        context->cmp_index = wqe->hdr.cmp_index;

        conn->tx_queued++;

        switch (wqe->hdr.opcode & ~ZHPE_HW_OPCODE_FENCE) {

        case ZHPE_HW_OPCODE_NOP:
            lfabt_cmdpost(nop, wqe, context);
            cq_write(context, 0);
            break;

        case ZHPE_HW_OPCODE_PUT:
            conn->msg.context = context;
            laddr = wqe->dma.rd_addr;
            mr = lcl_mr[TO_KEYIDX(laddr)];
            /* Check if key unregistered. (Race handling.) */
            if ((uintptr_t)mr & 1) {
                cq_write(conn->msg.context, -EINVAL);
                break;
            }
            conn->ldsc = fi_mr_desc(mr);
            conn->msg_iov.iov_base = TO_PTR(TO_ADDR(laddr));
            conn->msg_iov.iov_len = wqe->dma.len;
            conn->rma_iov.len = wqe->dma.len;
            raddr = wqe->dma.wr_addr;
            conn->rma_iov.addr = TO_ADDR(raddr);
            conn->rma_iov.key = bdom->rkey[TO_KEYIDX(raddr)].rkey;
            conn->msg.addr = bdom->rkey[TO_KEYIDX(raddr)].av_idx;
            lfabt_cmdpost(dma, wqe, context);
            rc = fi_writemsg(fab_conn->ep, &conn->msg, flags);
            if (rc < 0) {
                if (rc == -FI_EAGAIN) {
                    cleanup_eagain(conn, context, &tx_queued);
                    goto eagain;
                }
                print_func_fi_err(__FUNCTION__, __LINE__,
                                  "fi_writemsg", "", rc);
                cq_write(context, rc);
                break;
            }
            break;

        case ZHPE_HW_OPCODE_GET:
            conn->msg.context = context;
            laddr = wqe->dma.wr_addr;
            mr = lcl_mr[TO_KEYIDX(laddr)];
            /* Check if key unregistered. (Race handling.) */
            if ((uintptr_t)mr & 1) {
                cq_write(context, -EINVAL);
                break;
            }
            conn->ldsc = fi_mr_desc(mr);
            conn->msg_iov.iov_base = TO_PTR(TO_ADDR(laddr));
            conn->msg_iov.iov_len = wqe->dma.len;
            conn->rma_iov.len = wqe->dma.len;
            raddr = wqe->dma.rd_addr;
            conn->rma_iov.addr = TO_ADDR(raddr);
            conn->rma_iov.key = bdom->rkey[TO_KEYIDX(raddr)].rkey;
            conn->msg.addr = bdom->rkey[TO_KEYIDX(raddr)].av_idx;
            lfabt_cmdpost(dma, wqe, context);
            rc = fi_readmsg(fab_conn->ep, &conn->msg, flags);
            if (rc < 0) {
                if (rc == -FI_EAGAIN) {
                    cleanup_eagain(conn, context, &tx_queued);
                    goto eagain;
                }
                print_func_fi_err(__FUNCTION__, __LINE__,
                                  "fi_readmsg", "", rc);
                cq_write(context, rc);
                break;
            }
            break;

        case ZHPE_HW_OPCODE_PUTIMM:
            conn->msg.context = context;
            /* No NULL descriptors! Use results buffer for sent data. */
            sendbuf = context->result->data;
            memcpy(sendbuf, wqe->imm.data, wqe->imm.len);
            laddr = (uintptr_t)sendbuf;
            conn->ldsc = conn->results_desc;
            conn->msg_iov.iov_base = TO_PTR(TO_ADDR(laddr));
            conn->msg_iov.iov_len = wqe->imm.len;
            conn->rma_iov.len = wqe->imm.len;
            raddr = wqe->imm.rem_addr;
            conn->rma_iov.addr = TO_ADDR(raddr);
            conn->rma_iov.key = bdom->rkey[TO_KEYIDX(raddr)].rkey;
            conn->msg.addr = bdom->rkey[TO_KEYIDX(raddr)].av_idx;
            lfabt_cmdpost(imm, wqe, context);
            rc = fi_writemsg(fab_conn->ep, &conn->msg, flags);
            if (rc < 0) {
                if (rc == -FI_EAGAIN) {
                    cleanup_eagain(conn, context, &tx_queued);
                    goto eagain;
                }
                print_func_fi_err(__FUNCTION__, __LINE__,
                                  "fi_writemsg", "", rc);
                cq_write(context, rc);
                break;
            }
            break;

        case ZHPE_HW_OPCODE_GETIMM:
            conn->msg.context = context;
            /* Return data in local results buffer. */
            context->result_len = wqe->imm.len;
            laddr = (uintptr_t)context->result->data;
            conn->ldsc = conn->results_desc;
            conn->msg_iov.iov_base = TO_PTR(TO_ADDR(laddr));
            conn->msg_iov.iov_len = wqe->imm.len;
            conn->rma_iov.len = wqe->imm.len;
            raddr = wqe->imm.rem_addr;
            conn->rma_iov.addr = TO_ADDR(raddr);
            conn->rma_iov.key = bdom->rkey[TO_KEYIDX(raddr)].rkey;
            conn->msg.addr = bdom->rkey[TO_KEYIDX(raddr)].av_idx;
            lfabt_cmdpost(imm, wqe, context);
            rc = fi_readmsg(fab_conn->ep, &conn->msg, flags);
            if (rc < 0) {
                if (rc == -FI_EAGAIN) {
                    cleanup_eagain(conn, context, &tx_queued);
                    goto eagain;
                }
                print_func_fi_err(__FUNCTION__, __LINE__,
                                  "fi_readmsg", "", rc);
                cq_write(context, rc);
                break;
            }
            break;

        case ZHPE_HW_OPCODE_ATM_ADD:
        case ZHPE_HW_OPCODE_ATM_CAS:
            conn->atm_msg.context = context;
            /* Return data in local results buffer.
             * No NULL descriptors! Use results buffer for sent data, too.
             */
            sendbuf = context->result->data;
            if ((wqe->atm.size & ZHPE_HW_ATOMIC_SIZE_MASK) ==
                ZHPE_HW_ATOMIC_SIZE_64) {
                conn->atm_msg.datatype = FI_UINT64;
                context->result_len = sizeof(uint64_t);
            } else {
                conn->atm_msg.datatype = FI_UINT32;
                context->result_len = sizeof(uint32_t);
            }
            memcpy(sendbuf, wqe->atm.operands, sizeof(wqe->atm.operands));
            laddr = (uintptr_t)sendbuf;
            conn->ldsc = conn->results_desc;
            conn->atm_op_ioc.addr = TO_PTR(TO_ADDR(laddr));
            conn->atm_res_ioc.addr = conn->atm_op_ioc.addr;
            conn->atm_cmp_ioc.addr =
                conn->atm_op_ioc.addr + sizeof(wqe->atm.operands[0]);
            raddr = wqe->atm.rem_addr;
            conn->atm_rma_ioc.addr = TO_ADDR(raddr);
            conn->atm_rma_ioc.key = bdom->rkey[TO_KEYIDX(raddr)].rkey;
            conn->atm_msg.addr = bdom->rkey[TO_KEYIDX(raddr)].av_idx;
            lfabt_cmdpost(atm, wqe, context);
            if ((wqe->hdr.opcode & ~ZHPE_HW_OPCODE_FENCE) !=
                ZHPE_HW_OPCODE_ATM_ADD) {
                conn->atm_msg.op = FI_CSWAP;
                rc = fi_compare_atomicmsg(fab_conn->ep, &conn->atm_msg,
                                          &conn->atm_cmp_ioc, &conn->ldsc, 1,
                                          &conn->atm_res_ioc,
                                          &conn->results_desc, 1, flags);
            } else {
                conn->atm_msg.op = FI_SUM;
                rc = fi_fetch_atomicmsg(fab_conn->ep, &conn->atm_msg,
                                        &conn->atm_res_ioc,
                                        &conn->results_desc, 1, flags);
            }
            if (rc < 0) {
                if (rc == -FI_EAGAIN) {
                    cleanup_eagain(conn, context, &tx_queued);
                    goto eagain;
                }
                print_func_fi_errn(__FUNCTION__, __LINE__,
                                   "fi_atomicmsg", conn->atm_msg.op, true, rc);
                cq_write(context, rc);
                break;
            }
            break;

        default:
            cq_write(context, -EINVAL);
            print_err("%s,%u:Unexpected opcode 0x%02x\n",
                      __FUNCTION__, __LINE__, wqe->hdr.opcode);
            goto done;
        }
    }
 eagain:
    /* Get completions. */
    (void)fab_completions(fab_conn->tx_cq, 0, cq_update, zq);

 done:
    iowrite64(wq_head, zq->qcm + ZHPE_XDM_QCM_CMD_QUEUE_HEAD_OFFSET);
    /* FIXME: Problematic: orderly shutdown handshake needed in libfabric.
     * Key revocation needs to be skipped. Must deal with outstanding
     * av processing.
     */

    return (conn->tx_queued != tx_queued);
}

static void *lfab_eng_thread(void *veng)
{
    struct engine       *eng = veng;
    struct timespec     ts_beg = { 0, 0 };
    bool                locked = false;
    struct timespec     ts_end;
    struct circleq_entry *circleq_entry;
    struct stuff        *conn;
    bool                queued;
    bool                outstanding;
    int                 rc;

    for (;;) {
        queued = false;
        outstanding = false;
        /* Handle per-engine work. */
        if (locked || STAILQ_FIRST(&eng->work_head.work_list)) {
            outstanding |= zhpeu_work_process(&eng->work_head, !locked, true);
            locked = false;
        }
        /* Process all queues. */
        CIRCLEQ_FOREACH(circleq_entry, &eng->zq_head, ptrs) {
            conn = container_of(circleq_entry, struct stuff, lentry);
            queued |= lfab_zq(conn);
            outstanding |= (conn->tx_queued != conn->tx_completed);
        }
        /* Dont' sleep if there are outstanding I/Os. */
        if (outstanding)
            continue;
        /* Time to sleep? */
        clock_gettime_monotonic(&ts_end);
        /* Reset the sleep clock if operations were started. */
        if (queued) {
            ts_beg = ts_end;
            continue;
        }
        if (ts_delta(&ts_beg, &ts_end) < SLEEP_THRESHOLD_NS)
            continue;
        /* Signaled? */
        if (!zhpeu_thr_wait_sleep_fast(&eng->work_head.thr_wait))
            continue;
        /* Time to sleep. */
        rc = zhpeu_thr_wait_sleep_slow(&eng->work_head.thr_wait, -1,
                                       true, false);
        assert(pthread_mutex_trylock(&eng->work_head.thr_wait.mutex) == EBUSY);
        locked = true;
        if (rc <= 0)
            ZHPEQ_TIMING_UPDATE_COUNT(&zhpeq_timing_tx_sleep);
        /* Reset the sleep clock. */
        clock_gettime_monotonic(&ts_beg);
    }

    return NULL;
}

static int lfab_lib_init(struct zhpeq_attr *attr)
{
    attr->backend = ZHPE_BACKEND_LIBFABRIC;
    attr->z.max_tx_queues = 1024;
    attr->z.max_rx_queues = 1024;
    attr->z.max_hw_qlen  = 65535;
    attr->z.max_sw_qlen  = 65535;
    attr->z.max_dma_len  = (1U << 31);

    zhpeu_work_head_init(&eng.work_head);
    CIRCLEQ_INIT(&eng.zq_head);

    return 0;
}

static int lfab_qfree_pre(struct zhpeq *zq)
{
    int                 ret = 0;
    struct stuff        *conn = zq->backend_data;

    if (conn)
        ret = lfab_eng_work_queue(&eng, worker_qfree_pre, conn);
    zq->backend_data = NULL;

    return ret;
}

static int lfab_qfree(struct zhpeq *zq)
{
    return 0;
}

static int lfab_wq_signal(struct zhpeq *zq)
{
    if (zhpeu_thr_wait_signal_fast(&eng.work_head.thr_wait))
        zhpeu_thr_wait_signal_slow(&eng.work_head.thr_wait, true, true);
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

static bool worker_fi_close(struct zhpeu_work_head *head,
                            struct zhpeu_work *work)
{
    struct fid          *fid = work->data;

    work->status = fi_close(fid);

    return false;
}

static bool worker_fi_mr_reg(struct zhpeu_work_head *head,
                             struct zhpeu_work *work)
{
    struct lfab_work_fi_mr_reg *data = work->data;

    work->status = fi_mr_reg(data->domain, data->buf, data->len, data->access,
                             0, 0, 0, data->mr_out, NULL);
    if (work->status < 0)
        *data->mr_out = NULL;

    return false;
}

static int lfab_mr_reg(struct zhpeq_dom *zdom,
                       const void *buf, size_t len,
                       uint32_t access, struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -ENOMEM;
    struct zdom_data    *bdom = zdom->backend_data;
    struct fab_dom      *fab_dom = bdom->fab_dom;
    struct zhpeq_mr_desc_v1 *desc = NULL;
    struct fid_mr       *mr = NULL;
    struct lfab_work_fi_mr_reg data = {
        .domain         = fab_dom->domain,
        .buf            = buf,
        .len            = len,
        .mr_out         = &mr,
    };
    union free_index    old;
    union free_index    new;
    uint32_t            index;

    desc = malloc(sizeof(*desc));
    if (!desc)
        goto done;
    if (access & ZHPEQ_MR_GET)
       data.access |= FI_READ;
    if (access & ZHPEQ_MR_PUT)
        data.access |= FI_WRITE;
    if (access & ZHPEQ_MR_GET_REMOTE)
        data.access |= FI_REMOTE_READ;
    if (access & ZHPEQ_MR_PUT_REMOTE)
        data.access |= FI_REMOTE_WRITE;
    ret = lfab_eng_work_queue(&eng, worker_fi_mr_reg, &data);
    if (ret < 0)
        goto done;

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
    desc->hdr.version = ZHPEQ_MR_V1;
    desc->qkdata.z.vaddr = (uintptr_t)buf;
    desc->qkdata.z.len = len;
    desc->qkdata.z.zaddr = (((uint64_t)index << KEY_SHIFT) +
                            TO_ADDR(desc->qkdata.z.vaddr));
    desc->qkdata.laddr = desc->qkdata.z.zaddr;
    desc->qkdata.z.access = access;
    *qkdata_out = &desc->qkdata;

    ret = 0;

 done:
    if (ret < 0) {
        if (mr)
            (void)lfab_eng_work_queue(&eng, worker_fi_close, &mr->fid);
        free(desc);
    }

    return ret;
}

static int lfab_mr_free(struct zhpeq_dom *zdom, struct zhpeq_key_data *qkdata)
{
    int                 ret = -EINVAL;
    struct zdom_data    *bdom = zdom->backend_data;
    struct zhpeq_mr_desc_v1 *desc = container_of(qkdata,
                                                 struct zhpeq_mr_desc_v1,
                                                 qkdata);
    uint32_t            index = TO_KEYIDX(qkdata->z.zaddr);

    if (desc->hdr.magic != ZHPE_MAGIC || desc->hdr.version != ZHPEQ_MR_V1)
        goto done;

    ret = lfab_eng_work_queue(&eng, worker_fi_close, &bdom->lcl_mr[index]->fid);
    free_lcl_mr(bdom, index);
    free(desc);

 done:
    return ret;
}

static void free_rkey(struct zdom_data *bdom, uint32_t index)
{
    union free_index    old;
    union free_index    new;

    for (old.blob = bdom->rkey_free.blob;;) {
        bdom->rkey[index].rkey = old.index;
        new.index = index;
        new.seq = old.seq + 1;
        new.blob = __sync_val_compare_and_swap(&bdom->rkey_free.blob, old.blob,
                                               new.blob);
        if (old.blob == new.blob)
            break;
        old.blob = new.blob;
    }
}

static int lfab_zmmu_import(struct zhpeq_dom *zdom, int open_idx,
                            const void *blob, size_t blob_len,
                            bool cpu_visible,
                            struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -EINVAL;
    struct zdom_data    *bdom = zdom->backend_data;
    const struct key_data_packed *pdata = blob;
    struct zhpeq_mr_desc_v1 *desc = NULL;
    union free_index    old;
    union free_index    new;

    if (blob_len != sizeof(*pdata) || cpu_visible)
        goto done;

    ret = -ENOMEM;
    desc = malloc(sizeof(*desc));
    if (!desc)
        goto done;
    desc->hdr.magic = ZHPE_MAGIC;
    desc->hdr.version = ZHPEQ_MR_V1 | ZHPEQ_MR_REMOTE;
    unpack_kdata(pdata, &desc->qkdata);

    ret = -ENOSPC;
    for (old.blob = bdom->rkey_free.blob;;) {
        if (old.index == FREE_END)
            goto done;
        new.index = bdom->rkey[old.index].rkey;
        new.seq = old.seq + 1;
        new.blob = __sync_val_compare_and_swap(&bdom->rkey_free.blob, old.blob,
                                               new.blob);
        if (old.blob == new.blob)
            break;
        old.blob = new.blob;
    }
    bdom->rkey[old.index].rkey = desc->qkdata.z.zaddr;
    bdom->rkey[old.index].av_idx = open_idx;
    desc->qkdata.z.zaddr = (((uint64_t)old.index << KEY_SHIFT) +
                            TO_ADDR(desc->qkdata.z.vaddr));
    *qkdata_out = &desc->qkdata;

    ret = 0;

 done:
    if (ret < 0)
        free(desc);

    return ret;
}

static int lfab_zmmu_free(struct zhpeq_dom *zdom, struct zhpeq_key_data *qkdata)
{
    int                 ret = -EINVAL;
    struct zdom_data    *bdom = zdom->backend_data;
    struct zhpeq_mr_desc_v1 *desc = container_of(qkdata,
                                                 struct zhpeq_mr_desc_v1,
                                                 qkdata);
    uint32_t            index = TO_KEYIDX(qkdata->z.zaddr);

    if (desc->hdr.magic != ZHPE_MAGIC ||
        desc->hdr.version != (ZHPEQ_MR_V1 | ZHPEQ_MR_REMOTE))
        goto done;

    free_rkey(bdom, index);
    free(desc);
    ret = 0;

 done:
    return ret;
}

static int lfab_zmmu_export(struct zhpeq_dom *zdom,
                            const struct zhpeq_key_data *qkdata,
                            void *blob, size_t *blob_len)
{
    struct zdom_data    *bdom = zdom->backend_data;

    if (*blob_len < sizeof(struct key_data_packed))
        return -EINVAL;

    *blob_len = sizeof(struct key_data_packed);
    pack_kdata(qkdata, blob,
               fi_mr_key(bdom->lcl_mr[TO_KEYIDX(qkdata->z.zaddr)]));

    return 0;
}

static void lfab_print_info(struct zhpeq *zq)
{
    struct fab_conn     *fab_conn = NULL;
    struct stuff        *conn;

    if (zq) {
        conn = zq->backend_data;
        fab_conn = conn->fab_conn;
    }
    fab_print_info(fab_conn);
}

static bool worker_fi_getname(struct zhpeu_work_head *head,
                              struct zhpeu_work *work)
{
    struct lfab_work_fi_getname *data = work->data;

    work->status = fi_getname(data->fid, data->buf, data->len_inout);

    return false;
}

static int lfab_getaddr(struct zhpeq *zq, union sockaddr_in46 *sa)
{
    int                 ret;
    struct stuff        *conn = zq->backend_data;
    struct fab_conn     *fab_conn = conn->fab_conn;
    size_t              sa_len = sizeof(*sa);
    struct lfab_work_fi_getname data = {
        .fid            = &fab_conn->ep->fid,
        .buf            = sa,
        .len_inout      = &sa_len,
    };

    ret = lfab_eng_work_queue(&eng, worker_fi_getname, &data);
    if (ret >= 0 && !sockaddr_valid(sa, sa_len, true))
        ret = -EAFNOSUPPORT;

    return ret;
}

static struct backend_ops ops = {
    .lib_init           = lfab_lib_init,
    .domain             = lfab_domain,
    .domain_free        = lfab_domain_free,
    .qalloc             = lfab_qalloc,
    .qalloc_post        = lfab_qalloc_post,
    .qfree_pre          = lfab_qfree_pre,
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
    .getaddr            = lfab_getaddr,
};

void zhpeq_backend_libfabric_init(int fd)
{
    backend_prov = getenv("ZHPE_BACKEND_LIBFABRIC_PROV");
    backend_dom = getenv("ZHPE_BACKEND_LIBFABRIC_DOM");

    if (fd != -1)
        return;

    zhpeq_register_backend(ZHPE_BACKEND_LIBFABRIC, &ops);
}
