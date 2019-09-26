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

STAILQ_HEAD(stailq_head, stailq_entry);

struct stailq_entry {
    STAILQ_ENTRY(stailq_entry) ptrs;
};

CIRCLEQ_HEAD(circleq_head, circleq_entry);

struct circleq_entry {
    CIRCLEQ_ENTRY(circleq_entry) ptrs;
};

struct rkey {
    uint64_t            rkey;
    uint64_t            av_idx;
};

struct zdom_data {
    struct fab_dom      *fab_dom;
    struct fid_mr       **lcl_mr;
    struct free_index   lcl_mr_free;
    struct rkey         *rkey;
    struct free_index   rkey_free;
};

enum engine_state {
    ENGINE_STOPPED,
    ENGINE_RUNNING,
};

/*
 * The sockets provider gets annoyed if you delete the listener before
 * deleting all the sockets derived from it. Seems stupid.
 */

/* A results structure with space for atomics operands. */
union results {
    char                data[ZHPE_IMM_MAX];
    uint32_t            operands32[2];
    uint64_t            operands64[2];
};

struct context {
    union {
        struct fi_context2  opaque;
        struct stailq_entry free_lentry;
    };
    struct fab_conn_plus *fab_plus;
    struct stuff        *conn;
    union results       *result;
    uint16_t            cmp_index;
    uint8_t             result_len;
#if ZHPE_IO_RECORD
    bool                done;
#endif
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

struct io_record {
    struct stuff        *conn;
    uint64_t            fi_addr;
    void                *buf;
    void                *desc;
    uint64_t            raddr;
    uint64_t            rkey;
    uint64_t            len;
    struct context      *context;
    uint8_t             op;
};

struct stuff {
    struct circleq_entry lentry;
    struct zhpeq        *zq;
    struct fab_conn_plus *fab_plus;
    uint64_t            tx_queued;
    uint64_t            tx_completed;
    struct iovec        msg_iov;
    struct fi_rma_iov   rma_iov;
    void                *ldsc;
    struct fi_msg_rma   msg;
    uint32_t            cq_tail;
    bool                allocated;
};

struct engine {
    struct zhpeu_work_head  work_head;
    pthread_t           thread;
    struct circleq_head zq_head;
    enum engine_state   state;
    bool                do_auto;
};

struct fab_conn_plus {
    struct fab_conn     *fab_conn;
    struct context      *context;
    size_t              context_entries;
    struct stailq_head  context_free;
    union results       *results;
    struct fid_mr       *results_mr;
    void                *results_desc;
};

/* A single engine thread, a single endpoint,and a single domain. */
static struct engine    eng;
static struct fab_dom   *one_dom;
static struct fab_conn_plus one_conn;

static void *lfab_eng_thread(void *veng);
static void cq_update(void *arg, void *vcqe, bool err);
static int stuff_free(struct stuff *stuff);
static inline void cq_write(void *vcontext, int status);

#ifdef ZHPE_IO_RECORD

static struct io_record io_rec[ZHPE_IO_RECORD] __attribute__((used));
static uint32_t         io_rec_idx;

static void
record_io_start(int rc, struct stuff *conn, uint64_t op, uint64_t fi_addr,
                void *buf, void *desc, uint64_t raddr, uint64_t rkey,
                uint64_t len, struct context *context)
{
    uint                idx;
    struct io_record    *io;

    if (rc == -FI_EAGAIN)
        return;

    idx = atm_inc(&io_rec_idx);
    io = &io_rec[idx & (ARRAY_SIZE(io_rec) - 1)];

    io->conn = conn;
    io->fi_addr = fi_addr;
    io->buf = buf;
    io->desc = desc;
    io->raddr = raddr;
    io->rkey = rkey;
    io->len = len;
    io->context = context;
    io->op = op;

    context->done = false;
}

static inline void record_io_done(struct context *context)
{
    context->done = true;
}

#else

static void
record_io_start(int rc, struct stuff *conn, uint64_t op, uint64_t fi_addr,
                void *buf, void *desc, uint64_t raddr, uint64_t rkey,
                uint64_t len, void *context)
{
}

static inline void record_io_done(struct context *context)
{
}
#endif

static int lfab_eng_work_queue(struct engine *eng, zhpeu_worker worker,
                               void *data)
{
    int                 ret = 0;
    struct zhpeu_work   work;

    zhpeu_work_init(&work);

    mutex_lock(&eng->work_head.thr_wait.mutex);

    if (eng->do_auto) {

        switch (eng->state) {

        case ENGINE_STOPPED:
            ret = -pthread_create(&eng->thread, NULL, lfab_eng_thread, eng);
            if (ret >= 0)
                eng->state = ENGINE_RUNNING;
            else
                print_func_err(__func__, __LINE__, "pthread_create",
                               "eng", ret);
            break;

        default:
            ret = 0;
            break;

        }
    }
    if (likely(ret >= 0)) {
        zhpeu_work_queue(&eng->work_head, &work, worker, data,
                        true, false, false);
        if (eng->do_auto)
            zhpeu_work_wait(&eng->work_head, &work, false, false);
        else
            while (zhpeu_work_process(&eng->work_head, false, false));

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
    struct stuff        *conn = data->conn;
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
     * mark all contexts associated with this conn so they won't generate
     * completions.
     */
    for (i = 0, context = conn->fab_plus->context;
         i < conn->fab_plus->context_entries; i++, context++) {
        if (context->conn == conn)
            context->conn = NULL;
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
    struct fab_conn     *fab_conn = conn->fab_plus->fab_conn;

    work->status = fab_av_remove(fab_conn->dom, data->fi_addr);

    return false;
}

static bool worker_av_op_recv(struct zhpeu_work_head *head,
                              struct zhpeu_work *work)
{
    struct lfab_work_av_op *data = work->data;
    struct stuff        *conn = data->conn;
    struct fab_conn     *fab_conn = conn->fab_plus->fab_conn;
    int                 rc;

    rc = fab_av_wait_recv(fab_conn, data->fi_addr, retry_none, NULL);
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
    struct fab_conn     *fab_conn = conn->fab_plus->fab_conn;
    int                 rc;

    rc = fab_av_wait_send(fab_conn, data->fi_addr, retry_none, NULL);
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
    struct fab_conn     *fab_conn = conn->fab_plus->fab_conn;
    int                 rc;

    rc = fab_av_insert(fab_conn->dom, &data->ep_addr, &data->fi_addr);
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

    rc = fab_conn_free(stuff->fab_plus->fab_conn);
    ret = (ret >= 0 ? rc : ret);

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
    struct fab_conn_plus *fab_plus = data;

    FI_CLOSE(fab_plus->results_mr);
    fab_plus->results_mr = NULL;
    free(fab_plus->context);
    fab_plus->context = NULL;
    free(fab_plus->results);
    fab_plus->results = NULL;
    free(fab_plus->fab_conn);
    fab_plus->fab_conn = NULL;
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
    bdom->lcl_mr[i] = TO_PTR(FREE_END);

    bdom->rkey = calloc_cachealigned(KEYTAB_SIZE, sizeof(*bdom->rkey));
    if (!bdom->rkey)
        goto done;
    bdom->rkey_free.index = 0;
    for (i = 0; i < KEYTAB_SIZE - 1; i++)
        bdom->rkey[i].rkey = i + 1;
    bdom->rkey[i].rkey = FI_KEY_NOTAVAIL;

    if (one_dom) {
        bdom->fab_dom = one_dom;
        atm_inc(&one_dom->use_count);
        ret = 0;
        goto done;
    }

    one_dom = fab_dom_alloc(onfree_one_dom, &one_dom);
    if (!one_dom)
            goto done;
    bdom->fab_dom = one_dom;
    ret = fab_dom_setup(NULL, NULL, false, backend_prov, backend_dom,
                        FI_EP_RDM, one_dom);
    if (ret < 0)
        goto done;

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
        page_up(ZHPE_XDM_QCM_CMPL_QUEUE_TAIL_TOGGLE_OFFSET + 8);
    zq->xqinfo.qcm.off = 0;
    zq->xqinfo.cmdq.ent = cmd_qlen;
    zq->xqinfo.cmdq.size = page_up(cmd_qlen * ZHPE_ENTRY_LEN);
    zq->xqinfo.cmdq.off = 0;
    zq->xqinfo.cmplq.ent = cmp_qlen;
    zq->xqinfo.cmplq.size = page_up(cmp_qlen * ZHPE_ENTRY_LEN);
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
    struct fab_conn_plus *fab_plus;
    size_t              req;
    struct context      *context;

    conn = stuff_alloc();
    if (!conn)
        goto done;
    zq->backend_data = conn;
    conn->zq = zq;
    fab_plus = conn->fab_plus = &one_conn;

    if (fab_plus->fab_conn) {
        ret = 0;
        atm_inc(&fab_plus->fab_conn->use_count);
        goto link;
    }
    fab_plus->fab_conn = fab_conn_alloc(bdom->fab_dom, onfree_one_conn,
                                        fab_plus);
    if (!fab_plus->fab_conn)
        goto done;
    ret = fab_ep_setup(fab_plus->fab_conn, NULL, 0, 0);
    if (ret < 0)
        goto done;

    /* Build free list of context structures big enough for all I/Os. */
    ret = -ENOMEM;
    fab_plus->context_entries =
        fab_plus->fab_conn->dom->finfo.info->tx_attr->size;

    req = fab_plus->context_entries * sizeof(*fab_plus->context);
    fab_plus->context = malloc_cachealigned(req);
    if (!fab_plus->context)
        goto done;

    req = fab_plus->context_entries * sizeof(*fab_plus->results);
    fab_plus->results = malloc_cachealigned(req);
    if (!fab_plus->results)
        goto done;
    ret = fi_mr_reg(fab_plus->fab_conn->dom->domain, fab_plus->results, req,
                    FI_READ | FI_WRITE, 0, 0, 0, &fab_plus->results_mr, NULL);
    if (ret < 0) {
        fab_plus->results_mr = NULL;
        print_func_fi_err(__func__, __LINE__, "fi_mr_req", "", ret);
        goto done;
    }
    fab_plus->results_desc = fi_mr_desc(fab_plus->results_mr);

    /* Initial contexts and free lists. */
    STAILQ_INIT(&fab_plus->context_free);
    for (req = 0, context = fab_plus->context;
         req < fab_plus->context_entries; req++, context++) {
        context->fab_plus = fab_plus;
        context->result = &fab_plus->results[req];
        context->result_len = 0;
        STAILQ_INSERT_TAIL(&fab_plus->context_free,
                           &context->free_lentry, ptrs);
    }

 link:
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

static int lfab_exchange(struct zhpeq *zq, int sock_fd, void *sa,
                         size_t *sa_len)
{
    int                 ret;
    struct stuff        *conn = zq->backend_data;
    struct fab_conn     *fab_conn = conn->fab_plus->fab_conn;

    ret = fab_av_xchg_addr(fab_conn, sock_fd, sa);
    if (ret >= 0)
        *sa_len = sockaddr_len(sa);

    return ret;
}

static int lfab_open(struct zhpeq *zq, void *sa)
{
    int                 ret;
    struct stuff        *conn = zq->backend_data;
    struct lfab_work_av_op data = {
        .conn           = conn,
        .fi_addr        = FI_ADDR_UNSPEC,
    };

    sockaddr_cpy(&data.ep_addr, sa);
    ret = lfab_eng_work_queue(&eng, worker_av_op_insert, &data);
    if (ret < 0)
        goto done;
    ret = data.fi_addr;
    if (data.fi_addr > AV_MAX) {
        print_err("%s,%u:av %lu exceeds AV_MAX %u\n",
                  __func__, __LINE__, data.fi_addr, AV_MAX);
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
    struct stuff        *conn;
    struct zhpeq        *zq;
    uint32_t            qmask;
    union zhpe_hw_cq_entry *cqe;

    record_io_done(context);

    conn = context->conn;
    if (!conn)
        goto done;

    zq = conn->zq;
    qmask = zq->xqinfo.cmplq.ent - 1;
    cqe = zq->cq + (conn->cq_tail & qmask);

    conn->tx_completed++;

    cqe->entry.index = context->cmp_index;
    cqe->entry.status = (status < 0 ? ZHPEQ_CQ_STATUS_FABRIC_UNRECOVERABLE :
                         ZHPEQ_CQ_STATUS_SUCCESS);
    if (context->result_len) {
        memcpy(cqe->entry.result.data, context->result->data,
               context->result_len);
        context->result_len = 0;
    }
    smp_wmb();
    /* The following two events can be seen out of order: do not care. */
    cqe->entry.valid = cq_valid(conn->cq_tail, qmask);
    conn->cq_tail++;
    iowrite64(conn->cq_tail & qmask,
              (char *)zq->qcm + ZHPE_XDM_QCM_CMPL_QUEUE_TAIL_TOGGLE_OFFSET);
 done:
    /* Place context on free list. */
    STAILQ_INSERT_TAIL(&context->fab_plus->context_free,
                       &context->free_lentry, ptrs);
}

static void cq_update(void *arg, void *vcqe, bool err)
{
    struct fi_cq_entry  *cqe;
    struct fi_cq_err_entry *cqerr;

    if (err) {
        cqerr = vcqe;
        /* sockets in 1.6.2 code may not provide context on error */
        assert(cqerr->op_context);
        cq_write(cqerr->op_context, -cqerr->err);
    } else {
        cqe = vcqe;
        cq_write(cqe->op_context, 0);
    }
}

static inline void cleanup_eagain(struct stuff *conn, struct context *context)
{
    conn->tx_queued--;
    /* Return context to head of free list. */
    STAILQ_INSERT_HEAD(&context->fab_plus->context_free,
                       &context->free_lentry, ptrs);
}

static bool lfab_zq(struct stuff *conn)
{
    struct zhpeq        *zq = conn->zq;
    struct fab_conn_plus *fab_plus = conn->fab_plus;
    struct fab_conn     *fab_conn = fab_plus->fab_conn;
    struct zdom_data    *bdom = zq->zdom->backend_data;
    struct fid_mr       **lcl_mr = bdom->lcl_mr;
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
    struct stailq_entry *stailq_entry;

    wq_head = (ioread64((char *)zq->qcm + ZHPE_XDM_QCM_CMD_QUEUE_HEAD_OFFSET) &
               qmask);
    smp_rmb();
    wq_tail = (ioread64((char *)zq->qcm + ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET) &
               qmask);
    for (; wq_head != wq_tail; wq_head = (wq_head + 1) & qmask) {

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

        if (STAILQ_EMPTY(&fab_plus->context_free))
            break;
        stailq_entry = STAILQ_FIRST(&fab_plus->context_free);
        STAILQ_REMOVE_HEAD(&fab_plus->context_free, ptrs);
        context = container_of(stailq_entry, struct context, free_lentry);
        context->conn = conn;
        context->cmp_index = wqe->hdr.cmp_index;

        conn->tx_queued++;

        switch (wqe->hdr.opcode & ~ZHPE_HW_OPCODE_FENCE) {

        case ZHPE_HW_OPCODE_NOP:
            cq_write(context, 0);
            break;

        case ZHPE_HW_OPCODE_PUT:
            conn->msg.context = context;
            laddr = wqe->dma.rd_addr;
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
            raddr = wqe->dma.wr_addr;
            conn->rma_iov.addr = TO_ADDR(raddr);
            conn->rma_iov.key = bdom->rkey[TO_KEYIDX(raddr)].rkey;
            conn->msg.addr = bdom->rkey[TO_KEYIDX(raddr)].av_idx;
            rc = fi_writemsg(fab_conn->ep, &conn->msg, flags);
            record_io_start(rc, conn, wqe->hdr.opcode, conn->msg.addr,
                            conn->msg.msg_iov[0].iov_base, conn->msg.desc[0],
                            conn->msg.rma_iov[0].addr, conn->msg.rma_iov[0].key,
                            conn->msg.msg_iov[0].iov_len, conn->msg.context);
            if (unlikely(rc < 0)) {
                if (rc == -FI_EAGAIN) {
                    cleanup_eagain(conn, context);
                    goto eagain;
                }
                print_func_fi_err(__func__, __LINE__,
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
            rc = fi_readmsg(fab_conn->ep, &conn->msg, flags);
            record_io_start(rc, conn, wqe->hdr.opcode, conn->msg.addr,
                            conn->msg.msg_iov[0].iov_base, conn->msg.desc[0],
                            conn->msg.rma_iov[0].addr, conn->msg.rma_iov[0].key,
                            conn->msg.msg_iov[0].iov_len, conn->msg.context);
            if (unlikely(rc < 0)) {
                if (rc == -FI_EAGAIN) {
                    cleanup_eagain(conn, context);
                    goto eagain;
                }
                print_func_fi_err(__func__, __LINE__,
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
            conn->ldsc = fab_plus->results_desc;
            conn->msg_iov.iov_base = TO_PTR(TO_ADDR(laddr));
            conn->msg_iov.iov_len = wqe->imm.len;
            conn->rma_iov.len = wqe->imm.len;
            raddr = wqe->imm.rem_addr;
            conn->rma_iov.addr = TO_ADDR(raddr);
            conn->rma_iov.key = bdom->rkey[TO_KEYIDX(raddr)].rkey;
            conn->msg.addr = bdom->rkey[TO_KEYIDX(raddr)].av_idx;
            rc = fi_writemsg(fab_conn->ep, &conn->msg, flags);
            record_io_start(rc, conn, wqe->hdr.opcode, conn->msg.addr,
                            conn->msg.msg_iov[0].iov_base, conn->msg.desc[0],
                            conn->msg.rma_iov[0].addr, conn->msg.rma_iov[0].key,
                            conn->msg.msg_iov[0].iov_len, conn->msg.context);
            if (unlikely(rc < 0)) {
                if (rc == -FI_EAGAIN) {
                    cleanup_eagain(conn, context);
                    goto eagain;
                }
                print_func_fi_err(__func__, __LINE__,
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
            conn->ldsc = fab_plus->results_desc;
            conn->msg_iov.iov_base = TO_PTR(TO_ADDR(laddr));
            conn->msg_iov.iov_len = wqe->imm.len;
            conn->rma_iov.len = wqe->imm.len;
            raddr = wqe->imm.rem_addr;
            conn->rma_iov.addr = TO_ADDR(raddr);
            conn->rma_iov.key = bdom->rkey[TO_KEYIDX(raddr)].rkey;
            conn->msg.addr = bdom->rkey[TO_KEYIDX(raddr)].av_idx;
            rc = fi_readmsg(fab_conn->ep, &conn->msg, flags);
            record_io_start(rc, conn, wqe->hdr.opcode, conn->msg.addr,
                            conn->msg.msg_iov[0].iov_base, conn->msg.desc[0],
                            conn->msg.rma_iov[0].addr, conn->msg.rma_iov[0].key,
                            conn->msg.msg_iov[0].iov_len, conn->msg.context);
            if (unlikely(rc < 0)) {
                if (rc == -FI_EAGAIN) {
                    cleanup_eagain(conn, context);
                    goto eagain;
                }
                print_func_fi_err(__func__, __LINE__,
                                  "fi_readmsg", "", rc);
                cq_write(context, rc);
                break;
            }
            break;

        default:
            cq_write(context, -EINVAL);
            print_err("%s,%u:Unexpected opcode 0x%02x\n",
                      __func__, __LINE__, wqe->hdr.opcode);
            goto done;
        }
    }
 eagain:
    /* Get completions. */
    (void)fab_completions(fab_conn->tx_cq, 0, cq_update, zq);

 done:
    iowrite64(wq_head, (char *)zq->qcm + ZHPE_XDM_QCM_CMD_QUEUE_HEAD_OFFSET);
    /* FIXME: Problematic: orderly shutdown handshake needed in libfabric.
     * Key revocation needs to be skipped. Must deal with outstanding
     * av processing.
     */

    return (conn->tx_queued != conn->tx_completed || wq_head != wq_tail);
}

static void *lfab_eng_thread(void *veng)
{
    struct engine       *eng = veng;
    bool                locked = false;
    struct timespec     ts_beg = { .tv_sec = 0 };
    struct timespec     ts_end;
    struct circleq_entry *circleq_entry;
    struct stuff        *conn;
    bool                outstanding;

    for (;;) {
        outstanding = false;
        /* Handle per-engine work. */
        if (locked || zhpeu_work_queued(&eng->work_head)) {
            outstanding |= zhpeu_work_process(&eng->work_head, !locked, true);
            locked = false;
        }
        /* Process all queues. */
        CIRCLEQ_FOREACH(circleq_entry, &eng->zq_head, ptrs) {
            conn = container_of(circleq_entry, struct stuff, lentry);
            outstanding |= lfab_zq(conn);
        }
        /* Don't sleep if there is outstanding work. */
        if (outstanding) {
            ts_beg.tv_sec = 0;
            continue;
        }
        /* Time to sleep? */
        clock_gettime_monotonic(&ts_end);
        if (!ts_beg.tv_sec) {
            /* Clock starts when we don't have any work. */
            ts_beg = ts_end;
            continue;
        }
        if (ts_delta(&ts_beg, &ts_end) < SLEEP_THRESHOLD_NS)
            continue;
        /* Signaled? */
        if (!zhpeu_thr_wait_sleep_fast(&eng->work_head.thr_wait))
            continue;
        /* Time to sleep. */
        (void)zhpeu_thr_wait_sleep_slow(&eng->work_head.thr_wait, -1,
                                        true, false);
        locked = true;
        ts_beg.tv_sec = 0;
    }

    return NULL;
}

static int lfab_lib_init(struct zhpeq_attr *attr)
{
    attr->backend = ZHPE_BACKEND_LIBFABRIC;
    attr->z.max_tx_queues = (1U << 10);
    attr->z.max_rx_queues = (1U << 10);
    attr->z.max_tx_qlen   = (1U << 16) - 1;
    attr->z.max_rx_qlen   = (1U << 20) - 1;
    attr->z.max_dma_len   = (1U << 31);

    zhpeu_work_head_init(&eng.work_head);
    CIRCLEQ_INIT(&eng.zq_head);

    return 0;
}

static int lfab_qfree_pre(struct zhpeq *zq)
{
    int                 ret = 0;
    struct lfab_work_qfree_pre data = {
        .conn           = zq->backend_data,
    };

    if (data.conn)
        ret = lfab_eng_work_queue(&eng, worker_qfree_pre, &data);
    zq->backend_data = NULL;

    return ret;
}

static int lfab_qfree(struct zhpeq *zq)
{
    return 0;
}

static int lfab_wq_signal(struct zhpeq *zq)
{
    struct circleq_entry *circleq_entry;
    struct stuff        *conn;

    if (eng.do_auto)
        zhpeu_thr_wait_signal(&eng.work_head.thr_wait);
    else {
        /* Process all queues. */
        mutex_lock(&eng.work_head.thr_wait.mutex);
        CIRCLEQ_FOREACH(circleq_entry, &eng.zq_head, ptrs) {
            conn = container_of(circleq_entry, struct stuff, lentry);
            lfab_zq(conn);
        }
        mutex_unlock(&eng.work_head.thr_wait.mutex);
    }

    return 0;
}

static ssize_t lfab_cq_poll(struct zhpeq *zq, size_t hint)
{
    return lfab_wq_signal(zq);
}

static void free_lcl_mr(struct zdom_data *bdom, uint32_t index)
{
    struct free_index   old;
    struct free_index   new;

    for (old = atm_load_rlx(&bdom->lcl_mr_free);;) {
        bdom->lcl_mr[index] = TO_PTR(old.index);
        new.index = (index << 1) | 1;
        new.seq = old.seq + 1;
        if (atm_cmpxchg(&bdom->lcl_mr_free, &old, new))
            break;
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
    struct fid_mr       *mr = NULL;
    struct lfab_work_fi_mr_reg data = {
        .domain         = fab_dom->domain,
        .buf            = buf,
        .len            = len,
        .mr_out         = &mr,
    };
    struct zhpeq_mr_desc_v1 *desc = NULL;
    struct zhpeq_key_data *qkdata;
    struct free_index   old;
    struct free_index   new;
    uint32_t            index;

    desc = malloc(sizeof(*desc));
    if (!desc)
        goto done;
    qkdata = &desc->qkdata;

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
    for (old = atm_load_rlx(&bdom->lcl_mr_free) ;;) {
        if (old.index == FREE_END)
            goto done;
        index = old.index >> 1;
        new.index = (uintptr_t)bdom->lcl_mr[index];
        new.seq = old.seq + 1;
        if (atm_cmpxchg(&bdom->lcl_mr_free, &old, new))
            break;
    }
    bdom->lcl_mr[index] = mr;

    access |= ZHPE_MR_INDIVIDUAL;
    desc->hdr.magic = ZHPE_MAGIC;
    desc->hdr.version = ZHPEQ_MR_V1;
    desc->hdr.zdom = zdom;
    qkdata->z.vaddr = (uintptr_t)buf;
    qkdata->z.len = len;
    qkdata->z.zaddr = ((uint64_t)index << KEY_SHIFT) + TO_ADDR(qkdata->z.vaddr);
    qkdata->laddr = qkdata->z.zaddr;
    qkdata->z.access = access;

    *qkdata_out = qkdata;
    ret = 0;

 done:
    if (ret < 0) {
        if (mr)
            (void)lfab_eng_work_queue(&eng, worker_fi_close, &mr->fid);
        free(desc);
    }

    return ret;
}

static int lfab_mr_free(struct zhpeq_key_data *qkdata)
{
    int                 ret = -EINVAL;
    struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, struct zhpeq_mr_desc_v1, qkdata);
    struct zdom_data    *bdom = desc->hdr.zdom->backend_data;
    uint32_t            index = TO_KEYIDX(qkdata->z.zaddr);

    ret = lfab_eng_work_queue(&eng, worker_fi_close, &bdom->lcl_mr[index]->fid);
    free_lcl_mr(bdom, index);

    return ret;
}

static void free_rkey(struct zdom_data *bdom, uint32_t index)
{
    struct free_index   old;
    struct free_index   new;

    for (old = atm_load_rlx(&bdom->rkey_free) ;;) {
        bdom->rkey[index].rkey = old.index;
        new.index = index;
        new.seq = old.seq + 1;
        if (atm_cmpxchg(&bdom->rkey_free, &old, new))
            break;
    }
}

static int lfab_zmmu_reg(struct zhpeq_key_data *qkdata)
{
    int                 ret = -ENOSPC;
    struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, struct zhpeq_mr_desc_v1, qkdata);
    struct zdom_data    *bdom = desc->hdr.zdom->backend_data;
    struct free_index   old;
    struct free_index   new;

    for (old = atm_load_rlx(&bdom->rkey_free) ;;) {
        if (old.index == FREE_END)
            goto done;
        new.index = bdom->rkey[old.index].rkey;
        new.seq = old.seq + 1;
        if (atm_cmpxchg(&bdom->rkey_free, &old, new))
            break;
    }
    bdom->rkey[old.index].rkey = qkdata->rsp_zaddr;
    bdom->rkey[old.index].av_idx = desc->open_idx;
    qkdata->z.zaddr = (((uint64_t)old.index << KEY_SHIFT) +
                       TO_ADDR(qkdata->z.vaddr));
    ret = 0;

 done:
    return ret;
}

static int lfab_zmmu_free(struct zhpeq_key_data *qkdata)
{
    struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, struct zhpeq_mr_desc_v1, qkdata);
    struct zdom_data    *bdom = desc->hdr.zdom->backend_data;

    free_rkey(bdom, TO_KEYIDX(qkdata->z.zaddr));

    return 0;
}

static int lfab_qkdata_export(const struct zhpeq_key_data *qkdata,
                              struct key_data_packed *blob)
{
    const struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, const struct zhpeq_mr_desc_v1, qkdata);
    struct zdom_data    *bdom = desc->hdr.zdom->backend_data;

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
        fab_conn = conn->fab_plus->fab_conn;
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

static int lfab_getaddr(struct zhpeq *zq, void *sa, size_t *sa_len)
{
    int                 ret;
    struct stuff        *conn = zq->backend_data;
    struct fab_conn     *fab_conn = conn->fab_plus->fab_conn;
    struct lfab_work_fi_getname data = {
        .fid            = &fab_conn->ep->fid,
        .buf            = sa,
        .len_inout      = sa_len,
    };
    size_t              olen = *sa_len;

    ret = lfab_eng_work_queue(&eng, worker_fi_getname, &data);
    if (ret >= 0) {
        if (!sockaddr_valid(sa, *sa_len, true))
            ret = -EAFNOSUPPORT;
        else if (*sa_len > olen)
            ret = -EOVERFLOW;
    }

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
    .exchange           = lfab_exchange,
    .open               = lfab_open,
    .close              = lfab_close,
    .wq_signal          = lfab_wq_signal,
    .cq_poll            = lfab_cq_poll,
    .mr_reg             = lfab_mr_reg,
    .mr_free            = lfab_mr_free,
    .qkdata_export      = lfab_qkdata_export,
    .zmmu_reg           = lfab_zmmu_reg,
    .zmmu_free          = lfab_zmmu_free,
    .print_info         = lfab_print_info,
    .getaddr            = lfab_getaddr,
};

void zhpeq_backend_libfabric_init(int fd)
{
    backend_prov = getenv("ZHPE_BACKEND_LIBFABRIC_PROV");
    backend_dom = getenv("ZHPE_BACKEND_LIBFABRIC_DOM");
    eng.do_auto = !!getenv("ZHPE_BACKEND_LIBFABRIC_AUTO");

    if (fd != -1 || !backend_prov)
        return;

    zhpeq_register_backend(ZHPE_BACKEND_LIBFABRIC, &ops);
}
