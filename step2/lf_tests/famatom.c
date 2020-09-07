/* Copyright (C) 2020 Hewlett Packard Enterprise Development LP.
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

#include <zhpeq_util_fab.h>
#include <zhpeq_util_fab_atomic.h>
#include <zhpeq.h>

#include <rdma/fi_ext_zhpe.h>

#define PROVIDER        "zhpe"
#define EP_TYPE         FI_EP_RDM
#define MR_MODE         (FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR)

#define BACKLOG         (10)

struct args {
    const char          *url;
    uint64_t            threads;
    uint64_t            ops;
    enum fi_progress    progress_mode;
    bool                seconds_mode;
};

union atomic_value {
    uint32_t            u32;
    uint64_t            u64;
};

struct atomic_sz {
    enum fi_datatype    type;
    uint64_t            type_mask;
    uint64_t            prev_mask;
};

struct context {
    struct fi_context2  ctx;
    union atomic_value operand0;
    union atomic_value operand1;
};

union ucontext {
    struct context      ctx;
    union ucontext      *next;
};

struct stuff {
    const struct args   *args;
    struct fab_dom      *fab_dom;
    struct fab_conn     fab_conn;
    fi_addr_t           dest_av;
    union ucontext      *ctx;
    union ucontext      *ctx_free;
    size_t              ctx_avail;
    size_t              ctx_cur;
    size_t              threadidx;
    pthread_t           thread;
    int                 status;
    uint64_t            ops;
    uint64_t            ops_done;
    /*
     * Obfuscation: gcc 9.2 is overly aggressive in detecting frees of
     * non-heap memory. I don't know how to tell it to stop.
     */
    void                (*free_me)(void *ptr);
};

struct atomic_op {
    enum fi_op          op;
    enum fi_datatype    type;
    uint64_t            off;
    uint64_t            operand0;
    uint64_t            operand1;
};

/* Assuming little endian for now. */

static struct atomic_op cli_sum_ops[] = {
    { FI_SUM, FI_UINT64, 0x00, 1, 0 },
    { FI_SUM, FI_UINT32, 0x08, 1, 0 },
    { FI_SUM, FI_UINT64, 0x10, 0x100000000UL, 0 },
    { FI_SUM, FI_UINT32, 0x18, 1, 0 },
    { FI_ATOMIC_OP_LAST },
};

#define CLI_SUM_OPS_SIZE (ARRAY_SIZE(cli_sum_ops) - 1)

#define SW_OFF          (0x20)

/* Visiblility to debugger. */
uint64_t                cli_sum_ops_size = CLI_SUM_OPS_SIZE;

static pthread_mutex_t  cli_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   cli_cond = PTHREAD_COND_INITIALIZER;
static struct fab_dom   cli_fab_dom0;
static struct stuff     *cli_conn0;
static struct fi_zhpe_ext_ops_v1 *cli_ext_ops;

static int update_error(int old, int new)
{
    return (old < 0 ? old : new);
}

static void ctx_free(struct stuff *conn, struct context *ctx)
{
    union ucontext      *uctx = (void *)ctx;

    uctx->next = conn->ctx_free;
    conn->ctx_free = uctx;
    conn->ctx_cur++;
}

static struct context *ctx_next(struct stuff *conn)
{
    struct context      *ret;
    union ucontext      *uctx;

    uctx = conn->ctx_free;
    ret = (void *)uctx;
    if (!ret)
        goto done;
    conn->ctx_free = uctx->next;
    conn->ctx_cur--;

 done:
    return ret;
}

static inline bool ctx_all_done(struct stuff *conn)
{
    return (conn->ctx_cur == conn->ctx_avail);
}

static void stuff_free(struct stuff *stuff)
{
    if (!stuff)
        return;

    fab_conn_free(&stuff->fab_conn);
    fab_dom_free(stuff->fab_dom);

    free(stuff->ctx);

    stuff->free_me(stuff);
}

static int do_mem_setup(struct stuff *conn)
{
    int                 ret = -EEXIST;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    struct fi_info      *info = fab_conn_info(fab_conn);
    size_t              req;
    size_t              i;

    conn->ctx_avail = info->tx_attr->size;
    req = sizeof(*conn->ctx) * conn->ctx_avail;
    ret = -posix_memalign((void **)&conn->ctx, page_size, req);
    if (ret < 0) {
        conn->ctx = NULL;
        print_func_errn(__func__, __LINE__, "posix_memalign", true, req, ret);
        goto done;
    }
    for (i = conn->ctx_avail; i > 0;)
        ctx_free(conn, &conn->ctx[--i].ctx);
    assert(ctx_all_done(conn));
 done:
    return ret;
}


static int do_fam_setup(struct stuff *conn)
{
    int                 ret;
    const struct args   *args = conn->args;
    struct fab_dom      *fab_dom = conn->fab_dom;
    struct sockaddr_zhpe *fam_sa;
    size_t              sa_len;

    /* Get ops vector */
    ret = fi_open_ops(&fab_dom->fabric->fid, FI_ZHPE_OPS_V1, 0,
                      (void **)&cli_ext_ops, NULL);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "fi_open_ops",
                           FI_ZHPE_OPS_V1, ret);
        goto done;
    }

    ret = cli_ext_ops->lookup(args->url, (void **)&fam_sa, &sa_len);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "ext_ops.lookup", args->url, ret);
        goto done;
    }
    ret = fi_av_insert(fab_dom->av, fam_sa, 1,  &conn->dest_av, 0, NULL);
    if (ret != 1) {
        print_err("%s,%u:fi_av_insert() returned %d\n",
                  __func__, __LINE__, ret);
        ret = -FI_EINVAL;
        goto done;
    }

done:

    return ret;
}

static void cq_update(void *vargs, void *vcqe, bool err)
{
    struct stuff        *conn = vargs;
    struct fi_cq_entry  *cqe = vcqe;
    struct fi_cq_err_entry *cqerr;

    ctx_free(conn, cqe->op_context);
    if (err) {
        cqerr = vcqe;
        conn->status = update_error(conn->status, -cqerr->err);
        print_err("%s,%u:I/O returned error %d:%s\n",
                  __func__, __LINE__, -cqerr->err, fi_strerror(cqerr->err));
    }
}

static ssize_t do_progress(struct stuff *conn)
{
    ssize_t             ret = 0;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    ssize_t             rc;

    /* Check both tx and rx sides to make progress.
     * FIXME: Should rx be necessary for one-sided?
     */
    rc = fab_completions(fab_conn->tx_cq, 0, cq_update, conn);
    ret = update_error(ret, rc);

    rc = fab_completions(fab_conn->rx_cq, 0, cq_update, conn);
    ret = update_error(ret, rc);
    ret = update_error(ret, conn->status);
    conn->status = 0;

    return ret;
}

static int do_wait_all(struct stuff *conn)
{
    int                 ret = 0;

    while (!ctx_all_done(conn)) {
        ret = do_progress(conn);
        if (ret < 0)
            break;
    }

    return ret;
}

static const char *type_str(enum fi_datatype type)
{
    switch (type) {

    case FI_UINT32:
        return "u32";

    case FI_UINT64:
        return "u64";

    default:
        return "BAD";
    }
}

static const char *op_str(enum fi_op op)
{
    switch (op) {

    case FI_ATOMIC_READ:
        return "rd";

    case FI_ATOMIC_WRITE:
        return "wr";

    case FI_BAND:
        return "band";

    case FI_BOR:
        return "bor";

    case FI_BXOR:
        return "bxor";

    case FI_CSWAP:
        return "cswap";

    default:
        return "BAD";
    }
}

static int cli_atomic(struct stuff *conn,
                      enum fi_op op, enum fi_datatype type, uint64_t off,
                      uint64_t operand0, uint64_t operand1, void *original)
{
    int                 ret = -FI_EAGAIN;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    struct context      *ctx;

    ctx = ctx_next(conn);
    if (!ctx)
        goto done;

    /*
     * The API requires us to guarantee that both operands are
     * stable for the duration of the call and that they be pointers to the
     * proper types.
     */

    switch (type) {

    case FI_UINT32:
        ctx->operand0.u32 = operand0;
        ctx->operand1.u32 = operand1;
        break;

    case FI_UINT64:
        ctx->operand0.u64 = operand0;
        ctx->operand1.u64 = operand1;
        break;

    default:
        ctx_free(conn, ctx);
        ret = -FI_EINVAL;
        goto done;
    }

    if (op >= FI_CSWAP)
        ret = fi_compare_atomic(fab_conn->ep, &ctx->operand1, 1, NULL,
                                &ctx->operand0, NULL, original, NULL,
                                conn->dest_av, off, 0, type, op, ctx);
    else if (original)
        ret = fi_fetch_atomic(fab_conn->ep, &ctx->operand0, 1, NULL,
                              original, NULL, conn->dest_av, 0, 0,
                              type, op, ctx);
    else
        ret = fi_atomic(fab_conn->ep, &ctx->operand0, 1, NULL, conn->dest_av,
                        0, 0, type, op, ctx);
    if (ret < 0) {
        if (ret != -FI_EAGAIN)
            print_func_errn(__func__, __LINE__, "fi_xxx_atomic", op,
                            false, ret);
        if (ctx)
            ctx_free(conn, ctx);
    } else
        conn->ops_done++;

 done:
    return ret;
}

static int cli_atomic_op(struct stuff *conn, struct atomic_op *op)
{
    return cli_atomic(conn, op->op, op->type, op->off, op->operand0,
                      op->operand1, NULL);
}

static int cli_atomic_original(struct stuff *conn,
                               enum fi_op op, enum fi_datatype type,
                               uint64_t off, uint64_t operand0,
                               uint64_t operand1, uint64_t *original)
{
    int                 ret;
    union atomic_value  orig;

    ret = cli_atomic(conn, op, type, off, operand0, operand1, &orig);
    if (ret < 0)
        goto done;
    ret = do_wait_all(conn);
    if (ret < 0)
        goto done;

    ret = zhpeu_fab_atomic_load(type, &orig, original);

 done:
    return ret;
}

/* NOTE: The result handling is different for the local case. */
static void lcl_atomic(struct stuff *conn,
                       enum fi_op op, enum fi_datatype type, void *dst,
                       uint64_t operand0, uint64_t operand1, uint64_t *original)
{
    int                 rc MAYBE_UNUSED;

    rc = zhpeu_fab_atomic_op(type, op, operand0, operand1, dst, original);
    assert(!rc);
}

static int cli_atomic_size_test1(struct stuff *conn, enum fi_op op,
                                 uint64_t operand0, uint64_t operand1,
                                 uint64_t start, uint64_t *end,
                                 struct atomic_sz *sz)
{
    int                 ret;
    uint64_t            lcl_result;
    uint64_t            lcl_fetched;
    uint64_t            rem_fetched;

    /*
     * Something to breakpoint on: moved this up here because
     * compiler/debugger are putting the function breakpoint in the wrong
     * place.
     */
    lcl_result = start;

    /*
     * Adjust the operand to preserve previous types' ops.
     * Adjust compare to deal with previous ops.
     */
    switch (op) {

    case FI_ATOMIC_READ:
        /* Nothing to do. */
        assert(operand0 == 0);
        assert(operand1 == 0);
        break;

    case FI_ATOMIC_WRITE:
        assert(operand1 == 0);
        break;

    case FI_BAND:
    case FI_BOR:
        assert(operand1 == 0);
        break;

    case FI_BXOR:
        assert(operand1 == 0);
        /* Zero out previous bits in operand. */
        operand0 &= ~sz->prev_mask;
        break;

    case FI_CSWAP:
        /* Account for previous op in compare. */
        operand0 = (operand0 & ~sz->prev_mask) | (start & sz->prev_mask);
        /* But make sure unused bits for the current size are wrong. */
        operand0 ^= ~sz->type_mask;
        break;

    default:
        ret = -FI_EINVAL;
        goto done;
    }

    lcl_atomic(conn, op, sz->type, &lcl_result, operand0, operand1,
               &lcl_fetched);
    ret = cli_atomic_original(conn, op, sz->type, SW_OFF, operand0, operand1,
                              &rem_fetched);
    if (ret < 0)
        goto done;

    ret = -FI_EINVAL;
    if (0 != (lcl_fetched & ~sz->type_mask)) {
        print_err("%s,%u:op %-4s type %-3s exp 0x%"PRIX64" saw 0x%"PRIX64"\n",
                  __func__, __LINE__, op_str(op), type_str(sz->type),
                  0UL, lcl_fetched & ~sz->type_mask);
        goto done;
    }
    if ((start & sz->type_mask) != (lcl_fetched & sz->type_mask)) {
        print_err("%s,%u:op %-4s type %-3s exp 0x%"PRIX64" saw 0x%"PRIX64"\n",
                  __func__, __LINE__, op_str(op), type_str(sz->type),
                  start & sz->type_mask, lcl_fetched & sz->type_mask);
        goto done;
    }
    if (lcl_fetched != rem_fetched) {
        print_err("%s,%u:op %-4s type %-3s exp 0x%"PRIX64" saw 0x%"PRIX64"\n",
                  __func__, __LINE__, op_str(op), type_str(sz->type),
                  lcl_fetched, rem_fetched);
        goto done;
    }

    start &= ~sz->type_mask;
    if (start != (lcl_result & ~sz->type_mask)) {
        print_err("%s,%u:op %-4s type %-3s exp 0x%"PRIX64" saw 0x%"PRIX64"\n",
                  __func__, __LINE__, op_str(op), type_str(sz->type),
                  start, lcl_result & ~sz->type_mask);
        goto done;
    }
    *end &= sz->type_mask;
    if (*end != (lcl_result & sz->type_mask)) {
        print_err("%s,%u:op %-4s type %-3s exp 0x%"PRIX64" saw 0x%"PRIX64"\n",
                  __func__, __LINE__, op_str(op), type_str(sz->type),
                  *end, lcl_result & sz->type_mask);
        goto done;
    }
    *end = lcl_result;
    ret = 0;

 done:
    return ret;
}

static int cli_atomic_size_test(struct stuff *conn, enum fi_op op,
                                uint64_t operand0, uint64_t operand1,
                                uint64_t start, uint64_t end)
{
    int                 ret;
    struct atomic_sz    sz[] = {
        { FI_UINT32, 0x00000000FFFFFFFFUL, 0x0000000000000000UL },
        { FI_UINT64, 0xFFFFFFFFFFFFFFFFUL, 0x00000000FFFFFFFFUL, },
    };
    size_t              i;
    uint64_t            val64;

    ret = cli_atomic_original(conn, FI_ATOMIC_READ, FI_UINT64, SW_OFF,
                              0, 0, &val64);
    if (ret < 0)
        goto done;
    if (start != val64) {
        print_err("%s,%u:op %-4s start 0x%"PRIX64" saw 0x%"PRIX64"\n",
                  __func__, __LINE__, op_str(op), start, val64);
        ret = -FI_EINVAL;
        goto done;
    }

    for (i = 0; i < ARRAY_SIZE(sz); i++) {
        val64 = end;
        ret = cli_atomic_size_test1(conn, op, operand0, operand1, start, &val64,
                                    &sz[i]);
        if (ret < 0)
            goto done;
        start = val64;
    }

    ret = cli_atomic_original(conn, FI_ATOMIC_READ, FI_UINT64, SW_OFF,
                              0, 0, &val64);
    if (ret < 0)
        goto done;
    if (end != val64) {
        print_err("%s,%u:op %-4s end 0x%"PRIX64" saw 0x%"PRIX64"\n",
                  __func__, __LINE__, op_str(op), end, val64);
        ret = -FI_EINVAL;
        goto done;
    }

 done:
    return ret;
}

static int cli_atomic_size_tests(struct stuff *conn)
{
    int                 ret;
    struct fi_zhpe_ep_counters counters = {
        .version        = FI_ZHPE_EP_COUNTERS_VERSION,
        .len            = sizeof(counters),
    };

    ret = cli_atomic_size_test(conn, FI_BOR,
                               0xFEDCBA9876543210UL, 0x0000000000000000UL,
                               0x0000000000000000UL, 0xFEDCBA9876543210UL);
    if (ret < 0)
        goto done;
    ret = cli_atomic_size_test(conn, FI_BAND,
                               0x8844221188442211UL, 0x0000000000000000UL,
                               0xFEDCBA9876543210UL, 0x8844221000442210UL);
    if (ret < 0)
        goto done;
    ret = cli_atomic_size_test(conn, FI_BXOR,
                               0xA5A5A5A5A5A5A5A5UL, 0x0000000000000000UL,
                               0x8844221000442210UL, 0x2DE187B5A5E187B5UL);
    if (ret < 0)
        goto done;
    ret = cli_atomic_size_test(conn, FI_CSWAP,
                               0x2DE187B5A5E187B5UL, 0xFEDCBA9876543210UL,
                               0x2DE187B5A5E187B5UL, 0xFEDCBA9876543210UL);
    if (ret < 0)
        goto done;
    ret = cli_atomic_size_test(conn, FI_ATOMIC_READ,
                               0x0000000000000000UL, 0x0000000000000000UL,
                               0xFEDCBA9876543210UL, 0xFEDCBA9876543210UL);
    if (ret < 0)
        goto done;
    ret = cli_atomic_size_test(conn, FI_ATOMIC_WRITE,
                               0x0000000100010101UL, 0x0000000000000000UL,
                               0xFEDCBA9876543210UL, 0x0000000100010101UL);
    if (ret < 0)
        goto done;

 done:
    return ret;
}

static int do_client_sum(struct stuff *conn)
{
    int                 ret = 0;
    const struct args   *args = conn->args;
    uint64_t            op_cnt = 0;
    struct atomic_op    *op = cli_sum_ops;
    uint64_t            start;

    if (conn->threadidx == 0) {
        /* Zero out test locations. */
        for (start = 0; start <= SW_OFF; start += sizeof(uint64_t)) {
            ret = cli_atomic(conn, FI_ATOMIC_WRITE, FI_UINT64, start,
                             0, 0, NULL);
            if (ret < 0) {
                assert_always(ret != -FI_EAGAIN);
                goto done;
            }
        }

        ret = cli_atomic_size_tests(conn);
        if (ret < 0)
            goto done;
    }

    start = get_cycles(NULL);
    for (;;) {
        if (args->seconds_mode) {
            if (get_cycles(NULL) - start >= conn->ops)
                break;
        } else if (op_cnt >= conn->ops)
            break;
        for (op = cli_sum_ops; op->op != FI_ATOMIC_OP_LAST;) {
            ret = do_progress(conn);
            if (ret < 0)
                break;
            ret = cli_atomic_op(conn, op);
            if (ret < 0) {
                if (ret == -FI_EAGAIN)
                    continue;
                break;
            }
            op++;
        }
        op_cnt++;
    }
    ret = update_error(ret, do_wait_all(conn));

 done:
    return ret;
}

static int do_client_sum_check(struct stuff *conn[], const struct args *args)
{
    int                 ret = 0;
    struct stuff        *conn0 = conn[0];
    uint64_t            results[CLI_SUM_OPS_SIZE];
    struct fi_zhpe_ep_counters counters = {
        .version        = FI_ZHPE_EP_COUNTERS_VERSION,
        .len            = sizeof(counters),
    };
    uint64_t            cli_ops = 0;
    size_t              i;
    uint64_t            off;

    /* Get thread ops. */
    for (i = 0; i < args->threads; i++) {
        cli_ops += conn[i]->ops_done;

        print_info("thread[%3lu]:cli_ops 0x%"PRIX64"\n",
                   i, conn[i]->ops_done);
    }

    for (i = 0; i < ARRAY_SIZE(cli_sum_ops) - 1; i++) {

        off = cli_sum_ops[i].off & ~(sizeof(uint64_t) - 1);
        ret = cli_atomic_original(conn0, FI_ATOMIC_READ, FI_UINT64, off, 0, 0,
                                  &results[i]);
        if (ret < 0)
            goto done;
        print_info("off 0x%02"PRIX64" result 0x%"PRIX64"\n", off, results[i]);
    }
    ret = 0;

 done:
    return ret;
}

static void *do_client_thread(void *vconn)
{
    int                 ret;
    struct stuff        *conn = vconn;
    const struct args   *args = conn->args;
    struct fab_dom      *fab_dom = conn->fab_dom;
    struct fab_conn     *fab_conn = &conn->fab_conn;

    if (conn->threadidx != 0) {
        /* Wait for thread 0 to initialize global state. */
        mutex_lock(&cli_mutex);
        while (!cli_conn0)
            cond_wait(&cli_cond, &cli_mutex);
        conn->dest_av = cli_conn0->dest_av;
        mutex_unlock(&cli_mutex);
    }

    if (conn->threadidx == 0) {
        ret = fab_dom_setupx(NULL, NULL, true, PROVIDER, NULL, EP_TYPE,
                             MR_MODE, args->progress_mode, fab_dom);
        if (ret < 0)
            goto done;
    }

    ret = fab_ep_setup(fab_conn, NULL, 0, 0);
    if (ret < 0)
        goto done;
    /* Allocate local memory. */
    ret = do_mem_setup(conn);
    if (ret < 0)
        goto done;
    if (conn->threadidx == 0) {
        ret = do_fam_setup(conn);
        if (ret < 0)
            goto done;
        /* Save our conn pointer as a flag for the other threads. */
        mutex_lock(&cli_mutex);
        cli_conn0 = conn;
        mutex_unlock(&cli_mutex);
        cond_broadcast(&cli_cond);
    }

    conn->ops = args->ops;
    if (args->seconds_mode)
        conn->ops *= get_tsc_freq();

    ret = do_client_sum(conn);

 done:
    conn->status = update_error(conn->status, ret);

    return NULL;
}

static int do_client(const struct args *args)
{
    int                 ret = 0;
    struct stuff        *conn[args->threads];
    size_t              i;
    void                *retval;
    int                 rc;

    for (i = 0; i < args->threads; i++)
        conn[i] = NULL;
    for (i = 0; i < args->threads; i++) {
        conn[i] = calloc(1, sizeof(*conn[i]));
        if (!conn[i]) {
            ret = -ENOMEM;
            break;
        }
        conn[i]->args = args;
        conn[i]->dest_av = FI_ADDR_UNSPEC;
        conn[i]->threadidx = i;
        conn[i]->free_me = free;
        conn[i]->fab_dom = &cli_fab_dom0;
        if (i == 0)
            fab_dom_init(&cli_fab_dom0);
        else
            atm_inc(&cli_fab_dom0.use_count);
        fab_conn_init(&cli_fab_dom0, &conn[i]->fab_conn);

        ret = -pthread_create(&conn[i]->thread, NULL, do_client_thread,
                              conn[i]);
        if (ret < 0) {
            stuff_free(conn[i]);
            conn[i] = NULL;
            break;
        }
    }
    for (i = 0; i < args->threads; i++) {
        if (!conn[i])
            break;
        if (ret < 0)
            (void)pthread_cancel(conn[i]->thread);
        rc = -pthread_join(conn[i]->thread, &retval);
        ret = update_error(ret, rc);
        if (rc < 0)
            continue;
        if (retval == PTHREAD_CANCELED) {
            ret = update_error(ret, -EINTR);
            continue;
        }
        ret = update_error(ret, conn[i]->status);
    }
    if (ret >= 0) {
        ret = do_client_sum_check(conn, args);
        if (ret < 0)
            goto done;
    }
    for (i = 0; i < args->threads; i++)
        stuff_free(conn[i]);
    ret = 0;

 done:
    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s [-ms] [-t <threads>] <url> <ops/seconds>\n"
        " -m : manual progress\n"
        " -s : interpet <ops> as seconds\n"
        " -t <threads> : number of client threads\n",
        appname);

    if (help) {
        printf("\n");
        fab_print_info(NULL);
    }

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = {
        .progress_mode  = FI_PROGRESS_AUTO,
    };
    int                 opt;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "msot:z")) != -1) {

        switch (opt) {

        case 'm':
            if (args.progress_mode != FI_PROGRESS_AUTO)
                usage(false);
            args.progress_mode = FI_PROGRESS_MANUAL;
            break;

        case 's':
            if (args.seconds_mode)
                usage(false);
            args.seconds_mode = true;
            break;

        case 't':
            if (args.threads)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "threads",
                                  optarg, &args.threads, 0, 1,
                                  SIZE_MAX, 0) < 0)
                usage(false);
            break;

        default:
            usage(false);

        }
    }

    opt = argc - optind;
    if (opt != 2)
        usage(false);

    if (!args.threads)
        args.threads = 1;
    args.url = argv[optind++];
    if (parse_kb_uint64_t(__func__, __LINE__, "ops",
                          argv[optind++], &args.ops, 0, 1,
                          SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
        usage(false);
    if (do_client(&args) < 0)
        goto done;

    ret = 0;

 done:
    return ret;
}
