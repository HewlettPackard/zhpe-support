/* Copyright (C) 2019-2020 Hewlett Packard Enterprise Development LP.
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

#define BACKLOG         (10)
#ifdef DEBUG
#define TIMEOUT         (-1)
#else
#define TIMEOUT         (10000)
#endif

/* As global variables for debugger */
static int              timeout = TIMEOUT;

struct cli_wire_msg {
    uint64_t            mr_mode;
    uint32_t            progress_mode;
    bool                once_mode;
};

struct mem_wire_msg {
    uint64_t            remote_key;
    uint64_t            remote_addr;
    uint64_t            bad_key;
    uint64_t            bad_addr;
};

struct svr_op_wire_msg {
    uint64_t            ops;
    uint64_t            val0;
};

struct args {
    const char          *node;
    const char          *service;
    uint64_t            threads;
    uint64_t            ops;
    uint64_t            mr_mode;
    enum fi_progress    progress_mode;
    bool                once_mode;
    bool                seconds_mode;
};

union atomic_value {
    uint8_t             u8;
    uint16_t            u16;
    uint32_t            u32;
    uint64_t            u64;
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

static void free_dummy(void *ptr)
{
}

struct stuff {
    const struct args   *args;
    struct fab_dom      *fab_dom;
    struct fab_conn     fab_conn;
    struct fab_mrmem    bad_mrmem;
    fi_addr_t           dest_av;
    union ucontext      *ctx;
    union ucontext      *ctx_free;
    size_t              ctx_avail;
    size_t              ctx_cur;
    struct mem_wire_msg rem;
    size_t              threadidx;
    pthread_t           thread;
    int                 sock_fd;
    int                 status;
    uint64_t            ops;
    uint64_t            ops_done;
    uint64_t            expected_cli;
    uint64_t            expected_hw;
    /*
     * Obfuscation: gcc 9.2 is overly aggressive in detecting frees of
     * non-heap memory. I don't know how to tell it to stop.
     */
    void                (*free_me)(void *ptr);
    bool                server;
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
/* Visiblility to debugger. */
uint64_t                cli_sum_ops_size = CLI_SUM_OPS_SIZE;

static struct atomic_op svr_sum_ops[] = {
    { FI_SUM, FI_UINT64, 0x00, 1, 0 },
    { FI_SUM, FI_UINT32, 0x08, 1, 0 },
    { FI_SUM, FI_UINT32, 0x10, 1, 0 },
    { FI_SUM, FI_UINT64, 0x18, 0x100000000UL, 0 },
    { FI_ATOMIC_OP_LAST },
};

#define SW_OFF          (0x20)

static pthread_mutex_t  cli_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   cli_cond = PTHREAD_COND_INITIALIZER;
static struct fab_dom   cli_fab_dom0;
static struct stuff     *cli_conn0;
static struct fi_zhpe_ext_ops_v1 *cli_ext_ops;

static void expected_ops(struct stuff *conn, int64_t cli, uint64_t hw)
{
    conn->expected_cli += cli;
    if (zhpeq_is_asic())
        conn->expected_hw += hw;
}

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

    fab_mrmem_free(&stuff->bad_mrmem);
    fab_conn_free(&stuff->fab_conn);
    fab_dom_free(stuff->fab_dom);

    free(stuff->ctx);

    FD_CLOSE(stuff->sock_fd);

    stuff->free_me(stuff);
}

static int do_mem_setup(struct stuff *conn)
{
    int                 ret = -EEXIST;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    struct fi_info      *info = fab_conn_info(fab_conn);
    size_t              req;
    size_t              i;

    /*
     * Server needs one context and one registered page; client needs a
     * context for tx entry and no registered memory.
     */
    conn->ctx_avail = info->tx_attr->size;
    if (conn->server) {
        conn->ctx_avail = 1;
        req = page_size;
        ret = fab_mrmem_alloc(fab_conn, &fab_conn->mrmem, req, 0);
        if (ret < 0)
            goto done;
        ret = fab_mrmem_alloc(fab_conn, &conn->bad_mrmem, req, FI_READ);
        if (ret < 0)
            goto done;
        memset(fab_conn->mrmem.mem, 0, req);
        memset(conn->bad_mrmem.mem, 0, req);
    }
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

static int do_mem_xchg(struct stuff *conn)
{
    int                 ret;
    const struct args   *args = conn->args;
    struct fab_conn     *fab_conn = &conn->fab_conn;

    if (conn->server) {
        conn->rem.remote_key = htobe64(fi_mr_key(fab_conn->mrmem.mr));
        conn->rem.bad_key = htobe64(fi_mr_key(conn->bad_mrmem.mr));
        if (args->mr_mode & FI_MR_VIRT_ADDR) {
            conn->rem.remote_addr = htobe64((uintptr_t)fab_conn->mrmem.mem);
            conn->rem.bad_addr = htobe64((uintptr_t)conn->bad_mrmem.mem);
        } else {
            conn->rem.remote_addr = be64toh(0);
            conn->rem.bad_addr = be64toh(0);
        }

        ret = sock_send_blob(conn->sock_fd, &conn->rem, sizeof(conn->rem));
        if (ret < 0)
            goto done;
    } else {
        ret = sock_recv_fixed_blob(conn->sock_fd, &conn->rem,
                                   sizeof(conn->rem));
        if (ret < 0)
            goto done;

        conn->rem.remote_key = be64toh(conn->rem.remote_key);
        conn->rem.remote_addr = be64toh(conn->rem.remote_addr);
        conn->rem.bad_key = be64toh(conn->rem.bad_key);
        conn->rem.bad_addr = be64toh(conn->rem.bad_addr);
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

    case FI_UINT8:
        return "u8";

    case FI_UINT16:
        return "u16";

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

    case FI_MSWAP:
        return "mswap";

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

    case FI_UINT8:
        ctx->operand0.u8 = operand0;
        ctx->operand1.u8 = operand1;
        break;

    case FI_UINT16:
        ctx->operand0.u16 = operand0;
        ctx->operand1.u16 = operand1;
        break;

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
                                conn->dest_av, conn->rem.remote_addr + off,
                                conn->rem.remote_key, type, op, ctx);
    else if (original)
        ret = fi_fetch_atomic(fab_conn->ep, &ctx->operand0, 1, NULL,
                              original, NULL, conn->dest_av,
                              conn->rem.remote_addr + off, conn->rem.remote_key,
                              type, op, ctx);
    else
        ret = fi_atomic(fab_conn->ep, &ctx->operand0, 1, NULL, conn->dest_av,
                        conn->rem.remote_addr + off, conn->rem.remote_key,
                        type, op, ctx);
    if (ret < 0) {
        print_func_errn(__func__, __LINE__, "fi_xxx_atomic", op, false, ret);
        if (ctx)
            ctx_free(conn, ctx);
    } else
        conn->ops_done++;

 done:
    return ret;
}

static int cli_bad_test(struct stuff *conn, const char *lbl, enum fi_op op)
{
    int                 ret = 0;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    uint64_t            result;
    struct context      *ctx;

    /*
     * The API requires us to guarantee the compare and operand are
     * stable for the duration of the call and that they be pointers to the
     * proper types.
     */
    ctx = ctx_next(conn);
    if (!ctx) {
        ret = -FI_EAGAIN;
        goto done;
    }
    ctx->operand0.u64 = 1;
    ret = fi_fetch_atomic(fab_conn->ep, &ctx->operand0, 1, NULL,
                          &result, NULL, conn->dest_av,
                          conn->rem.bad_addr, conn->rem.bad_key,
                          FI_UINT64, op, ctx);
    if (ret) {
        ctx_free(conn, ctx);
        if (ret > 0) {
            print_err("%s,%u:%s fi_fetch_atomic() returned %d > 0\n",
                      __func__, __LINE__, lbl, ret);
            ret = -22;
        } else
            print_func_err(__func__, __LINE__, "fi_fetch_atomic", lbl, ret);
        goto done;
    }

    ret = do_wait_all(conn);
    if (ret == -EINVAL) {
        print_info("%s,%u:%s saw expected error -EINVAL\n",
                   __func__, __LINE__, lbl);
        ret = 0;
    } else {
        print_err("%s,%u:%s saw unexpected return %d\n",
                  __func__, __LINE__, lbl, ret);
        if (ret >= 0)
            ret = -22;
        goto done;
    }

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

static void lcl_atomic_op(struct stuff *conn, struct atomic_op *op)
{
    struct fab_conn     *fab_conn = &conn->fab_conn;
    void                *dst = ((char *)fab_conn->mrmem.mem + op->off);
    uint64_t            dontcare;

    return lcl_atomic(conn, op->op, op->type, dst, op->operand0, op->operand1,
                      &dontcare);
}

static int do_server_sum(struct stuff *conn)
{
    int                 ret = 0;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    struct svr_op_wire_msg svr_msg = {
        .ops            = 0,
    };
    struct atomic_op    *op;
    struct context      *ctx;
    uint64_t            i;

    ctx = ctx_next(conn);
    ret = fi_recv(fab_conn->ep, NULL, 0, NULL, FI_ADDR_UNSPEC, ctx);
    if (ret < 0) {
        ctx_free(conn, ctx);
        print_func_fi_err(__func__, __LINE__, "fi_recv", "", ret);
        goto done;
    }

    for (;;) {
        for (i = 0; i < 100000 ; i++) {
            for (op = svr_sum_ops; op->op != FI_ATOMIC_OP_LAST; op++)
                lcl_atomic_op(conn, op);
        }
        svr_msg.ops += i;
        ret = do_progress(conn);
        if (ret < 0)
            goto done;
        if (ctx_all_done(conn))
            break;
    }
    svr_msg.val0 = atm_load_rlx((uint64_t *)fab_conn->mrmem.mem);
    svr_msg.ops = htobe64(svr_msg.ops);
    svr_msg.val0 = htobe64(svr_msg.val0);
    ctx = ctx_next(conn);
    ret = fi_send(fab_conn->ep, &svr_msg, sizeof(svr_msg), NULL, conn->dest_av,
                  ctx);
    if (ret < 0) {
        ctx_free(conn, ctx);
        print_func_fi_err(__func__, __LINE__, "fi_send", "", ret);
        goto done;
    }
    ret = do_wait_all(conn);
    if (ret < 0)
        goto done;

    ctx = ctx_next(conn);
    ret = fi_recv(fab_conn->ep, NULL, 0, NULL, FI_ADDR_UNSPEC, ctx);
    if (ret < 0) {
        ctx_free(conn, ctx);
        print_func_fi_err(__func__, __LINE__, "fi_recv", "", ret);
        goto done;
    }
    ret = do_wait_all(conn);

 done:
    return ret;
}

struct atomic_sz {
    enum fi_datatype    type;
    uint64_t            type_mask;
    uint64_t            prev_mask;
};

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

    case FI_MSWAP:
        /* Make sure any unused bits for the current size are wrong. */
        operand0 = (start ^ ~sz->type_mask) | (operand0 & sz->type_mask);
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
        { FI_UINT8,  0x00000000000000FFUL, 0x0000000000000000UL },
        { FI_UINT16, 0x000000000000FFFFUL, 0x00000000000000FFUL },
        { FI_UINT32, 0x00000000FFFFFFFFUL, 0x000000000000FFFFU },
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

    /* BOR: 6 cli_op, 2 hw_op */
    expected_ops(conn, 6, 2);
    ret = cli_atomic_size_test(conn, FI_BOR,
                               0xFEDCBA9876543210UL, 0x0000000000000000UL,
                               0x0000000000000000UL, 0xFEDCBA9876543210UL);
    if (ret < 0)
        goto done;
    /* BAND: 6 cli_op, 2 hw_op */
    expected_ops(conn, 6, 2);
    ret = cli_atomic_size_test(conn, FI_BAND,
                               0x8844221188442211UL, 0x0000000000000000UL,
                               0xFEDCBA9876543210UL, 0x8844221000442210UL);
    if (ret < 0)
        goto done;
    /* BXOR: 6 cli_op, 2 hw_op */
    expected_ops(conn, 6, 2);
    ret = cli_atomic_size_test(conn, FI_BXOR,
                               0xA5A5A5A5A5A5A5A5UL, 0x0000000000000000UL,
                               0x8844221000442210UL, 0x2DE187B5A5E187B5UL);
    if (ret < 0)
        goto done;
    /* MSWAP: 6 cli_op, 4 hw_op */
    expected_ops(conn, 6, 4);
    ret = cli_atomic_size_test(conn, FI_MSWAP,
                               0xFFFFFFFFFFFFFFFFUL, 0xFEDCBA9876543210UL,
                               0x2DE187B5A5E187B5UL, 0xFEDCBA9876543210UL);
    if (ret < 0)
        goto done;
    /* MSWAP: 6 cli_op, 4 hw_op */
    expected_ops(conn, 6, 4);
    ret = cli_atomic_size_test(conn, FI_MSWAP,
                               0x0123456789ABCDEFUL, 0xFFFFFFFFFFFFFFFFUL,
                               0xFEDCBA9876543210UL, 0xFFFFFFFFFFFFFFFFUL);
    if (ret < 0)
        goto done;
    /* CSWAP: 6 cli_op, 4 hw_op */
    expected_ops(conn, 6, 4);
    ret = cli_atomic_size_test(conn, FI_CSWAP,
                               0xFFFFFFFFFFFFFFFFUL, 0xFEDCBA9876543210UL,
                               0xFFFFFFFFFFFFFFFFUL, 0xFEDCBA9876543210UL);
    if (ret < 0)
        goto done;
    /* ATOMIC_READ: 6 cli_op, 4 hw_op */
    expected_ops(conn, 6, 4);
    ret = cli_atomic_size_test(conn, FI_ATOMIC_READ,
                               0x0000000000000000UL, 0x0000000000000000UL,
                               0xFEDCBA9876543210UL, 0xFEDCBA9876543210UL);
    if (ret < 0)
        goto done;
    /* ATOMIC_WRITE: 6 cli_op, 4 hw_op */
    expected_ops(conn, 6, 4);
    ret = cli_atomic_size_test(conn, FI_ATOMIC_WRITE,
                               0x0000000100010101UL, 0x0000000000000000UL,
                               0xFEDCBA9876543210UL, 0x0000000100010101UL);
    if (ret < 0)
        goto done;
    /* Check op counts. */
    if (!expected_saw("cli_ops", conn->expected_cli, conn->ops_done)) {
        ret = -FI_EINVAL;
        goto done;
    }
    ret = cli_ext_ops->ep_counters(conn->fab_conn.ep, &counters);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "ext_op_counters",
                       FI_ZHPE_OPS_V1, ret);
        goto done;
    }
    if (!expected_saw("thread0_hw_ops", conn->expected_hw,
                      counters.hw_atomics)) {
        ret = -FI_EINVAL;
        goto done;
    }

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
    uint64_t            dummy;

    /* Do an atomic op to fetch the key information. (1 hw_op, 1 cli_op) */
    expected_ops(conn, 1, 1);
    ret = cli_atomic_original(conn, FI_ATOMIC_READ, FI_UINT64, SW_OFF, 0, 0,
                              &dummy);
    if (ret < 0)
        goto done;
    if (conn->threadidx == 0) {
        ret = cli_bad_test(conn, "HW", FI_SUM);
        if (ret < 0)
            goto done;
        ret = cli_bad_test(conn, "SW", FI_BOR);
        if (ret < 0)
            goto done;
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

static uint64_t shift32(uint32_t low, uint32_t high)
{
    return (uint64_t)low + (((uint64_t)high) << 32);
}

static int do_client_sum_check(struct stuff *conn[], const struct args *args)
{
    int                 ret = 0;
    struct stuff        *conn0 = conn[0];
    struct fab_conn     *fab_conn0 = &cli_conn0->fab_conn;
    uint64_t            results[CLI_SUM_OPS_SIZE];
    struct fi_zhpe_ep_counters counters = {
        .version        = FI_ZHPE_EP_COUNTERS_VERSION,
        .len            = sizeof(counters),
    };
    uint64_t            hw_ops = 0;
    uint64_t            cli_ops = 0;
    struct svr_op_wire_msg svr_msg;
    struct context      *ctx;
    size_t              i;
    uint64_t            off;

    /* Tell server to stop. */
    ctx = ctx_next(conn0);
    ret = fi_send(fab_conn0->ep, NULL, 0, NULL, conn0->dest_av, ctx);
    if (ret < 0) {
        ctx_free(conn0, ctx);
        print_func_fi_err(__func__, __LINE__, "fi_send", "", ret);
        goto done;
    }
    ret = do_wait_all(conn0);
    if (ret < 0)
        goto done;
    /* Receive server op count. */
    ctx = ctx_next(conn0);
    ret = fi_recv(fab_conn0->ep, &svr_msg, sizeof(svr_msg), NULL,
                  FI_ADDR_UNSPEC, ctx);
    if (ret < 0) {
        ctx_free(conn0, ctx);
        print_func_fi_err(__func__, __LINE__, "fi_recv", "", ret);
        goto done;
    }
    ret = do_wait_all(conn0);
    if (ret < 0)
        goto done;
    svr_msg.ops = be64toh(svr_msg.ops);
    svr_msg.val0 = be64toh(svr_msg.val0);

    /* Get thread ops. */
    for (i = 0; i < args->threads; i++) {
        ret = cli_ext_ops->ep_counters(conn[i]->fab_conn.ep, &counters);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "ext_op_counters",
                           FI_ZHPE_OPS_V1, ret);
            goto done;
        }
        counters.hw_atomics -= conn[i]->expected_hw;
        if (!expected_saw("hw_ops %", (uint64_t)0,
                          counters.hw_atomics % CLI_SUM_OPS_SIZE)) {
            ret = -FI_EINVAL;
            goto done;
        }
        counters.hw_atomics /= CLI_SUM_OPS_SIZE;
        conn[i]->ops_done -= conn[i]->expected_cli;
        if (!expected_saw("cli_ops %", (uint64_t)0,
                          conn[i]->ops_done % CLI_SUM_OPS_SIZE)) {
            ret = -FI_EINVAL;
            goto done;
        }
        conn[i]->ops_done /= CLI_SUM_OPS_SIZE;
        if (zhpeq_is_asic() &&
            !expected_saw("cli vs hw", conn[i]->ops_done,
                          counters.hw_atomics)) {
            ret = -FI_EINVAL;
            goto done;
        }

        hw_ops += counters.hw_atomics;
        cli_ops += conn[i]->ops_done;

        print_info("thread[%3lu]:cli_ops 0x%"PRIX64" hw_ops 0x%"PRIX64"\n",
                   i, conn[i]->ops_done, counters.hw_atomics);
    }

    print_info("svr_ops 0x%"PRIX64"\n", svr_msg.ops);

    for (i = 0; i < ARRAY_SIZE(cli_sum_ops) - 1; i++) {

        off = cli_sum_ops[i].off & ~(sizeof(uint64_t) - 1);
        ret = cli_atomic_original(conn0, FI_ATOMIC_READ, FI_UINT64, off, 0, 0,
                                  &results[i]);
        if (ret < 0)
            goto done;
        print_info("off 0x%02"PRIX64" result 0x%"PRIX64"\n", off, results[i]);
    }
    /* Tell server to exit. */
    ctx = ctx_next(conn0);
    ret = fi_send(fab_conn0->ep, NULL, 0, NULL, conn0->dest_av, ctx);
    if (ret < 0) {
        ctx_free(conn0, ctx);
        print_func_fi_err(__func__, __LINE__, "fi_send", "", ret);
        goto done;
    }
    ret = do_wait_all(conn0);
    if (ret < 0)
        goto done;
    ret = -FI_EINVAL;
    if (!expected_saw("val0", svr_msg.val0, results[0]))
        goto done;
    if (!expected_saw("res[0]", svr_msg.ops + cli_ops, results[0]))
        goto done;
    if (!expected_saw("res[1]", shift32(svr_msg.ops + cli_ops, 0), results[1]))
        goto done;
    if (!expected_saw("res[2]", shift32(svr_msg.ops, cli_ops), results[2]))
        goto done;
    if (!expected_saw("res[3]", shift32(cli_ops, svr_msg.ops), results[3]))
        goto done;
    print_info("okay\n");
    ret = 0;

 done:
    return ret;
}

static int do_server_one(const struct args *oargs, int conn_fd)
{
    int                 ret;
    struct args         one_args = *oargs;
    struct args         *args = &one_args;
    struct fab_dom      fab_dom_lcl;
    struct stuff        conn_lcl = {
        .args           = args,
        .sock_fd        = conn_fd,
        .dest_av        = FI_ADDR_UNSPEC,
        .server         = true,
        .fab_dom        = &fab_dom_lcl,
        .free_me        = free_dummy,
    };
    struct stuff        *conn = &conn_lcl;
    struct fab_dom      *fab_dom = conn->fab_dom;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    struct cli_wire_msg cli_msg;

    fab_dom_init(fab_dom);
    fab_conn_init(fab_dom, fab_conn);

    /* Get the client parameters over the socket. */
    ret = sock_recv_fixed_blob(conn->sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    args->mr_mode = be64toh(cli_msg.mr_mode);
    args->progress_mode = ntohl(cli_msg.progress_mode);
    args->once_mode = !!cli_msg.once_mode;

    ret = fab_dom_setupx(NULL, NULL, true, PROVIDER, NULL, EP_TYPE,
                         args->mr_mode, args->progress_mode, fab_dom);
    if (ret < 0)
        goto done;
    ret = fab_ep_setup(fab_conn, NULL, 0, 0);
    if (ret < 0)
        goto done;
    ret = fab_av_xchg(fab_conn, conn->sock_fd, timeout, &conn->dest_av);
    if (ret < 0)
        goto done;

    /* Now let's exchange the memory parameters to the other side. */
    ret = do_mem_setup(conn);
    if (ret < 0)
        goto done;
    ret = do_mem_xchg(conn);
    if (ret < 0)
        goto done;

    ret = do_server_sum(conn);

 done:
    stuff_free(conn);

    if (ret >= 0)
        ret = (cli_msg.once_mode ? 1 : 0);

    return ret;
}

static int do_server(const struct args *args)
{
    int                 ret;
    int                 listener_fd = -1;
    int                 conn_fd = -1;
    struct addrinfo     *resp = NULL;
    int                 oflags = 1;

    ret = do_getaddrinfo(NULL, args->service,
                         AF_INET6, SOCK_STREAM, true, &resp);
    if (ret < 0)
        goto done;
    listener_fd = socket(resp->ai_family, resp->ai_socktype,
                         resp->ai_protocol);
    if (listener_fd == -1) {
        ret = -errno;
        print_func_err(__func__, __LINE__, "socket", "", ret);
        goto done;
    }
    if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR,
                   &oflags, sizeof(oflags)) == -1) {
        ret = -errno;
        print_func_err(__func__, __LINE__, "setsockopt", "", ret);
        goto done;
    }
    /* None of the usual: no polling; no threads; no cloexec; no nonblock. */
    if (bind(listener_fd, resp->ai_addr, resp->ai_addrlen) == -1) {
        ret = -errno;
        print_func_err(__func__, __LINE__, "bind", "", ret);
        goto done;
    }
    if (listen(listener_fd, BACKLOG) == -1) {
        ret = -errno;
        print_func_err(__func__, __LINE__, "listen", "", ret);
        goto done;
    }
    for (ret = 0; !ret;) {
        conn_fd = accept(listener_fd, NULL, NULL);
        if (conn_fd == -1) {
            ret = -errno;
            print_func_err(__func__, __LINE__, "accept", "", ret);
            goto done;
        }
        ret = do_server_one(args, conn_fd);
    }

done:
    if (listener_fd != -1)
        close(listener_fd);
    if (resp)
        freeaddrinfo(resp);

    return ret;
}

static void *do_client_thread(void *vconn)
{
    int                 ret;
    struct stuff        *conn = vconn;
    const struct args   *args = conn->args;
    struct fab_dom      *fab_dom = conn->fab_dom;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    struct cli_wire_msg cli_msg;

    if (conn->threadidx != 0) {
        /* Wait for thread 0 to initialize global state. */
        mutex_lock(&cli_mutex);
        while (!cli_conn0)
            cond_wait(&cli_cond, &cli_mutex);
        conn->rem.remote_addr = cli_conn0->rem.remote_addr;
        conn->rem.remote_key = cli_conn0->rem.remote_key;
        conn->dest_av = cli_conn0->dest_av;
        mutex_unlock(&cli_mutex);
    }

    if (conn->threadidx == 0) {
        ret = connect_sock(args->node, args->service);
        if (ret < 0)
            goto done;
        conn->sock_fd = ret;

        cli_msg.mr_mode = htobe64(args->mr_mode);
        cli_msg.progress_mode = htonl(args->progress_mode);
        cli_msg.once_mode = args->once_mode;
        ret = sock_send_blob(conn->sock_fd, &cli_msg, sizeof(cli_msg));
        if (ret < 0)
            goto done;
        ret = fab_dom_setupx(NULL, NULL, true, PROVIDER, NULL, EP_TYPE,
                             args->mr_mode, args->progress_mode, fab_dom);
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
        /* Exchange addresses with the server. */
        ret = fab_av_xchg(fab_conn, conn->sock_fd, timeout, &conn->dest_av);
        if (ret < 0)
            goto done;
        /* Exchange the memory parameters with the server. */
        ret = do_mem_xchg(conn);
        if (ret < 0)
            goto done;
        /* Get ops vector */
        ret = fi_open_ops(&fab_dom->fabric->fid, FI_ZHPE_OPS_V1, 0,
                          (void **)&cli_ext_ops, NULL);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "fi_open_ops",
                           FI_ZHPE_OPS_V1, ret);
            goto done;
        }
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
        conn[i]->sock_fd = -1;
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
        "Usage:%s [-os] [-t <threads>] <port> [<node> <ops/seconds>]\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "Server requires just port; client requires all 5 arguments.\n"
        "Client only options:\n"
        " -m : manual progress\n"
        " -o : run once and then server will exit\n"
        " -s : interpet <ops> as seconds\n"
        " -t <threads> : number of client threads\n"
        " -z : zero-based keys\n",
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
        .mr_mode        = (FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR),
        .progress_mode  = FI_PROGRESS_AUTO,
    };
    bool                client_opt = false;
    int                 opt;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "msot:z")) != -1) {

        /* All opts are client only, now. */
        client_opt = true;

        switch (opt) {

        case 'o':
            if (args.once_mode)
                usage(false);
            args.once_mode = true;
            break;

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
                                  SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        case 'z':
            if (!(args.mr_mode & FI_MR_VIRT_ADDR))
                usage(false);
            args.mr_mode &= ~FI_MR_VIRT_ADDR;
            break;

        default:
            usage(false);

        }
    }

    opt = argc - optind;

    if (opt == 1) {
        args.service = argv[optind++];
        if (client_opt)
            usage(false);
        if (do_server(&args) < 0)
            goto done;
    } else if (opt == 3) {
        if (!args.threads)
            args.threads = 1;
        args.service = argv[optind++];
        args.node = argv[optind++];
        if (parse_kb_uint64_t(__func__, __LINE__, "ops",
                              argv[optind++], &args.ops, 0, 1,
                              SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
            usage(false);
        if (do_client(&args) < 0)
            goto done;
    } else
        usage(false);

    ret = 0;

 done:
    return ret;
}
