/*
 * Copyright (C) 2020 Hewlett Packard Enterprise Development LP.
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

#undef _ZHPEQ_TEST_COMPAT_
#include <zhpeq.h>
#include <zhpeq_util.h>

#define BACKLOG         (10)
#ifdef DEBUG
#define TIMEOUT         (-1)
#else
#define TIMEOUT         (10000)
#endif
#define DEFAULT_QLEN    (1023U)
#define DEFAULT_WARMUP  (100U)

static struct zhpeq_attr zhpeq_attr;

struct args {
    uint64_t            ops;
    uint64_t            warmup;
    uint32_t            slice_mask;
    bool                points_mode;
};

struct stuff {
    const struct args   *args;
    struct zhpeq_dom    *zqdom;
    struct zhpeq_tq     *ztq;
    uint64_t            *times;
    size_t              n_times;
    size_t              cur_times;
    int                 sock_fd;
    size_t              ops;
    size_t              warmup;
    void                *addr_cookie;
    uint32_t            dgcid;
    uint32_t            rspctxid;
};

static void stuff_free(struct stuff *stuff)
{
    if (!stuff)
        return;

    zhpeq_domain_remove_addr(stuff->zqdom, stuff->addr_cookie);
    zhpeq_tq_free(stuff->ztq);
    zhpeq_domain_free(stuff->zqdom);
    free(stuff->times);

    FD_CLOSE(stuff->sock_fd);
}

static int do_nop(struct stuff *conn, uint warmup, uint ops)
{
    int                 ret = 0;
    struct zhpeq_tq     *ztq = conn->ztq;
    uint64_t            start = 0;
    int32_t             reservation;
    union zhpe_hw_wq_entry *wqe;
    struct zhpe_cq_entry *cqe;
    uint                i;
    uint64_t            delta;

    /* Keep reusing the same command buffer. */
    ret = zhpeq_tq_reserve(ztq);
    if (ret < 0) {
        if (ret != -EAGAIN)
            zhpeu_print_func_err(__func__, __LINE__, "zhpeq_tq_reserve", "",
                                 ret);
        goto done;
    }
    reservation = ret;
    wqe = zhpeq_tq_get_wqe(ztq, reservation);
    zhpeq_tq_nop(wqe, 0);

    for (i = 0; i < warmup + ops; i++) {
        if (unlikely(i == warmup))
            start = get_cycles(NULL);
        zhpeq_tq_insert(ztq, ret);
        zhpeq_tq_commit(ztq);
        while (!(cqe = zhpeq_tq_cq_entry(ztq)));
        ztq->cq_head++;
    }
    delta = get_cycles(NULL) - start;
    if (likely(i > 0))
        zhpeu_print_info("%s:%s:ave %.3lf\n",
                         zhpeu_appname, "nop_lat", cycles_to_usec(delta, ops));
    zhpeq_tq_unreserve(ztq, reservation);

 done:
    return ret;
}

static int do_nop_points(struct stuff *conn, uint warmup, uint ops)
{
    int                 ret = 0;
    struct zhpeq_tq     *ztq = conn->ztq;
    uint64_t            start;
    uint                i;
    int32_t             reservation;
    union zhpe_hw_wq_entry *wqe;
    struct zhpe_cq_entry *cqe;
    struct zhpeu_timing nop_lat;
    uint64_t            delta;

    /* Keep reusing the same command buffer. */
    ret = zhpeq_tq_reserve(ztq);
    if (ret < 0) {
        if (ret != -EAGAIN)
            zhpeu_print_func_err(__func__, __LINE__, "zhpeq_tq_reserve", "",
                                 ret);
        goto done;
    }
    reservation = ret;
    wqe = zhpeq_tq_get_wqe(ztq, reservation);
    zhpeq_tq_nop(wqe, 0);

    for (i = 0; i < warmup + ops; i++) {
        if (unlikely(i == warmup)) {
            zhpeu_timing_reset(&nop_lat);
            conn->cur_times = 0;
        }
        start = get_cycles(NULL);
        zhpeq_tq_insert(ztq, ret);
        zhpeq_tq_commit(ztq);
        while (!(cqe = zhpeq_tq_cq_entry(ztq)));
        delta = get_cycles(NULL) - start;
        zhpeu_timing_update(&nop_lat, delta);
        conn->times[conn->cur_times++] = delta;
        ztq->cq_head++;
    }
    zhpeu_timing_print(&nop_lat, "nop_lat", 1);
    zhpeq_tq_unreserve(ztq, reservation);
    for (i = 0; i < conn->cur_times; i++)
        printf("%.3f\n", cycles_to_usec(conn->times[i], 1));

 done:
    return ret;
}

static int do_q_setup(struct stuff *conn)
{
    int                 ret;
    const struct args   *args = conn->args;

    ret = -EINVAL;

    /* Allocate domain. */
    ret = zhpeq_domain_alloc(&conn->zqdom);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", ret);
        goto done;
    }
    /* Allocate zqueues. */
    ret = zhpeq_tq_alloc(conn->zqdom, DEFAULT_QLEN, DEFAULT_QLEN,
                         0, 0, args->slice_mask,  &conn->ztq);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_tq_alloc", "", ret);
        goto done;
    }

 done:
    return ret;
}

static int do_test(const struct args *args)
{
    int                 ret = 0;
    struct stuff        conn = {
        .args           = args,
        .ops       = args->ops,
    };

    conn.warmup = args->warmup;
    /* Compute warmup operations. */
    if (conn.warmup == UINT64_MAX) {
        conn.warmup = conn.ops / 10;
        if (conn.warmup < DEFAULT_WARMUP)
            conn.warmup = DEFAULT_WARMUP;
    }
    conn.n_times = max(conn.ops, conn.warmup);

    conn.times = calloc(conn.n_times, sizeof(*conn.times));
    if (!conn.times) {
        ret = -ENOMEM;
        goto done;
    }

    /* Build the queues before sending parameters to server. */
    ret = do_q_setup(&conn);
    if (ret < 0)
        goto done;

    /* Run test. */
    if (args->points_mode)
        ret = do_nop_points(&conn, conn.warmup, conn.ops);
    else
        ret = do_nop(&conn, conn.warmup, conn.ops);
    if (ret < 0)
        goto done;
    ret = 0;

 done:
    stuff_free(&conn);

    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    zhpeu_print_usage(
        help,
        "Usage:%s [-P] [-S <slice>] [-w <warmup_ops>] <op_count/seconds>\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "Server requires just port; client requires all 3 arguments.\n"
        "Client only options:\n"
        " -P : dump points\n"
        " -S <slice> : 0 - %u\n"
        " -w <ops> : number of warmup operations\n",
        zhpeu_appname, (uint)ZHPE_MAX_SLICES - 1);

    if (help)
        zhpeq_print_tq_info(NULL);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = {
        .warmup         = UINT64_MAX,
    };
    int                 opt;
    int                 rc;
    uint64_t            v64;

    zhpeu_util_init(argv[0], LOG_INFO, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
    if (rc < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "PS:w:")) != -1) {

        switch (opt) {

        case 'P':
            if (args.points_mode)
                usage(false);
            args.points_mode = true;
            break;

        case 'S':
            if (args.slice_mask != 0)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("slice", optarg, &v64, 0,
                                         0, ZHPE_MAX_SLICES - 1, 0) < 0)
                usage(false);
            args.slice_mask = (1U << v64);
            break;

        case 'w':
            if (args.warmup != UINT64_MAX)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("warmup", optarg, &args.warmup, 0, 0,
                                         UINT64_MAX - 1,
                                         PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        default:
            usage(false);

        }
    }

    opt = argc - optind;

    if (opt != 1)
        usage(false);
    if (_zhpeu_parse_kb_uint64_t("op_counts", argv[optind++], &args.ops, 0, 1,
                                 UINT64_MAX, PARSE_KB | PARSE_KIB) < 0)
        usage(false);
    if (do_test(&args) < 0)
        goto done;
    ret = 0;

 done:
    return ret;
}
