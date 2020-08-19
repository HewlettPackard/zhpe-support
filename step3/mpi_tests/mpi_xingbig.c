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


#include <zhpeq.h>

#include <mpi.h>

#define OPS_MAX         (1024U)

enum z_op_types {
    ZNONE,
    ZGET,
    ZPUT,
};

enum z_role {
    ZNOROLE,
    ZCLIENT,
    ZSERVER,
};


/* global variables */
int  my_rank;
int  my_partner;
int  worldsize;
static struct zhpeq_attr zhpeq_attr;

#define MPI_CALL(_func, ...)                                    \
do {                                                            \
    int                 __rc = _func(__VA_ARGS__);              \
                                                                \
    if (unlikely(__rc != MPI_SUCCESS)) {                        \
        zhpeu_print_err("%s,%u:%d:%s() returned %d\n",          \
                        __func__, __LINE__, my_rank, #_func,    \
                        __rc);                                  \
        MPI_Abort(MPI_COMM_WORLD, 1);                           \
    }                                                           \
} while (0)

struct args {
    int                 argc;
    char                **argv;
    uint64_t            size;
    uint64_t            ops;
    uint64_t            seconds;
    uint64_t            runs;
    int                 slice;
    enum z_op_types     op_type;
    enum z_role         role;
};

struct stuff {
    /* Both client and server. */
    const struct args   *args;
    struct zhpeq_dom    *zqdom;
    void                *local_buf;
    struct zhpeq_key_data *local_kdata;
    uint64_t            ops_completed;
    /* Client only. */
    struct zhpeq_tq     *ztq;
    struct zhpeq_key_data *remote_kdata;
    void                *addr_cookie;
    /* Server only. */
    struct zhpeq_rq     *zrq;
};

struct rankdata {
    uint64_t            run_nsec;
    struct timespec     start_time;
    uint64_t            ops_completed;
    int                 slice;
};

struct rundata {
    double              mops;
    double              mbs;
    double              skew;
};

/* get/put servers all send ops_completed to rank 0*/
static void print_rankdata_nonzero(struct timespec *start_time,
                                   uint64_t run_cyc, struct stuff *conn)
{
    struct rankdata     rd_self;

    assert_always(my_rank != 0);

    rd_self.start_time  = *start_time;
    rd_self.run_nsec = cycles_to_nsec(run_cyc);
    rd_self.ops_completed = conn->ops_completed;
    rd_self.slice = conn->ztq->tqinfo.slice;

    MPI_CALL(MPI_Gather, &rd_self, sizeof(rd_self), MPI_BYTE,
             NULL, 0, MPI_BYTE, 0, MPI_COMM_WORLD);
}

static void print_rankdata_zero(const struct stuff *conn, struct rundata *run)
{
    const struct args   *args = conn->args;
    struct rankdata     *rd = NULL;
    struct rankdata     rd_self;
    struct timespec     first_start_time;
    uint64_t            first_end_nsec;
    int                 i, first_client;
    uint64_t            start_delta;
    uint64_t            end_delta;
    uint64_t            max_skew;
    double              run_usec;
    double              mbs;
    double              mops;
    char                time_str[ZHPEU_TM_STR_LEN];

    assert_always(my_rank == 0);
    rd_self.ops_completed = conn->ops_completed;
    rd_self.slice = conn->zrq->rqinfo.slice;

    rd = xcalloc(worldsize, sizeof(*rd));

    MPI_CALL(MPI_Gather, &rd_self, sizeof(rd_self), MPI_BYTE,
             rd, sizeof(*rd), MPI_BYTE, 0, MPI_COMM_WORLD);

    first_client = worldsize/2;
    first_start_time = rd[first_client].start_time;
    for (i = first_client + 1; i < worldsize; i++) {
        if (ts_cmp(&first_start_time, &rd[i].start_time) > 0)
            first_start_time = rd[i].start_time;
    }

    /* Include start skew when finding the first end time. */
    start_delta = ts_delta(&first_start_time, &rd[first_client].start_time);
    first_end_nsec = start_delta + rd[first_client].run_nsec;
    for (i = first_client + 1; i < worldsize; i++) {
        start_delta = ts_delta(&first_start_time, &rd[i].start_time);
        first_end_nsec = min(first_end_nsec, start_delta + rd[i].run_nsec);
    }

    zhpeu_tm_to_str(time_str, sizeof(time_str),
                    localtime(&first_start_time.tv_sec),
                    first_start_time.tv_nsec);

    printf("command:");
    for (i = 0; i < args->argc; i++)
        printf(" %s", args->argv[i]);
    printf("\n");
    printf("time:   %s\n", time_str);
    printf("times below in usec\n");
    max_skew = 0;
    run->mops = 0.0;
    /* print out just client ops completed */
    for (i = first_client; i < worldsize; i++) {
        start_delta = ts_delta(&first_start_time, &rd[i].start_time);
        end_delta = start_delta + rd[i].run_nsec - first_end_nsec;
        max_skew = max(max_skew,start_delta +  end_delta);
        run_usec =  (double)rd[i].run_nsec / 1000.0;
        mops = (double)rd[i].ops_completed / run_usec;
        mbs = (double)rd[i].ops_completed * args->size / run_usec;
        printf("rank:%3d; slice:%d; start skew:%10.3f; run time:%12.3f;"
               " end skew:%10.3lf; ops:%10" PRIu64 "; Mops/s:%10.3f;"
               " MB/s:%10.3f\n",
               i, rd[i].slice, (double)start_delta / 1000.0, run_usec,
               (double)end_delta / 1000.0, rd[i].ops_completed, mops, mbs);
        run->mops += mops;
        run->mbs += mbs;
    }
    run->skew = (double)max_skew / 1000.0;
    printf("total Mops/s:%10.3f; MB/s:%10.3f; max skew:%10.3f \n",
           run->mops, run->mbs, run->skew);
}

static void stuff_free(struct stuff *stuff)
{
    if (!stuff)
        return;

    zhpeq_qkdata_free(stuff->remote_kdata);
    zhpeq_qkdata_free(stuff->local_kdata);

    if (stuff->addr_cookie)
        zhpeq_domain_remove_addr(stuff->zqdom, stuff->addr_cookie);

    zhpeq_rq_free(stuff->zrq);
    zhpeq_tq_free(stuff->ztq);
    zhpeq_domain_free(stuff->zqdom);

    if (stuff->local_buf)
        munmap(stuff->local_buf, stuff->args->size);
}

/* server allocates and broadcasts ztq_remote_rx_addr to all clients */
/* if not immediate, clients allocate and register tx_addr */
static int do_mem_setup(struct stuff *conn)
{
    int                 ret = -ENOMEM;
    const struct args   *args = conn->args;
    char                blob[ZHPEQ_MAX_KEY_BLOB];
    size_t              blob_len;
    MPI_Status          mpi_status;
    int                 mpi_cnt;

    conn->local_buf = _zhpeu_mmap(NULL, args->size,
                                  PROT_READ | PROT_WRITE,
                                  MAP_ANONYMOUS | MAP_SHARED, -1 , 0);

    ret = zhpeq_mr_reg(conn->zqdom, conn->local_buf, conn->args->size,
                       (ZHPEQ_MR_GET | ZHPEQ_MR_PUT |
                        ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE),
                       &conn->local_kdata);

    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_mr_reg", "", ret);
        goto done;
    }

    /* only server exports ztq_local_kdata */
    if (args->role == ZSERVER) {
        blob_len = sizeof(blob);
        ret = zhpeq_qkdata_export(conn->local_kdata,
                                  conn->local_kdata->z.access, blob, &blob_len);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_qkdata_export", "", ret);
            goto done;
        }
    }

    if (args->role == ZSERVER) {
        MPI_CALL(MPI_Send, blob, blob_len, MPI_BYTE, my_partner,
                 0, MPI_COMM_WORLD);
    } else {
        MPI_CALL(MPI_Recv, blob, ZHPEQ_MAX_KEY_BLOB, MPI_BYTE, my_partner, 0,
                 MPI_COMM_WORLD, &mpi_status);
        MPI_Get_count(&mpi_status, MPI_BYTE, &mpi_cnt);

        /* only clients import remote memory */
        ret = zhpeq_qkdata_import(conn->zqdom, conn->addr_cookie,
                                  blob, mpi_cnt, &conn->remote_kdata);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_qkdata_import", "", ret);
            goto done;
        }
        ret = zhpeq_zmmu_reg(conn->remote_kdata);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_zmmu_reg", "", ret);
            goto done;

        }
    }
 done:
    return ret;
}

static void ztq_completions(struct stuff *conn)
{
    struct zhpe_cq_entry *cqe;

    while ((cqe = zhpeq_tq_cq_entry(conn->ztq))) {
        /* unlikely() to optimize the no-error case. */
        if (unlikely(cqe->status != ZHPE_HW_CQ_STATUS_SUCCESS)) {
            print_err("%s,%u:index 0x%x status 0x%x\n", __func__, __LINE__,
                      cqe->index, cqe->status);
            MPI_Abort(MPI_COMM_WORLD, 1);
            break;
        }
        zhpeq_tq_cq_entry_done(conn->ztq, cqe);
        conn->ops_completed++;
    }
}

static void ztq_read(struct stuff *conn)
{
    const struct args   *args = conn->args;
    union zhpe_hw_wq_entry *wqe;
    int32_t             rc;

    rc = zhpeq_tq_reserve(conn->ztq);
    assert_always(rc >= 0);
    wqe = zhpeq_tq_get_wqe(conn->ztq, rc);
    zhpeq_tq_get(wqe, 0, (uintptr_t)conn->local_buf, args->size,
                 conn->remote_kdata->z.zaddr);
    zhpeq_tq_insert(conn->ztq, rc);
    zhpeq_tq_commit(conn->ztq);
}

static void ztq_write(struct stuff *conn)
{
    const struct args   *args = conn->args;
    union zhpe_hw_wq_entry *wqe;
    int32_t             rc;

    rc = zhpeq_tq_reserve(conn->ztq);
    assert_always(rc >= 0);
    wqe = zhpeq_tq_get_wqe(conn->ztq, rc);
    zhpeq_tq_put(wqe, 0, (uintptr_t)conn->local_buf, args->size,
                 conn->remote_kdata->z.zaddr);
    zhpeq_tq_insert(conn->ztq, rc);
    zhpeq_tq_commit(conn->ztq);
}

static void delay_start(struct stuff *stuff)
{
    struct timespec     ts_start;
    struct timespec     ts_now;
    struct timespec     ts_delay;

    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    /*
     * Try to manage barrier latency. Assume all nodes synchronized with NTP;
     * and rank 0 will send out a start time 1 second in its future and all
     * ranks will start at that time.
     */
    if (my_rank == 0) {
        clock_gettime(CLOCK_REALTIME, &ts_start);
        ts_start.tv_sec += 1;
    }
    MPI_CALL(MPI_Bcast, &ts_start, sizeof(ts_start), MPI_BYTE,
             0, MPI_COMM_WORLD);
    clock_gettime(CLOCK_REALTIME, &ts_now);
    assert_always(ts_cmp(&ts_now, &ts_start) < 0);
    ts_delay.tv_nsec = ts_delta(&ts_now, &ts_start);
    ts_delay.tv_sec = ts_delay.tv_nsec / NSEC_PER_SEC;
    ts_delay.tv_nsec %= NSEC_PER_SEC;
    if (nanosleep(&ts_delay, &ts_now) == -1) {
        zhpeu_print_func_err(__func__, __LINE__, "nanosleep", "", -errno);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
}

static int do_client_unidir(struct stuff *conn,
                            void (*op)(struct stuff *conn))
{
    const struct args   *args = conn->args;
    uint64_t            run_cyc = args->seconds * get_tsc_freq();
    uint64_t            ops_started = 0;
    uint64_t            start_cyc;
    struct timespec     start_time;

    conn->ops_completed = 0;
    delay_start(conn);
    clock_gettime(CLOCK_REALTIME, &start_time);
    start_cyc = get_cycles(NULL);
    run_cyc += start_cyc;

    while (true) {
        if (wrap64sub(get_cycles(NULL), run_cyc) > 0)
            break;
        for (; conn->ops_completed - ops_started < args->ops; ops_started++)
            op(conn);
        ztq_completions(conn);
    }

    while (conn->ops_completed != ops_started)
        ztq_completions(conn);

    run_cyc = get_cycles(NULL) - start_cyc;

    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    print_rankdata_nonzero(&start_time, run_cyc, conn);

    return 0;
}

static int do_queue_setup(struct stuff *conn)
{
    int                 ret;
    const struct args   *args = conn->args;
    struct sockaddr_zhpe sa;
    size_t              sa_len = sizeof(sa);
    int                 slice_mask;
    char                *cp;

    /* Allocate domain. */
    ret = zhpeq_domain_alloc(&conn->zqdom);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", ret);
        goto done;
    }

    if (args->slice < 0) {
        /* mpi_hybrid.sh already sets this correctly so why not use it? */
        cp = getenv("FI_ZHPE_QUEUE_SLICE");
        if (cp)
            slice_mask = (1 << (atoi(cp) & (ZHPE_MAX_SLICES - 1)));
        else
            slice_mask = (1 << (my_rank & (ZHPE_MAX_SLICES - 1)));
    } else
        slice_mask = (1 << args->slice);
    slice_mask |= SLICE_DEMAND;

    /* Each client needs a ztq. */
    if (args->role == ZCLIENT) {
        ret = zhpeq_tq_alloc(conn->zqdom, args->ops, args->ops,
                             0, 0, slice_mask, &conn->ztq);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_tq_qalloc", "", ret);
            goto done;
        }
    }

    if (args->role == ZSERVER) {
        /* Each server gets a zrq */
        ret = zhpeq_rq_alloc(conn->zqdom, 1, slice_mask, &conn->zrq);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_rq_qalloc", "", ret);
            goto done;
        }

        ret = zhpeq_rq_get_addr(conn->zrq, &sa, &sa_len);
        if (ret < 0)
            goto done;

        MPI_CALL(MPI_Send, &sa, sa_len, MPI_BYTE,
                 my_partner, 0, MPI_COMM_WORLD);
    } else {
        MPI_CALL(MPI_Recv, &sa, sizeof(sa), MPI_BYTE, my_partner, 0,
                 MPI_COMM_WORLD, MPI_STATUS_IGNORE);

        /* clients insert the remote address in the domain. */
        ret = zhpeq_domain_insert_addr(conn->zqdom, &sa, &conn->addr_cookie);
        if (ret < 0) {
            print_func_err(__func__, __LINE__,
                           "zhpeq_domain_insert_addr", "", ret);
            goto done;
        }
    }

    /* server allocates memory and tells clients memory parameters . */
    /* clients set up and initialize memory. */
    ret = do_mem_setup(conn);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "do_mem_setup", "", ret);
        goto done;
    }
 done:
    return ret;
}

/* One server per client, for get, put */
static int do_server(const struct args *args)
{
    int                 ret = 0;
    struct stuff        stuff = {
        .args           = args,
    };
    struct stuff        *conn = &stuff;
    struct rundata      *runs = NULL;
    double              mops_min;
    double              mops_max;
    double              mops_tot;
    double              mbs_min;
    double              mbs_max;
    double              mbs_tot;
    double              skew_min;
    double              skew_max;
    double              skew_tot;
    uint                i;
    struct rankdata     rd_self;

    assert_always(args->role == ZSERVER);

    ret = do_queue_setup(conn);
    if (ret < 0)
        goto done;

    runs = xcalloc(args->runs, sizeof(*runs));

    for (i = 0; i < args->runs; i++) {
        delay_start(conn);
        MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);

        if (my_rank == 0)
            print_rankdata_zero(conn, &runs[i]);
        else {
            /* Data will be thrown away */
            MPI_CALL(MPI_Gather, &rd_self, sizeof(rd_self), MPI_BYTE,
                     NULL, 0, MPI_BYTE, 0, MPI_COMM_WORLD);
        }
    }

    if (my_rank != 0)
        goto done;

    mops_min = mops_max = mops_tot = runs[0].mops;
    mbs_min = mbs_max = mbs_tot = runs[0].mbs;
    skew_min = skew_max = skew_tot = runs[0].skew;
    for (i = 1; i < args->runs; i++) {
        mops_min = min(mops_min, runs[i].mops);
        mops_max = max(mops_max, runs[i].mops);
        mops_tot += runs[i].mops;
        mbs_min = min(mbs_min, runs[i].mbs);
        mbs_max = max(mbs_max, runs[i].mbs);
        mbs_tot += runs[i].mbs;
        skew_min = min(skew_min, runs[i].skew);
        skew_max = max(skew_max, runs[i].skew);
        skew_tot += runs[i].skew;
    }
    printf("\n");
    printf("Mops/s min:%10.3f; ave:%10.3f; max:%10.3f\n",
           mops_min, mops_tot / (double)args->runs, mops_max);
    printf("MB/s min:%10.3f; ave:%10.3f; max:%10.3f\n",
           mbs_min, mbs_tot / (double)args->runs, mbs_max);
    printf("skew   min:%10.3f; ave:%10.3f; max:%10.3f\n",
           skew_min, skew_tot / (double)args->runs, skew_max);

 done:
    free(runs);
    stuff_free(conn);

    return ret;
}

static int do_client(const struct args *args)
{
    int                 ret;
    struct stuff        stuff = {
        .args           = args,
    };
    struct stuff        *conn = &stuff;
    uint64_t            i;

    ret = do_queue_setup(conn);
    if (ret < 0)
        goto done;

    for (i = 0; i < args->runs; i++) {
        ret = do_client_unidir(conn,
                               (args->op_type == ZGET ? ztq_read : ztq_write));
        if (ret < 0)
            goto done;
    }

 done:
    stuff_free(conn);

    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s [-gp] [-S slice] <transfer_len> <I/Os> <seconds> <runs>\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "All four argumentsl one of [-gp]; and an even number\n"
        "of ranks are required.\n"
        "Options:\n"
        " -g: use get to transfer data\n"
        " -p: use put to transfer data\n"
        " -S <slice number>: slice number from 0-3\n",
        appname);

    if (help)
        zhpeq_print_tq_info(NULL);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = {
        .slice          = -1,
        .role           = ZNOROLE,
    };
    int                 opt;
    uint64_t            val64;
    int                 rc;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
    if (rc < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    MPI_CALL(MPI_Init, &argc, &argv);
    args.argc = argc;
    args.argv = argv;

    MPI_CALL(MPI_Comm_rank, MPI_COMM_WORLD, &my_rank);
    MPI_CALL(MPI_Comm_size, MPI_COMM_WORLD, &worldsize);

    args.role = my_rank < worldsize/2 ? ZSERVER : ZCLIENT;
    my_partner = ( my_rank + worldsize/2)%worldsize;

    while ((opt = getopt(argc, argv, "gpS:")) != -1) {

        switch (opt) {

        case 'g':
            if (args.op_type != ZNONE)
                usage(false);
            if (worldsize%2 != 0)
                usage(false);
            args.op_type = ZGET;
            break;

        case 'p':
            if (args.op_type != ZNONE)
                usage(false);
            if (worldsize%2 != 0)
                usage(false);
            args.op_type = ZPUT;
            break;

        case 'S':
            if (args.slice > 0)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "slice",
                                  optarg, &val64, 0, 0, 3, 0) < 0)
                usage(false);
            args.slice = val64;
            break;

        default:
            usage(false);

        }
    }

    if (args.op_type == ZNONE)
        usage(false);

    if (args.role == ZNOROLE)
        usage(false);

    opt = argc - optind;

    if (opt != 4 || worldsize < 2 || worldsize % 2 != 0)
        usage(false);

    if (parse_kb_uint64_t(__func__, __LINE__, "size",
                          argv[optind++], &args.size, 0,
                          ZHPEQ_MAX_IMM + 1, SIZE_MAX,
                          PARSE_KB | PARSE_KIB) < 0 ||
        parse_kb_uint64_t(__func__, __LINE__, "ops",
                          argv[optind++], &args.ops, 0, 1, OPS_MAX,
                          PARSE_KB | PARSE_KIB) < 0 ||
        parse_kb_uint64_t(__func__, __LINE__, "seconds",
                          argv[optind++], &args.seconds, 0, 1, SIZE_MAX,
                          PARSE_KB | PARSE_KIB) < 0 ||
        parse_kb_uint64_t(__func__, __LINE__, "runs",
                          argv[optind++], &args.runs, 0, 1, SIZE_MAX,
                          PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    /* Make sure barrier connections are built. */
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);

    if (args.role == ZSERVER) {
        if (do_server(&args) < 0)
            goto done;
    } else {
        if (do_client(&args) < 0)
            goto done;
    }

    /* Take this out to check finalize race. */
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);

    ret = 0;

 done:
    if (ret > 0)
        MPI_Abort(MPI_COMM_WORLD, ret);
    MPI_CALL(MPI_Finalize);

    return ret;
}
