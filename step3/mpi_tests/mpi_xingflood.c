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

enum z_op_types {
    ZNONE,
    ZGET,
    ZPUT,
};


/* global variables */
int  my_rank;
int  worldsize;

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
    uint64_t            ring_xfer_len;
    uint64_t            ring_entries;
    uint64_t            seconds;
    uint64_t            runs;
    uint32_t            stride;
    int                 slice;
    enum z_op_types     op_type;
};

struct stuff {
    /* Borth client and server. */
    const struct args   *args;
    struct zhpeq_dom    *zqdom;
    size_t              ring_xfer_aligned;
    size_t              ring_cycles;
    size_t              ring_len;
    uint32_t            cmdq_entries;
    void                *local_buf;
    size_t              local_len;
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
    double              skew;
};

static void print_rankdata_nonzero(struct timespec *start_time,
                                   uint64_t run_cyc, struct stuff *conn)
{
    struct rankdata     rd_self;

    assert_always(my_rank != 0);

    rd_self.start_time  = *start_time;
    rd_self.run_nsec = cycles_to_nsec(run_cyc);
    rd_self.ops_completed = conn->ops_completed;
    rd_self.slice = conn->ztq->tqinfo.slice;

    /* Lazy about structs. */
    MPI_CALL(MPI_Gather, &rd_self, sizeof(rd_self), MPI_BYTE,
             NULL, 0, MPI_BYTE, 0, MPI_COMM_WORLD);
}

static void print_rankdata_zero(const struct args *args, struct rundata *run)
{
    struct rankdata     *rd = NULL;
    struct rankdata     rd_self = { 0 };
    struct timespec     first_start_time;
    uint64_t            first_end_nsec;
    int                 i;
    uint64_t            start_delta;
    uint64_t            end_delta;
    uint64_t            max_skew;
    double              run_usec;
    double              mops;
    char                time_str[ZHPEU_TM_STR_LEN];

    assert_always(my_rank == 0);

    rd = xcalloc(worldsize, sizeof(*rd));

    /* Lazy about structs. */
    MPI_CALL(MPI_Gather, &rd_self, sizeof(rd_self), MPI_BYTE,
             rd, sizeof(*rd), MPI_BYTE, 0, MPI_COMM_WORLD);

    first_start_time = rd[1].start_time;
    for (i = 2; i < worldsize; i++) {
        if (ts_cmp(&first_start_time, &rd[i].start_time) > 0)
            first_start_time = rd[i].start_time;
    }

    /* Include start skew when finding the first end time. */
    start_delta = ts_delta(&first_start_time, &rd[1].start_time);
    first_end_nsec = start_delta + rd[1].run_nsec;
    for (i = 2; i < worldsize; i++) {
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
    for (i = 1; i < worldsize; i++) {
        start_delta = ts_delta(&first_start_time, &rd[i].start_time);
        end_delta = start_delta + rd[i].run_nsec - first_end_nsec;
        max_skew = max(max_skew,start_delta +  end_delta);
        run_usec =  (double)rd[i].run_nsec / 1000.0;
        mops = (double)rd[i].ops_completed / run_usec;
        printf("rank:%3d; slice:%d; start skew:%10.3f; run time:%12.3f;"
               " end skew:%10.3lf; ops:%10" PRIu64 "; Mops/s:%10.3f\n",
               i, rd[i].slice, (double)start_delta / 1000.0, run_usec,
               (double)end_delta / 1000.0, rd[i].ops_completed, mops);
        run->mops += mops;
    }
    run->skew = (double)max_skew / 1000.0;
    printf("total Mops/s:%10.3f; max skew:%10.3f \n", run->mops, run->skew);
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
        munmap(stuff->local_buf, stuff->local_len);
}

/* server allocates and broadcasts ztq_remote_rx_addr to all clients */
/* if not immediate, clients allocate and register tx_addr */
static int do_mem_setup(struct stuff *conn)
{
    int                 ret;
    char                blob[ZHPEQ_MAX_KEY_BLOB];
    size_t              blob_len;
    uint64_t            remote_zaddr;
    size_t              cmd_off;

    const struct args   *args = conn->args;
    union zhpe_hw_wq_entry *wqe;
    int                 i;

    ret = -EEXIST;

    /* everyone needs to set up ring */
    conn->ring_xfer_aligned = l1_up(args->ring_xfer_len);
    conn->ring_len = conn->ring_xfer_aligned * conn->cmdq_entries;

    if (my_rank == 0)
        conn->local_len = conn->ring_len * (worldsize - 1);
    else if (args->ring_xfer_len > ZHPEQ_MAX_IMM)
        conn->local_len = conn->ring_len;

    if (conn->local_len) {
        conn->local_buf = _zhpeu_mmap(NULL, conn->local_len,
                                      PROT_READ | PROT_WRITE,
                                      MAP_ANONYMOUS | MAP_SHARED, -1 , 0);
        ret = zhpeq_mr_reg(conn->zqdom, conn->local_buf, conn->local_len,
                           (ZHPEQ_MR_GET | ZHPEQ_MR_PUT |
                            ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE),
                           &conn->local_kdata);

        /* only server exports ztq_local_kdata */
        if (my_rank == 0) {
            blob_len = sizeof(blob);
            ret = zhpeq_qkdata_export(conn->local_kdata,
                                      conn->local_kdata->z.access,
                                      blob, &blob_len);
            if (ret < 0) {
                print_func_err(__func__, __LINE__, "zhpeq_qkdata_export", "",
                               ret);
                goto done;
            }
        }
    }

    MPI_CALL(MPI_Bcast, blob, ZHPEQ_MAX_KEY_BLOB, MPI_BYTE, 0, MPI_COMM_WORLD);
    MPI_CALL(MPI_Bcast, &blob_len, 1, MPI_UINT64_T, 0, MPI_COMM_WORLD);

    /* only clients import remote memory */
    if (my_rank > 0) {
        ret = zhpeq_qkdata_import(conn->zqdom, conn->addr_cookie,
                                  blob, blob_len, &conn->remote_kdata);
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

    if (my_rank > 0) {
        /* Loop and fill in all commmand buffers. */
        remote_zaddr = (conn->remote_kdata->z.zaddr +
                        conn->ring_len * (my_rank - 1));
        for (i = 0, cmd_off = 0; i < conn->cmdq_entries;
             i++, cmd_off += conn->ring_xfer_aligned) {

            wqe = &conn->ztq->wq[i];
            wqe->hdr.cmp_index = i;

            switch (args->op_type) {

            case ZGET:
                if (args->ring_xfer_len <= ZHPEQ_MAX_IMM)
                    zhpeq_tq_geti(wqe, 0, args->ring_xfer_len,
                                  remote_zaddr + cmd_off);
                else
                    zhpeq_tq_get(wqe, 0, (uintptr_t)conn->local_buf + cmd_off,
                                 args->ring_xfer_len, remote_zaddr + cmd_off);
                break;

            case ZPUT:
                if (args->ring_xfer_len <= ZHPEQ_MAX_IMM)
                    memset(zhpeq_tq_puti(wqe, 0, args->ring_xfer_len,
                                         remote_zaddr + cmd_off),
                           0, args->ring_xfer_len);
                else
                    zhpeq_tq_put(wqe, 0, (uintptr_t)conn->local_buf + cmd_off,
                                 args->ring_xfer_len, remote_zaddr + cmd_off);
                break;

            default:
                ret = -EINVAL;
                break;
            }
        }
    }
 done:
    return ret;
}

static inline struct zhpe_cq_entry *tq_cq_entry(struct zhpeq_tq *ztq,
                                                uint32_t off)
{
    uint32_t            qmask = ztq->tqinfo.cmplq.ent - 1;
    uint32_t            qindex = ztq->cq_head + off;
    struct zhpe_cq_entry *cqe = zhpeq_q_entry(ztq->cq, qindex, qmask);

    /* likely() to optimize the success case. */
    if (likely(zhpeq_cmp_valid(cqe, qindex, qmask)))
        return cqe;

    return NULL;
}

static void ztq_completions(struct stuff *conn)
{
    struct zhpeq_tq     *ztq = conn->ztq;
    struct              zhpe_cq_entry *cqe;
    uint32_t            mystride;

    mystride = min((uint32_t)conn->args->stride,
                   (uint32_t)(ztq->wq_tail_commit - ztq->cq_head));
    if (unlikely(mystride == 0))
        return;

    while ((cqe = tq_cq_entry(ztq, mystride - 1))) {
        /* unlikely() to optimize the no-error case. */
        if (unlikely(cqe->status != ZHPE_HW_CQ_STATUS_SUCCESS))
            print_err("ERROR: %s,%u:rank %3d index 0x%x status 0x%x\n",
                      __func__, __LINE__, my_rank, cqe->index, cqe->status);
        ztq->cq_head += mystride;
        conn->ops_completed += mystride;
    }
}

/* check for completions, send as many as we've got, and ring doorbell. */
static void ztq_write(struct stuff *conn)
{
    struct zhpeq_tq     *ztq = conn->ztq;
    uint32_t            qmask;
    uint32_t            avail;

    qmask = ztq->tqinfo.cmdq.ent - 1;
    avail = qmask - (ztq->wq_tail_commit - ztq->cq_head);

    if (unlikely(avail >= qmask / 2)) {
        ztq->wq_tail_commit += avail;
        qcmwrite64(ztq->wq_tail_commit & qmask,
                   ztq->qcm, ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
    }
}

/* Use existing pre-populated command buffer. */
static int do_client_unidir(struct stuff *conn)
{
    uint64_t            run_cyc = conn->args->seconds * get_tsc_freq();
    uint64_t            start_cyc;
    struct timespec     start_time;

    conn->ops_completed = 0;
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    clock_gettime(CLOCK_REALTIME, &start_time);
    start_cyc = get_cycles(NULL);
    run_cyc += start_cyc;

    while (true) {
        if ((int64_t)(run_cyc - get_cycles(NULL)) <= 0)
            break;
        ztq_write(conn);
        ztq_completions(conn);
    }

    while ((int32_t)(conn->ztq->wq_tail_commit - conn->ztq->cq_head) > 0)
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
    uint32_t            ent_sum, ent_max;
    int                 slice_mask;

    ret = -EINVAL;

    /* Allocate domain. */
    ret = zhpeq_domain_alloc(&conn->zqdom);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", ret);
        goto done;
    }

    /* Only clients get a ztq. */
    if (my_rank > 0) {
        if (args->slice < 0)
            slice_mask = (1 << ((my_rank - 1) & (ZHPE_MAX_SLICES - 1)));
        else
            slice_mask = (1 << args->slice);
        slice_mask |= SLICE_DEMAND;

        ret = zhpeq_tq_alloc(conn->zqdom, args->ring_entries,
                             args->ring_entries, 0, 0, slice_mask, &conn->ztq);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_tq_qalloc", "", ret);
            goto done;
        }
        conn->cmdq_entries = conn->ztq->tqinfo.cmplq.ent;
    }

    /* verify everyone's command queue is same size */
    MPI_CALL(MPI_Reduce, &conn->cmdq_entries, &ent_sum, 1,
             MPI_UINT32_T, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_CALL(MPI_Reduce, &conn->cmdq_entries, &ent_max, 1,
             MPI_UINT32_T, MPI_MAX, 0, MPI_COMM_WORLD);

    if (my_rank == 0) {
        if ((ent_max * (worldsize - 1)) != ent_sum) {
            print_err("%s,%u:cmdq entries inconsistent: %u %u\n",
                      __func__, __LINE__, ent_max, ent_sum);
           goto done;
        }
        conn->cmdq_entries = ent_max;

        /* only server gets a zrq */
        ret = zhpeq_rq_alloc(conn->zqdom, 1, 0, &conn->zrq);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_rq_qalloc", "", ret);
            goto done;
        }

        ret = zhpeq_rq_get_addr(conn->zrq, &sa, &sa_len);
        if (ret < 0)
            goto done;
    }

    /* server sends remote address to clients */
    MPI_CALL(MPI_Bcast, &sa_len, 1, MPI_UINT64_T, 0, MPI_COMM_WORLD);
    MPI_CALL(MPI_Bcast, &sa, (int)sa_len, MPI_BYTE, 0, MPI_COMM_WORLD);

    /* clients insert the remote address in the domain. */
    if (my_rank > 0) {
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
        print_func_err(__func__, __LINE__, "do_mem_xchg", "", ret);
        goto done;
    }
 done:
    return ret;
}

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
    double              skew_min;
    double              skew_max;
    double              skew_tot;
    uint                i;

    assert_always(my_rank == 0);

    ret = do_queue_setup(conn);
    if (ret < 0)
        goto done;

    runs = xcalloc(args->runs, sizeof(*runs));

    for (i = 0; i < args->runs; i++) {
        MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
        MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
        print_rankdata_zero(args, &runs[i]);
    }

    mops_min = mops_max = mops_tot = runs[0].mops;
    skew_min = skew_max = skew_tot = runs[0].skew;
    for (i = 1; i < args->runs; i++) {
        mops_min = min(mops_min, runs[i].mops);
        mops_max = max(mops_max, runs[i].mops);
        mops_tot += runs[i].mops;
        skew_min = min(skew_min, runs[i].skew);
        skew_max = max(skew_max, runs[i].skew);
        skew_tot += runs[i].skew;
    }
    printf("\n");
    printf("Mops/s min:%10.3f; ave:%10.3f; max:%10.3f\n",
           mops_min, mops_tot / (double)args->runs, mops_max);
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
        ret = do_client_unidir(conn);
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
        "Usage:%s [-gp] [-s stride] [-S slice] "
        "<transfer_len> <ring_entries> <seconds> <runs>\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "All four arguments, one of [-gp] and at least two ranks required.\n"
        "Options:\n"
        " -g: use get to transfer data\n"
        " -p: use put to transfer data\n"
        " -s <stride>: stride for checking completions\n"
        " -S <slice number>: slice number from 0-3\n"
        "",
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
    };
    int                 opt;
    uint64_t            val64;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    if (argc == 1)
        usage(true);

    MPI_CALL(MPI_Init, &argc, &argv);
    args.argc = argc;
    args.argv = argv;

    MPI_CALL(MPI_Comm_rank, MPI_COMM_WORLD, &my_rank);
    MPI_CALL(MPI_Comm_size, MPI_COMM_WORLD, &worldsize);

    while ((opt = getopt(argc, argv, "gps:S:")) != -1) {

        switch (opt) {

        case 'g':
            if (args.op_type != ZNONE)
                usage(false);
            args.op_type = ZGET;
            break;

        case 'p':
            if (args.op_type != ZNONE)
                usage(false);
            args.op_type = ZPUT;
            break;

        case 's':
            if (args.stride)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "stride",
                                  optarg, &val64, 0, 1, UINT32_MAX,
                                  PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            args.stride = val64;
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

    if (!args.stride)
        args.stride = 1;

    opt = argc - optind;

    if (opt != 4 || worldsize < 2)
        usage(false);

    if (parse_kb_uint64_t(__func__, __LINE__, "transfer_len",
                          argv[optind++], &args.ring_xfer_len, 0,
                          1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 ||
        parse_kb_uint64_t(__func__, __LINE__, "ring_entries",
                          argv[optind++], &args.ring_entries, 0, 2, 65536,
                          PARSE_KB | PARSE_KIB) < 0 ||
        parse_kb_uint64_t(__func__, __LINE__, "seconds",
                          argv[optind++], &args.seconds, 0, 1, SIZE_MAX,
                          PARSE_KB | PARSE_KIB) < 0 ||
        parse_kb_uint64_t(__func__, __LINE__, "runs",
                          argv[optind++], &args.runs, 0, 1, SIZE_MAX,
                          PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    /*
     * If ring entries is a power-of-two, decrement by 1 to make tq_alloc
     * round up to that value.
     */
    if (!(args.ring_entries & (args.ring_entries - 1)))
        args.ring_entries--;

    /* Make sure barrier connections are built. */
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);

    if (my_rank == 0) {
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
