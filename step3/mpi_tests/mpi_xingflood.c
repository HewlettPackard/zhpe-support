/*
 * Copyright (C) 2017-2020 Hewlett Packard Enterprise Development LP.
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

/*
 * John said that the goal is to fill the command buffers and send them without
 * involving the command queue.
 *
 *      - Unidirectional
 *      - Instead of reserving entries, fill them all and leave them populated.
 *      - At set up time, allocate the command buffer (zhpeq_tq_alloc) and
 *        then populate all the wq entries, using zhpe_tq_puti.
 *      - Make ztq_write check if the tail is 1/2 the size of the array
 *        and do a zhpeq_tq_commit if so.
 *      - Keep size < ZHPEQ_MAX_IMM
 *      - Clean up options/usage/extraneous functions
 *      - Launch servers and clients separately using MPI, and set port number to
 *        initial port number + rank id.
 *      - After that works, then launch servers and clients at once
 *        using MPI, and set port number to port number + rank id%(worldsize/2)
 *      - Use MPI instead of socket communication.
 *      - Use a single server (rank 0).
 *      - Delete extraneous args.
 *      - Simplify:
 *          - Server needs only to allocate/share receive queue.
 *          - Client does not need transmit nor receive queue.
 *          - Client does not need transmit nor receive queue.
 *          - Server needs tell clients the sa.
 *      - Have rank 0 allocate a single buffer big enough for everyone,
 *        broadcast the information, and have the other ranks compute their spot.
 *        Exchange addresses and insert the remote address in the domain.
 *
 *      - make stride a parameter
 *
 * TIME:
 *      John Byrne:
 *        - Take the do_barrier function in mpi_barrier and use it to
 *          measure the skew of your barrier.
 *        - Take a look in mpi_zbw to see how MPI_Comm_split gets used.
 *        - You can make a communicator for 1-64 to synchronize the start
 *          and use MPI_COMM_WORLD for the end.
 *        - Also sample the wall clock after the cycles at the end of
 *          each rank and sort and show the maximum skew.
 *          Instead of passing ops_completed to cycles_to_usec() pass in 1
 *          to get the wall clock time and adjust the ops-per-second
 *          calculation accordingly.
 *          Print out both versions of the time from the cycles and the clock.
 *          Look in the tqinfo and print out the slice and queue.
 *
 *  - Get do_barrier to work with all ranks
 *  - Split so just clients call do_barrier
 */

#include <zhpeq.h>
#include <zhpeq_util.h>
#include <zhpe_stats.h>

#include <sys/queue.h>

#include <mpi.h>

#define BACKLOG         (10)
#ifdef DEBUG
#define TIMEOUT         (-1)
#else
#define TIMEOUT         (10000)
#endif
#define WARMUP_MIN      (1024)
#define RX_WINDOW       (64)
#define TX_WINDOW       (64)
#define L1_CACHELINE    ((size_t)64)
#define ZTQ_LEN         (1023)

/* global variables */
int  my_rank;
int  worldsize;
int  client_rank;
int  client_worldsize;
MPI_Comm client_comm;

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

static struct zhpeq_attr zhpeq_attr;

/* server-only */
struct rx_queue {
    STAILQ_ENTRY(rx_queue) list;
    union {
        void            *buf;
        uint64_t        idx;
    };
};

/* server-only */
STAILQ_HEAD(rx_queue_head, rx_queue);

struct args {
    uint64_t            ring_entry_len;
    uint64_t            ring_entries;
    uint64_t            ring_ops;
    uint32_t            stride;
    int                 slice;
    bool                use_geti;
};

struct stuff {
    const struct args   *args;
    struct zhpeq_dom    *zqdom;
    struct zhpeq_tq     *ztq;                /* client-only */
    struct zhpeq_rq     *zrq;                /* server only */
    struct zhpeq_key_data *ztq_local_kdata;  /* server-only */
    struct zhpeq_key_data *ztq_remote_kdata; /* client-only */
    uint64_t            ztq_remote_rx_zaddr; /* client-only */
    void                *rx_addr;            /* server-only */
    uint64_t            ops_completed;       /* client-only */
    size_t              ring_entry_aligned;
    size_t              ring_ops;
    size_t              ring_end_off;
    uint32_t            cmdq_entries;
    void                *addr_cookie;
};


struct timerank {
    struct timespec     ts_barrier;
    int                 rank;
};

int tr_compare(const void *v1, const void *v2)
{
    int                 ret;
    const struct timerank *tr1 = v1;
    const struct timerank *tr2 = v2;

    ret = arithcmp(tr1->ts_barrier.tv_sec, tr2->ts_barrier.tv_sec);
    if (ret)
        return ret;
    ret = arithcmp(tr1->ts_barrier.tv_nsec, tr2->ts_barrier.tv_nsec);
    if (ret)
        return ret;
    ret = arithcmp(tr1->rank, tr2->rank);
    if (ret)
        return ret;

    return 0;
}

void do_barrier(int barrier_id)
{
    struct timerank     *tr_all = NULL;
    struct timerank     tr_self;
    int                 i;
    uint64_t            delta;
    char                time_str[ZHPEU_TM_STR_LEN];

    tr_self.rank = my_rank;
    if (client_rank == 0)
        tr_all = xcalloc(client_worldsize, sizeof(*tr_all));

// printf("my_rank is %d; client_rank is %d; client_worldsize is %d\n",my_rank, client_rank, client_worldsize);

    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
   // MPI_CALL(MPI_Barrier, client_comm);
    clock_gettime(CLOCK_REALTIME, &tr_self.ts_barrier);

    /* Lazy about structs. */
    MPI_CALL(MPI_Gather, &tr_self, sizeof(tr_self), MPI_CHAR,
             tr_all, sizeof(*tr_all), MPI_CHAR, 0, client_comm);

    if (client_rank != 0)
        return;

    qsort(tr_all, client_worldsize, sizeof(*tr_all), tr_compare);

    zhpeu_tm_to_str(time_str, sizeof(time_str),
                    localtime(&tr_all[0].ts_barrier.tv_sec),
                    tr_all[0].ts_barrier.tv_nsec);

#if 0
    for (i = 0;  i < client_worldsize - 1; i++) {
        delta = ts_delta(&tr_all[0].ts_barrier, &tr_all[i].ts_barrier);
        printf("do_barrier output: barrier %5d rank %3d delta %10.3f usec\n",
               barrier_id, tr_all[i].rank, (double)delta / 1000.0);
    }
#endif
    i = client_worldsize - 1;
    delta = ts_delta(&tr_all[0].ts_barrier, &tr_all[i].ts_barrier);
    printf("do_barrier output: barrier %5d rank %3d delta %10.3f usec\n",
            barrier_id, tr_all[i].rank, (double)delta / 1000.0);
}

static void stuff_free(struct stuff *stuff)
{
    if (!stuff)
        return;

    if (stuff->ztq) {
        zhpeq_qkdata_free(stuff->ztq_remote_kdata);
        zhpeq_qkdata_free(stuff->ztq_local_kdata);
    }
    if (my_rank > 0) {
        zhpeq_domain_remove_addr(stuff->zqdom, stuff->addr_cookie);
        if (stuff->zrq)
            zhpeq_rq_free(stuff->zrq);
    } else {
        zhpeq_tq_free(stuff->ztq);
    }
    zhpeq_domain_free(stuff->zqdom);

    if ((my_rank == 0) && (stuff->rx_addr))
        munmap(stuff->rx_addr, stuff->ring_end_off);
}

/* server allocates and broadcasts ztq_remote_rx_addr to all clients */
static int do_mem_setup(struct stuff *conn)
{
    int                 ret;
    char                blob[ZHPEQ_MAX_KEY_BLOB];
    size_t              blob_len;
    uint64_t            ztq_remote_rx_addr;

    const struct args   *args = conn->args;
    size_t              mask = L1_CACHELINE - 1;
    size_t              req;
    union zhpe_hw_wq_entry *wqe;
    int                 i;

    ret = -EEXIST;

    /* everyone needs this */
    conn->ring_entry_aligned = (args->ring_entry_len + mask) & ~mask;

    /* only server sets up rx_addr */
    if (my_rank == 0) {
        req = conn->ring_entry_aligned * conn->cmdq_entries * (worldsize - 1);
        conn->ring_end_off = req;

        conn->rx_addr = mmap( NULL, req, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_SHARED,
                         -1 , 0);

        ret = zhpeq_mr_reg(conn->zqdom, conn->rx_addr, req,
                           (ZHPEQ_MR_GET | ZHPEQ_MR_PUT |
                            ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE),
                           &conn->ztq_local_kdata);

        blob_len = sizeof(blob);
        ret = zhpeq_qkdata_export(conn->ztq_local_kdata,
                                  conn->ztq_local_kdata->z.access,
                                  blob, &blob_len);
        if (ret < 0) {
                print_func_err(__func__, __LINE__, "zhpeq_qkdata_export", "", ret);
                goto done;
        }
    }

    MPI_CALL(MPI_Bcast, blob, ZHPEQ_MAX_KEY_BLOB, MPI_CHAR, 0, MPI_COMM_WORLD);

    MPI_CALL(MPI_Bcast, &blob_len, 1, MPI_UINT64_T, 0, MPI_COMM_WORLD);

    ztq_remote_rx_addr = (uintptr_t)conn->rx_addr;

    MPI_CALL(MPI_Bcast, &ztq_remote_rx_addr, 1, MPI_UINT64_T, 0, MPI_COMM_WORLD);

    /* only clients set up ztq_remote_rx_addr */
    if (my_rank > 0) {
        ztq_remote_rx_addr += conn->ring_entry_aligned *
                              conn->cmdq_entries * (my_rank - 1);
        ret = zhpeq_qkdata_import(conn->zqdom, conn->addr_cookie, blob, blob_len,
                              &conn->ztq_remote_kdata);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_qkdata_import", "", ret);
            goto done;
        }
        ret = zhpeq_zmmu_reg(conn->ztq_remote_kdata);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_zmmu_reg", "", ret);
            goto done;

        }
        ret = zhpeq_rem_key_access(conn->ztq_remote_kdata,
                               ztq_remote_rx_addr, conn->ring_end_off,
                               0, &conn->ztq_remote_rx_zaddr);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_rem_key_access",
                           "", ret);
            goto done;
        }
    }

    if (my_rank > 0) {
        if (args->use_geti) {
            /* Loop and fill in my commmand buffers with geti commands. */
            for (i =0; i<conn->cmdq_entries; i++) {
                wqe = &conn->ztq->wq[i];
                zhpeq_tq_geti(wqe, 0, args->ring_entry_len,
                       conn->ztq_remote_rx_zaddr+(i*conn->ring_entry_aligned));
                wqe->hdr.cmp_index = i;
            }
        } else {
            /* Loop and fill in my commmand buffers puti commands. */
            for (i =0; i<conn->cmdq_entries; i++) {
                wqe = &conn->ztq->wq[i];
                memset(zhpeq_tq_puti(wqe, 0, args->ring_entry_len,
                       conn->ztq_remote_rx_zaddr+(i*conn->ring_entry_aligned)),
                       0, args->ring_entry_len);
                wqe->hdr.cmp_index = i;
            }
        }
#if 0
        wqe = &conn->ztq->wq[conn->cmdq_entries - 1];
        printf("%s,%u:rank %d op 0x%04x cmp_index 0x%04x len 0x%02x"
               " rem 0x%016" PRIx64 "\n",
               __func__, __LINE__, my_rank, wqe->hdr.opcode, wqe->hdr.cmp_index,
               wqe->imm.len, wqe->imm.rem_addr);
#endif
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
            print_err("ERROR: %s,%u:rank %d index 0x%x status 0x%x\n",
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

    if (unlikely(avail > qmask / 2)) {
        if (unlikely(conn->ring_ops < avail)) {
            if (unlikely(!conn->ring_ops))
                return;
            avail = conn->ring_ops;
        }
        ztq->wq_tail_commit += avail;
        qcmwrite64(ztq->wq_tail_commit & qmask,
                   ztq->qcm, ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
        conn->ring_ops -= avail;
    }
}

/* Use existing pre-populated command buffer. */
static int do_client_unidir(struct stuff *conn)
{
    double              clocktime;
    struct timespec     start_clocktime;
    struct timespec     now_clocktime;

    //MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    /* call do_barrier here */
    do_barrier(1);

    clock_gettime(CLOCK_REALTIME, &start_clocktime);

    while (conn->ring_ops) {
        ztq_write(conn);
        ztq_completions(conn);
    }

    while ((int32_t)(conn->ztq->wq_tail_commit - conn->ztq->cq_head) > 0)
        ztq_completions(conn);

    clock_gettime(CLOCK_REALTIME, &now_clocktime);
    clocktime = (double)ts_delta(&start_clocktime, &now_clocktime) / 1000.0;

    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);

    if (my_rank == 0)
        printf("queue size:%"PRIu32"\n",conn->ztq->tqinfo.cmdq.ent);

    printf("%s:rank:%d; ops count:%"PRIu64"; slice:%d; queue:%d;"
           "clocktime, usec:%.3f; ops per sec:%.3f\n",
           appname, my_rank, conn->ops_completed, conn->ztq->tqinfo.slice,
           conn->ztq->tqinfo.queue, clocktime,
           (double)(conn->ops_completed * 1000000) / clocktime);

    return 0;
}

int do_queue_setup(struct stuff *conn)
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
                             args->ring_entries, 0, 1, slice_mask, &conn->ztq);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_tq_qalloc", "", ret);
            goto done;
        }
        conn->cmdq_entries = conn->ztq->tqinfo.cmplq.ent;
    }

    /* verify everyone's command queue is same size */
    MPI_CALL(MPI_Reduce, &conn->cmdq_entries, &ent_sum, 1, MPI_UINT32_T,
                        MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_CALL(MPI_Reduce, &conn->cmdq_entries, &ent_max, 1, MPI_UINT32_T,
                        MPI_MAX, 0, MPI_COMM_WORLD);

    if (my_rank == 0) {
        if ((ent_max * (worldsize -1))  != ent_sum) {
           print_func_err(__func__, __LINE__, "ent_min != ent_max", "",
                          ent_sum);
           print_func_err(__func__, __LINE__, "ent_min != ent_max", "",
                          ent_max);
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

static int do_server(const struct args *oargs)
{
    int                 ret;
    struct args         one_args = *oargs;
    struct args         *args = &one_args;
    struct stuff        conn = {
        .args           = args,
    };

    ret = do_queue_setup(&conn);
    if (ret < 0)
        goto done;

    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
 done:
    stuff_free(&conn);
    return ret;
}

static int do_client(const struct args *args)
{
    int                 ret;
    struct stuff        conn = {
        .args           = args,
        .ring_ops       = args->ring_ops,
    };

    ret = do_queue_setup(&conn);
    if (ret < 0)
        goto done;

    ret = do_client_unidir(&conn);
    if (ret < 0)
        goto done;


 done:
    stuff_free(&conn);
    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s [-g] [-s stride] [-S slice]\n"
        "    <entry_len> <ring_entries> <op_count>\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "All three arguments required.\n"
        "Options:\n"
        " -g: use geti instead of puti to transfer data\n"
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
    struct args         args = { .stride=0,
                                 .slice=-1,
                                 .use_geti=false,
                               };
    int                 opt;
    int                 rc;
    uint64_t            stride64;
    uint64_t            slice64;
    int                 color;

    MPI_CALL(MPI_Init, &argc,&argv);
    MPI_CALL(MPI_Comm_rank, MPI_COMM_WORLD, &my_rank);
    MPI_CALL(MPI_Comm_size, MPI_COMM_WORLD, &worldsize);

    color = (my_rank == 0) ? MPI_UNDEFINED : 1;
    MPI_CALL(MPI_Comm_split, MPI_COMM_WORLD, color, my_rank, &client_comm);

    if (my_rank > 0) {
         MPI_CALL(MPI_Comm_rank, client_comm, &client_rank);
         MPI_CALL(MPI_Comm_size, client_comm, &client_worldsize);
    }
    zhpeq_util_init(argv[0], LOG_INFO, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "gs:S:")) != -1) {

        switch (opt) {

        case 'g':
            if (args.use_geti)
                usage(false);
            args.use_geti=true;
            break;

        case 's':
            if (args.stride)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "stride",
                                  optarg, &stride64, 0, 1,
                                  UINT32_MAX, PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            args.stride=(uint32_t)(stride64);
            break;

        case 'S':
            if (args.slice > 0)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "slice",
                                  optarg, &slice64, 0, 0,
                                  3, PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            args.slice=(int)(slice64);
            break;

        default:
            usage(false);

        }
    }

    if (! args.stride)
        args.stride=64;

    if (my_rank == 0)
        printf("args.stride was %d\n",args.stride);

    opt = argc - optind;

    if (opt != 3)
        usage(false);

    if (parse_kb_uint64_t(__func__, __LINE__, "entry_len",
                          argv[optind++], &args.ring_entry_len, 0,
                          sizeof(uint8_t), ZHPEQ_MAX_IMM,
                          PARSE_KB | PARSE_KIB) < 0 ||
               parse_kb_uint64_t(__func__, __LINE__, "ring_entries",
                          argv[optind++], &args.ring_entries, 0, 1,
                             SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 ||
               parse_kb_uint64_t(__func__, __LINE__,
                          "op_counts",
                          argv[optind++], &args.ring_ops, 0, 1,
                          SIZE_MAX,
                          PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    if (my_rank == 0) {
        if (do_server(&args) < 0)
            goto done;
    } else {
        if (do_client(&args) < 0)
            goto done;
    }

    ret = 0;

 done:
    if (ret > 0)
        MPI_Abort(MPI_COMM_WORLD, ret);
    if (my_rank > 0)
        MPI_CALL(MPI_Comm_free, &client_comm);
    MPI_CALL(MPI_Finalize);
    return ret;
}
