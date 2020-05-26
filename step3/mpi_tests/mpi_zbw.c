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

#include <sys/utsname.h>

#include <mpi.h>

#undef _ZHPEQ_TEST_COMPAT_

#include <zhpeq_util.h>
#include <zhpe_stats.h>

/* If the number of samples per sec exceeds this, I'm happy! */
#define SAMPLES_PER_SEC  (1000000UL)

enum {
    TAG_CONN,
    TAG_DATA,
    TAG_DONE,
};

enum {
    UNIDIR              = 0x0,
    BIDIR               = 0x1,
    SEND                = 0x0,
    PUT                 = 0x2,
    GET                 = 0x4,
    NTO1                = 0x7,
    SENDU               = SEND | UNIDIR,
    SENDB               = SEND | BIDIR,
    GETU                = GET | UNIDIR,
    GETB                = GET | BIDIR,
    PUTU                = PUT | UNIDIR,
    PUTB                = PUT | BIDIR,
};

struct io_rec {
    uint64_t            timestamp;
    uint32_t            cnt;
    int                 rank;
};

struct stuff {
    uint64_t            size;
    uint64_t            tx_ops;
    uint64_t            rx_ops;
    uint64_t            seconds;
    const char          *results_dir;
    MPI_Request         *tx_req;
    uint64_t            tx_req_cnt;
    uint64_t            tx_queued;
    uint64_t            tx_done;
    uint64_t            tx_end_cnt;
    struct io_rec       *tx_rec;
    uint64_t            tx_rec_idx;
    MPI_Request         *rx_req;
    MPI_Request         rx_req_done;
    uint64_t            rx_req_cnt;
    uint64_t            rx_queued;
    uint64_t            rx_done;
    uint64_t            rx_end_cnt;
    uint64_t            rx_end_tot;
    int                 rx_end_rcv;
    uint64_t            rx_end_buf;
    struct io_rec       *rx_rec;
    struct io_rec       **rx_rank_rec;
    uint64_t            rx_rec_idx;
    uint64_t            rec_cnt;
    struct timespec     start_ts;
    struct timespec     end_ts;
    struct timespec     barrier_ts;
    uint64_t            start;
    uint64_t            end;
    MPI_Status          *statuses;
    int                 *indicies;
    MPI_Win             *win;
    int                 dst;
    int                 op_type;
    bool                verbose;
};

struct timerank {
    struct timespec     time;
    int                 rank;
    pid_t               pid;
};

struct timegather {
    struct timerank     *tr;
    int                 min_idx;
};

static int n_ranks = -1;
static int my_rank = -1;

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

static_assert(MPI_UNDEFINED < 0, "MPI_UNDEFINED");

static bool do_recv_loop(struct stuff *stuff, char *rx_buf)
{
    int                 last = -1;
    struct io_rec       *rec = NULL;
    int                 out_cnt;
    int                 i;
    int                 index;
    int                 cnt;
    uint64_t            now;

    MPI_CALL(MPI_Testsome, 1, &stuff->rx_req_done, &out_cnt,
             &i, stuff->statuses);
    if (unlikely(out_cnt == 1)) {

        MPI_Get_count(&stuff->statuses[0], MPI_UINT64_T, &cnt);
        if (unlikely(stuff->statuses[0].MPI_ERROR != MPI_SUCCESS || cnt != 1))
            MPI_Abort(MPI_COMM_WORLD, 1);

        stuff->rx_end_tot += stuff->rx_end_buf;
        if (stuff->op_type == NTO1 && ++stuff->rx_end_rcv < n_ranks - 1)
            MPI_CALL(MPI_Irecv, &stuff->rx_end_buf, 1, MPI_UINT64_T,
                     MPI_ANY_SOURCE, TAG_DONE, MPI_COMM_WORLD,
                     &stuff->rx_req_done);
        else
            stuff->rx_end_cnt = stuff->rx_end_tot;
    }

    MPI_CALL(MPI_Testsome, stuff->rx_req_cnt, stuff->rx_req, &out_cnt,
             stuff->indicies, stuff->statuses);
    if (unlikely(out_cnt <= 0))
        goto done;
    stuff->rx_done += out_cnt;
    now = get_cycles(NULL);

    memset(stuff->rx_rank_rec, 0, sizeof(*stuff->rx_rank_rec) * n_ranks);
    for (i = 0; i < out_cnt; i++) {
        MPI_Get_count(&stuff->statuses[i], MPI_CHAR, &cnt);
        if (unlikely(stuff->statuses[i].MPI_ERROR != MPI_SUCCESS ||
                     cnt != stuff->size))
            MPI_Abort(MPI_COMM_WORLD, 1);

        if (unlikely(stuff->statuses[i].MPI_SOURCE != last)) {
            last = stuff->statuses[i].MPI_SOURCE;
            if (!(rec = stuff->rx_rank_rec[last])) {
                rec = &stuff->rx_rec[stuff->rx_rec_idx++];
                stuff->rx_rank_rec[last] = rec;
                assert_always(stuff->rx_rec_idx < stuff->rec_cnt);
                rec->timestamp = now;
                rec->cnt = 0;
                rec->rank = last;
            }
        }
        rec->cnt++;

        index = stuff->indicies[i];
        MPI_CALL(MPI_Irecv, rx_buf + stuff->size * index,
                 stuff->size, MPI_CHAR, MPI_ANY_SOURCE, TAG_DATA,
                 MPI_COMM_WORLD, &stuff->rx_req[index]);
        stuff->rx_queued++;
    }

 done:
    return unlikely(stuff->rx_done >= stuff->rx_end_cnt);
}

static void do_recv_start(struct stuff *stuff, char *rx_buf)
{
    assert(stuff->rx_req_cnt == 0);
    stuff->rx_end_cnt = UINT64_MAX;

    MPI_CALL(MPI_Irecv, &stuff->rx_end_buf, 1, MPI_UINT64_T, MPI_ANY_SOURCE,
             TAG_DONE, MPI_COMM_WORLD, &stuff->rx_req_done);

    for (; stuff->rx_req_cnt < stuff->rx_ops; stuff->rx_req_cnt++) {
        MPI_CALL(MPI_Irecv, rx_buf + stuff->size * stuff->rx_req_cnt,
                 stuff->size, MPI_CHAR, MPI_ANY_SOURCE, TAG_DATA,
                 MPI_COMM_WORLD, &stuff->rx_req[stuff->rx_req_cnt]);
        stuff->rx_queued++;
    }
}

static bool do_send_loop(struct stuff *stuff, char *tx_buf)
{
    bool                ret = false;
    int                 out_cnt;
    int                 i;
    int                 index;
    struct io_rec       *rec;
    uint64_t            now;

    MPI_CALL(MPI_Testsome, stuff->tx_req_cnt, stuff->tx_req, &out_cnt,
             stuff->indicies, stuff->statuses);
    if (unlikely(out_cnt <= 0)) {
        ret = unlikely(out_cnt == MPI_UNDEFINED);
        goto done;
    }
    stuff->tx_done += out_cnt;
    now = get_cycles(NULL);

    if (unlikely((int64_t)(stuff->end - now) < 0)) {
        if (stuff->tx_end_cnt == UINT64_MAX) {
            stuff->tx_end_cnt = stuff->tx_queued;
            MPI_CALL(MPI_Send, &stuff->tx_end_cnt, 1, MPI_UINT64_T,
                     stuff->dst, TAG_DONE, MPI_COMM_WORLD);
        }
    }

    rec = &stuff->tx_rec[stuff->tx_rec_idx++];
    assert_always(stuff->tx_rec_idx < stuff->rec_cnt);
    rec->timestamp = now;
    rec->cnt = out_cnt;
    rec->rank = my_rank;

    for (i = 0; i < out_cnt; i++) {
        if (unlikely(stuff->tx_queued >= stuff->tx_end_cnt))
            break;
        if (unlikely(stuff->statuses[i].MPI_ERROR != MPI_SUCCESS))
            MPI_Abort(MPI_COMM_WORLD, 1);

        index = stuff->indicies[i];
        MPI_CALL(MPI_Isend, tx_buf + stuff->size * index,
                 stuff->size, MPI_CHAR, stuff->dst, TAG_DATA,
                 MPI_COMM_WORLD, &stuff->tx_req[index]);
        stuff->tx_queued++;
    }

 done:
    return ret;
}

static void do_send_start(struct stuff *stuff, char *tx_buf)
{
    assert(stuff->tx_req_cnt == 0);
    stuff->tx_end_cnt = UINT64_MAX;

    for (; stuff->tx_req_cnt < stuff->tx_ops; stuff->tx_req_cnt++) {
        MPI_CALL(MPI_Isend, tx_buf + stuff->size * stuff->tx_req_cnt,
                 stuff->size, MPI_CHAR, stuff->dst, TAG_DATA,
                 MPI_COMM_WORLD, &stuff->tx_req[stuff->tx_req_cnt]);
        stuff->tx_queued++;
    }
}

static int tr_compare(const void *v1, const void *v2)
{
    int                 ret;
    const struct timerank *tr1 = v1;
    const struct timerank *tr2 = v2;

    ret = arithcmp(tr1->time.tv_sec, tr2->time.tv_sec);
    if (ret)
        return ret;
    ret = arithcmp(tr1->time.tv_nsec, tr2->time.tv_nsec);
    if (ret)
        return ret;
    ret = arithcmp(tr1->rank, tr2->rank);
    if (ret)
        return ret;

    return 0;
}

static void gather_times(struct timespec *time, struct timegather *gathered)
{
    struct timerank     *tr_all = NULL;
    struct timerank     tr_self = {
        .time           = *time,
        .rank           = my_rank,
        .pid            = getpid(),
    };
    int                 i;

    if (my_rank == 0)
        tr_all = xcalloc(n_ranks, sizeof(*gathered->tr));

    /* Lazy about structs. */
    MPI_CALL(MPI_Gather, &tr_self, sizeof(tr_self), MPI_BYTE,
             tr_all, sizeof(*tr_all), MPI_BYTE, 0, MPI_COMM_WORLD);

    if (my_rank != 0)
        return;

    gathered->tr = tr_all;
    qsort(tr_all, n_ranks, sizeof(*tr_all), tr_compare);

    for (i = 0; i < n_ranks; i++) {
        if (tr_all[i].time.tv_sec || tr_all[i].time.tv_nsec)
            break;
    }
    assert_always(i < n_ranks);
    gathered->min_idx = i;
}

static void dump_times(const char *label, FILE *outfile,
                       struct timerank *tr, int min_idx)
{
    int                 i;
    uint64_t            delta;

    for (i = min_idx; i < n_ranks; i++) {
        delta = ts_delta(&tr[min_idx].time, &tr[i].time);
        fprintf(outfile, "%s:%s rank %3d pid %d delta %10.3f usec\n",
               __func__, label, tr[i].rank, tr[i].pid, (double)delta / 1000.0);
    }
}

static void dump_info(int argc, char **argv, struct stuff *stuff)
{
    FILE                *info_file = NULL;
    struct timegather   startg   = { .tr = NULL };
    struct timegather   endg     = { .tr = NULL };
    struct timegather   barrierg = { .tr = NULL };
    char                *fname;
    char                time_str[ZHPEU_TM_STR_LEN];
    struct utsname      utsname;
    char                *cp;
    int                 rc;
    int                 i;

    gather_times(&stuff->start_ts, &startg);
    gather_times(&stuff->end_ts, &endg);
    gather_times(&stuff->barrier_ts, &barrierg);

    zhpeu_tm_to_str(time_str, sizeof(time_str),
                    localtime(&startg.tr[startg.min_idx].time.tv_sec),
                    startg.tr[startg.min_idx].time.tv_nsec);

    if (uname(&utsname) == -1) {
        rc = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "uname", NULL, rc);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    cp = strchr(utsname.nodename, '.');
    if (cp)
        *cp = '\0';

    xasprintf(&fname, "%s/info", stuff->results_dir);
    info_file = fopen(fname, "w");
    if (!info_file) {
        rc = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "fopen", fname, rc);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    free(fname);

    fprintf(info_file, "%-10s %s\n", "time:", time_str);
    fprintf(info_file, "%-10s", "command:");
    for (i = 0; i < argc; i++)
        fprintf(info_file, " %s", argv[i]);
    fprintf(info_file, "\n");
    fprintf(info_file, "%-10s %" PRIu64 "\n", "opsize:", stuff->size);
    fprintf(info_file, "%-10s %" PRIu64 "\n", "runtime:", stuff->seconds);
    fprintf(info_file, "%-10s %s\n", "host:", utsname.nodename);
    fprintf(info_file, "%-10s %d\n", "my_rank:", my_rank);
    fprintf(info_file, "%-10s %d\n", "n_ranks:", n_ranks);

    fprintf(info_file, "\n");
    dump_times("start  ", info_file , startg.tr, startg.min_idx);
    fprintf(info_file, "\n");
    dump_times("end    ", info_file , endg.tr, endg.min_idx);
    fprintf(info_file, "\n");
    dump_times("barrier", info_file , barrierg.tr, barrierg.min_idx);
}

static void dump_rec_open(struct stuff *stuff, const char *base_str,
                          FILE **results_files, int start_rank, int ranks)
{
    char                *fname;
    int                 i;
    int                 rc;

    for (i = start_rank + ranks - 1; i >= start_rank; i--) {
        xasprintf(&fname, "%s/%s.%d", stuff->results_dir, base_str, i);
        results_files[i] = fopen(fname, "w");
        if (!results_files[i]) {
            rc = -errno;
            zhpeu_print_func_err(__func__, __LINE__, "fopen", fname, rc);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        free(fname);
    }
}

static void dump_rec(struct stuff *stuff, bool send)
{
    FILE                **results_files = NULL;
    uint64_t            *totals = NULL;
    uint64_t            *times = NULL;
    uint64_t            *counts = NULL;
    struct io_rec       *rec;
    uint64_t            rec_idx;
    uint64_t            i;
    const char          *base_str;
    int                 rank;

    results_files = xcalloc(n_ranks, sizeof(*results_files));
    totals = xcalloc(n_ranks, sizeof(*totals));
    counts = xcalloc(n_ranks, sizeof(*counts));
    times = xcalloc(n_ranks, sizeof(*times));

    if (send) {
        switch (stuff->op_type) {

        case SENDU:
        case SENDB:
        case NTO1:
            base_str = "send";
            break;

        case GETU:
        case GETB:
            base_str = "get";
            break;

        case PUTU:
        case PUTB:
            base_str = "put";
            break;

        default:
            return;
        }
        rec = stuff->tx_rec;
        rec_idx = stuff->tx_rec_idx;
        dump_rec_open(stuff, base_str, results_files, my_rank, 1);
    } else {
        base_str = "recv";
        rec = stuff->rx_rec;
        rec_idx = stuff->rx_rec_idx;

        switch (stuff->op_type) {

        case SENDU:
        case SENDB:
            dump_rec_open(stuff, base_str, results_files, rec->rank, 1);
            break;

        case NTO1:
            dump_rec_open(stuff, base_str, results_files, 1, n_ranks - 1);
            break;

        default:
            return;
        }
    }

    for (i = 0; i < rec_idx; i++) {
        rank = rec[i].rank;
        totals[rank] += rec[i].cnt;
        times[rank] = rec[i].timestamp - stuff->start;
        if (stuff->verbose || !counts[rank])
            fprintf(results_files[rank], "%.3f,%lu\n",
                    cycles_to_usec(times[rank], 1), totals[rank]);
        counts[rank]++;
    }
    if (!stuff->verbose) {
        for (rank = 0; rank < n_ranks; rank++) {
            if (counts[rank] > 1)
                fprintf(results_files[rank], "%.3f,%lu\n",
                        cycles_to_usec(times[rank], 1), totals[rank]);
        }
    }

    for (i = 0; i < n_ranks; i++) {
        if (results_files[i])
            fclose(results_files[i]);
    }
    free(results_files);
    free(totals);
}

static void do_recv(struct stuff *stuff)
{
    char                *rx_buf;
    size_t              req;
    int                 conns;
    int                 cnt;

    req = stuff->size * stuff->rx_ops;
    MPI_CALL(MPI_Alloc_mem, req, MPI_INFO_NULL, &rx_buf);
    memset(rx_buf, 0, req);

    if (stuff->op_type == NTO1)
        conns = my_rank - 1;
    else
        conns = 1;
    /* Make sure connection to dst established. */
    for (; conns > 0; conns--) {
        MPI_CALL(MPI_Recv, rx_buf, 1, MPI_CHAR, MPI_ANY_SOURCE, TAG_CONN,
                 MPI_COMM_WORLD, &stuff->statuses[0]);
        MPI_Get_count(&stuff->statuses[0], MPI_CHAR, &cnt);
        if (unlikely(stuff->statuses[0].MPI_ERROR != MPI_SUCCESS || cnt != 1))
            MPI_Abort(MPI_COMM_WORLD, 1);
    }

    do_recv_start(stuff, rx_buf);

    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    clock_gettime(CLOCK_REALTIME, &stuff->start_ts);

    stuff->start = get_cycles(NULL);
    stuff->end += stuff->start;
    clock_gettime(CLOCK_REALTIME, &stuff->start_ts);
    zhpe_stats_stamp(zhpe_stats_subid(DBG, 0),
                     (uintptr_t)__func__, __LINE__, 0, 0, 0, 0);

    while (!do_recv_loop(stuff, rx_buf));
    clock_gettime(CLOCK_REALTIME, &stuff->end_ts);
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    clock_gettime(CLOCK_REALTIME, &stuff->barrier_ts);
    MPI_CALL(MPI_Free_mem, rx_buf);

    dump_rec(stuff, false);
}

static void do_send(struct stuff *stuff)
{
    char               *tx_buf;
    size_t              req;

    req = stuff->size * stuff->tx_ops;
    MPI_CALL(MPI_Alloc_mem, req, MPI_INFO_NULL, &tx_buf);
    memset(tx_buf, 0, req);

    /* Make sure connection to dst established. */
    MPI_CALL(MPI_Send, tx_buf, 1, MPI_CHAR, stuff->dst, TAG_CONN,
             MPI_COMM_WORLD);

    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);

    stuff->start = get_cycles(NULL);
    stuff->end += stuff->start;
    clock_gettime(CLOCK_REALTIME, &stuff->start_ts);
    zhpe_stats_stamp(zhpe_stats_subid(DBG, 0),
                     (uintptr_t)__func__, __LINE__, 0, 0, 0, 0);

    do_send_start(stuff, tx_buf);

    while (!do_send_loop(stuff, tx_buf));
    clock_gettime(CLOCK_REALTIME, &stuff->end_ts);
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    clock_gettime(CLOCK_REALTIME, &stuff->barrier_ts);
    MPI_CALL(MPI_Free_mem, tx_buf);

    dump_rec(stuff, true);
}

#if 0

static void do_send_recv(struct stuff *stuff)
{
    int                 half = n_ranks / 2;
    int                 quarter = n_ranks / 4;

    if (my_rank < half) {
        if (my_rank < quarter)
            do_send(stuff);
        else
            do_recv(stuff);
    } else if (my_rank >= half) {
        if (my_rank - half < quarter)
            do_recv(stuff);
        else
            do_send(stuff);
    }
}

#else

static void do_send_recv(struct stuff *stuff)
{
    bool                recv_done = false;
    bool                send_done = false;
    char                *rx_buf;
    char                *tx_buf;
    size_t              req;
    int                 cnt;

    req = stuff->size * stuff->rx_ops;
    MPI_CALL(MPI_Alloc_mem, req, MPI_INFO_NULL, &rx_buf);
    memset(rx_buf, 0, req);
    req = stuff->size * stuff->tx_ops;
    MPI_CALL(MPI_Alloc_mem, req, MPI_INFO_NULL, &tx_buf);
    memset(tx_buf, 0, req);

    if (my_rank < stuff->dst)
        MPI_CALL(MPI_Send, tx_buf, 1, MPI_CHAR, stuff->dst, TAG_CONN,
                 MPI_COMM_WORLD);
    else {
        MPI_CALL(MPI_Recv, rx_buf, 1, MPI_CHAR, stuff->dst, TAG_CONN,
                 MPI_COMM_WORLD, &stuff->statuses[0]);
        MPI_Get_count(&stuff->statuses[0], MPI_CHAR, &cnt);
        if (unlikely(stuff->statuses[0].MPI_ERROR != MPI_SUCCESS || cnt != 1))
            MPI_Abort(MPI_COMM_WORLD, 1);
    }

    do_recv_start(stuff, rx_buf);

    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);

    stuff->start = get_cycles(NULL);
    stuff->end += stuff->start;
    clock_gettime(CLOCK_REALTIME, &stuff->start_ts);
    zhpe_stats_stamp(zhpe_stats_subid(DBG, 0),
                     (uintptr_t)__func__, __LINE__, 0, 0, 0, 0);

    do_send_start(stuff, tx_buf);

    while (unlikely(!recv_done || !send_done)) {
        recv_done = do_recv_loop(stuff, rx_buf);
        send_done = do_send_loop(stuff, tx_buf);
    }
    clock_gettime(CLOCK_REALTIME, &stuff->end_ts);
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    clock_gettime(CLOCK_REALTIME, &stuff->barrier_ts);
    MPI_CALL(MPI_Free_mem, rx_buf);
    MPI_CALL(MPI_Free_mem, tx_buf);

    dump_rec(stuff, false);
    dump_rec(stuff, true);
}

#endif

static void do_rma_comm_create(struct stuff *stuff, MPI_Comm *pair_comm,
                               int *dst)
{
    int                 color;
    int                 pair_size;

    if (my_rank < stuff->dst) {
        color = my_rank;
        *dst = 1;
    } else {
        color = stuff->dst;
        *dst = 0;
    }
    MPI_CALL(MPI_Comm_split, MPI_COMM_WORLD, color, 0, pair_comm);

    MPI_CALL(MPI_Comm_size, *pair_comm, &pair_size);
    assert_always(pair_size == 2);
}

static void do_rma_comm_destroy(MPI_Comm *pair_comm)
{
    MPI_CALL(MPI_Comm_free, pair_comm);
}

static void do_rma_win_create(struct stuff *stuff, MPI_Comm comm,
                              MPI_Win *win, char **base)
{
    size_t              req = stuff->size * stuff->tx_ops;

    MPI_CALL(MPI_Alloc_mem, req, MPI_INFO_NULL, base);
    MPI_CALL(MPI_Win_create, *base, req, 1, MPI_INFO_NULL, comm, win);
}

static void do_rma_win_destroy(MPI_Win *win, char **base)
{
    MPI_CALL(MPI_Win_free, win);
    MPI_CALL(MPI_Free_mem, *base);
    *base = NULL;
}

static void do_rma_loop(struct stuff *stuff, MPI_Win win, char *base, int dst,
                        bool put)
{
    uint64_t            i;
    struct io_rec       *rec;
    uint64_t            now;

    MPI_CALL(MPI_Win_lock, (put ? MPI_LOCK_EXCLUSIVE : MPI_LOCK_SHARED),
             dst, 0, win);
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);

    stuff->start = get_cycles(NULL);
    stuff->end += stuff->start;
    clock_gettime(CLOCK_REALTIME, &stuff->start_ts);

    for (;;) {
        if (put) {
            for (i = 0; i < stuff->tx_ops; i++) {
                zhpe_stats_stamp_dbg(__func__, __LINE__, 0, 0, 0, 0);
                MPI_CALL(MPI_Put, base + stuff->size * i, stuff->size,
                         MPI_CHAR, dst, stuff->size * i, stuff->size,
                         MPI_CHAR, win);
                zhpe_stats_stamp_dbg(__func__, __LINE__, 0, 0, 0, 0);
            }
        } else {
            for (i = 0; i < stuff->tx_ops; i++) {
                zhpe_stats_stamp_dbg(__func__, __LINE__, 0, 0, 0, 0);
                MPI_CALL(MPI_Get, base + stuff->size * i, stuff->size,
                         MPI_CHAR, dst, stuff->size * i, stuff->size,
                         MPI_CHAR, win);
                zhpe_stats_stamp_dbg(__func__, __LINE__, 0, 0, 0, 0);
            }
        }
        zhpe_stats_stamp_dbg(__func__, __LINE__, 0, 0, 0, 0);
        MPI_CALL(MPI_Win_flush_local, dst, win);
        zhpe_stats_stamp_dbg(__func__, __LINE__, 0, 0, 0, 0);

        now = get_cycles(NULL);
        rec = &stuff->tx_rec[stuff->tx_rec_idx++];
        assert_always(stuff->tx_rec_idx < stuff->rec_cnt);
        rec->timestamp = now;
        rec->cnt = stuff->tx_ops;
        rec->rank = my_rank;

        if (unlikely((int64_t)(stuff->end - now) < 0))
            break;
    }
    clock_gettime(CLOCK_REALTIME, &stuff->end_ts);
    MPI_CALL(MPI_Win_unlock, dst, win);
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    clock_gettime(CLOCK_REALTIME, &stuff->barrier_ts);

    dump_rec(stuff, true);
}

static void do_rma_unidir_remote(struct stuff *stuff)
{
    MPI_Comm            pair_comm;
    int                 dst;
    MPI_Win             win;
    char                *base;

    do_rma_comm_create(stuff, &pair_comm, &dst);
    do_rma_win_create(stuff, pair_comm, &win, &base);
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    do_rma_win_destroy(&win, &base);
    do_rma_comm_destroy(&pair_comm);
}

static void do_rma_unidir(struct stuff *stuff, bool put)
{
    MPI_Comm            pair_comm;
    int                 dst;
    MPI_Win             win;
    char                *base;

    do_rma_comm_create(stuff, &pair_comm, &dst);
    do_rma_win_create(stuff, pair_comm, &win, &base);
    do_rma_loop(stuff, win, base, dst, put);
    do_rma_win_destroy(&win, &base);
    do_rma_comm_destroy(&pair_comm);
}

static void do_rma_bidir(struct stuff *stuff, bool put)
{
    MPI_Comm            pair_comm;
    int                 dst;
    MPI_Win             win1;
    char                *base1;
    MPI_Win             win2;
    char                *base2;

    do_rma_comm_create(stuff, &pair_comm, &dst);
    do_rma_win_create(stuff, pair_comm, &win1, &base1);
    do_rma_win_create(stuff, pair_comm, &win2, &base2);
    if (dst == 1)
        do_rma_loop(stuff, win1, base1, dst, put);
    else
        do_rma_loop(stuff, win2, base2, dst, put);
    do_rma_win_destroy(&win1, &base1);
    do_rma_win_destroy(&win2, &base2);
    do_rma_comm_destroy(&pair_comm);
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    zhpeu_print_usage(
        help,
        "Usage:%s [-bn] <size> <tx-ops> <rx-ops> <seconds> <results_dir>]\n"
        "<size> and <xx-ops>  may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        " -b : bi-directional traffic (exclusive with -n)\n"
        " -g : one-sided get\n"
        " -n : n-to-1 traffic (exclusive with -b, -g, -p)\n"
        " -p : one-sided put\n",
        zhpeu_appname);

    MPI_CALL(MPI_Finalize);
    _exit(help ? 0 : 255);
}

static void gdb_barrier(void)
{
    /* For debugging, the second barrier is a useful breakpoint. */
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct stuff        stuffy  = { 0 };
    struct stuff        *stuff = &stuffy;
    int                 opt;

    zhpeu_util_init(argv[0], LOG_INFO, false);

    zhpe_stats_init(zhpeu_appname);
    zhpe_stats_test(0);
    zhpe_stats_open(1);
    zhpe_stats_disable();

    MPI_CALL(MPI_Init, &argc, &argv);
    MPI_CALL(MPI_Comm_size, MPI_COMM_WORLD, &n_ranks);
    MPI_CALL(MPI_Comm_rank, MPI_COMM_WORLD, &my_rank);

    /*
     * An early barrier before initializing stats to allow per-node
     * scripts to clean up. Also initializes barrier connections.
     */
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);

    zhpe_stats_enable();

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "bgnpv")) != -1) {

        switch (opt) {

        case 'b':
            if (stuff->op_type & BIDIR)
                usage(false);
            stuff->op_type |= BIDIR;
            break;

        case 'g':
            if (stuff->op_type & GET)
                usage(false);
            stuff->op_type |= GET;
            break;

        case 'n':
            if (stuff->op_type & NTO1)
                usage(false);
            stuff->op_type = NTO1;
            break;

        case 'p':
            if (stuff->op_type & PUT)
                usage(false);
            stuff->op_type |= PUT;
            break;

        case 'v':
            if (stuff->verbose)
                usage(false);
            stuff->verbose = true;
            break;

        default:
            usage(false);

        }
    }

    opt = argc - optind;

    if (opt != 5)
        usage(false);

    if (_zhpeu_parse_kb_uint64_t("size", argv[optind++], &stuff->size,
                                 0, 1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 ||
        _zhpeu_parse_kb_uint64_t("ops", argv[optind++], &stuff->tx_ops,
                                 0, 1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 ||
        _zhpeu_parse_kb_uint64_t("ops", argv[optind++], &stuff->rx_ops,
                                 0, 1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 ||
        _zhpeu_parse_kb_uint64_t("seconds", argv[optind++], &stuff->seconds,
                                 0, 1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    stuff->results_dir = argv[optind++];

    if (stuff->op_type != NTO1) {
#if 0
        if (stuff->op_type == SENDB) {
            if (n_ranks & 3) {
                zhpeu_print_err("Ranks must be a multiple of 4 for this"
                                " test\n");
                goto done;
            }
        } else
#endif
        if (n_ranks & 1) {
            zhpeu_print_err("Ranks must be a multiple of 2 for this test\n");
            goto done;
        }
    }

    stuff->rec_cnt = stuff->seconds * SAMPLES_PER_SEC;
    stuff->rx_req = xcalloc(stuff->rx_ops, sizeof(*stuff->rx_req));
    stuff->rx_rec = xcalloc(stuff->rec_cnt, sizeof(*stuff->rx_rec));
    stuff->rx_rank_rec = xcalloc(n_ranks, sizeof(*stuff->rx_rank_rec));
    stuff->statuses = xcalloc(max(stuff->tx_ops, stuff->rx_ops),
                              sizeof(*stuff->statuses));
    stuff->indicies = xcalloc(max(stuff->tx_ops, stuff->rx_ops),
                              sizeof(*stuff->indicies));
    stuff->tx_req = xcalloc(stuff->tx_ops, sizeof(*stuff->tx_req));
    stuff->tx_rec = xcalloc(stuff->rec_cnt, sizeof(*stuff->tx_rec));

    stuff->end = stuff->seconds * zhpeu_init_time->freq;

    if (stuff->op_type == NTO1) {
        if (my_rank == 0)
            do_recv(stuff);
        else
            do_send(stuff);
    } else if (my_rank >= n_ranks / 2) {
        stuff->dst = my_rank - n_ranks / 2;

        switch (stuff->op_type) {

        case SENDU:
            do_recv(stuff);
            break;

        case SENDB:
            do_send_recv(stuff);
            break;

        case GETU:
        case PUTU:
            do_rma_unidir_remote(stuff);
            break;

        case GETB:
            do_rma_bidir(stuff, false);
            break;

        case PUTB:
            do_rma_bidir(stuff, true);
            break;

        default:
            goto done;
        }
    } else {
        stuff->dst = my_rank + n_ranks / 2;

        switch (stuff->op_type) {

        case SENDU:
            do_send(stuff);
            break;

        case SENDB:
            do_send_recv(stuff);
            break;

        case GETU:
            do_rma_unidir(stuff, false);
            break;

        case GETB:
            do_rma_bidir(stuff, false);
            break;

        case PUTU:
            do_rma_unidir(stuff, true);
            break;

        case PUTB:
            do_rma_bidir(stuff, true);
            break;

        default:
            goto done;
        }
    }

    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    if (my_rank == 0)
        dump_info(argc, argv, stuff);
    else {
        gather_times(&stuff->start_ts, NULL);
        gather_times(&stuff->end_ts, NULL);
        gather_times(&stuff->barrier_ts, NULL);
    }
    gdb_barrier();
    ret = 0;

 done:
    free(stuff->rx_req);
    free(stuff->rx_rec);
    free(stuff->rx_rank_rec);
    free(stuff->statuses);
    free(stuff->indicies);
    free(stuff->tx_req);
    free(stuff->tx_rec);
    MPI_CALL(MPI_Finalize);
    zhpe_stats_close();
    zhpe_stats_finalize();

    return ret;
}
