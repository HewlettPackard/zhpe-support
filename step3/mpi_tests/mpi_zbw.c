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

#include <mpi.h>

#undef _ZHPEQ_TEST_COMPAT_

#include <zhpeq_util.h>
#include <zhpe_stats.h>

#define OPS_MIN         (32)
#define OPS_MAX         (512)
#define OPS_MAX_SIZE    (4 * MiB)

/* If the number of samples per sec exceeds this, I'm happy! */
#define SAMPLES_PER_SEC  (1000000UL)

enum {
    TAG_CONN,
    TAG_SELF,
    TAG_TIMING,
    TAG_DATA,
    TAG_RX_DONE,
    TAG_TX_DONE,
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
    uint64_t            bw_est;
    uint64_t            seconds;
    int                 tx_ops;
    int                 rx_ops;
    const char          *results_dir;
    MPI_Request         *tx_req;
    MPI_Request         tx_done_req;
    uint64_t            tx_req_cnt;
    uint64_t            tx_queued;
    uint64_t            tx_recorded;
    struct io_rec       *tx_rec;
    uint64_t            tx_rec_idx;
    bool                tx_drain;
    MPI_Request         *rx_req;
    MPI_Request         rx_done_req;
    uint64_t            rx_req_cnt;
    uint64_t            rx_done;
    uint64_t            rx_recorded;
    uint64_t            rx_end_cnt;
    uint64_t            rx_end_buf1;
    uint64_t            rx_end_buf2;
    bool                rx_drain;
    struct io_rec       *rx_rec;
    struct io_rec       **rx_rank_rec;
    uint64_t            rx_rec_idx;
    uint64_t            rec_cnt;
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
    uint64_t            rx_nsec;
    uint64_t            tx_nsec;
    int                 rank;
    pid_t               pid;
};

struct timeinfo {
    double              min;
    double              max;
    double              ave;
};

static int world_ranks = -1;
static int node_ranks = -1;
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
    int                 done;

    MPI_CALL(MPI_Testsome, stuff->rx_req_cnt, stuff->rx_req, &out_cnt,
             stuff->indicies, stuff->statuses);
    now = get_cycles(NULL);
    if (unlikely(out_cnt <= 0)) {
        assert_always(out_cnt != MPI_UNDEFINED);
        goto done;
    }

    memset(stuff->rx_rank_rec, 0, sizeof(*stuff->rx_rank_rec) * world_ranks);
    for (i = 0; i < out_cnt; i++) {
        if (unlikely(stuff->statuses[i].MPI_ERROR != MPI_SUCCESS))
            MPI_Abort(MPI_COMM_WORLD, 1);

        index = stuff->indicies[i];

        MPI_Get_count(&stuff->statuses[i], MPI_CHAR, &cnt);
        if (unlikely(stuff->size != cnt))
            MPI_Abort(MPI_COMM_WORLD, 1);
        stuff->rx_done++;

        if (likely(!stuff->rx_drain)) {
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
            stuff->rx_recorded++;
        }

        MPI_CALL(MPI_Irecv, rx_buf + stuff->size * index,
                 stuff->size, MPI_CHAR, stuff->dst, TAG_DATA,
                 MPI_COMM_WORLD, &stuff->rx_req[index]);
    }

 done:
    if (unlikely(wrap64sub(now, stuff->end) >= 0)) {
        if (!stuff->rx_drain) {
            if (stuff->op_type == NTO1)
                MPI_CALL(MPI_Ireduce, &stuff->rx_end_buf1, &stuff->rx_end_buf2,
                         1, MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD,
                         &stuff->rx_done_req);
            else {
                MPI_CALL(MPI_Irecv, &stuff->rx_end_buf1, 1, MPI_UINT64_T,
                         stuff->dst, TAG_TX_DONE, MPI_COMM_WORLD,
                         &stuff->rx_done_req);

                if (out_cnt <= 0) {
                    rec = &stuff->rx_rec[stuff->rx_rec_idx++];
                    assert_always(stuff->rx_rec_idx < stuff->rec_cnt);
                    rec->timestamp = now;
                    rec->cnt = 0;
                    rec->rank = stuff->dst;
                }
            }
            stuff->rx_drain = true;
        } else if (stuff->rx_done_req != MPI_REQUEST_NULL) {
            MPI_CALL(MPI_Test, &stuff->rx_done_req, &done, stuff->statuses);
            if (done) {
                if (stuff->op_type != NTO1) {
                    MPI_Get_count(&stuff->statuses[0], MPI_UINT64_T, &cnt);
                    if (unlikely(1 != cnt))
                        MPI_Abort(MPI_COMM_WORLD, 1);
                }
                stuff->rx_end_cnt = stuff->rx_end_buf1;
            }
        }
    }

    return unlikely(stuff->rx_done >= stuff->rx_end_cnt);
}

static void do_recv_start(struct stuff *stuff, char *rx_buf)
{
    assert(stuff->rx_req_cnt == 0);
    stuff->rx_end_cnt = UINT64_MAX;

    for (; stuff->rx_req_cnt < stuff->rx_ops; stuff->rx_req_cnt++)
        MPI_CALL(MPI_Irecv, rx_buf + stuff->size * stuff->rx_req_cnt,
                 stuff->size, MPI_CHAR, stuff->dst, TAG_DATA,
                 MPI_COMM_WORLD, &stuff->rx_req[stuff->rx_req_cnt]);
}

static bool do_send_loop(struct stuff *stuff, char *tx_buf)
{
    bool                ret = false;
    int                 out_cnt;
    int                 i;
    int                 index;
    struct io_rec       *rec;
    uint64_t            now;
    int                 done;

    MPI_CALL(MPI_Testsome, stuff->tx_req_cnt, stuff->tx_req, &out_cnt,
             stuff->indicies, stuff->statuses);
    now = get_cycles(NULL);
    if (unlikely(out_cnt <= 0)) {
        ret = unlikely(out_cnt == MPI_UNDEFINED);
        goto done;
    }

    if (unlikely(stuff->tx_drain)) {
        for (i = 0; i < out_cnt; i++) {
            if (unlikely(stuff->statuses[i].MPI_ERROR != MPI_SUCCESS))
                MPI_Abort(MPI_COMM_WORLD, 1);
        }
    } else {
        rec = &stuff->tx_rec[stuff->tx_rec_idx++];
        assert_always(stuff->tx_rec_idx < stuff->rec_cnt);
        rec->timestamp = now;
        rec->rank = my_rank;

        for (i = 0 ; i < out_cnt; i++) {
            if (unlikely(stuff->statuses[i].MPI_ERROR != MPI_SUCCESS))
                MPI_Abort(MPI_COMM_WORLD, 1);
            rec->cnt++;
            stuff->tx_recorded++;

            index = stuff->indicies[i];

            MPI_CALL(MPI_Isend, tx_buf + stuff->size * index,
                     stuff->size, MPI_CHAR, stuff->dst, TAG_DATA,
                     MPI_COMM_WORLD, &stuff->tx_req[index]);
            stuff->tx_queued++;
        }

    }

 done:
    if (unlikely(wrap64sub(now, stuff->end) >= 0)) {
        if (!stuff->tx_drain) {
            if (stuff->op_type == NTO1)
                MPI_CALL(MPI_Ireduce, &stuff->tx_queued, NULL, 1,
                         MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD,
                         &stuff->tx_done_req);
            else {
                MPI_CALL(MPI_Isend, &stuff->tx_queued, 1, MPI_UINT64_T,
                         stuff->dst, TAG_TX_DONE, MPI_COMM_WORLD,
                         &stuff->tx_done_req);

                if (out_cnt <= 0) {
                    rec = &stuff->tx_rec[stuff->tx_rec_idx++];
                    assert_always(stuff->tx_rec_idx < stuff->rec_cnt);
                    rec->timestamp = now;
                    rec->cnt = 0;
                    rec->rank = my_rank;
                }
            }
            stuff->tx_drain = true;
        } else if (stuff->tx_done_req != MPI_REQUEST_NULL) {
            MPI_CALL(MPI_Test, &stuff->tx_done_req, &done, stuff->statuses);
            if (done) {
                if (unlikely(stuff->statuses[0].MPI_ERROR != MPI_SUCCESS))
                    MPI_Abort(MPI_COMM_WORLD, 1);
            }
        }
    }

    return ret;
}

static void do_send_start(struct stuff *stuff, char *tx_buf)
{
    assert(stuff->tx_req_cnt == 0);

    for (; stuff->tx_req_cnt < stuff->tx_ops; stuff->tx_req_cnt++) {
        MPI_CALL(MPI_Isend, tx_buf + stuff->size * stuff->tx_req_cnt,
                 stuff->size, MPI_CHAR, stuff->dst, TAG_DATA,
                 MPI_COMM_WORLD, &stuff->tx_req[stuff->tx_req_cnt]);
        stuff->tx_queued++;
    }
}

static void gather_times(struct stuff *stuff, struct timeinfo *rx_tinfo,
                         struct timeinfo *tx_tinfo)
{
    struct timerank     *tr_all = NULL;
    struct timerank     tr_self = {
        .rank           = my_rank,
        .pid            = getpid(),
    };
    uint64_t            min_rx_nsec;
    uint64_t            max_rx_nsec;
    uint64_t            tot_rx_nsec;
    uint64_t            min_tx_nsec;
    uint64_t            max_tx_nsec;
    uint64_t            tot_tx_nsec;
    uint64_t            nsec;
    int                 i;
    int                 rx_ranks;
    int                 tx_ranks;

    if (my_rank == 0)
        tr_all = xcalloc(world_ranks, sizeof(*tr_all));

    if (stuff->rx_rec_idx) {
        nsec = cycles_to_nsec(stuff->rx_rec[stuff->rx_rec_idx - 1].timestamp -
                              stuff->start);
        tr_self.rx_nsec = nsec;
    }
    if (stuff->tx_rec_idx) {
        nsec = cycles_to_nsec(stuff->tx_rec[stuff->tx_rec_idx - 1].timestamp -
                              stuff->start);
        tr_self.tx_nsec = nsec;
    }
    /* Lazy about structs. */
    MPI_CALL(MPI_Gather, &tr_self, sizeof(tr_self), MPI_CHAR,
             tr_all, sizeof(*tr_all), MPI_CHAR, 0, MPI_COMM_WORLD);

    if (my_rank != 0)
        return;

    rx_ranks = tx_ranks = 0;
    max_rx_nsec = tot_rx_nsec = 0;
    min_rx_nsec = ~(uint64_t)0;
    max_tx_nsec = tot_tx_nsec = 0;
    min_tx_nsec = ~(uint64_t)0;
    for (i = 0; i < world_ranks; i++) {
        nsec = tr_all[i].rx_nsec;
        if (nsec) {
            rx_ranks++;
            tot_rx_nsec += nsec;
            min_rx_nsec = min(min_rx_nsec, nsec);
            max_rx_nsec = max(max_rx_nsec, nsec);
        }
        nsec = tr_all[i].tx_nsec;
        if (nsec) {
            tx_ranks++;
            tot_tx_nsec += nsec;
            min_tx_nsec = min(min_tx_nsec, nsec);
            max_tx_nsec = max(max_tx_nsec, nsec);
        }
    }
    if (rx_ranks) {
        rx_tinfo->min = (double)min_rx_nsec / 1000.0;
        rx_tinfo->max = (double)max_rx_nsec / 1000.0;
        rx_tinfo->ave = (double)tot_rx_nsec / (1000.0 * rx_ranks);
    }
    if (tx_ranks) {
        tx_tinfo->min = (double)min_tx_nsec / 1000.0;
        tx_tinfo->max = (double)max_tx_nsec / 1000.0;
        tx_tinfo->ave = (double)tot_tx_nsec / (1000.0 * tx_ranks);
    }
}

static void dump_info(int argc, char **argv, struct stuff *stuff)
{
    FILE                *info_file = NULL;
    struct timeinfo     rx_tinfo;
    struct timeinfo     tx_tinfo;
    char                *fname;
    int                 rc;
    int                 i;
    char                host[256];

    gather_times(stuff, &rx_tinfo, &tx_tinfo);

    if (gethostname(host, sizeof(host)) == -1) {
        rc = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "gethostname", NULL, rc);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    host[sizeof(host) - 1] = '\0';

    xasprintf(&fname, "%s/info", stuff->results_dir);
    info_file = fopen(fname, "w");
    if (!info_file) {
        rc = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "fopen", fname, rc);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    free(fname);

    fprintf(info_file, "%-10s", "command:");
    for (i = 0; i < argc; i++)
        fprintf(info_file, " %s", argv[i]);
    fprintf(info_file, "\n");
    fprintf(info_file, "%-13s %" PRIu64 "\n", "opsize:", stuff->size);
    fprintf(info_file, "%-13s %" PRIu64 "\n", "runtime:", stuff->seconds);
    fprintf(info_file, "%-13s %s\n", "host:", host);
    fprintf(info_file, "%-13s %d\n", "world_ranks:", world_ranks);
    fprintf(info_file, "%-13s %d\n", "node_ranks:", node_ranks);
    fprintf(info_file, "%-13s %d\n", "ops:", stuff->tx_ops);
    fprintf(info_file,
            "%-13s min: %10.3f usec max: %10.3f usec ave: %10.3f usec\n",
            "rx times", rx_tinfo.min, rx_tinfo.max, rx_tinfo.ave);
    fprintf(info_file,
            "%-13s min: %10.3f usec max: %10.3f usec ave: %10.3f usec\n",
            "tx times", tx_tinfo.min, tx_tinfo.max, tx_tinfo.ave);
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
    uint64_t            ops_expected = 0;
    struct io_rec       *rec;
    uint64_t            rec_idx;
    uint64_t            i;
    const char          *base_str;
    int                 rank;
    uint64_t            ops_seen;

    results_files = xcalloc(world_ranks, sizeof(*results_files));
    totals = xcalloc(world_ranks, sizeof(*totals));
    counts = xcalloc(world_ranks, sizeof(*counts));
    times = xcalloc(world_ranks, sizeof(*times));

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
        ops_expected = stuff->tx_recorded;
        dump_rec_open(stuff, base_str, results_files, my_rank, 1);
    } else {
        base_str = "recv";
        rec = stuff->rx_rec;
        rec_idx = stuff->rx_rec_idx;
        ops_expected = stuff->rx_recorded;

        switch (stuff->op_type) {

        case SENDU:
        case SENDB:
            dump_rec_open(stuff, base_str, results_files, rec->rank, 1);
            break;

        case NTO1:
            dump_rec_open(stuff, base_str, results_files, 1, world_ranks - 1);
            break;

        default:
            return;
        }
    }

    for (i = 0, ops_seen = 0; i < rec_idx; i++) {
        rank = rec[i].rank;
        totals[rank] += rec[i].cnt;
        ops_seen += rec[i].cnt;
        times[rank] = rec[i].timestamp - stuff->start;
        if (stuff->verbose || !counts[rank])
            fprintf(results_files[rank], "%.3f,%lu\n",
                    cycles_to_usec(times[rank], 1), totals[rank]);
        counts[rank]++;
    }
    assert_always(!ops_expected || ops_expected == ops_seen);

    if (!stuff->verbose) {
        for (rank = 0; rank < world_ranks; rank++) {
            if (counts[rank] > 1)
                fprintf(results_files[rank], "%.3f,%lu\n",
                        cycles_to_usec(times[rank], 1), totals[rank]);
        }
    }

    for (i = 0; i < world_ranks; i++) {
        if (results_files[i])
            fclose(results_files[i]);
    }
    free(results_files);
    free(totals);
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
    MPI_CALL(MPI_Bcast, &ts_start, sizeof(ts_start), MPI_CHAR,
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
    zhpe_stats_stamp_dbg(__func__, __LINE__, my_rank, stuff->dst, 0, 0);
    stuff->start = get_cycles(NULL);
    stuff->end += stuff->start;
}

static void do_send_to_self(void *buf, size_t req)
{
    MPI_Request         rx_req;
    MPI_Status          status;
    int                 cnt;

    MPI_CALL(MPI_Irecv, buf, req, MPI_CHAR, my_rank, TAG_SELF,
             MPI_COMM_WORLD, &rx_req);
    MPI_CALL(MPI_Send, buf, req, MPI_CHAR, my_rank, TAG_SELF, MPI_COMM_WORLD);
    MPI_CALL(MPI_Wait, &rx_req, &status);
    if (status.MPI_TAG != TAG_SELF || status.MPI_SOURCE != my_rank)
        MPI_Abort(MPI_COMM_WORLD, 1);
    MPI_Get_count(&status, MPI_CHAR, &cnt);
    if (cnt != req)
        MPI_Abort(MPI_COMM_WORLD, 1);
}

static void do_recv(struct stuff *stuff)
{
    char                *rx_buf;
    size_t              req;

    req = stuff->size * stuff->rx_ops;
    MPI_CALL(MPI_Alloc_mem, req, MPI_INFO_NULL, &rx_buf);
    memset(rx_buf, 0, req);

    /* Send buffer to ourselves to pre-register it. */
    do_send_to_self(rx_buf, req);

    do_recv_start(stuff, rx_buf);

    delay_start(stuff);
    zhpe_stats_stamp(zhpe_stats_subid(DBG, 0),
                     (uintptr_t)__func__, __LINE__, 0, 0, 0, 0);

    while (!do_recv_loop(stuff, rx_buf));
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
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

    /* Send buffer to ourselves to pre-register it. */
    do_send_to_self(tx_buf, req);

    delay_start(stuff);
    zhpe_stats_stamp(zhpe_stats_subid(DBG, 0),
                     (uintptr_t)__func__, __LINE__, 0, 0, 0, 0);

    do_send_start(stuff, tx_buf);

    while (!do_send_loop(stuff, tx_buf));
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    MPI_CALL(MPI_Free_mem, tx_buf);

    dump_rec(stuff, true);
}

#if 0

static void do_send_recv(struct stuff *stuff)
{
    int                 half = world_ranks / 2;
    int                 quarter = world_ranks / 4;

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
    /* Send buffer to ourselves to pre-register it. */
    do_send_to_self(rx_buf, req);

    req = stuff->size * stuff->tx_ops;
    MPI_CALL(MPI_Alloc_mem, req, MPI_INFO_NULL, &tx_buf);
    memset(tx_buf, 0, req);
    /* Send buffer to ourselves to pre-register it. */
    do_send_to_self(tx_buf, req);

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

    delay_start(stuff);
    zhpe_stats_stamp(zhpe_stats_subid(DBG, 0),
                     (uintptr_t)__func__, __LINE__, 0, 0, 0, 0);

    do_send_start(stuff, tx_buf);

    while (unlikely(!recv_done || !send_done)) {
        recv_done = do_recv_loop(stuff, rx_buf);
        send_done = do_send_loop(stuff, tx_buf);
    }
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
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
    delay_start(stuff);

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

        if (unlikely(wrap64sub(now, stuff->end) >= 0))
            break;
    }
    MPI_CALL(MPI_Win_unlock, dst, win);
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);

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

static void setup_connections_nto1(struct stuff *stuff)
{
    int                 total_conns;
    int                 cur_ops;
    int                 i;

    /* Do send-receive between all partners. */
    if (my_rank == 0) {
        for (total_conns = world_ranks - 1; total_conns > 0;
             total_conns -= cur_ops) {
            cur_ops = min(total_conns, (int)stuff->rx_ops);
            for (i = 0; i < cur_ops; i++)
                MPI_CALL(MPI_Irecv, NULL, 0, MPI_CHAR, MPI_ANY_SOURCE,
                         TAG_CONN, MPI_COMM_WORLD, &stuff->rx_req[i]);
            MPI_CALL(MPI_Waitall, cur_ops, stuff->rx_req, stuff->statuses);
            for (i = 0; i < cur_ops; i++) {
                if (unlikely(stuff->statuses[i].MPI_ERROR != MPI_SUCCESS))
                    MPI_Abort(MPI_COMM_WORLD, 1);
            }
        }
    } else
        /* Send to rank 0. */
        MPI_CALL(MPI_Send, NULL, 0, MPI_CHAR, 0, TAG_CONN, MPI_COMM_WORLD);
}

static void setup_connections_pair(struct stuff *stuff)
{

    /* Do send-receive between all partners. */
    if (my_rank >= world_ranks / 2) {
        /* We receive from our partner. */
        stuff->dst = my_rank - world_ranks / 2;
        MPI_CALL(MPI_Recv, NULL, 0, MPI_CHAR, stuff->dst,
                 TAG_CONN, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    } else {
        /* We send to our partner. */
        stuff->dst = my_rank + world_ranks / 2;
        MPI_CALL(MPI_Send, NULL, 0, MPI_CHAR, stuff->dst,
                 TAG_CONN, MPI_COMM_WORLD);
    }
#ifdef HAVE_ZHPE_STATS
    /* Now handshake for timestamping purposes. */
    {
        int                 i;

        MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
        zhpe_stats_stamp_dbg(__func__, __LINE__, my_rank, stuff->dst, 0, 0);
        for (i = 0; i < 10; i++) {
            if (my_rank >= world_ranks / 2) {
                MPI_CALL(MPI_Recv, NULL, 0, MPI_CHAR, stuff->dst,
                         TAG_TIMING, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                MPI_CALL(MPI_Send, NULL, 0, MPI_CHAR, stuff->dst,
                         TAG_TIMING, MPI_COMM_WORLD);
            } else {
                MPI_CALL(MPI_Send, NULL, 0, MPI_CHAR, stuff->dst,
                         TAG_TIMING, MPI_COMM_WORLD);
                MPI_CALL(MPI_Recv, NULL, 0, MPI_CHAR, stuff->dst,
                         TAG_TIMING, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
        }
        zhpe_stats_stamp_dbg(__func__, __LINE__, my_rank, stuff->dst, 0, 0);
        /* No barriers or anything to complicate the trace. */
        sleep(1);
   }
#endif
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    zhpeu_print_usage(
        help,
        "Usage:%s [-bgnp] <size> <seconds> <results_dir>]\n"
        "<size> is the per-operation size and <bw_est> is an estimate\n"
        "of tx/rx butes/sec available on a node; this is used to compute\n"
        "the number of outstanding operations\n"
        "<size> and <bw_est>  may be postfixed with [kmgtKMGT] to specify\n"
        "the base units. Lower case is base 10; upper case is base 2.\n"
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
    MPI_Comm            node_comm;

    zhpeu_util_init(argv[0], LOG_INFO, false);

    zhpe_stats_init(zhpeu_appname);
    zhpe_stats_test(0);
    zhpe_stats_open(1);

    MPI_CALL(MPI_Init, &argc, &argv);
    MPI_CALL(MPI_Comm_size, MPI_COMM_WORLD, &world_ranks);
    MPI_CALL(MPI_Comm_rank, MPI_COMM_WORLD, &my_rank);
    MPI_CALL(MPI_Comm_split_type, MPI_COMM_WORLD, MPI_COMM_TYPE_SHARED,
             0, MPI_INFO_NULL, &node_comm);
    MPI_CALL(MPI_Comm_size, node_comm, &node_ranks);
    MPI_CALL(MPI_Comm_free, &node_comm);

    /*
     * An early barrier before initializing stats to allow per-node
     * scripts to clean up. Also initializes barrier connections.
     */
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);

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

    if (opt != 3)
        usage(false);

    if (_zhpeu_parse_kb_uint64_t("size", argv[optind++], &stuff->size,
                                 0, 1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 ||
        _zhpeu_parse_kb_uint64_t("seconds", argv[optind++], &stuff->seconds,
                                 0, 1, INT_MAX, PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    stuff->results_dir = argv[optind++];

    if (stuff->op_type != NTO1) {
        if (world_ranks & 1) {
            zhpeu_print_err("Ranks must be a multiple of 2 for this test\n");
            goto done;
        }
    }

    stuff->tx_ops = OPS_MAX_SIZE / stuff->size * OPS_MIN;
    stuff->tx_ops = max(stuff->tx_ops, OPS_MIN);
    stuff->tx_ops = min(stuff->tx_ops, OPS_MAX);
    stuff->rx_ops = stuff->tx_ops;
    stuff->rec_cnt = stuff->seconds * SAMPLES_PER_SEC;
    stuff->rx_req = xcalloc(stuff->rx_ops, sizeof(*stuff->rx_req));
    stuff->rx_rec = xcalloc(stuff->rec_cnt, sizeof(*stuff->rx_rec));
    stuff->rx_rank_rec = xcalloc(world_ranks, sizeof(*stuff->rx_rank_rec));
    stuff->statuses = xcalloc(max(stuff->tx_ops, stuff->rx_ops),
                              sizeof(*stuff->statuses));
    stuff->indicies = xcalloc(max(stuff->tx_ops, stuff->rx_ops),
                              sizeof(*stuff->indicies));
    stuff->tx_req = xcalloc(stuff->tx_ops, sizeof(*stuff->tx_req));
    stuff->tx_rec = xcalloc(stuff->rec_cnt, sizeof(*stuff->tx_rec));

    stuff->end = stuff->seconds * zhpeu_init_time->freq;

    switch (stuff->op_type) {

    case NTO1:
        setup_connections_nto1(stuff);
        if (my_rank == 0)
            do_recv(stuff);
        else
            do_send(stuff);
        break;

    case SENDU:
        setup_connections_pair(stuff);
        if (my_rank >= world_ranks / 2)
            do_recv(stuff);
        else
            do_send(stuff);
        break;

    case SENDB:
        setup_connections_pair(stuff);
        do_send_recv(stuff);
        break;

    case GETU:
        setup_connections_pair(stuff);
        if (my_rank >= world_ranks / 2)
            do_rma_unidir_remote(stuff);
        else
            do_rma_unidir(stuff, false);
        break;

    case PUTU:
        setup_connections_pair(stuff);
        if (my_rank >= world_ranks / 2)
            do_rma_unidir_remote(stuff);
        else
            do_rma_unidir(stuff, true);
        break;

    case GETB:
        setup_connections_pair(stuff);
        do_rma_bidir(stuff, false);
        break;

    case PUTB:
        setup_connections_pair(stuff);
        do_rma_bidir(stuff, true);
        break;

    default:
        goto done;
    }

    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    if (my_rank == 0)
        dump_info(argc, argv, stuff);
    else
        gather_times(stuff, NULL, NULL);
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
