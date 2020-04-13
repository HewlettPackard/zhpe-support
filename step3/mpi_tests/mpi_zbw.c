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

/* If the number of samples per sec exceeds this, I'm happy! */
#define SAMPLES_PER_SEC (1000000UL)

enum {
    TAG_DATA,
    TAG_DONE,
};

struct io_rec {
    uint64_t            timestamp;
    uint64_t            cnt;
};

struct stuff {
    uint64_t            size;
    uint64_t            ops;
    uint64_t            seconds;
    const char          *results_dir;
    void                *buf;
    MPI_Request         *tx_req;
    uint64_t            tx_req_cnt;
    uint64_t            tx_queued;
    uint64_t            tx_done;
    uint64_t            tx_end_time;
    uint64_t            tx_end_cnt;
    struct io_rec       *tx_rec;
    uint64_t            tx_rec_idx;
    MPI_Request         *rx_req;
    uint64_t            rx_req_cnt;
    uint64_t            rx_queued;
    uint64_t            rx_done;
    uint64_t            rx_end_cnt;
    uint64_t            rx_end_tot;
    int                 rx_end_rcv;
    uint64_t            rx_end_buf;
    struct io_rec       *rx_rec;
    uint64_t            rx_rec_idx;
    uint64_t            rec_cnt;
    uint64_t            start;
    uint64_t            end;
    int                 *indicies;
    int                 dst;
    bool                bidir_opt;
    bool                nto1_opt;
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

static bool do_recv_loop(struct stuff *stuff)
{
    int                 out_cnt;
    int                 i;
    struct io_rec       *rec;

    MPI_CALL(MPI_Testsome, stuff->rx_req_cnt, stuff->rx_req, &out_cnt,
             stuff->indicies, MPI_STATUSES_IGNORE);
    if (unlikely(out_cnt <= 0))
        goto done;

    rec = &stuff->rx_rec[stuff->rx_rec_idx++];
    assert_always(stuff->rx_rec_idx < stuff->rec_cnt);
    rec->timestamp = get_cycles(NULL);

    for (i = 0; i < out_cnt; i++) {
        if (likely(stuff->indicies[i] > 0)) {
            stuff->rx_done++;
            MPI_CALL(MPI_Irecv, stuff->buf, stuff->size, MPI_CHAR,
                     MPI_ANY_SOURCE, TAG_DATA, MPI_COMM_WORLD,
                     &stuff->rx_req[stuff->indicies[i]]);
            stuff->rx_queued++;
        } else {
            stuff->rx_end_tot += stuff->rx_end_buf;
            if (stuff->nto1_opt && ++stuff->rx_end_rcv < n_ranks - 1)
                MPI_CALL(MPI_Irecv, &stuff->rx_end_buf, 1, MPI_UINT64_T,
                         MPI_ANY_SOURCE, TAG_DONE, MPI_COMM_WORLD,
                         &stuff->rx_req[0]);
            else
                stuff->rx_end_cnt = stuff->rx_end_tot;
        }
    }
    rec->cnt = stuff->rx_done;

 done:
    return unlikely(stuff->rx_done >= stuff->rx_end_cnt);
}

static void do_recv_start(struct stuff *stuff)
{
    assert(stuff->rx_req_cnt == 0);
    stuff->rx_end_cnt = UINT64_MAX;
    MPI_CALL(MPI_Irecv, &stuff->rx_end_buf, 1, MPI_UINT64_T, MPI_ANY_SOURCE,
             TAG_DONE, MPI_COMM_WORLD, &stuff->rx_req[stuff->rx_req_cnt++]);

    for (; stuff->rx_req_cnt <= stuff->ops * 2; stuff->rx_req_cnt++) {
        MPI_CALL(MPI_Irecv, stuff->buf, stuff->size, MPI_CHAR, MPI_ANY_SOURCE,
                 TAG_DATA, MPI_COMM_WORLD, &stuff->rx_req[stuff->rx_req_cnt]);
        stuff->rx_queued++;
    }
}

static bool do_send_loop(struct stuff *stuff)
{
    bool                ret = false;
    int                 out_cnt;
    int                 i;
    struct io_rec       *rec;

    MPI_CALL(MPI_Testsome, stuff->tx_req_cnt, stuff->tx_req, &out_cnt,
             stuff->indicies, MPI_STATUSES_IGNORE);
    if (unlikely(out_cnt <= 0)) {
        ret = unlikely(out_cnt == MPI_UNDEFINED);
        goto done;
    }

    rec = &stuff->tx_rec[stuff->tx_rec_idx++];
    assert_always(stuff->tx_rec_idx < stuff->rec_cnt);
    rec->timestamp = get_cycles(NULL);

    if (unlikely((int64_t)(stuff->end - rec->timestamp) < 0)) {
        if (stuff->tx_end_cnt == UINT64_MAX) {
            stuff->tx_end_cnt = stuff->tx_queued;
            MPI_CALL(MPI_Isend, &stuff->tx_end_cnt, 1, MPI_UINT64_T,
                     stuff->dst, TAG_DONE, MPI_COMM_WORLD, &stuff->tx_req[0]);
        }
    }

    for (i = 0; likely(i < out_cnt); i++) {
        if (likely(stuff->indicies[i] > 0)) {
            stuff->tx_done++;
            if (unlikely(stuff->tx_queued >= stuff->tx_end_cnt))
                continue;
            MPI_CALL(MPI_Isend, stuff->buf, stuff->size, MPI_CHAR,
                     stuff->dst, TAG_DATA, MPI_COMM_WORLD,
                     &stuff->tx_req[stuff->indicies[i]]);
            stuff->tx_queued++;
        }
    }
    rec->cnt = stuff->tx_done;

 done:
    return ret;
}

static void do_send_start(struct stuff *stuff)
{
    stuff->tx_end_cnt = UINT64_MAX;
    stuff->tx_req[stuff->tx_req_cnt++] = MPI_REQUEST_NULL;

    for (; stuff->tx_req_cnt <= stuff->ops; stuff->tx_req_cnt++) {
        MPI_CALL(MPI_Isend, stuff->buf, stuff->size, MPI_CHAR, stuff->dst,
                 TAG_DATA, MPI_COMM_WORLD, &stuff->tx_req[stuff->tx_req_cnt]);
        stuff->tx_queued++;
    }
}

static void dump_rec(struct stuff *stuff, bool send)
{
    FILE                *results_file = NULL;
    char                *fname;
    struct io_rec       *rec;
    uint64_t            rec_idx;
    const char         *label;
    int                 rc;
    uint64_t            i;

    zhpe_stats_disable();
    if (send) {
        rec = stuff->tx_rec;
        rec_idx = stuff->tx_rec_idx;
        label = "send";
    } else {
        rec = stuff->rx_rec;
        rec_idx = stuff->rx_rec_idx;
        label = "recv";
    }

    xasprintf(&fname, "%s/%s.%d", stuff->results_dir, label, my_rank);
    results_file = fopen(fname, "w");
    free(fname);
    if (!results_file) {
        rc = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "fopen", fname, rc);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    fprintf(results_file, "%lu %lu %lu %s\n",
            stuff->size, stuff->ops, stuff->seconds, getenv("HOSTNAME"));
    for (i = 0; i < rec_idx; i++)
        fprintf(results_file, "%.3f,%lu\n",
                cycles_to_usec(rec[i].timestamp - stuff->start, 1),
                rec[i].cnt * stuff->size);
    fclose(results_file);
}

static void do_recv(struct stuff *stuff)
{
    do_recv_start(stuff);
    while (!do_recv_loop(stuff));
    dump_rec(stuff, false);
}

static void do_send(struct stuff *stuff)
{
    do_send_start(stuff);
    while (!do_send_loop(stuff));
    dump_rec(stuff, true);
}

static void do_send_recv(struct stuff *stuff)
{
    bool                recv_done = false;
    bool                send_done = false;

    do_recv_start(stuff);
    do_send_start(stuff);

    while (unlikely(!recv_done && !send_done)) {
        recv_done = do_recv_loop(stuff);
        send_done = do_send_loop(stuff);
    }
    dump_rec(stuff, false);
    dump_rec(stuff, true);
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    zhpeu_print_usage(
        help,
        "Usage:%s [-bn] <size> <ops-outstanding> <seconds> <results_dir>]\n"
        "<size> and <ops>  may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        " -b : bi-directional traffic (exclusive with -n)\n"
        " -n : n-to-1 traffic (exclusive with -b)\n",
        zhpeu_appname);

    MPI_CALL(MPI_Finalize);
    _exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct stuff        stuff  = { 0 };
    int                 opt;

    zhpeu_util_init(argv[0], LOG_INFO, false);

    zhpe_stats_init(zhpeu_appname);
    zhpe_stats_test(0);
    zhpe_stats_open(1);
    zhpe_stats_disable();

    MPI_CALL(MPI_Init, &argc, &argv);
    MPI_CALL(MPI_Comm_size, MPI_COMM_WORLD, &n_ranks);
    MPI_CALL(MPI_Comm_rank, MPI_COMM_WORLD, &my_rank);

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "bn")) != -1) {

        switch (opt) {

        case 'b':
            if (stuff.bidir_opt || stuff.nto1_opt)
                usage(false);
            stuff.bidir_opt = true;
            break;

        case 'n':
            if (stuff.bidir_opt || stuff.nto1_opt)
                usage(false);
            stuff.nto1_opt = true;
            break;

        default:
            usage(false);

        }
    }

    opt = argc - optind;

    if (opt != 4)
        usage(false);

    if (_zhpeu_parse_kb_uint64_t("size", argv[optind++], &stuff.size,
                                 0, 1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 ||
        _zhpeu_parse_kb_uint64_t("ops", argv[optind++], &stuff.ops,
                                 0, 1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 ||
        _zhpeu_parse_kb_uint64_t("seconds", argv[optind++], &stuff.seconds,
                                 0, 1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    stuff.results_dir = argv[optind++];

    if (!stuff.nto1_opt && (n_ranks & 1)) {
        zhpeu_print_err("An even number of ranks is required for !nto1\n");
        goto done;
    }

    stuff.buf = _zhpeu_mmap(NULL, stuff.size, PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (!stuff.buf)
        goto done;

    stuff.rec_cnt = stuff.seconds * SAMPLES_PER_SEC;
    stuff.rx_req = xcalloc(stuff.ops * 2 + 1, sizeof(*stuff.rx_req));
    stuff.rx_rec = xcalloc(stuff.rec_cnt, sizeof(*stuff.rx_rec));
    stuff.indicies = xcalloc(stuff.ops * 2 + 1, sizeof(*stuff.indicies));
    stuff.tx_req = xcalloc(stuff.ops + 1, sizeof(*stuff.tx_req));
    stuff.tx_rec = xcalloc(stuff.rec_cnt, sizeof(*stuff.tx_rec));

    stuff.end = stuff.seconds * zhpeu_init_time->freq;
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    zhpe_stats_enable();
    stuff.start = get_cycles(NULL);
    stuff.end += stuff.start;
    if (stuff.nto1_opt) {
        if (my_rank == 0) {
            do_recv(&stuff);
        } else
            do_send(&stuff);
    } else {
        if (my_rank >= n_ranks / 2) {
            stuff.dst = my_rank - n_ranks / 2;
            if (stuff.bidir_opt)
                do_send_recv(&stuff);
            else
                do_recv(&stuff);
        } else {
            stuff.dst = my_rank + n_ranks / 2;
            if (stuff.bidir_opt)
                do_send_recv(&stuff);
            else
                do_send(&stuff);
        }
    }
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    ret = 0;

 done:
    if (stuff.buf)
        munmap(stuff.buf, stuff.size);
    free(stuff.rx_req);
    free(stuff.rx_rec);
    free(stuff.indicies);
    free(stuff.tx_req);
    free(stuff.tx_rec);
    MPI_CALL(MPI_Finalize);
    zhpe_stats_close();
    zhpe_stats_finalize();

    return ret;
}
