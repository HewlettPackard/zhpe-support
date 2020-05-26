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

void do_barrier(int barrier)
{
    struct timerank     *tr_all = NULL;
    struct timerank     tr_self = { .rank = my_rank };
    double              delta_us = 0.0;
    uint64_t            delta;
    int                 i;

    if (my_rank == 0)
        tr_all = xcalloc(n_ranks, sizeof(*tr_all));

    zhpe_stats_stamp_dbg(__func__, __LINE__, 0, 0, 0, 0);
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    clock_gettime(CLOCK_REALTIME, &tr_self.ts_barrier);

    /* Lazy about structs. */
    zhpe_stats_stamp_dbg(__func__, __LINE__, 0, 0, 0, 0);
    MPI_CALL(MPI_Gather, &tr_self, sizeof(tr_self), MPI_CHAR,
             tr_all, sizeof(*tr_all), MPI_CHAR, 0, MPI_COMM_WORLD);

    if (my_rank != 0)
        return;

    qsort(tr_all, n_ranks, sizeof(*tr_all), tr_compare);

    for (i = 0;  i < n_ranks; i++) {
        delta = ts_delta(&tr_all[0].ts_barrier, &tr_all[i].ts_barrier);
        delta_us = (double)delta / 1000.0;
        if (tr_all[i].rank < 0 || tr_all[i].rank >= n_ranks ||
            delta_us > 1000.0)
            fprintf(stderr, "BAD     %5d rank %3d delta %10.3f usec\n",
                    barrier, tr_all[i].rank, delta_us);
        else if (i == n_ranks - 1)
            printf("barrier %5d rank %3d delta %10.3f usec\n",
                   barrier, tr_all[n_ranks - 1].rank, delta_us);
    }
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    zhpeu_print_usage(
        help,
        "Usage:%s <barriers>\n",
        zhpeu_appname);

    MPI_CALL(MPI_Finalize);
    _exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    uint64_t            barriers;
    uint64_t            i;

    zhpeu_util_init(argv[0], LOG_INFO, false);

    MPI_CALL(MPI_Init, &argc, &argv);

    MPI_CALL(MPI_Comm_size, MPI_COMM_WORLD, &n_ranks);
    MPI_CALL(MPI_Comm_rank, MPI_COMM_WORLD, &my_rank);

    if (argc != 2)
        usage(false);

    if (_zhpeu_parse_kb_uint64_t("barriers", argv[1], &barriers, 0, 1, SIZE_MAX,
                                 PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    zhpe_stats_init(zhpeu_appname);
    zhpe_stats_enable();

    for (i = 0; i < barriers; i++)
        do_barrier(i);
    zhpe_stats_disable();

    zhpe_stats_close();
    zhpe_stats_finalize();
    MPI_CALL(MPI_Finalize);

    return 0;
}
