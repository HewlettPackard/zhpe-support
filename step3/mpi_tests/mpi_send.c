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


static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    zhpeu_print_usage(
        help,
        "Usage:%s <loops> <size>\n"
        "Two ranks required\n",
        zhpeu_appname);

    MPI_CALL(MPI_Finalize);
    _exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    char                *buf = NULL;
    size_t              buf_size;
    uint64_t            loops;
    uint64_t            size;
    uint64_t            i;

    zhpeu_util_init(argv[0], LOG_INFO, false);

    zhpe_stats_init(zhpeu_appname);
    zhpe_stats_test(0);
    zhpe_stats_open(1);
    zhpe_stats_enable();
    zhpe_stats_start(0);
    zhpe_stats_start(10);
    zhpe_stats_disable();

    MPI_CALL(MPI_Init, &argc, &argv);

    MPI_CALL(MPI_Comm_size, MPI_COMM_WORLD, &n_ranks);
    MPI_CALL(MPI_Comm_rank, MPI_COMM_WORLD, &my_rank);

    if (!my_rank) {
        if (argc == 1)
            usage(true);
        else if (argc != 3 || n_ranks != 2)
            usage(false);
    }

    if (_zhpeu_parse_kb_uint64_t("loops", argv[1], &loops, 0, 1, SIZE_MAX,
                                 PARSE_KB | PARSE_KIB) < 0 ||
        _zhpeu_parse_kb_uint64_t("size", argv[2], &size, 0, 0, SIZE_MAX,
                                 PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    buf_size = (size ?: 1) * 2;
    buf = zhpeu_mmap(NULL, buf_size, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (!buf)
        goto done;

    zhpe_stats_enable();
    zhpe_stats_stop(10);
    zhpe_stats_start(20);
    zhpe_stats_disable();

    memset(buf + size, 0xFF, size);
    if (!my_rank) {
        printf("loops %" PRIu64 " size %" PRIu64 "\n", loops, size);

        zhpe_stats_enable();
        for (i = 0; i < loops; i++) {
            zhpe_stats_start(100);
            MPI_CALL(MPI_Send, buf, size, MPI_BYTE, 1, 0, MPI_COMM_WORLD);
            zhpe_stats_stop(100);
            zhpe_stats_start(110);
            MPI_CALL(MPI_Recv, buf + size, size, MPI_BYTE, 1, 0, MPI_COMM_WORLD,
                     MPI_STATUS_IGNORE);
            zhpe_stats_stop(110);
        }
        zhpe_stats_disable();
        MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    }
    else {
        for (i = 0; i < loops; i++) {
            MPI_CALL(MPI_Recv, buf + size, size, MPI_BYTE, 0, 0, MPI_COMM_WORLD,
                     MPI_STATUS_IGNORE);
            MPI_CALL(MPI_Send, buf, size, MPI_BYTE, 0, 0, MPI_COMM_WORLD);
        }
        MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    }
    ret = 0;

    zhpe_stats_enable();
    zhpe_stats_stop(20);
    zhpe_stats_start(30);
    zhpe_stats_disable();

 done:
    if (buf)
        munmap(buf, size);
    MPI_CALL(MPI_Finalize);

    zhpe_stats_close();
    zhpe_stats_finalize();

    return ret;
}
