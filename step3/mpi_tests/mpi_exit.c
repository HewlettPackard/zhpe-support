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

#include <zhpeq_util.h>

static int n_ranks = -1;
static int my_rank = -1;

#define MPI_CALL(_func, ...)                                    \
do {                                                            \
    int                 __rc = _func(__VA_ARGS__);              \
                                                                \
    if (unlikely(__rc != MPI_SUCCESS)) {                        \
        print_err("%s,%u:%d:%s() returned %d\n",                \
                  __func__, __LINE__, my_rank, #_func, __rc);   \
        MPI_Abort(MPI_COMM_WORLD, 1);                           \
    }                                                           \
} while (0)

static char             buf[4096];

int main(int argc, char **argv)
{
    MPI_Request         *requests = NULL;
    int                 req = 0;
    int                 i;
    uint64_t            wakeup;

    MPI_CALL(MPI_Init, &argc, &argv);
    MPI_CALL(MPI_Comm_size, MPI_COMM_WORLD, &n_ranks);
    MPI_CALL(MPI_Comm_rank, MPI_COMM_WORLD, &my_rank);

    requests = xcalloc(n_ranks * 2, sizeof(*requests));

    for (i = 0; i < n_ranks; i++) {
        MPI_CALL(MPI_Irecv, buf, sizeof(buf), MPI_CHAR, i, 0, MPI_COMM_WORLD,
                 &requests[req++]);
    }
    for (i = 0; i < n_ranks; i++) {
        MPI_CALL(MPI_Isend, buf, sizeof(buf), MPI_CHAR, i, 0, MPI_COMM_WORLD,
                 &requests[req++]);
    }
    MPI_CALL(MPI_Waitall, req, requests, MPI_STATUSES_IGNORE);
    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);

    wakeup = get_cycles(NULL) + zhpeu_init_time->freq;
    MPI_CALL(MPI_Bcast, &wakeup, 1, MPI_UINT64_T, 0, MPI_COMM_WORLD);

    /* Try to synchrnoize exit as accurately as possible. */
    while ((int64_t)(get_cycles(NULL) - wakeup) < 0);
    /* Exit without cleaning up. */
    _exit(0);

    return 0;
}
