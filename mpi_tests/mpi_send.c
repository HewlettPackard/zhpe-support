/*
 * Copyright (C) 2017-2018 Hewlett Packard Enterprise Development LP.
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

#define WARMUP          (100)

int main(int argc, char **argv)
{
    int                 ret = 1;
    uint64_t            size = 1;
    void                *buf = NULL;
    uint64_t            loops;
    uint64_t            i;
    int                 n_proc;
    int                 n_rank;

    if (MPI_Init(&argc, &argv) != MPI_SUCCESS)
        goto done;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Need loops and, optionally, size.\n");
        goto done;
    }

    if (parse_kb_uint64_t(__func__, __LINE__, "loops",
                          argv[1], &loops, 0, 1, SIZE_MAX,
                          PARSE_KB | PARSE_KIB) < 0)
        goto done;
    if (argc == 3 &&
        parse_kb_uint64_t(__func__, __LINE__, "size",
                          argv[2], &size, 0, 1, SIZE_MAX,
                          PARSE_KB | PARSE_KIB) < 0)
        goto done;

    buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
               MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (buf == MAP_FAILED) {
        buf = NULL;
        goto done;
    }

    if (MPI_Comm_size(MPI_COMM_WORLD, &n_proc) != MPI_SUCCESS)
        goto done;

    if (MPI_Comm_rank(MPI_COMM_WORLD, &n_rank) != MPI_SUCCESS)
        goto done;

    if (!n_rank) {
        if (n_proc != 2) {
            fprintf(stderr, "Need 2 ranks, not %d\n", n_proc);
            goto done;
        }
        printf("loops %Lu size %Lu\n", (ullong)loops, (ullong)size);
        for (i = 0; i < WARMUP; i++) {
            if (MPI_Send(buf, size, MPI_BYTE, 1, 0, MPI_COMM_WORLD)
                != MPI_SUCCESS)
                goto done;
            if (MPI_Recv(buf, size, MPI_BYTE, 1, 0, MPI_COMM_WORLD,
                         MPI_STATUS_IGNORE) != MPI_SUCCESS)
                goto done;
        }

        for (i = 0; i < loops; i++) {
            if (MPI_Send(buf, size, MPI_BYTE, 1, 0, MPI_COMM_WORLD)
                != MPI_SUCCESS)
                goto done;
            if (MPI_Recv(buf, size, MPI_BYTE, 1, 0, MPI_COMM_WORLD,
                         MPI_STATUS_IGNORE) != MPI_SUCCESS)
                goto done;
        }
        printf("RANK %d\n", n_rank);
        MPI_Barrier(MPI_COMM_WORLD);
    }
    else {
        for (i = 0; i < WARMUP; i++) {
            if (MPI_Recv(buf, size, MPI_BYTE, 0, 0, MPI_COMM_WORLD,
                         MPI_STATUS_IGNORE) != MPI_SUCCESS)
                goto done;
            if (MPI_Send(buf, size, MPI_BYTE, 0, 0, MPI_COMM_WORLD)
                != MPI_SUCCESS)
                goto done;
        }

        for (i = 0; i < loops; i++) {
            if (MPI_Recv(buf, size, MPI_BYTE, 0, 0, MPI_COMM_WORLD,
                         MPI_STATUS_IGNORE) != MPI_SUCCESS)
                goto done;
            if (MPI_Send(buf, size, MPI_BYTE, 0, 0, MPI_COMM_WORLD)
                != MPI_SUCCESS)
                goto done;
        }
        MPI_Barrier(MPI_COMM_WORLD);
        printf("RANK %d\n", n_rank);
    }
    ret = 0;

 done:
    if (buf)
        munmap(buf, size);
    MPI_Finalize();
    if (ret)
        fprintf(stderr, "error\n");

    return ret;
}
