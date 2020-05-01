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
        "Usage:%s <pages>\n"
        "Allocate a region of <pages> and force IOMMU invalidations\n"
        "<pages>  may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n",
        zhpeu_appname);

    MPI_CALL(MPI_Finalize);
    _exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 255;
    char                tmp_fname[] = "/dev/shm/inv.XXXXXX";
    int                 fd = -1;
    char                *map = NULL;
    char                *cur;
    uint64_t            pages;
    uint64_t            i;

    MPI_CALL(MPI_Init, &argc, &argv);
    MPI_CALL(MPI_Comm_size, MPI_COMM_WORLD, &n_ranks);
    MPI_CALL(MPI_Comm_rank, MPI_COMM_WORLD, &my_rank);

    if (argc == 1)
        usage(true);

    if (argc != 2)
        usage(false);

    if (_zhpeu_parse_kb_uint64_t("pages", argv[1], &pages,
                                 0, 1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
        goto done;

    ret = 1;

    fd = mkstemp(tmp_fname);
    if (fd == -1) {
        zhpeu_print_func_err(__func__, __LINE__, "mkstemp", tmp_fname, -errno);
        goto done;
    }
    if (unlink(tmp_fname) == -1) {
        zhpeu_print_func_err(__func__, __LINE__, "unlink", tmp_fname, -errno);
        goto done;
    }

    /* Map pages for entire range. */
    map = _zhpeu_mmap(NULL, zhpeu_init_time->pagesz * pages,
                      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
    if (!map)
        goto done;

    MPI_CALL(MPI_Barrier, MPI_COMM_WORLD);
    /* Punch holes in region making 1 page ranges. */
    for (i = 1; i < pages; i += 2) {
        cur = map + i * zhpeu_init_time->pagesz;
        if (_zhpeu_munmap(cur, zhpeu_init_time->pagesz) < 0)
            goto done;
    }

    ret = 0;

 done:
    /* Free whole range. */
    if (_zhpeu_munmap(map, zhpeu_init_time->pagesz * pages) < 0 && !ret)
        ret = 1;
    MPI_CALL(MPI_Finalize);

    return ret;
}
