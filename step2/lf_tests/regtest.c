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

#include <sys/mman.h>

#include <zhpe_stats.h>
#include <zhpeq_util_fab.h>

#define PROVIDER        "zhpe"
#define EP_TYPE         FI_EP_RDM

struct args {
    uint64_t            start_size;
    uint64_t            steps;
    uint64_t            iterations;
};

static int do_reg(const struct args *args)
{
    int                 ret = 0;
    char                *buf = NULL;
    struct fid_mr       *mr = NULL;
    const uint64_t      lcl_acc =  FI_READ | FI_WRITE;
    const uint64_t      rem_acc =  FI_REMOTE_READ | FI_REMOTE_WRITE;
    size_t              buf_size;
    struct fab_dom      fab_dom;
    uint64_t            size;
    uint64_t            steps;
    uint64_t            i;

    fab_dom_init(&fab_dom);

    buf_size = (size_t)args->start_size << (args->steps - 1);
    buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (buf == MAP_FAILED) {
        ret = -errno;
        buf = NULL;
        print_func_errn(__func__, __LINE__, "mmap", buf_size, false, ret);
        goto done;
    }
    ret = fab_dom_setup(NULL, NULL, true, PROVIDER, NULL, EP_TYPE, &fab_dom);
    if (ret < 0)
        goto done;

    for (size = args->start_size, steps = 0; steps < args->steps;
         size <<= 1, steps++) {
        zhpe_stats_stamp(0, size, 0, 0, 0, 0, 0);
        /* Warmups, local+remote. */
        for (i = 0; i < 10; i++) {
            ret = fi_mr_reg(fab_dom.domain, buf, buf_size, lcl_acc | rem_acc,
                            0, 0, 0, &mr, NULL);
            if (ret < 0) {
                print_func_fi_err(__func__, __LINE__, "fi_mr_reg", "", ret);
                goto done;
            }
            fi_close(&mr->fid);
        }
        /* Gathering statistics, local+remote. */
        zhpe_stats_enable();
        for (i = 0; i < args->iterations; i++)  {
            zhpe_stats_start(10);
            ret = fi_mr_reg(fab_dom.domain, buf, size, lcl_acc | rem_acc,
                            0, 0, 0, &mr, NULL);
            zhpe_stats_stop(10);
            if (ret < 0) {
                print_func_fi_err(__func__, __LINE__, "fi_mr_reg", "", ret);
                goto done;
            }
            zhpe_stats_start(20);
            fi_close(&mr->fid);
            zhpe_stats_stop(20);
        }
        zhpe_stats_disable();
        /* Warmups, local only. */
        for (i = 0; i < 10; i++) {
            ret = fi_mr_reg(fab_dom.domain, buf, buf_size, lcl_acc,
                            0, 0, 0, &mr, NULL);
            if (ret < 0) {
                print_func_fi_err(__func__, __LINE__, "fi_mr_reg", "", ret);
                goto done;
            }
            fi_close(&mr->fid);
        }
        /* Gathering statistics, local only. */
        zhpe_stats_enable();
        for (i = 0; i < args->iterations; i++)  {
            zhpe_stats_start(30);
            ret = fi_mr_reg(fab_dom.domain, buf, size, lcl_acc,
                            0, 0, 0, &mr, NULL);
            zhpe_stats_stop(30);
            if (ret < 0) {
                print_func_fi_err(__func__, __LINE__, "fi_mr_reg", "", ret);
                goto done;
            }
            zhpe_stats_start(40);
            fi_close(&mr->fid);
            zhpe_stats_stop(40);
        }
        zhpe_stats_disable();
    }
 done:
    if (buf)
        munmap(buf, buf_size);
    fab_dom_free(&fab_dom);

    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s <start-size> <steps> <iterations>\n"
        "Register/free memory and collect zhpe statistics\n"
        "sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "(Note: must set ZHPE_STATS_DIR if using stats.)\n",
        appname);

    if (help) {
        printf("\n");
        fab_print_info(NULL);
    }

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = { 0 };

    zhpeq_util_init(argv[0], LOG_INFO, false);

    zhpe_stats_init("reg");
    zhpe_stats_test(0);
    zhpe_stats_open(1);

    if (argc != 4)
        usage(true);

    if (parse_kb_uint64_t(__func__, __LINE__, "start-size",
                          argv[1], &args.start_size, 0, 1, SIZE_MAX, 0) < 0 ||
        parse_kb_uint64_t(__func__, __LINE__, "steps",
                          argv[2], &args.steps, 0, 1, 64,
                          PARSE_KB | PARSE_KIB) ||
        parse_kb_uint64_t(__func__, __LINE__, "iterations",
                          argv[3], &args.iterations, 0, 1,
                          SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    if (do_reg(&args) < 0)
        goto done;

    ret = 0;
 done:

    zhpe_stats_stop_all();
    zhpe_stats_close();
    zhpe_stats_finalize();

    return ret;
}
