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

#include <zhpeq.h>

#include <limits.h>

static struct zhpeq_attr zhpeq_attr;

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s <ops>\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n",
        appname);

    exit(255);
}

static void do_pci_rd(struct zhpeq_rq *zrq, size_t ops)
{
    size_t              i;
    struct zhpeu_timing pci_rd;
    uint64_t            start;

    zhpeu_timing_reset(&pci_rd);
    for (i = 0; i < ops; i++) {
        start = get_cycles(NULL);
        qcmread64(zrq->qcm, ZHPE_RDM_QCM_RCV_QUEUE_HEAD_OFFSET);
        zhpeu_timing_update(&pci_rd, get_cycles(NULL) - start);
    }
    zhpeu_timing_print(&pci_rd, "pci_rd", 1);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct zhpeq_rq     *zrq = NULL;
    struct zhpeq_dom    *zqdom = NULL;
    uint64_t            u64;
    size_t              ops;
    int                 qlen;
    int                 rc;

    zhpeq_util_init(argv[0], LOG_DEBUG, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
    if (rc < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);
    else if (argc != 2)
        usage(false);

    if (parse_kb_uint64_t(__func__, __LINE__, "ops",
                          argv[optind++], &u64, 0,
                          1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    ops = u64;

    rc = zhpeq_domain_alloc(&zqdom);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", rc);
        goto done;
    }

    qlen = 63;
    rc = zhpeq_rq_alloc(zqdom, qlen, 0, &zrq);
    if (rc < 0) {
        print_func_errn(__func__, __LINE__, "zhpeq_rq_alloc", qlen, false, rc);
        goto done;
    }
    do_pci_rd(zrq, ops);
    ret = 0;

 done:
    zhpeq_rq_free(zrq);
    zhpeq_domain_free(zqdom);

    printf("%s:done, ret = %d\n", appname, ret);

    return ret;
}
