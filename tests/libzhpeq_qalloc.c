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

#include <internal.h>

#include <limits.h>

static struct zhpeq_attr   attr;

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s [-s <seed>] <queues> [qlen]\n"
        "<queues> is the number of queues created (max:%u).\n"
        "[qlen]   is the number of entries in a queue (max:%u);"
        " if [qlen] is not\n"
        "         specified, qlen will be selected randomly and [-s]"
        " allows\n"
        "         specifying a seed for random().\n",
        appname, attr.z.max_tx_queues, attr.z.max_hw_qlen);

    exit(255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct zhpeq        **zq = NULL;
    struct zhpeq_dom    *zdom;
    uint                *shuffle = NULL;
    bool                seed = false;
    size_t              qlen = 0;
    size_t              req;
    int                 rc;
    size_t              queues;
    int                 opt;
    size_t              h;
    size_t              i;
    uint64_t            u64;
    ulong               check_off;
    ulong               check_val;

    zhpeq_util_init(argv[0], LOG_DEBUG, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION);
    if (rc < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    rc = zhpeq_query_attr(&attr);
    if (rc < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_query_attr", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    if (!expected_saw("sizeof(wq_entry)", ZHPE_HW_ENTRY_LEN,
                      sizeof(union zhpe_hw_wq_entry)))
        goto done;
    if (!expected_saw("sizeof(cq_entry)", ZHPE_HW_ENTRY_LEN,
                      sizeof(union zhpe_hw_cq_entry)))
        goto done;

    while ((opt = getopt(argc, argv, "s:")) != -1) {

        switch (opt) {

        case 's':
            if (seed)
                usage(false);
            if (parse_kb_uint64_t(__FUNCTION__, __LINE__, "count",
                                  optarg, &u64, 0, 1, UINT_MAX, 0) < 0)
                usage(false);
            seed = true;
            random_seed(seed);
            break;

        default:
            usage(false);

        }
    }

    argc -= optind;
    if (argc < 1 || argc > 2)
        usage(false);

    if (parse_kb_uint64_t(__FUNCTION__, __LINE__, "queues",
                          argv[optind++], &u64, 0,
                          1, attr.z.max_tx_queues, 0) < 0)
        usage(false);

    queues = u64;

    if (argc > 1) {
        if (parse_kb_uint64_t(__FUNCTION__, __LINE__, "qlen",
                              argv[optind++], &u64, 0,
                              2, attr.z.max_hw_qlen, 0) < 0)
            usage(false);
        qlen = u64;
    }

    zq = do_calloc(queues, sizeof(*zq));
    if (!zq)
        goto done;
    shuffle = do_calloc(queues, sizeof(*shuffle));
    if (!shuffle)
        goto done;
    if (qlen) {
        for (i = 0; i < queues; i++)
            shuffle[i] = i;
    } else
        random_array(shuffle, queues);

    rc = zhpeq_domain_alloc(NULL, &zdom);
    if (rc < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_domain_alloc", "", rc);
        goto done;
    }

    /*
     * Allocate queues, with random lengths if qlen == 0, and set
     * debugging values used to check that memory is allocated correctly.
     * The shuffle array puts the list in random order.
     *
     * XXX: this test requires the driver be loaded with debug=1 (TESTMODE)
     */
    for (h = 0; h < queues; h++) {
        i = shuffle[h];
        if (zq[i])
            print_err("%s,%u:random_array() broken\n", __FUNCTION__, __LINE__);
        req = (qlen ?: random_range(2, attr.z.max_hw_qlen));
        rc = zhpeq_alloc(zdom, req, &zq[i]);
        if (rc < 0) {
            print_func_errn(__FUNCTION__, __LINE__, "zhpeq_alloc", qlen, false,
                            rc);
            goto done;
        }
        if (zq[i]->info.qlen < req) {
            print_err("%s,%u:returned qlen %u < req %lu.\n",
                      __FUNCTION__, __LINE__, zq[i]->info.qlen, req);
            goto done;
        }
        if (zq[i]->info.qlen & (zq[i]->info.qlen - 1)) {
            print_err("%s,%u:returned qlen %u not a power of 2.\n",
                      __FUNCTION__, __LINE__, zq[i]->info.qlen);
            goto done;
        }
        check_off = page_size - sizeof(ulong);
        if (attr.z.backend != ZHPEQ_BACKEND_ZHPE
            && check_off >= sizeof(*zq[i]->qcm)) {
            check_val = *(ulong *)((void *)zq[i]->qcm + check_off);
            if (!expected_saw("qcm", 0, check_val))
                goto done;
            *(ulong *)((void *)zq[i]->qcm + check_off) =
                zq[i]->info.reg_off + check_off;
        }
        for (check_off = page_size - sizeof(ulong);
             check_off < zq[i]->info.qsize;
             check_off += page_size) {
            check_val = *(ulong *)((void *)zq[i]->wq + check_off);
            if (!expected_saw("wq", 0, check_val))
                goto done;
            *(ulong *)((void *)zq[i]->wq + check_off) =
                zq[i]->info.wq_off + check_off;
            check_val = *(ulong *)((void *)zq[i]->cq + check_off);
            if (!expected_saw("cq", 0, check_val))
                goto done;
            *(ulong *)((void *)zq[i]->cq + check_off) =
                zq[i]->info.cq_off + check_off;
        }
    }
    for (i = 0; i < queues; i++) {
        check_off = page_size - sizeof(ulong);
        if (attr.z.backend != ZHPEQ_BACKEND_ZHPE
            && check_off >= sizeof(*zq[i]->qcm)) {
            check_val = *(ulong *)((void *)zq[i]->qcm + check_off);
            if (!expected_saw("qcm", zq[i]->info.reg_off + check_off,
                              check_val))
                goto done;
        }
        for (check_off = page_size - sizeof(ulong);
             check_off < zq[i]->info.qsize;
             check_off += page_size) {
            check_val = *(ulong *)((void *)zq[i]->wq + check_off);
            if (!expected_saw("wq", zq[i]->info.wq_off + check_off, check_val))
                goto done;
            check_val = *(ulong *)((void *)zq[i]->cq + check_off);
            if (!expected_saw("cq", zq[i]->info.cq_off + check_off, check_val))
                goto done;
        }
    }
    /* Free queues: if qlen == 0, free a random 50%. */
    for (i = 0; i < queues; i++) {
        if (!qlen && random_range(0, 1))
            continue;
        zhpeq_free(zq[i]);
        zq[i] = NULL;
    }
    /* Check remaining queues. */
    for (i = 0; i < queues; i++) {
        if (!zq[i])
            continue;
        check_off = page_size - sizeof(ulong);
        if (attr.z.backend != ZHPEQ_BACKEND_ZHPE
            && check_off >= sizeof(*zq[i]->qcm)) {
            check_val = *(ulong *)((void *)zq[i]->qcm + check_off);
            if (!expected_saw("regs", zq[i]->info.reg_off + check_off,
                              check_val))
                goto done;
        }
        for (check_off = page_size - sizeof(ulong);
             check_off < zq[i]->info.qsize;
             check_off += page_size) {
            check_val = *(ulong *)((void *)zq[i]->wq + check_off);
            if (!expected_saw("wq", zq[i]->info.wq_off + check_off, check_val))
                goto done;
            check_val = *(ulong *)((void *)zq[i]->cq + check_off);
            if (!expected_saw("cq", zq[i]->info.cq_off + check_off, check_val))
                goto done;
        }
    }
    /* If qlen == 0, leave a mess for exit+driver to clean up. */
    ret = 0;

 done:
    zhpeq_domain_free(zdom);
    do_free(zq);
    do_free(shuffle);

    printf("%s:done, ret = %d\n", appname, ret);

    return ret;
}
