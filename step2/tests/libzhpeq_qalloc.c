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
        appname, attr.z.max_tx_queues, attr.z.max_tx_qlen);

    exit(255);
}

static bool pages_ok(const char *label, volatile void *ptr, size_t off,
                     size_t size, bool zero)
{
    bool                ret = false;
    uint64_t            check_off;
    uint64_t            check_val;
    volatile uint64_t   *check_ptr;

    /* FIXME: A lot of hardcoding. */
    size -= sizeof(*check_ptr);
    for (check_off = page_size - sizeof(*check_ptr);
         check_off <= size; check_off += page_size) {
        check_ptr = (void *)((char *)ptr + check_off);
        check_val = *check_ptr;
        if (zero) {
            if (!expected_saw(label, 0, check_val))
                goto done;
            *check_ptr = off + check_off;
        } else if (!expected_saw(label, off + check_off, check_val))
            goto done;
    }
    ret = true;

 done:
    return ret;
}

static int qcm_ok(volatile void *qcm, struct zhpe_xqinfo *info, size_t i,
                  bool zhpe, bool zero)
{
    bool                ret = false;
    uint64_t            check_off;
    uint64_t            check_val;
    volatile uint64_t   *check_ptr;

    if (zhpe) {
        check_off = 0;
        check_ptr = (void *)((char *)qcm + check_off);
        check_val = *check_ptr;
        if (check_val == 0 && (check_val & 0x3F)) {
            print_err("Offset 0x%Lx unexpected value 0x%Lx\n",
                      (ullong)check_off, (ullong)check_val);
            goto done;
        }
        check_off = 8;
        check_ptr = (void *)((char *)qcm + check_off);
        check_val = *check_ptr;
        if (check_val == 0 && (check_val & 0x3F)) {
            print_err("Offset 0x%Lx unexpected value 0x%Lx\n",
                      (ullong)check_off, (ullong)check_val);
            goto done;
        }
        check_off = 0x10;
        check_ptr = (void *)((char *)qcm + check_off);
        check_val = *check_ptr;
        if (!expected_saw("cmdq.ent", info->cmdq.ent, check_val & 0xFFFFFFFFUL))
            goto done;
        if (!expected_saw("cmplq.ent", info->cmplq.ent, check_val >> 32))
            goto done;
        check_off = 0x18;
        check_ptr = (void *)((char *)qcm + check_off);
        check_val = *check_ptr;
        if ((check_val & 0xFFFF) == 0 ||
            ((check_val >> 20) & 0xF) != (i & 0xF) ||
            ((check_val >> 24) & 0x1) != (i & 0x1) ||
            ((check_val >> 24) & 0xFE) != 0x40 ||
            ((check_val >> 32) & 0xFFFF) == 0 ||
            (check_val >> 48) != 0) {
            print_err("Offset 0x%Lx unexpected value 0x%Lx\n",
                      (ullong)check_off, (ullong)check_val);
            goto done;
        }
        check_off = 0x20;
        check_ptr = (void *)((char *)qcm + check_off);
        check_val = *check_ptr;
        if (!expected_saw("mstop", 0, check_val))
            goto done;
        check_off = 0x28;
        check_ptr = (void *)((char *)qcm + check_off);
        check_val = *check_ptr;
        if (!expected_saw("active", 0x8000, check_val))
            goto done;
        check_off = 0x40;
        check_ptr = (void *)((char *)qcm + check_off);
        check_val = *check_ptr;
        if (!expected_saw("stop", 0, check_val))
            goto done;
    }
    check_off = 0x80;
    check_ptr = (void *)((char *)qcm + check_off);
    check_val = *check_ptr;
    if (!expected_saw("cmdt", 0, check_val))
        goto done;
    check_off = 0xc0;
    check_ptr = (void *)((char *)qcm + check_off);
    check_val = *check_ptr;
    if (!expected_saw("cmph", 0, check_val))
        goto done;
    check_off = 0x100;
    check_ptr = (void *)((char *)qcm + check_off);
    check_val = *check_ptr;
    if (!expected_saw("cmpt", 0x80000000, check_val))
        goto done;
    if (!zhpe && !pages_ok("qcm", qcm, info->qcm.off, info->qcm.size, zero))
        goto done;
    ret = true;
 done:
    return ret;
}

static bool queue_ok(const char *label, volatile void *ptr,
                     struct zhpe_queue *q, bool zero)
{
    return pages_ok(label, ptr, q->off, q->size, zero);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct zhpeq        **zq = NULL;
    struct zhpeq_dom    *zdom;
    uint                *shuffle = NULL;
    bool                seed = false;
    size_t              qlen = 0;
    size_t              cmd_len;
    size_t              cmp_len;
    int                 rc;
    size_t              queues;
    int                 opt;
    size_t              h;
    size_t              i;
    uint64_t            u64;
    bool                zhpe;

    zhpeq_util_init(argv[0], LOG_DEBUG, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    rc = zhpeq_query_attr(&attr);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_query_attr", "", rc);
        goto done;
    }
    zhpe = (attr.backend == ZHPEQ_BACKEND_ZHPE);

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
            if (parse_kb_uint64_t(__func__, __LINE__, "count",
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

    if (parse_kb_uint64_t(__func__, __LINE__, "queues",
                          argv[optind++], &u64, 0,
                          1, attr.z.max_tx_queues, 0) < 0)
        usage(false);

    queues = u64;

    if (argc > 1) {
        if (parse_kb_uint64_t(__func__, __LINE__, "qlen",
                              argv[optind++], &u64, 0,
                              2, attr.z.max_tx_qlen, 0) < 0)
            usage(false);
        qlen = u64;
    }

    zq = calloc(queues, sizeof(*zq));
    if (!zq)
        goto done;
    shuffle = calloc(queues, sizeof(*shuffle));
    if (!shuffle)
        goto done;
    if (qlen) {
        for (i = 0; i < queues; i++)
            shuffle[i] = i;
    } else
        random_array(shuffle, queues);

    rc = zhpeq_domain_alloc(&zdom);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", rc);
        goto done;
    }

    /*
     * Allocate queues, with random lengths if qlen == 0, and set
     * debugging values used to check that memory is allocated correctly.
     * The shuffle array puts the list in random order.
     */
    for (h = 0; h < queues; h++) {
        i = shuffle[h];
        if (zq[i])
            print_err("%s,%u:random_array() broken\n", __func__, __LINE__);
        cmd_len = (qlen ?: random_range(2, attr.z.max_tx_qlen));
        cmp_len = (qlen ?: random_range(2, attr.z.max_tx_qlen));
        rc = zhpeq_alloc(zdom, cmd_len, cmp_len, i & 0xF, i & 0x1, 0, &zq[i]);
        if (rc < 0) {
            print_func_errn(__func__, __LINE__, "zhpeq_alloc", qlen, false,
                            rc);
            goto done;
        }
        if (zq[i]->xqinfo.cmdq.ent < cmd_len) {
            print_err("%s,%u:returned cmd_len %u < %lu.\n",
                      __func__, __LINE__, zq[i]->xqinfo.cmdq.ent, cmd_len);
            goto done;
        }
        if (zq[i]->xqinfo.cmdq.ent & (zq[i]->xqinfo.cmdq.ent - 1)) {
            print_err("%s,%u:returned qlen %u not a power of 2.\n",
                      __func__, __LINE__, zq[i]->xqinfo.cmdq.ent);
            goto done;
        }
        if (zq[i]->xqinfo.cmplq.ent < cmp_len) {
            print_err("%s,%u:returned cmp_len %u < %lu.\n",
                      __func__, __LINE__, zq[i]->xqinfo.cmplq.ent, cmp_len);
            goto done;
        }
        if (zq[i]->xqinfo.cmplq.ent & (zq[i]->xqinfo.cmplq.ent - 1)) {
            print_err("%s,%u:returned qlen %u not a power of 2.\n",
                      __func__, __LINE__, zq[i]->xqinfo.cmplq.ent);
            goto done;
        }
        if (!qcm_ok(zq[i]->qcm, &zq[i]->xqinfo, i, zhpe, true))
            goto done;
        if (!queue_ok("cmdq",  zq[i]->wq, &zq[i]->xqinfo.cmdq, true))
            goto done;
        if (!queue_ok("cmpq",  zq[i]->cq, &zq[i]->xqinfo.cmplq, true))
            goto done;
    }
    for (i = 0; i < queues; i++) {
        if (!qcm_ok(zq[i]->qcm, &zq[i]->xqinfo, i, zhpe, false))
            goto done;
        if (!queue_ok("cmdq",  zq[i]->wq, &zq[i]->xqinfo.cmdq, false))
            goto done;
        if (!queue_ok("cmpq",  zq[i]->cq, &zq[i]->xqinfo.cmplq, false))
            goto done;
    }
    /* Free a random 50%. */
    for (i = 0; i < queues; i++) {
        if (random_range(0, 1))
            continue;
        zhpeq_free(zq[i]);
        zq[i] = NULL;
    }
    /* Check remaining queues. */
    for (i = 0; i < queues; i++) {
        if (!zq[i])
            continue;
        if (!qcm_ok(zq[i]->qcm, &zq[i]->xqinfo, i, zhpe, false))
            goto done;
        if (!queue_ok("cmdq",  zq[i]->wq, &zq[i]->xqinfo.cmdq, false))
            goto done;
        if (!queue_ok("cmpq",  zq[i]->cq, &zq[i]->xqinfo.cmplq, false))
            goto done;
    }
    /* Leave a mess for exit+driver to clean up. */
    ret = 0;

 done:
    zhpeq_domain_free(zdom);
    free(zq);
    free(shuffle);

    printf("%s:done, ret = %d\n", appname, ret);

    return ret;
}
