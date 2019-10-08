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

#include <zhpeq_util_fab.h>

#include <rdma/fi_ext_zhpe.h>

#define PROVIDER        "zhpe"
#define EP_TYPE         FI_EP_RDM

struct args {
    uint64_t            nfams;
    uint64_t            fam_size;
    uint64_t            step_size;
};

struct stuff {
    const struct args   *args;
    struct fab_dom      fab_dom;
    struct fab_conn     fab_conn;
    bool                allocated;
};

static void stuff_free(struct stuff *stuff)
{
    if (!stuff)
        return;

    fab_conn_free(&stuff->fab_conn);
    fab_dom_free(&stuff->fab_dom);

    if (stuff->allocated)
        free(stuff);
}

static ssize_t do_progress(struct fid_cq *cq, size_t *cmp)
{
    ssize_t             ret = 0;
    ssize_t             rc;

    rc = fab_completions(cq, 0, NULL, NULL);
    if (rc >= 0)
        *cmp += rc;
    else
        ret = rc;

    return ret;
}

static int do_fam(const struct args *args)
{
    int                 ret = -FI_ENOMEM;
    struct stuff        conn = {
            .args = args,
    };
    struct fab_dom      *fab_dom = &conn.fab_dom;
    struct fab_conn     *fab_conn = &conn.fab_conn;
    void                **fam_sa = NULL;
    fi_addr_t           *fam_addr = NULL;
    char                *url = NULL;
    size_t              tx_op = 0;
    size_t              tx_cmp = 0;
    size_t              sa_len;
    struct fi_zhpe_ext_ops_v1 *ext_ops;
    size_t              i;
    size_t              off;
    uint64_t            *v;
    size_t              exp;

    fam_sa = calloc(args->nfams, sizeof(*fam_sa));
    fam_addr = calloc(args->nfams, sizeof(*fam_addr));
    if (!fam_sa || !fam_addr)
        goto done;
    fab_dom_init(fab_dom);
    fab_conn_init(fab_dom, fab_conn);

    ret = fab_dom_setup(NULL, NULL, true, PROVIDER, NULL, EP_TYPE, fab_dom);
    if (ret < 0)
        goto done;
    ret = fab_ep_setup(fab_conn, NULL, 0, 0);
    if (ret < 0)
        goto done;
    ret = fab_mrmem_alloc(fab_conn, &fab_conn->mrmem,
                          sizeof(*v) * args->nfams, 0);
    if (ret < 0)
        goto done;
    v = (void *)fab_conn->mrmem.mem;

    /* This is where it gets new. */
    ret = fi_open_ops(&fab_dom->fabric->fid, FI_ZHPE_OPS_V1, 0,
                      (void **)&ext_ops, NULL);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "fi_open_ops", FI_ZHPE_OPS_V1, ret);
        goto done;
    }
    for (i = 0; i < args->nfams; i++) {
        if (zhpeu_asprintf(&url, "zhpe:///fam%Lu", (ullong)i) == -1) {
            ret = -FI_ENOMEM;
            goto done;
        }
        ret = ext_ops->lookup(url, &fam_sa[i], &sa_len);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "ext_ops.lookup", url, ret);
            goto done;
        }
        free(url);
        url = NULL;
        ret = fi_av_insert(fab_dom->av, fam_sa[i], 1,  &fam_addr[i], 0, NULL);
        if (ret != 1) {
            print_err("%s,%u:fi_av_insert() returned %d\n",
                      __func__, __LINE__, ret);
            ret = -FI_EINVAL;
            goto done;
        }
    }
    for (off = 0; off < args->fam_size; off += args->step_size) {
        for (i = 0; i < args->nfams; i++, tx_op++) {
            v[i] = (off << 8) + i + 1;
            for (;;) {
                ret = fi_write(fab_conn->ep, &v[i], sizeof(v[i]),
                               fi_mr_desc(fab_conn->mrmem.mr), fam_addr[i],
                               off, FI_ZHPE_FAM_RKEY, NULL);
                if (ret >= 0)
                    break;
                if (ret != -FI_EAGAIN) {
                    print_func_err(__func__, __LINE__, "fi_write", "", ret);
                    goto done;
                }
                do_progress(fab_conn->tx_cq, &tx_cmp);
            }
        }
        while (tx_cmp != tx_op)
            do_progress(fab_conn->tx_cq, &tx_cmp);
    }
    for (off = 0; off < args->fam_size; off += args->step_size) {
        for (i = 0; i < args->nfams; i++, tx_op++) {
            v[i] = ~(uint64_t)0;
            for (;;) {
                ret = fi_read(fab_conn->ep, &v[i], sizeof(v[i]),
                              fi_mr_desc(fab_conn->mrmem.mr), fam_addr[i],
                               off, FI_ZHPE_FAM_RKEY, NULL);
                if (ret >= 0)
                    break;
                if (ret != -FI_EAGAIN) {
                    print_func_err(__func__, __LINE__, "fi_read", "", ret);
                    goto done;
                }
                do_progress(fab_conn->tx_cq, &tx_cmp);
            }
        }
        while (tx_cmp != tx_op)
            do_progress(fab_conn->tx_cq, &tx_cmp);
        for (i = 0; i < args->nfams; i++) {
            exp = (off << 8) + i + 1;
            if (v[i] != exp) {
                print_err("%s,%u:off 0x%Lx expected 0x%Lx, saw 0x%Lx\n",
                          __func__, __LINE__, (ullong)off, (ullong)exp,
                          (ullong)v[i]);
            }
        }
    }
 done:
    if (fam_sa) {
        for (i = 0; i < args->nfams; i++)
            free(fam_sa[i]);
        free(fam_sa);
    }
    free(fam_addr);
    free(url);
    stuff_free(&conn);

    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s <n-fams> <fam-size> <step-size>\n"
        "Write a ramp in each FAM with <step-size> bytes between writes\n"
        "and read it back.\n"
        "sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n",
        appname);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = { 0 };

    zhpeq_util_init(argv[0], LOG_INFO, false);

    if (argc != 4)
        usage(true);

    if (parse_kb_uint64_t(__func__, __LINE__, "nfams",
                          argv[1], &args.nfams, 0, 1, SIZE_MAX, 0) < 0 ||
        parse_kb_uint64_t(__func__, __LINE__, "fam-size",
                          argv[2], &args.fam_size, 0, 1,
                          SIZE_MAX, PARSE_KB | PARSE_KIB) ||
        parse_kb_uint64_t(__func__, __LINE__, "step-size",
                          argv[3], &args.step_size, 0, 1,
                          SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    if (do_fam(&args) < 0)
        goto done;

    ret = 0;
 done:

    return ret;
}
