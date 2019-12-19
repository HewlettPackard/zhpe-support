/*
 * Copyright (C) 2017-2019 Hewlett Packard Enterprise Development LP.
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

#include <limits.h>

#include <zhpeq_util_fab.h>

#include <rdma/fi_ext_zhpe.h>

#define MAX_OP_BYTES    ((size_t)1 << 30)
#define MAX_OP_U64      (MAX_OP_BYTES / sizeof(uint64_t))

#define PROVIDER        "zhpe"
#define EP_TYPE         FI_EP_RDM

enum rw {
    RW,
    RDONLY,
    WRONLY,
};

struct args {
    char                **url;
    size_t              n_url;
    uint64_t            off;
    uint64_t            len;
    uint64_t            base;
    uint64_t            seed;
    uint64_t            iosize;
    uint64_t            key;
    enum rw             rw;
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
    uint64_t            rd_cyc = 0;
    uint64_t            wr_cyc = 0;
    size_t              tx_cmp;
    size_t              tx_out;
    size_t              sa_len;
   struct fi_zhpe_ext_ops_v1 *ext_ops;
    size_t              i;
    size_t              f;
    size_t              ramp;
    size_t              rbase;
    size_t              off;
    size_t              len;
    size_t              bufbytes;
    size_t              bufu64;
    size_t              iou64;
    size_t              iolen;
    size_t              iobytes;
    size_t              iooff;
    uint64_t            *v64;
    size_t              v;
    uint64_t            start;

    fam_sa = calloc(args->n_url, sizeof(*fam_sa));
    fam_addr = calloc(args->n_url, sizeof(*fam_addr));
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
                          MAX_OP_BYTES * args->n_url, 0);
    if (ret < 0)
        goto done;
    v64 = fab_conn->mrmem.mem;

    ret = fi_open_ops(&fab_dom->fabric->fid, FI_ZHPE_OPS_V1, 0,
                      (void **)&ext_ops, NULL);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "fi_open_ops", FI_ZHPE_OPS_V1, ret);
        goto done;
    }
    for (f = 0; f < args->n_url; f++) {
        ret = ext_ops->lookup(args->url[f], &fam_sa[f], &sa_len);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "ext_ops.lookup", url, ret);
            goto done;
        }
        ret = fi_av_insert(fab_dom->av, fam_sa[f], 1,  &fam_addr[f], 0, NULL);
        if (ret != 1) {
            print_err("%s,%u:fi_av_insert() returned %d\n",
                      __func__, __LINE__, ret);
            ret = -FI_EINVAL;
            goto done;
        }
    }

    srandom(args->seed);
    rbase = random();

    iou64 = args->iosize / sizeof(uint64_t);

    if (args->rw != RDONLY) {
        for (len = args->len, off = args->off, ramp = rbase; len > 0;
             len -= bufbytes, off += MAX_OP_BYTES, ramp += MAX_OP_U64) {
            bufbytes = len;
            if (bufbytes > MAX_OP_BYTES)
                bufbytes = MAX_OP_BYTES;
            bufu64 = bufbytes / sizeof(uint64_t);

            for (f = 0, v = 0; f < args->n_url;
                 f++, v += MAX_OP_U64) {
                for (i = 0; i < bufu64; i++)
                    v64[v + i] = ramp + i + f;
            }

            start = get_cycles(NULL);
            for (f = 0, v = 0, tx_out = 0, tx_cmp = 0;
                 f < args->n_url; f++) {
                for (iolen = bufbytes, iooff = off; iolen > 0;
                     (iolen -= iobytes, iooff += args->iosize, v += iou64,
                      tx_out++)) {
                    iobytes = iolen;
                    if (iobytes > args->iosize)
                        iobytes = args->iosize;
                    for (;;) {
                        ret = fi_write(fab_conn->ep, v64 + v, iobytes,
                                       fi_mr_desc(fab_conn->mrmem.mr),
                                       fam_addr[f], iooff, args->key, NULL);
                        if (ret >= 0)
                            break;
                        if (ret != -FI_EAGAIN) {
                            print_func_err(__func__, __LINE__,
                                           "fi_write", "", ret);
                            goto done;
                        }
                        if ((ret = do_progress(fab_conn->tx_cq, &tx_cmp)) < 0)
                            goto done;
                    }
                }
            }
            while (tx_cmp != tx_out) {
                if ((ret = do_progress(fab_conn->tx_cq, &tx_cmp)) < 0)
                    goto done;
            }
            wr_cyc += get_cycles(NULL) - start;
        }
        print_info("write %0.3f MB/s\n",
                   ((double)args->len / cycles_to_usec(wr_cyc, 1)));
    }

    memset(fab_conn->mrmem.mem, 0, MAX_OP_BYTES * args->n_url);

    if (args->rw != WRONLY) {
        for (len = args->len, off = args->off, ramp = rbase; len > 0;
             len -= bufbytes, off += bufbytes, ramp += bufu64) {
            bufbytes = len;
            if (bufbytes > MAX_OP_BYTES)
                bufbytes = MAX_OP_BYTES;
            bufu64 = bufbytes / sizeof(uint64_t);

            start = get_cycles(NULL);
            for (f = 0, v = 0, tx_out = 0, tx_cmp = 0;
                 f < args->n_url; f++) {
                for (iolen = bufbytes, iooff = off; iolen > 0;
                     (iolen -= iobytes, iooff += args->iosize, v += iou64,
                      tx_out++)) {
                    iobytes = iolen;
                    if (iobytes > args->iosize)
                        iobytes = args->iosize;
                    for (;;) {
                        ret = fi_read(fab_conn->ep, v64 + v, iobytes,
                                      fi_mr_desc(fab_conn->mrmem.mr),
                                      fam_addr[f], iooff, args->key, NULL);
                        if (ret >= 0)
                            break;
                        if (ret != -FI_EAGAIN) {
                            print_func_err(__func__, __LINE__,
                                           "fi_read", "", ret);
                            goto done;
                        }
                        if ((ret = do_progress(fab_conn->tx_cq, &tx_cmp)) < 0)
                            goto done;
                    }
                }
            }
            while (tx_cmp != tx_out) {
                if ((ret = do_progress(fab_conn->tx_cq, &tx_cmp)) < 0)
                    goto done;
            }
            rd_cyc += get_cycles(NULL) - start;

            for (f = 0, v = 0; f < args->n_url; f++, v += MAX_OP_U64) {
                for (i = 0; i < bufu64; i++) {
                    if (v64[v + i] != ramp + i + f)
                        print_err("%s,%u:off 0x%lx expected 0x%lx,"
                                  " saw 0x%" PRIx64 "\n", __func__, __LINE__,
                                  off + i * sizeof(*v64), ramp + i + f, v64[i]);
                }
            }
        }
        print_info("read  %0.3f MB/s\n",
                   ((double)args->len / cycles_to_usec(rd_cyc, 1)));
    }
 done:
    if (fam_sa) {
        for (i = 0; i < args->n_url; i++)
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
        "Usage:%s [-rw] [-i <iosize>] [-k <key>] [-s <seed>]"
        " <zhpe:///<fam|ion><number>>... <off> <len>\n"
        "Writes a ramp of 64-bit ints into FAM specified by url over\n"
        "range <off> - <off + len - 1>  and reads it back\n"
        "<off> and <len> are in bytes and must be a multiple of 8.\n"
        "sizes may be postfixed with [kmgtKMGT] to specify the base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        " -i <iosize> : size of I/O, may have size postfix (default = 1G)\n"
        " -k <key> : specify 1 for MSA region (default = 0)\n"
        " -r : read only\n"
        " -s <seed>: srandom() seed for ramp start (default = 0)\n"
        " -w : write only\n",
        appname);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = { .iosize = MAX_OP_BYTES };
    size_t              i;
    int                 opt;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    while ((opt = getopt(argc, argv, "i:k:rs:w")) != -1) {

        switch (opt) {

        case 'i':
            if (args.iosize != MAX_OP_BYTES)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "iosize",
                                  optarg, &args.iosize, 0, 1, GiB - 1,
                                  PARSE_KB | PARSE_KIB) < 0)
                goto done;
            break;

        case 'k':
            if (args.key)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "key",
                                  optarg, &args.key, 0, 1, 1, 0) < 0)
                goto done;
            break;

        case 'r':
            if (args.rw != RW)
                usage(false);
            args.rw = RDONLY;
            break;

        case 's':
            if (args.seed)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "seed",
                                  optarg, &args.seed, 0, 1,
                                  UINT_MAX, PARSE_KB | PARSE_KIB) < 0)
                goto done;
            break;

        case 'w':
            if (args.rw != RW)
                usage(false);
            args.rw = WRONLY;
            break;

        default:
            usage(false);

        }
    }

    argc -= optind;

    if (argc < 3)
        usage(true);
    args.n_url = argc - 2;
    args.url = calloc(args.n_url, sizeof(*args.url));
    if (!args.url)
        goto done;

    for (i = 0; i < args.n_url; i++)
        args.url[i] = argv[optind++];
    if (parse_kb_uint64_t(__func__, __LINE__, "off",
                          argv[optind++], &args.off, 0, 0, SIZE_MAX,
                          PARSE_KB | PARSE_KIB ) < 0 ||
        parse_kb_uint64_t(__func__, __LINE__, "len",
                          argv[optind++], &args.len, 0, 1,
                          SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
        usage(false);
    if ((args.off & (sizeof(uint64_t) - 1)) ||
        (args.len & (sizeof(uint64_t) - 1)) ||
        (args.iosize & (sizeof(uint64_t) - 1))) {
        print_err("%s,%u:offset, len, and iosize must be a multiple of %lu\n",
                  __func__, __LINE__, sizeof(uint64_t));
        goto done;
    }

    if (do_fam(&args) < 0)
        goto done;

    ret = 0;
 done:
    free(args.url);

    return ret;
}
