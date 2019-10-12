/*
 * Copyright (C) 2019 Hewlett Packard Enterprise Development LP.
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

/*
 * This is a self-contained hello world that takes one argument: a memory length.
*/

#define _GNU_SOURCE

#include <zhpeq_util_fab.h>

#include <rdma/fi_ext_zhpe.h>

#include <rdma/fabric.h>

struct av_init_retry_args {
    struct timespec     ts_beg;
    uint64_t            timeout_ns;
};

static int av_init_retry(void *vargs)
{
    struct av_init_retry_args *args = vargs;
    struct timespec     ts_cur;

    if (!args->timeout_ns)
        return -FI_ETIMEDOUT;
    clock_gettime_monotonic(&ts_cur);
    if (ts_delta(&args->ts_beg, &ts_cur) >= args->timeout_ns)
        return -FI_ETIMEDOUT;

    /* Retry. */
    return 0;
}

int av_init(const char *callf, uint line, struct fab_conn *conn,
                 int timeout, fi_addr_t *fi_addr)
{
    int                 ret;
    bool                fi_addr_valid = false;
    int                 (*retry)(void *args) = av_init_retry;
    union sockaddr_in46 ep_addr;
    struct av_init_retry_args retry_args;
    size_t addr_len = sizeof(ep_addr);

    /* FIXME: Is there something wrong with this? */
    if (timeout == 0)
        retry_args.timeout_ns = 0;
    else if (timeout < 0)
        retry = NULL;
    else {
        retry_args.timeout_ns = (uint64_t)timeout * 100000;
        clock_gettime_monotonic(&retry_args.ts_beg);
    }

    ret = fi_getname(&conn->ep->fid, &ep_addr, &addr_len);

    if (ret < 0)
        goto done;
    ret = _fab_av_insert(callf, line, conn->dom, &ep_addr, fi_addr);
    if (ret < 0)
        goto done;
    fi_addr_valid = true;
    ret = _fab_av_wait_send(callf, line, conn, *fi_addr, retry, &retry_args);
    if (ret < 0)
        goto done;
    ret = _fab_av_wait_recv(callf, line, conn, *fi_addr, retry, &retry_args);

 done:
    if (ret < 0) {
        if (fi_addr_valid)
            _fab_av_remove(callf, line, conn->dom, *fi_addr);
        print_func_err(callf, line, "_fab_av_init", "", ret);
    }

    return ret;
}


#define fab_mrmem_alloc_aligned(...) \
    _fab_mrmem_alloc_aligned(__func__, __LINE__, __VA_ARGS__)

int _fab_mrmem_alloc_aligned(const char *callf, uint line,
                     struct fab_conn *conn, struct fab_mrmem *mrmem,
                     size_t len, uint64_t access, size_t alignment)
{
    int                 ret = 0;

    ret = -posix_memalign(&mrmem->mem, alignment, len);
    if (ret) {
        mrmem->mem = NULL;
        print_func_errn(callf, line, "posix_memalign",
                        len, true, ret);
        goto done;
    }
    memset(mrmem->mem, 0, len);
    mrmem->len = len;

    if (!access)
        access = (FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE);
    ret = fi_mr_reg(conn->dom->domain, mrmem->mem, len, access, 0, 0, 0,
                    &mrmem->mr, NULL);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_mr_reg", "", ret);
        goto done;
    }

 done:
    return ret;
}

int fab_mrmem_free(struct fab_mrmem *mrmem)
{
    int                 ret = 0;

    if (!mrmem)
        goto done;

    ret = FI_CLOSE(mrmem->mr);
    free(mrmem->mem);

 done:
    return ret;
}

struct args {
    const char          *provider;
    const char          *domain;
    uint64_t            mmap_len;
    uint8_t             ep_type;
};


static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s <mmap_len>\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n",
        appname);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    size_t                 i;
    int                 ret = 1;
    struct args         args = {
        .provider       = "zhpe",
        .ep_type        = FI_EP_RDM,
    };
    /* params for fab_mrmem_alloc */
    struct fab_dom      fab_dom;
    struct fab_conn     local_fab_conn;

    /* params for mmap */
    size_t              length;
    struct fid_ep       * local_fi_ep;
    fi_addr_t           local_fi_addr;

    struct fab_mrmem    mrmem;
    uint16_t *p;

    struct fi_zhpe_ext_ops_v1 *ext_ops;

    void                *buf;

    struct fi_zhpe_mmap_desc * mdesc;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    if (argc == 1)
        usage(true);


    /* set up fab_dom */
    fab_dom_init(&fab_dom);
    ret = fab_dom_setup(NULL, NULL, true, args.provider, args.domain,
                        args.ep_type, &fab_dom);
    if (ret< 0)
        goto done;

    /* set up fab_conn */
    fab_conn_init(&fab_dom, &local_fab_conn);

    ret = fab_ep_setup(&local_fab_conn, NULL, 1, 1);
    if (ret< 0)
        goto done;

    ret = av_init(__func__, __LINE__, &local_fab_conn,
                 10000, &local_fi_addr);
    if (ret != 0) {
        print_func_err(__func__, __LINE__, "av_init", "local_fi_addr", ret);
        goto done;
    }

    /* set length */
    if (parse_kb_uint64_t(__func__, __LINE__, "mmap_len",
        argv[1], &args.mmap_len, 0,
        sizeof(uint16_t), SIZE_MAX,
        PARSE_KB | PARSE_KIB))
            usage(false);
    length = page_up(args.mmap_len);

    /* set mrmem */
    ret = fab_mrmem_alloc_aligned(&local_fab_conn, &mrmem, length, 0, 2*1024*1024UL);
    if (ret != 0) {
        print_func_err(__func__, __LINE__, "fab_mrmem_alloc_aligned", FI_ZHPE_OPS_V1, ret);
        goto done;
      }

    local_fi_ep = local_fab_conn.ep;


    /* Get ext ops and mmap remote region. */
    ret = fi_open_ops(&fab_dom.fabric->fid, FI_ZHPE_OPS_V1, 0,
                      (void **)&ext_ops, NULL);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "fi_open_ops", FI_ZHPE_OPS_V1, ret);
        goto done;
    }

    uint64_t remote_mr_key = mrmem.mr->key;

    ret = ext_ops->mmap(NULL, length, PROT_READ | PROT_WRITE,
                             MAP_SHARED, 0, local_fi_ep, local_fi_addr,
                             remote_mr_key, FI_ZHPE_MMAP_CACHE_WB,
                             &mdesc);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "ext_mmap", FI_ZHPE_OPS_V1, ret);
        goto done;
    }

    printf("Writing to mdesc->addr:\n");
    buf = (char *) mdesc->addr;
    for (i = 0, p = buf; i < args.mmap_len; i += sizeof (*p), p++)
        *p = (i | 1);


    printf("Checking contents of mdesc->addr:\n");
    ret=0;
    for (i = 0, p = buf; i < args.mmap_len;
         i += sizeof(*p), p++) {
        if (*p != (typeof(*p))(i | 1)) {
            if (!ret)
                print_err("first error: off 0x%08lx saw 0x%04x\n", i, *p);
            ret++;
        }
    }
    print_err("Saw %d errors\n", ret);
    ret = ext_ops->munmap(mdesc);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "ext_mmap", FI_ZHPE_OPS_V1, ret);
        goto done;
    }


done:

    fab_mrmem_free(&mrmem);
    fab_conn_free(&local_fab_conn);
    fab_dom_free(&fab_dom);

    return ret;
}
