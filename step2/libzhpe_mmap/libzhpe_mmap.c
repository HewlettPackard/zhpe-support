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

#define _GNU_SOURCE

#include <zhpe_mmap.h>
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

static int av_init(const char *callf, uint line, struct fab_conn *conn,
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

/*
  free needs to find mdesc to give to munmap
  Because libzhpe_mmap only exposes an alloc
  mdesc will only get used once.
  Also, we're on a single node.
*/
struct mdesc_holder {
    struct  mdesc_holder * next;
    struct  mdesc_holder * prev;
    struct  fab_mrmem * mrmem;
    struct  fi_zhpe_mmap_desc  * mmap_desc;
    // also need to track mmap_desc
};

static struct fab_dom * fab_dom;
static struct fab_conn * local_fab_conn;
static struct fi_zhpe_ext_ops_v1 * ext_ops;
static fi_addr_t local_fi_addr;

static struct mdesc_holder * head_mdesc_holder;
static size_t mdesc_nbr;  // take a number
static size_t mdesc_cntr; // wait your turn

struct args {
    const char *domain;
};

/* active addresses will never be reused so we don't need to check length. */
static int find_and_remove_holder (void * addr)
{
    int ret = -1;
    size_t mynum;
    struct mdesc_holder *cur;

    if ( head_mdesc_holder == NULL )
       return (ret);

    mynum = atm_inc(&mdesc_nbr);

    while (mynum < mdesc_cntr);

    cur = head_mdesc_holder;

    while (cur != NULL) {
        if (cur->mmap_desc->addr == addr) {
            if (cur->prev != NULL)
                cur->prev->next = cur->next;

            if (cur->next != NULL)
                cur->next->prev = cur->prev;

            if (head_mdesc_holder == cur)
                head_mdesc_holder = NULL;
            ret = ext_ops->munmap((struct fi_zhpe_mmap_desc *)(cur->mmap_desc));
            free(cur);
            cur = NULL;
        } else {
            cur = cur->next;
        }
    }

    atm_inc(&mdesc_cntr);
    return(ret);
}

static void mrmem_holder_teardown()
{
    size_t mynum;
    struct mdesc_holder *cur;
    struct mdesc_holder *holder;
    int ret;

    if ( head_mdesc_holder == NULL )
       return;

    mynum = atm_inc(&mdesc_nbr);

    while (mynum < mdesc_cntr);

    cur = head_mdesc_holder;

    while (cur != NULL) {
        holder = cur;
        ret = ext_ops->munmap((struct fi_zhpe_mmap_desc *)(cur->mmap_desc));
        if ( ret != 0 )
            print_func_err(__func__, __LINE__, "mrmem_holder_teardown", FI_ZHPE_OPS_V1, ret);
        cur = holder->next;
        free(holder);
    }

    atm_inc(&mdesc_cntr);
}

void libzhpe_mmap_teardown(void)
{
    mrmem_holder_teardown();
    fab_conn_free(local_fab_conn);
}

int zhpe_mmap_init(void){
    int                 ret = 1;

    struct args    args = { };

    ret = atexit(libzhpe_mmap_teardown);
    if (ret != 0)
        goto done;

    mdesc_nbr = 0;
    mdesc_cntr = 0;

    fab_dom = calloc(1, sizeof(struct fab_dom));
    local_fab_conn = calloc(1, sizeof(struct fab_conn));
    head_mdesc_holder = NULL;
    ext_ops = calloc(1, sizeof(struct fi_zhpe_ext_ops_v1));

    zhpeq_util_init("zhpe_mmap", LOG_INFO, false);

    fab_dom_init(fab_dom);
    ret = fab_dom_setup(NULL, NULL, true, "zhpe", args.domain,
                        FI_EP_RDM, fab_dom);
    if (ret != 0)
        goto done;

    fab_conn_init(fab_dom, local_fab_conn);

    ret = fab_ep_setup(local_fab_conn, NULL, 1, 1);
    if (ret != 0)
        goto done;

    ret = av_init(__func__, __LINE__, local_fab_conn,
                 10000, &local_fi_addr);
    if (ret != 0) {
        print_func_err(__func__, __LINE__, "av_init", "local_fi_addr", ret);
        goto done;
    }

   /* Get ext ops and mmap remote region. */
    ret = fi_open_ops(&fab_dom->fabric->fid, FI_ZHPE_OPS_V1, 0,
                      (void **)&ext_ops, NULL);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "fi_open_ops", FI_ZHPE_OPS_V1, ret);
        goto done;
    }


done:
    return ret;
}

/* hand back address. When given the address later at free, unmap, etc. */
void * zhpe_mmap_alloc(size_t mmap_len)
{
    int ret = 1;
    struct fab_mrmem * mrmem;
    size_t length;
    struct fid_ep     * local_fi_ep;
    struct fi_zhpe_mmap_desc * mmap_desc;
    struct mdesc_holder * holder;
    size_t mynum;

    length = page_up(mmap_len);
    mrmem = calloc(1, sizeof(struct fab_mrmem));
    mmap_desc = calloc(1, sizeof(struct fi_zhpe_mmap_desc));
    holder = calloc(1, sizeof(struct mdesc_holder));
    holder->mrmem = mrmem;
    holder->mmap_desc = mmap_desc;
    holder->prev = NULL;

    /* alloc mrmem -- do not alloc aligned */
    ret = fab_mrmem_alloc(local_fab_conn, holder->mrmem, length, 0);
    if (ret != 0) {
        print_func_err(__func__, __LINE__, "fab_mrmem_alloc",
            FI_ZHPE_OPS_V1, ret);
        goto done;
      }

    uint64_t remote_mr_key = mrmem->mr->key;

    local_fi_ep = local_fab_conn->ep;

    ret = ext_ops->mmap(NULL, length, PROT_READ | PROT_WRITE,
                             MAP_SHARED, 0, local_fi_ep, local_fi_addr,
                             remote_mr_key, FI_ZHPE_MMAP_CACHE_WB, &holder->mmap_desc);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "ext_mmap", FI_ZHPE_OPS_V1, ret);
        goto done;
    }

    mynum = atm_inc(&mdesc_nbr);

    while (mynum < mdesc_cntr);

    if ( head_mdesc_holder == NULL ) {
        holder->next = NULL;
        head_mdesc_holder = holder;
    } else {
        head_mdesc_holder->prev=holder;
        holder->next = head_mdesc_holder;
        head_mdesc_holder = holder;
    }

    atm_inc(&mdesc_cntr);

  done:

    return holder->mmap_desc->addr;
}

/* ask John if we need to handle if someone tries to free the same thing twice? */
int zhpe_mmap_free(void *buf)
{
    int ret = -1;


    ret = find_and_remove_holder (buf);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpe_mmap_free", FI_ZHPE_OPS_V1, ret);
        goto done;
    }

  done:
    return ret;
}
