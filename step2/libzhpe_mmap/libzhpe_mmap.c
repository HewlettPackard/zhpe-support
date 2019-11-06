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

/*
  free needs to find mdesc to give to munmap
  Because libzhpe_mmap only exposes an alloc
  each mdesc will only get used once.
  Also, we're on a single node.
*/
struct mdesc_holder {
    struct  mdesc_holder *next;
    struct  mdesc_holder *prev;
    struct  fab_mrmem *mrmem;
    struct  fi_zhpe_mmap_desc *mmap_desc;
};

/* Not going to do anyting with data but dom_alloc wants it */
static void onfree_one_dom(struct fab_dom *dom, void * data)
{
    free(dom);
}

/* does this really need to hang on to the local_fab_dom? */
struct z_mmap_metadata {
    struct fab_conn *local_fab_conn;
    struct fab_dom *local_fab_dom;
    struct fi_zhpe_ext_ops_v1 *ext_ops;

    fi_addr_t my_local_fi_addr;
    struct mdesc_holder *head_mdesc_holder;
};

static pthread_mutex_t zmm_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct z_mmap_metadata zm_stuff;

/* lock must be held to get here */
static int holder_free( struct mdesc_holder *cur, void *data)
{
    int ret;
    struct z_mmap_metadata * zm_mdata = data;
    ret = zm_mdata->ext_ops->munmap((struct fi_zhpe_mmap_desc *)(cur->mmap_desc));
    if (ret < 0)
        print_func_err(__func__, __LINE__, "holder_free", "munmap", ret);
    cur->mmap_desc = NULL;

    fab_mrmem_free(cur->mrmem);
    free(cur);
    return ret;
}

/* fi_conn is held by z_mmap_metadata */
/* Free z_mmap_metadata when the conn is freed. */
static void onfree_one_conn(struct fab_conn *conn, void *data)
{
    struct z_mmap_metadata *zm_metadata = data;
    int ret=-1;

printf("Entered onfree_one_conn\n");
    holder_free(zm_metadata->head_mdesc_holder, data);

    free(zm_metadata->ext_ops);
    ret = fab_conn_free(zm_metadata->local_fab_conn);
    if (ret != 0)
        printf("fab_conn_free error %d\n", ret);
    ret = fab_dom_free(zm_metadata->local_fab_dom);
    if (ret != 0)
        printf("fab_dom_free error %d\n", ret);

    zm_metadata->local_fab_conn = NULL;
    zm_metadata->ext_ops = NULL;
    zm_metadata->head_mdesc_holder = NULL;
}


/* clean when mmap_holder is empty */
/* lock must be held to get here */
static int libzhpe_mmap_finalize( void *data)
{
    struct z_mmap_metadata *zm_metadata = data;
printf("entered libzhpe_mmap_finalize\n");
    int ret = -1;
    ret = fab_conn_free(zm_metadata->local_fab_conn);
    if (ret != 0)
        printf("fab_conn_free error %d\n", ret);

    ret = fab_dom_free(zm_metadata->local_fab_dom);
    if (ret != 0)
        printf("fab_dom_free error %d\n", ret);

    zm_stuff.local_fab_dom = NULL;

    zm_stuff.local_fab_conn = NULL;

    return ret;
}

/* active addresses will never be reused so we don't need to check length. */
static int find_and_remove_holder (void *addr, void *data)
{
    int ret = -1;
    struct z_mmap_metadata *zm_mdata = data;
    struct mdesc_holder *cur;
    bool lastholder = false;

    if (zm_mdata->head_mdesc_holder == NULL )
       return (ret);

    cur = zm_mdata->head_mdesc_holder;

    while (cur != NULL) {
        if (cur->mmap_desc->addr == addr) {
            ret = 0;

            if ((cur->prev == NULL) && (cur->next == NULL)) {
            /* we are removing the last holder */
                lastholder = true;
                zm_mdata->head_mdesc_holder = NULL;
            }
            else if (zm_mdata->head_mdesc_holder == cur) {
                     zm_mdata->head_mdesc_holder = cur->next;
                     cur->next->prev = NULL;
                 } else {
                     cur->prev->next = cur->next;
                     cur->next->prev = cur->prev;
                 }
            holder_free(cur, data);
            cur = NULL;
        } else {
            cur = cur->next;
        }
    }

    if (lastholder) {
        printf("lastholder\n", ret);
        ret = libzhpe_mmap_finalize(data);
        if (ret != 0)
            printf("fab_conn_free error %d\n", ret);
    }

    return(ret);
}

struct args {
    const char *domain;
};

/* lock must be held to get here */
static int libzhpe_mmap_init(){
    int ret = 1;
/*     struct args    args = { }; */

printf("entered libzhpe_mmap_init\n");
    zm_stuff.local_fab_dom = fab_dom_alloc(onfree_one_dom, zm_stuff.local_fab_dom);
    if (!zm_stuff.local_fab_dom)
            goto done;
    ret = fab_dom_setup(NULL, NULL, true, "zhpe", NULL,
                        FI_EP_RDM, zm_stuff.local_fab_dom);
    if (ret != 0) {
        printf("fab_dom_setup failed with %d\n",ret);
        goto done;
    }

    zm_stuff.local_fab_conn = fab_conn_alloc(zm_stuff.local_fab_dom, NULL, NULL);

    zhpeq_util_init("zhpe_mmap", LOG_INFO, false);

    ret = fab_ep_setup(zm_stuff.local_fab_conn, NULL, 1, 1);
    if (ret != 0) {
        printf("fab_ep_setup failed with %d\n",ret);
        goto done;
    }

    ret = av_init(__func__, __LINE__, zm_stuff.local_fab_conn,
                 10000, &zm_stuff.my_local_fi_addr);
    if (ret != 0) {
        print_func_err(__func__, __LINE__, "av_init", "local_fi_addr", ret);
        goto done;
    }

   /* Get ext ops and mmap remote region. */
    ret = fi_open_ops(&zm_stuff.local_fab_dom->fabric->fid, FI_ZHPE_OPS_V1, 0,
                      (void **)&zm_stuff.ext_ops, NULL);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "fi_open_ops", FI_ZHPE_OPS_V1, ret);
        goto done;
    }

    return ret;

done:
    ret = libzhpe_mmap_finalize( (void *) &zm_stuff);
    return ret;
}


/* hand back address. When given the address later at free, unmap, etc. */
void *zhpe_mmap_alloc(size_t mmap_len)
{
    int ret = -1;

printf("Entered zhpe_mmap_alloc\n");

    struct fab_mrmem *mrmem;
    size_t length;
    struct fid_ep    *local_fi_ep;
    struct fi_zhpe_mmap_desc *mmap_desc;
    struct mdesc_holder *holder;

    mutex_lock(&zmm_mutex);

    if (zm_stuff.local_fab_conn == NULL) {
printf("zm_stufflocal was null\n");
        ret = libzhpe_mmap_init();
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "zhpe_mmap_init", FI_ZHPE_OPS_V1, ret);
            goto err;
        }
    }

    if (mmap_len == 0)
        length = page_up(1);
    else
        length = page_up(mmap_len);
    mrmem = calloc(1, sizeof(struct fab_mrmem));
    mmap_desc = calloc(1, sizeof(struct fi_zhpe_mmap_desc));
    holder = calloc(1, sizeof(struct mdesc_holder));
    holder->mrmem = mrmem;
    holder->mmap_desc = mmap_desc;
    holder->prev = NULL;

    ret = fab_mrmem_alloc(zm_stuff.local_fab_conn, holder->mrmem, length, 0);
    if (ret != 0) {
        print_func_err(__func__, __LINE__, "fab_mrmem_alloc",
            FI_ZHPE_OPS_V1, ret);
        goto err;
      }

    uint64_t remote_mr_key = mrmem->mr->key;

    local_fi_ep = zm_stuff.local_fab_conn->ep;

    ret = zm_stuff.ext_ops->mmap(NULL, length, PROT_READ | PROT_WRITE,
                             MAP_SHARED, 0, local_fi_ep, zm_stuff.my_local_fi_addr,
                             remote_mr_key, FI_ZHPE_MMAP_CACHE_WB, &holder->mmap_desc);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "ext_mmap", FI_ZHPE_OPS_V1, ret);
        goto err2;
    }

    if ( zm_stuff.head_mdesc_holder == NULL ) {
        holder->next = NULL;
        zm_stuff.head_mdesc_holder = holder;
    } else {
        zm_stuff.head_mdesc_holder->prev=holder;
        holder->next = zm_stuff.head_mdesc_holder;
        zm_stuff.head_mdesc_holder = holder;
    }
    mutex_unlock(&zmm_mutex);

    return holder->mmap_desc->addr;

  err2:
    free(zm_stuff.ext_ops);

  err:
    free(mrmem);
    free(mmap_desc);
    free(holder);

    mutex_unlock(&zmm_mutex);
    return NULL;
}

int zhpe_munmap_free(void *buf)
{
    int ret = -1;

    mutex_lock(&zmm_mutex);
    if (zm_stuff.local_fab_conn == NULL)
        goto err;

    ret = find_and_remove_holder(buf, (void *) &zm_stuff);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "find_and_remove_holder", FI_ZHPE_OPS_V1, ret);
        goto err;
    }

    mutex_unlock(&zmm_mutex);
    return ret;

  err:
    mutex_unlock(&zmm_mutex);
    return ret;
}
