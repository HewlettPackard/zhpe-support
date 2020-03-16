/*
 * Copyright (C) 019 Hewlett Packard Enterprise Development LP.
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

#include <lf_common.h>

#define BACKLOG         (10)
#ifdef DEBUG
#define TIMEOUT         (-1)
#else
#define TIMEOUT         (10000)
#endif

/* As global variables for debugger */
static int              timeout = TIMEOUT;

struct lf_param_wire_msg {
    unt64_t             tx_avail;
    unt64_t             rx_avail;
    unt64_t             memsize;
    uint8_t             ep_type;
};

struct lf_mem_wire_msg {
    uint64_t            remote_key;
    uint64_t            remote_addr;
    uint64_t            remote_size;
};

void lf_ctx_free(struct lf_conn *lf_conn, void *vctx)
{
    union lf_context    *ctx = (void *)vctx;

    ctx->next = lf_conn->ctx_free;
    lf_conn->ctx_free = ctx;
    lf_conn->ctx_cur++;
}

union lf_context *lf_ctx_next(struct lf_conn *lf_conn)
{
    union lf_context    *ret;

    ret = conn->ctx_free;
    if (likely(ret)) {
        lf_conn->ctx_free = ret->next;
        lf_conn->ctx_cur--;
    }

    return ret;
}

bool lf_ctx_all_done(struct lf_conn *conn)
{
    return (conn->ctx_cur == conn->ctx_avail);
}

static int lf_conn_ctx_alloc(struct lf_conn *lf_conn, size_t ctx_size)
{
    int                 ret = -FI_ENOMEM;
    size_t              i;

    lf_conn->ctx_size = ctx_size;
    lf_conn->ctx_avail = lf_conn->tx_avail + lf_conn->rx_avail;
    lf_conn->ctx = _calloc_cachealigned(ctx_avail, ctx_size);
    if (!lf_conn->ctx)
        goto done;
    for (i = ctx_avail * ctx_size ; i > 0; i -= ctx_size)
        lf_ctx_free(conn, (char *)conn->ctx + i);
    lf_ctx_free(conn, conn->ctx);
}

static int update_error(int old, int new)
{
    return (old < 0 ? old : new);
}

static void cq_update(void *vargs, void *vcqe, bool err)
{
    struct lf_conn      *lf_conn = vargs;
    struct fi_cq_entry  *cqe = vcqe;
    struct fi_cq_err_entry *cqerr;

    lf_ctx_free(conn, cqe->op_context);
    if (err) {
        cqerr = vcqe;
        conn->status = update_error(conn->status, -cqerr->err);
        print_err("%s,%u:I/O returned error %d:%s\n",
                  __func__, __LINE__, -cqerr->err, fi_strerror(cqerr->err));
    }
}

int lf_progress(struct lf_conn *lf_conn)
{
    int                 ret = 0;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    int                 rc;

    /* Check both tx and rx sides to make progress. */
    rc = fab_completions(fab_conn->tx_cq, 0, cq_update, lf_conn);
    ret = update_error(ret, rc);

    rc = fab_completions(fab_conn->rx_cq, 0, cq_update, lf_conn);
    ret = update_error(ret, rc);
    ret = update_error(ret, conn->status);

    return ret;
}

int lf_wait_all(struct lf_conn *lf_conn)
{
    int                 ret = 0;

    while (!lf_ctx_all_done(lf_conn)) {
        ret = do_progress(lf_conn);
        if (ret < 0)
            break;
    }

    return ret;
}

void lf_conn_free(struct lf_conn *lf_conn)
{
    if (!lf_conn)
        return;

    FD_CLOSE(lf_conn->sock_fd);
    fab_conn_free(lf_conn->fab_conn);
    fab_conn_free(lf_conn->fab_listener);
    fab_dom_free(lf_conn->fab_dom);
    free(lf_conn->ctx);
    free(lf_conn);
}

void lf_params_free(struct lf_params *param)
{
    if (!param || !param->free_str)
        return;

    free(param->provider);
    free(param->domain);
}

int lf_server_recv_params(int sock_fd, struct lf_params *param)
{
    int                 ret;
    struct params_wire_msg msg;
    char                *s;

    param->provider = NULL;
    param->domain = NULL;
    param->free_str = true;

    ret = zhpeu_sock_recv_fixed_blob(sock_fd, &copy, sizeof(copy));
    if (ret < 0)
        goto done;
    param->tx_avail = be64toh(msg.tx_avail);
    param->rx_avail = be64toh(msg.rx_avail);
    param->memsize  = be64toh(msg.memsize);
    ret = zhpeu_sock_recv_string(sock_fd, &s);
    if (ret < 0)
        goto done;
    param->provider = s;
    ret = zhpeu_sock_recv_string(sock_fd, &s);
    if (ret < 0)
        goto done;
    param->domain = s;

 done:
    if (ret < 0)
        lf_svr_params_free(param);

    return ret;
}

int lf_client_send_params(int sock_fd, struct lf_params *param)
{
    int                 ret;
    struct params_wire_msg msg;

    msg.tx_avail = htobe64(param->tx_avail);
    msg.rx_avail = htobe64(param->rx_avail);
    msg.memsize  = htobe64(param->memsize);
    msg.ep_type  = param->ep_type;

    ret = zhpeu_sock_send_blob(sock_fd, &msg, sizeof(msg));
    if (ret < 0)
        goto done;
    ret = zhpeu_sock_send_string(sock_fd, param->provider);
    if (ret < 0)
        goto done;
    ret = zhpeu_sock_recv_string(conn.sock_fd, param->domain);
    if (ret < 0)
        goto done;

 done:
    return ret;
}

int lf_conn_alloc(const struct lf_params *param, struct lf_conn **lf_conn_out)
{
    int                 ret = -FI_ENOMEM;
    struct mem_wire_msg mem_msg = { 0 };

    *lf_conn_out = NULL;
    lf_conn = calloc_cachealigned(1, sizeof(*lf_conn));
    if (!lf_conn)
        goto done;
    lf_conn->sock_fd = -1;
    lf_conn->fab_dom = fab_dom_alloc(NULL, NULL);
    if (!lf_conn->fab_dom)
        goto done;
    lf_conn->fab_conn = fab_conn_alloc(lf_conn->fab_dom, NULL, NULL);
    if (!lf_conn->fab_conn)
        goto done;
    lf_conn->fab_listener = fab_conn_alloc(lf_conn->fab_dom, NULL, NULL);
    if (!lf_conn->fab_listener)
        goto done;

    ret = _fab_dom_setup(NULL, NULL, true, param->provider, param->domain,
                         param->tx_avail, param->rx_avail, param->ep_type,
                         lf_conn->fab_dom);
    if (ret < 0)
        goto done;
    lf_conn->tx_avail = param->tx_avail;
    if (!lf_conn->tx_avail)
        lf_conn->tx_avail = fab_conn_info(lf_conn->fab_conn)->tx_attr.size;
    lf_conn->rx_avail = rx_avail;
    if (!lf_conn->rx_avail)
        lf_conn->rx_avail = fab_conn_info(lf_conn->fab_conn)->rx_attr.size;

    if (param->memsize > 0) {
        ret = _fab_mrmem_alloc(fab_conn, &lf_conn->fab_conn->mrmem, memsize, 0);
        mem_msg.remote_key = htobe64(fi_mr_key(lf_conn->fab_conn->mrmem.mr));
        mem_msg.remote_addr = htobe64((uintptr)lf_conn->fab_conn->mrmem.mem);
        mem_msg.remote_size = htobe64(lf_conn->fab_conn->mrmem.len);
    }
    ret = zhpeu_sock_send_blob(sock_fd, &mem_msg,sizeof(mem_msg));
    if (ret < 0)
        goto done;
    ret = zhpeu_sock_recv_fixed_blob(sock_fd, &mem_msg,sizeof(mem_msg));
    if (ret < 0)
        goto done;
    lf_conn->remote_addr = be64toh(mem_msg.remote_addr);
    lf_conn->remote_key  = be64toh(mem_msg.remote_key);
    lf_conn->remote_size = be64toh(mem_msg.remote_size);

 done:
    if (ret >= 0)
        *lf_conn_out = lf_conn;
    else
        lf_conn_free(lf_conn);

    return ret;
}

int lf_server_ep_setup(struct lf_conn *lf_conn)
{
    int                 ret;
    union sockaddr_in46 addr;
    size_t              addr_len;

    if (param->ep_type == FI_EP_RDM) {
        ret = _fab_ep_setup(lf_conn->fab_conn, NULL,
                            param->tx_avail, param->rx_avail);
        if (ret < 0)
            goto done;
        ret = _fab_av_xchg(lf_conn->fab_conn, lf_conn->sock_fd, timeout,
                           &lf_conn->remote_fi_addr);
        if (ret < 0)
            goto done;
    } else {
        ret = _fab_listener_setup(BACKLOG, lf_conn->fab_listener);
        if (ret < 0)
            goto done;

        /* And send our port to the client. */
        addr_len = sizeof(addr);
        ret = fi_getname(&lf_conn->fab_listener->pep->fid, &addr, &addr_len);
        if (ret >= 0 && !zhpeu_sockaddr_valid(&addr, addr_len, true))
            ret = -EAFNOSUPPORT;
        if (ret < 0) {
            fab_print_func_fi_err(__func__, __LINE__, "fi_getname", "", ret);
            goto done;
        }
        ret = zhpeu_sock_send_blob(sock_fd, &addr, sizeof(addr));
        if (ret < 0)
            goto done;

        /* Now let's wait for a connection request at the libfabric level. */
        ret = _fab_listener_wait_and_accept(lf_conn->fab_listener, timeout,
                                            tx_avail, rx_avail,
                                            lf_conn->fab_conn);
        if (ret < 0)
            goto done;
    }

 done:
    return ret;
}

int lf_client_ep_setup(struct lf_conn *lf_conn)
{
    int                 ret = -FI_ENOMEM;
    struct mem_wire_msg mem_msg = { 0 };
    union sockaddr_in46 addr;
    size_t              addr_len;
    struct lf_conn      *lf_conn;

    *lf_conn_out = NULL;
    lf_conn = calloc_cachealigned(1, sizeof(*lf_conn));
    if (!lf_conn)
        goto done;
    lf_conn->tx_avail = tx_avail;
    lf_conn->rx_avail = rx_avail;

    lf_conn->fab_dom = fab_dom_alloc(NULL, NULL);
    if (!lf_conn->fab_dom)
        goto done;
    lf_conn->fab_conn = fab_conn_alloc(lf_conn->fab_dom, NULL, NULL);
    if (!lf_conn->fab_conn)
        goto done;

    ret = _fab_dom_setup(NULL, NULL, true, param->provider, param->domain,
                         param->ep_type, lf_conn->fab_dom);
    if (ret < 0)
        goto done;
    lf_conn->tx_avail = param->tx_avail;
    if (!lf_conn->tx_avail)
        lf_conn->tx_avail = fab_conn_info(lf_conn->fab_conn)->tx_attr.size;
    lf_conn->rx_avail = rx_avail;
    if (!lf_conn->rx_avail)
        lf_conn->rx_avail = fab_conn_info(lf_conn->fab_conn)->rx_attr.size;

    if (param->ep_type == FI_EP_RDM) {
        ret = _fab_ep_setup(lf_conn->fab_conn, NULL,
                            param->tx_avail, param->rx_avail);
        if (ret < 0)
            goto done;
        ret = _fab_av_xchg(lf_conn->fab_conn, sock_fd, timeout,
                           &lf_conn->remote_fi_addr);
        if (ret < 0)
            goto done;
    } else {
        ret = zhpeu_sock_recv_fixed_blob(conn.sock_fd, &addr, sizeof(addr));
        if (ret < 0)
            goto done;

        fab_conn_info(fab_conn)->dest_addr = zhpeu_sockaddr_dup(&addr);
        if (!fab_conn_info(fab_conn)->dest_addr) {
            ret = -FI_ENOMEM;
            goto done;
        }

        /* Connect at the libfabric level. */
        ret = _fab_connect(timeout, param->tx_avail, param->rx_avail, fab_conn);
        if (ret < 0)
            goto done;
    }

    /* Registered memory allocation and exchange. */
    mem_msg.remote_size = htobe64(param->memsize);
    if (param->memsize > 0) {
        ret = _fab_mrmem_alloc(fab_conn, &lf_conn->fab_conn->mrmem,
                               param->memsize, 0);
        if (ret < 0)
            goto done;
        mem_msg.remote_key = htobe64(fi_mr_key(lf_conn->fab_conn->mrmem.mr));
        mem_msg.remote_addr = htobe64((uintptr)lf_conn->fab_conn->mrmem.mem);
    }
    ret = zhpeu_sock_send_blob(sock_fd, &mem_msg,sizeof(mem_msg));
    if (ret < 0)
        goto done;
    ret = zhpeu_sock_recv_fixed_blob(sock_fd, &mem_msg,sizeof(mem_msg));
    if (ret < 0)
        goto done;
    lf_conn->remote_addr = be64toh(mem_msg.remote_addr);
    lf_conn->remote_key  = be64toh(mem_msg.remote_key);
    lf_conn->remote_size = be64toh(mem_msg.remote_size);

 done:
    if (ret >= 0)
        *lf_conn_out = lf_conn;
    else
        lf_conn_free(lf_conn);

    return ret;
}
