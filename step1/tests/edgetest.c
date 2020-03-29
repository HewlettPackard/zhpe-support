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

#include <zhpeq.h>
#include <zhpeq_util.h>

#define BACKLOG         (10)
#ifdef DEBUG
#define TIMEOUT         (-1)
#else
#define TIMEOUT         (10000)
#endif
#define L1_CACHELINE    ((size_t)64)
#define ZTQ_LEN         (31)

static struct zhpeq_attr zhpeq_attr;

struct cli_wire_msg {
    uint64_t            buf_len;
    bool                imm;
    bool                once_mode;
    bool                qcm;
    bool                verbose;
};

struct op_wire_msg {
    uint64_t            coff;
    uint64_t            soff;
    uint64_t            op_len;
};

struct error_wire_msg {
    int32_t             error;
};

struct op_context {
    int                 (*handler)(struct zhpe_cq_entry *ztq_cqe,
                                   struct op_context *ctxt);
    void                *data;
    size_t              len;
};

struct args {
    const char          *node;
    const char          *service;
    uint64_t            buf_len;
    uint64_t            write_min;
    uint64_t            write_max;
    uint64_t            coff_min;
    uint64_t            coff_max;
    uint64_t            soff_min;
    uint64_t            soff_max;
    bool                imm;
    bool                once_mode;
    bool                qcm;
    bool                stop;
    bool                verbose;
};

struct checker_data {
    uint8_t             *buf;
    struct op_wire_msg  op_msg;
    bool                banner_done;
};

struct stuff {
    const struct args   *args;
    struct zhpeq_dom    *zqdom;
    struct zhpeq_tq     *ztq;
    struct zhpeq_rq     *zrq;
    struct zhpeq_key_data *lcl_kdata;
    struct zhpeq_key_data *rem_kdata;
    uint64_t            lcl_zaddr;
    uint64_t            rem_zaddr;
    void                *addr_cookie;
    int                 sock_fd;
    bool                allocated;
};

static void stuff_free(struct stuff *stuff)
{
    void                *buf;

    if (!stuff)
        return;

    if (stuff->args && stuff->args->qcm) {
        zhpeq_print_qkdata(__func__, __LINE__, stuff->rem_kdata);
        zhpeq_print_qkdata(__func__, __LINE__, stuff->lcl_kdata);
        zhpeq_print_tq_qcm(__func__, __LINE__, stuff->ztq);
    }
    zhpeq_qkdata_free(stuff->rem_kdata);
    if (stuff->lcl_kdata) {
        buf = (void *)stuff->lcl_kdata->z.vaddr;
        zhpeq_qkdata_free(stuff->lcl_kdata);
        free(buf);
    }
    zhpeq_domain_remove_addr(stuff->zqdom, stuff->addr_cookie);
    zhpeq_rq_free(stuff->zrq);
    zhpeq_tq_free(stuff->ztq);
    zhpeq_domain_free(stuff->zqdom);

    FD_CLOSE(stuff->sock_fd);

    if (stuff->allocated)
        free(stuff);
}

static int do_mem_setup(struct stuff *conn)
{
    int                 ret = -EEXIST;
    const struct args   *args = conn->args;
    void                *buf = NULL;
    size_t              req;

    /* Size of an array of entries plus a tail index. */
    req = args->buf_len;
    ret = -posix_memalign(&buf, page_size, req);
    if (ret < 0) {
        buf = NULL;
        print_func_errn(__func__, __LINE__, "posix_memalign", req, false,
                        ret);
        goto done;
    }

    ret = zhpeq_mr_reg(conn->zqdom, buf, req,
                       (ZHPEQ_MR_GET | ZHPEQ_MR_PUT |
                        ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE),
                       &conn->lcl_kdata);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_mr_reg", "", ret);
        goto done;
    }
    buf = NULL;
    if (args->qcm)
        zhpeq_print_qkdata(__func__, __LINE__, conn->lcl_kdata);

 done:
    free(buf);

    return ret;
}

static int do_mem_xchg(struct stuff *conn)
{
    int                 ret;
    char                blob[ZHPEQ_MAX_KEY_BLOB];
    size_t              blob_len;

    blob_len = sizeof(blob);
    ret = zhpeq_qkdata_export(conn->lcl_kdata, conn->lcl_kdata->z.access,
                              blob, &blob_len);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_zmmu_export", "", ret);
        goto done;
    }

    ret = sock_send_blob(conn->sock_fd, blob, blob_len);
    if (ret < 0)
        goto done;
    ret = sock_recv_fixed_blob(conn->sock_fd, blob, blob_len);
    if (ret < 0)
        goto done;

    ret = zhpeq_qkdata_import(conn->zqdom, conn->addr_cookie, blob, blob_len,
                              &conn->rem_kdata);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_zmmu_import", "", ret);
        goto done;
    }
    ret = zhpeq_zmmu_reg(conn->rem_kdata);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_zmmu_reg", "", ret);
        goto done;
    }
    if (conn->args->qcm)
        zhpeq_print_qkdata(__func__, __LINE__, conn->rem_kdata);

 done:
    return ret;
}

static int ztq_completions(struct zhpeq_tq *ztq)
{
    ssize_t             ret = 0;
    int                 rc;
    struct zhpe_cq_entry *cqe;
    struct zhpe_cq_entry cqe_copy;
    struct op_context   *ctxt;

    while ((cqe = zhpeq_tq_cq_entry(ztq))) {
        /* unlikely() to optimize the no-error case. */
        if (unlikely(cqe->status != ZHPE_HW_CQ_STATUS_SUCCESS)) {
            cqe_copy = *cqe;
            zhpeq_tq_cq_entry_done(ztq, cqe);
            ret = -EIO;
            print_err("%s,%u:index 0x%x status 0x%x\n", __func__, __LINE__,
                      cqe_copy.index, cqe_copy.status);
            break;
        }
        ctxt = zhpeq_tq_cq_context(ztq, cqe);
        zhpeq_tq_cq_entry_done(ztq, cqe);
        ret++;
        if (ctxt && ctxt->handler) {
            rc = ctxt->handler(cqe, ctxt);
            if (rc < 0) {
                ret = rc;
                break;
            }
        }
    }

    return ret;
}

static int geti_handler(struct zhpe_cq_entry *cqe, struct op_context *ctxt)
{
    memcpy(ctxt->data, cqe->result.data, ctxt->len);

    return 0;
}

static int ztq_rma_op(struct zhpeq_tq *ztq, bool read, void *lcl_buf,
                      uint64_t lcl_zaddr, size_t len, uint64_t rem_zaddr)
{
    int32_t             ret;
    struct op_context   ctxt = {
        .handler        = NULL,
    };
    union zhpe_hw_wq_entry  *wqe;

    ret = zhpeq_tq_reserve(ztq);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_tq_reserve", "", ret);
        goto done;
    }
    zhpeq_tq_set_context(ztq, ret, &ctxt);
    wqe = zhpeq_tq_get_wqe(ztq, ret);
    if (read) {
        if (lcl_buf) {
            ctxt.handler = geti_handler;
            ctxt.data = lcl_buf;
            ctxt.len = len;
            zhpeq_tq_geti(wqe, 0, len, rem_zaddr);
        } else
            zhpeq_tq_get(wqe, 0, lcl_zaddr, len, rem_zaddr);
    } else if (lcl_buf)
        memcpy(zhpeq_tq_puti(wqe, 0, len, rem_zaddr), lcl_buf, len);
    else
        zhpeq_tq_put(wqe, 0, lcl_zaddr, len, rem_zaddr);
    zhpeq_tq_insert(ztq, ret);
    zhpeq_tq_commit(ztq);
    while (!(ret = ztq_completions(ztq)));
    if (ret > 0 && !expected_saw("completions", 1, ret))
        ret = -EIO;

 done:
    return ret;
}

static void fill_buf(struct stuff *conn, struct checker_data *data, bool client)
{
    uint8_t             fill;

    if (client)
        fill = 0xFF;
    else
        fill = 0x00;

    memset(data->buf, fill, conn->args->buf_len);
}

static void ramp_buf(struct stuff *conn, struct checker_data *data, bool client)
{
    size_t              off;
    uint8_t             fill;
    uint8_t             start;
    size_t              end;
    size_t              i;
    uint8_t             v;

    if (client) {
        off = data->op_msg.coff;
        fill = 0xFF;
        start = 0x01;
    } else {
        off = data->op_msg.soff;
        fill = 0x00;
        start = 0x02;
    }
    end = off + data->op_msg.op_len;

    memset(data->buf, fill, off);
    memset(data->buf + end,  fill, conn->args->buf_len - end);
    for (i = off, v = start; i < end ; i++, v = (v == 0xFE ? 0x01 : v + 1))
        data->buf[i] = v;
}

static void print_banner(struct checker_data *data, bool err)
{
    const char          *fmt;

    fmt = "coff 0x%05lx soff 0x%05lx op_len 0x%05lx\n";
    if (err)
        print_err(fmt, data->op_msg.coff, data->op_msg.soff,
                  data->op_msg.op_len);
    else
        print_info(fmt, data->op_msg.coff, data->op_msg.soff,
                   data->op_msg.op_len);
}

static bool checker(struct checker_data *data,
                    const char *label, bool imm, size_t off,
                    uint8_t expected, uint8_t saw)
{

    if (expected == saw)
        return false;
    if (!data->banner_done) {
        print_banner(data, true);
        data->banner_done = true;
    }
    print_err("%s imm %d off 0x%04lx exp 0x%02x saw 0x%02x\n",
              label, imm, off, expected, saw);

    return true;
}

static int check_buf(struct stuff *conn, struct checker_data *data,
                      bool imm, bool client)
{
    int                 ret = 0;
    size_t              off;
    uint8_t             fill;
    uint8_t             start;
    size_t              end;
    size_t              i;
    uint8_t             v;

    /* Invert start from ramp_buf(). */
    if (client) {
        off = data->op_msg.coff;
        fill = 0xFF;
        start = 0x02;
    } else {
        off = data->op_msg.soff;
        fill = 0x00;
        start = 0x01;
    }
    end = off + data->op_msg.op_len;

    for (i = 0; i < off; i++) {
        if (checker(data, "head", imm, i, fill, data->buf[i]))
            ret = -ERANGE;
    }
    for (v = start; i < end ; i++, v = (v == 0xFE ? 0x01 : v + 1)) {
        if (checker(data, "data", imm, i, v, data->buf[i]))
            ret = -ERANGE;
    }
    for (; i < conn->args->buf_len; i++) {
        if (checker(data, "tail", imm, i, fill, data->buf[i]))
            ret = -ERANGE;
    }

    return ret;
}

static int do_server_1op(struct stuff *conn, struct checker_data *data,
                         bool imm)
{
    int                 ret;
    struct error_wire_msg err_msg;

    /* Fill buffer for put. */
    fill_buf(conn, data, false);
    ret = sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
    ret = sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
    /* Check put; status will be sent to client. */
    err_msg.error = htonl(check_buf(conn, data, imm, false));

    /* Fill buffer for get. */
    ramp_buf(conn, data, false);
    ret = sock_send_blob(conn->sock_fd, &err_msg, sizeof(err_msg));

 done:
    return ret;
}

static int do_server_ops(struct stuff *conn)
{
    int                 ret;
    struct checker_data data = {
        .buf            = (void *)conn->lcl_kdata->z.vaddr,
    };

    for (;;) {
        data.banner_done = false;
        ret = sock_recv_fixed_blob(conn->sock_fd, &data.op_msg,
                                    sizeof(data.op_msg));
        if (ret < 0)
            goto done;
        data.op_msg.coff = be64toh(data.op_msg.coff);
        data.op_msg.soff = be64toh(data.op_msg.soff);
        data.op_msg.op_len = be64toh(data.op_msg.op_len);
        if (!data.op_msg.op_len)
            goto done;
        if (data.op_msg.op_len <= ZHPEQ_MAX_IMM && conn->args->imm) {
            ret = do_server_1op(conn, &data, true);
            if (ret < 0)
                goto done;
            /* We need another ack before do_server_1op kills the buffer. */
            ret = sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
            if (ret < 0)
                goto done;
        }
        ret = do_server_1op(conn, &data, false);
        if (ret < 0)
            goto done;
        if (!data.banner_done && conn->args->verbose)
            print_banner(&data, false);
    }

 done:
    return ret;
}

static int do_client_1op(struct stuff *conn, struct checker_data *data,
                         bool imm, int *data_err)
{
    int                 ret;
    uint8_t             *lcl_buf = (imm ? data->buf + data->op_msg.coff : NULL);
    uint64_t            lcl_zaddr = (conn->lcl_kdata->z.vaddr +
                                     data->op_msg.coff);
    uint64_t            rem_zaddr = (conn->rem_kdata->z.zaddr +
                                     data->op_msg.soff);
    struct error_wire_msg err_msg;
    int                 rc;

    /* Wait for server to be ready. */
    ret = sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
    /* Fill buffer for put. */
    ramp_buf(conn, data, true);
    /* Do put. */
    ret = ztq_rma_op(conn->ztq, false, lcl_buf, lcl_zaddr, data->op_msg.op_len,
                     rem_zaddr);
    if (ret < 0)
        goto done;
    ret = sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Wait for server to be ready. */
    ret = sock_recv_fixed_blob(conn->sock_fd, &err_msg, sizeof(err_msg));
    if (ret < 0)
        goto done;
    rc = ntohl(err_msg.error);
    if (rc < 0) {
        *data_err = rc;
        if (conn->args->stop)
            goto done;
    }

    /* Overwrite ramp for get. */
    fill_buf(conn, data, true);
    /* Do get. */
    ret = ztq_rma_op(conn->ztq, true, lcl_buf, lcl_zaddr, data->op_msg.op_len,
                     rem_zaddr);
    if (ret < 0)
        goto done;
    rc = check_buf(conn, data, imm, true);
    if (rc < 0) {
        *data_err = rc;
        if (conn->args->stop)
            goto done;
    }

 done:
    return ret;
}

static int do_client_op(struct stuff *conn, size_t coff, size_t soff,
                        size_t op_len, int *data_err)
{
    int                 ret;
    struct checker_data data = {
        .buf            = (void *)conn->lcl_kdata->z.vaddr,
    };

    data.op_msg.coff = htobe64(coff);
    data.op_msg.soff = htobe64(soff);
    data.op_msg.op_len = htobe64(op_len);
    ret = sock_send_blob(conn->sock_fd, &data.op_msg, sizeof(data.op_msg));
    if (ret < 0)
        goto done;
    if (!op_len)
        goto done;
    /* The right way for local routines. */
    data.op_msg.coff = coff;
    data.op_msg.soff = soff;
    data.op_msg.op_len = op_len;

    if (data.op_msg.op_len <= ZHPEQ_MAX_IMM && conn->args->imm) {
        ret = do_client_1op(conn, &data, true, data_err);
        if (ret < 0)
            goto done;
        if (*data_err && conn->args->stop)
            goto done;
        ret = sock_send_blob(conn->sock_fd, NULL, 0);
        if (ret < 0)
            goto done;
    }
    ret = do_client_1op(conn, &data, false, data_err);
    if (!data.banner_done && conn->args->verbose)
        print_banner(&data, false);

 done:
    return ret;
}

int do_ztq_setup(struct stuff *conn)
{
    int                 ret;
    union sockaddr_in46 sa;
    size_t              sa_len = sizeof(sa);

    ret = -EINVAL;

    /* Allocate domain. */
    ret = zhpeq_domain_alloc(&conn->zqdom);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", ret);
        goto done;
    }
    /* Allocate zqueues. */
    ret = zhpeq_tq_alloc(conn->zqdom, ZTQ_LEN, ZTQ_LEN, 0, 0, 0,  &conn->ztq);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_tq_alloc", "", ret);
        goto done;
    }
    if (conn->args->qcm)
        zhpeq_print_tq_qcm(__func__, __LINE__, conn->ztq);

    ret = zhpeq_rq_alloc(conn->zqdom, 1, 0, &conn->zrq);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_rq_qalloc", "", ret);
        goto done;
    }

    /* Exchange addresses and insert the remote address in the domain. */
    ret = zhpeq_rq_xchg_addr(conn->zrq, conn->sock_fd, &sa, &sa_len);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_tq_xchg_addr", "", ret);
        goto done;
    }
    ret = zhpeq_domain_insert_addr(conn->zqdom, &sa, &conn->addr_cookie);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_domain_insert_addr", "", ret);
        goto done;
    }
    /* Now let's exchange the memory parameters to the other side. */
    ret = do_mem_setup(conn);
    if (ret < 0)
        goto done;
    ret = do_mem_xchg(conn);
    if (ret < 0)
        goto done;

 done:
    return ret;
}

static int do_server_one(const struct args *oargs, int conn_fd)
{
    int                 ret;
    struct args         one_args = *oargs;
    struct args         *args = &one_args;
    struct stuff        conn = {
        .args           = args,
        .sock_fd        = conn_fd,
    };
    struct cli_wire_msg cli_msg;

    /* Let's take a moment to get the client parameters over the socket. */
    ret = sock_recv_fixed_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    args->buf_len = be64toh(cli_msg.buf_len);
    args->imm = !!cli_msg.imm;
    args->once_mode = !!cli_msg.once_mode;
    args->qcm = !!cli_msg.qcm;
    args->verbose = !!cli_msg.verbose;

    /* Dummy for ordering. */
    ret = sock_send_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    ret = do_ztq_setup(&conn);
    if (ret < 0)
        goto done;

    ret = do_server_ops(&conn);

 done:
    stuff_free(&conn);

    if (ret >= 0)
        ret = (cli_msg.once_mode ? 1 : 0);

    return ret;
}

static int do_server(const struct args *args)
{
    int                 ret;
    int                 listener_fd = -1;
    int                 conn_fd = -1;
    struct addrinfo     *resp = NULL;
    int                 oflags = 1;

    ret = do_getaddrinfo(NULL, args->service,
                         AF_INET6, SOCK_STREAM, true, &resp);
    if (ret < 0)
        goto done;
    listener_fd = socket(resp->ai_family, resp->ai_socktype,
                         resp->ai_protocol);
    if (listener_fd == -1) {
        ret = -errno;
        print_func_err(__func__, __LINE__, "socket", "", ret);
        goto done;
    }
    if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR,
                   &oflags, sizeof(oflags)) == -1) {
        ret = -errno;
        print_func_err(__func__, __LINE__, "setsockopt", "", ret);
        goto done;
    }
    /* None of the usual: no polling; no threads; no cloexec; no nonblock. */
    if (bind(listener_fd, resp->ai_addr, resp->ai_addrlen) == -1) {
        ret = -errno;
        print_func_err(__func__, __LINE__, "bind", "", ret);
        goto done;
    }
    if (listen(listener_fd, BACKLOG) == -1) {
        ret = -errno;
        print_func_err(__func__, __LINE__, "listen", "", ret);
        goto done;
    }
    for (ret = 0; !ret;) {
        conn_fd = accept(listener_fd, NULL, NULL);
        if (conn_fd == -1) {
            ret = -errno;
            print_func_err(__func__, __LINE__, "accept", "", ret);
            goto done;
        }
        ret = do_server_one(args, conn_fd);
    }

done:
    if (listener_fd != -1)
        close(listener_fd);
    if (resp)
        freeaddrinfo(resp);

    return ret;
}

static int do_client(const struct args *args)
{
    int                 ret;
    struct stuff        conn = {
        .args           = args,
        .sock_fd        = -1,
    };
    int                 data_err = 0;
    struct cli_wire_msg cli_msg;
    uint64_t            op_len;
    uint64_t            coff;
    uint64_t            soff;
    int                 rc;

    ret = connect_sock(args->node, args->service);
    if (ret < 0)
        goto done;
    conn.sock_fd = ret;

    /* Write the ring parameters to the server. */
    cli_msg.buf_len = htobe64(args->buf_len);
    cli_msg.imm = args->imm;
    cli_msg.once_mode = args->once_mode;
    cli_msg.qcm = args->qcm;
    cli_msg.verbose = args->verbose;

    ret = sock_send_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    /* Dummy for ordering. */
    ret = sock_recv_fixed_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    ret = do_ztq_setup(&conn);
    if (ret < 0)
        goto done;

    for (op_len = args->write_min; op_len <= args->write_max; op_len++) {
        for (coff = args->coff_min; coff <= args->coff_max; coff++) {
            for (soff = args->soff_min; soff <= args->soff_max; soff++) {
                ret = do_client_op(&conn, coff, soff, op_len, &data_err);
                if (ret < 0)
                    goto done;
                if (data_err < 0 && args->stop)
                    goto err;
            }
        }
    }

 err:
    /* Send zero length to cause server exit. */
    rc = do_client_op(&conn, 0, 0, 0, &data_err);
    if (rc < 0 && ret >= 0)
        ret = rc;

 done:
    stuff_free(&conn);

    return (ret < 0 ? ret : data_err);
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s [-ioqsv] <port> [<node> <buf_len>\n"
        "    <write_max> <cli_off_max> <svr_off_max>\n"
        "    [<write_min> <cli_off_min> <svr_off_min>]]\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "Server requires just port; client requires 6 or 9 arguments.\n"
        "Client only options:\n"
        " -i : disable immediate ops\n"
        " -o : run once and then server will exit\n"
        " -q : print qcm and key data\n"
        " -s : stop on first error\n"
        " -v : verbose: print a line for each loop\n",
        appname);

    if (help)
        zhpeq_print_tq_info(NULL);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = {
        .imm            = true,
    };
    bool                client_opt = false;
    int                 opt;
    int                 rc;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "ioqsv")) != -1) {

        /* All opts are client only, now. */
        client_opt = true;

        switch (opt) {

        case 'i':
            if (!args.imm)
                usage(false);
            args.imm = false;
            break;

        case 'o':
            if (args.once_mode)
                usage(false);
            args.once_mode = true;
            break;

        case 'q':
            if (args.qcm)
                usage(false);
            args.qcm = true;
            break;

        case 's':
            if (args.stop)
                usage(false);
            args.stop = true;
            break;

        case 'v':
            if (args.verbose)
                usage(false);
            args.verbose = true;
            break;

        default:
            usage(false);

        }
    }

    opt = argc - optind;

    if (opt == 1) {
        args.service = argv[optind++];
        if (client_opt)
            usage(false);
        if (do_server(&args) < 0)
            goto done;
    } else if (opt == 6 || opt == 9) {
        args.service = argv[optind++];
        args.node = argv[optind++];
        if (parse_kb_uint64_t(__func__, __LINE__, "buf_len",
                              argv[optind++], &args.buf_len, 0, 1,
                              SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 ||
            parse_kb_uint64_t(__func__, __LINE__, "write_max",
                              argv[optind++], &args.write_max, 0, 1,
                              args.buf_len, PARSE_KB | PARSE_KIB) < 0 ||
            parse_kb_uint64_t(__func__, __LINE__, "cli_off_max",
                              argv[optind++], &args.coff_max, 0, 0,
                              args.buf_len - args.write_max,
                              PARSE_KB | PARSE_KIB) < 0 ||
            parse_kb_uint64_t(__func__, __LINE__, "svr_off_max",
                              argv[optind++], &args.soff_max, 0, 0,
                              args.buf_len - args.write_max,
                              PARSE_KB | PARSE_KIB) < 0)
            usage(false);
        if (opt == 9) {
            if (parse_kb_uint64_t(__func__, __LINE__, "write_min",
                                  argv[optind++], &args.write_min, 0, 1,
                                  args.write_max, PARSE_KB | PARSE_KIB) < 0 ||
                parse_kb_uint64_t(__func__, __LINE__, "cli_off_min",
                                  argv[optind++], &args.coff_min, 0, 0,
                                  args.coff_max, PARSE_KB | PARSE_KIB) < 0 ||
                parse_kb_uint64_t(__func__, __LINE__, "svr_off_min",
                                  argv[optind++], &args.soff_min, 0, 0,
                                  args.soff_max, PARSE_KB | PARSE_KIB) < 0)
                usage(false);
        } else {
            args.write_min = args.write_max;
            args.coff_min = args.coff_max;
            args.soff_min = args.soff_max;
        }

        if (do_client(&args) < 0)
            goto done;
    } else
        usage(false);

    ret = 0;

 done:
    return ret;
}
