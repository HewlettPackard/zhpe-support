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

#include <zhpeq.h>
#include <zhpeq_util_fab.h>

/* Need internal.h for backend timing stuff. */
#include <internal.h>

#define BACKLOG         (10)
#ifdef DEBUG
#define TIMEOUT         (-1)
#else
#define TIMEOUT         (10000)
#endif
#define L1_CACHELINE    ((size_t)64)
#define ZQ_LEN          (31)

struct cli_wire_msg {
    uint64_t            buf_len;
    bool                once_mode;
};

struct svr_wire_msg {
    int                 dummy;
};

struct op_wire_msg {
    uint64_t            coff;
    uint64_t            soff;
    uint64_t            op_len;
};

struct op_context {
    int                 (*handler)(struct zhpeq_cq_entry *zq_cqe,
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
};

struct stuff {
    const struct args   *args;
    struct zhpeq_dom    *zdom;
    struct zhpeq        *zq;
    struct zhpeq_key_data *lcl_kdata;
    struct zhpeq_key_data *rem_kdata;
    uint64_t            lcl_zaddr;
    uint64_t            rem_zaddr;
    int                 sock_fd;
    int                 open_idx;
    bool                allocated;
};

static void stuff_free(struct stuff *stuff)
{
    void                *buf;

    if (!stuff)
        return;

    if (stuff->zq) {
#if 0
        zhpeq_print_qkdata(__FUNCTION__, __LINE__, stuff->zdom,
                           stuff->rem_kdata);
#endif
        zhpeq_zmmu_free(stuff->zdom, stuff->rem_kdata);
        buf = (void *)stuff->lcl_kdata->z.vaddr;
#if 0
        zhpeq_print_qkdata(__FUNCTION__, __LINE__, stuff->zdom,
                           stuff->lcl_kdata);
#endif
        zhpeq_mr_free(stuff->zdom, stuff->lcl_kdata);
        free(buf);
    }
    if (stuff->open_idx != -1)
        zhpeq_backend_close(stuff->zq, stuff->open_idx);
    zhpeq_print_qcm(__FUNCTION__, __LINE__, stuff->zq);
    zhpeq_free(stuff->zq);
    zhpeq_domain_free(stuff->zdom);

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
        print_func_errn(__FUNCTION__, __LINE__, "posix_memalign", req, false,
                        ret);
        goto done;
    }

    ret = zhpeq_mr_reg(conn->zdom, buf, req,
                       (ZHPEQ_MR_GET | ZHPEQ_MR_PUT |
                        ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE),
                       0, &conn->lcl_kdata);
    if (ret < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_mr_reg", "", ret);
        goto done;
    }
    buf = NULL;
#if 0
    zhpeq_print_qkdata(__FUNCTION__, __LINE__, conn->zdom, conn->lcl_kdata);
#endif

 done:
    free(buf);

    return ret;
}

static int do_mem_xchg(struct stuff *conn)
{
    int                 ret;
    void                *blob = NULL;
    size_t              blob_len;

    ret = zhpeq_zmmu_export(conn->zdom, conn->lcl_kdata, &blob, &blob_len);
    if (ret < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_zmmu_export", "", ret);
        goto done;
    }

    ret = sock_send_blob(conn->sock_fd, blob, blob_len);
    if (ret < 0)
        goto done;
    ret = sock_recv_fixed_blob(conn->sock_fd, blob, blob_len);
    if (ret < 0)
        goto done;

    ret = zhpeq_zmmu_import(conn->zdom, conn->open_idx, blob, blob_len,
                            false, &conn->rem_kdata);
    if (ret < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_zmmu_import", "", ret);
        goto done;
    }
#if 0
    zhpeq_print_qkdata(__FUNCTION__, __LINE__, conn->zdom, conn->rem_kdata);
#endif

 done:
    free(blob);

    return ret;
}

static inline int zq_completions(struct zhpeq *zq)
{
    ssize_t             ret = 0;
    int                 rc;
    ssize_t             i;
    struct zhpeq_cq_entry zq_comp[1];
    struct op_context   *ctxt;

    ret = zhpeq_cq_read(zq, zq_comp, ARRAY_SIZE(zq_comp));
    if (ret < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_cq_read", "", ret);
        goto done;
    }
    for (i = ret; i > 0;) {
        i--;
        if (zq_comp[i].z.status != ZHPEQ_CQ_STATUS_SUCCESS) {
            print_err("%s,%u:I/O error\n", __FUNCTION__, __LINE__);
            ret = -EIO;
            break;
        }
        ctxt = zq_comp[i].z.context;
        if (ctxt) {
            rc = ctxt->handler(&zq_comp[i], ctxt);
            if (rc < 0) {
                ret = rc;
                break;
            }
        }
    }

 done:

    return ret;
}

static int geti_handler(struct zhpeq_cq_entry *cqe, struct op_context *ctxt)
{
    memcpy(ctxt->data, cqe->z.result.data, ctxt->len);

    return 0;
}

static int zq_op(struct zhpeq *zq, bool read, void *lcl_buf, uint64_t lcl_zaddr,
                 size_t len, uint64_t rem_zaddr)
{
    int64_t             ret;
    uint32_t            zq_index;
    struct op_context   ctxt;
    const char          *op_str;

    ret = zhpeq_reserve(zq, 1);
    if (ret < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_reserve", "", ret);
        goto done;
    }
    zq_index = ret;
    if (read) {
        if (lcl_buf) {
            op_str = "zhpeq_geti";
            ctxt.handler = geti_handler;
            ctxt.data = lcl_buf;
            ctxt.len = len;
            ret = zhpeq_geti(zq, zq_index, false, len, rem_zaddr, &ctxt);
        } else {
            op_str = "zhpeq_get";
            ret = zhpeq_get(zq, zq_index, false, lcl_zaddr, len, rem_zaddr,
                            NULL);
        }
    } else if (lcl_buf) {
        op_str = "zhpeq_puti";
        ret = zhpeq_puti(zq, zq_index, false, lcl_buf, len, rem_zaddr, NULL);
    } else {
        op_str = "zhpeq_put";
        ret = zhpeq_put(zq, zq_index, false, lcl_zaddr, len, rem_zaddr, NULL);
    }
    if (ret < 0) {
        print_func_err(__FUNCTION__, __LINE__, op_str, "", ret);
        goto done;
    }
    ret = zhpeq_commit(zq, zq_index, 1);
    if (ret < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_commit", "", ret);
        goto done;
    }
    while (!(ret = zq_completions(zq)));
    if (ret > 0 && !expected_saw("completions", 1, ret))
        ret = -EIO;

 done:
    return ret;
}

static inline void ramp_buf(uint8_t *buf, size_t buf_len, size_t off,
                            size_t op_len, uint8_t fill, uint8_t start)
{
    size_t              end = off + op_len;
    size_t              i;
    uint8_t             v;

    memset(buf, fill, off);
    memset(buf + end,  fill, buf_len - end);
    for (i = off, v = start; i < end ; i++, v = (v == 0xFE ? 0x01 : v + 1))
        buf[i] = v;
}

static int check_buf(uint8_t *buf, size_t buf_len, size_t off,
                     size_t op_len, uint8_t fill, uint8_t start)
{
    int                 ret = 0;
    size_t              end = off + op_len;
    size_t              i;
    uint8_t             v;

    for (i = 0; i < off; i++) {
        if (expected_saw("head", fill, buf[i]))
            continue;
        print_err("boff 0x%05lx\n", i);
        ret = -ERANGE;
    }
    for (v = start; i < end ; i++, v = (v == 0xFE ? 0x01 : v + 1)) {
        if (expected_saw("data", v, buf[i]))
            continue;
        print_err("boff 0x%05lx\n", i);
        ret = -ERANGE;
    }
    for (; i < buf_len; i++) {
        if (expected_saw("tail", fill, buf[i]))
            continue;
        print_err("boff 0x%05lx\n", i);
        ret = -ERANGE;
    }

    (void)ret;
    return 0;
}

static int do_server_ops(struct stuff *conn)
{
    int                 ret;
    uint8_t             fill = 0x00;
    uint8_t             sramp = 0x01;
    uint8_t             cramp = 0x02;
    const struct args   *args = conn->args;
    uint8_t             *buf = (void *)conn->lcl_kdata->z.vaddr;
    size_t              buf_len = args->buf_len;
    struct op_wire_msg  op_msg;
    size_t              coff;
    size_t              soff;
    size_t              op_len;

    for (;;) {
        ret = sock_recv_fixed_blob(conn->sock_fd, &op_msg, sizeof(op_msg));
        if (ret < 0)
            goto done;
        coff = be64toh(op_msg.coff);
        soff = be64toh(op_msg.soff);
        op_len = be64toh(op_msg.op_len);
        if (!op_len)
            goto done;
        print_err("coff 0x%05lx soff 0x%05lx op_len 0x%05lx\n",
                  coff, soff, op_len);

        /* Fill buffer for put. */
        memset(buf, fill, buf_len);
        ret = sock_send_blob(conn->sock_fd, NULL, 0);
        if (ret < 0)
            goto done;
        ret = sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
        if (ret < 0)
            goto done;
        /* Check put. */
        ret = check_buf(buf, buf_len, soff, op_len, fill, cramp);
        if (ret < 0)
            goto done;

        /* Fill buffer for get. */
        ramp_buf(buf, buf_len, soff, op_len, fill, sramp);
        ret = sock_send_blob(conn->sock_fd, NULL, 0);
        if (ret < 0)
            goto done;
    }

 done:

    return ret;
}

static int do_client_op(struct stuff *conn, size_t coff, size_t soff,
                        size_t op_len)
{
    int                 ret;
    uint8_t             fill = 0xFF;
    uint8_t             sramp = 0x01;
    uint8_t             cramp = 0x02;
    const struct args   *args = conn->args;
    uint8_t             *buf = (void *)conn->lcl_kdata->z.vaddr;
    size_t              buf_len = args->buf_len;
    uint64_t            lcl_zaddr = conn->lcl_kdata->laddr + coff;
    uint64_t            rem_zaddr = conn->rem_kdata->z.zaddr + soff;
    struct op_wire_msg  op_msg;

    print_err("coff 0x%05lx soff 0x%05lx op_len 0x%05lx\n", coff, soff, op_len);
    op_msg.coff = htobe64(coff);
    op_msg.soff = htobe64(soff);
    op_msg.op_len = htobe64(op_len);
    ret = sock_send_blob(conn->sock_fd, &op_msg, sizeof(op_msg));
    if (ret < 0)
        goto done;
    if (!op_len)
        goto done;

    /* Wait for server to be ready. */
    ret = sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
    /* Fill buffer for put. */
    ramp_buf(buf, buf_len, coff, op_len, fill, cramp);
    /* Do put. */
    ret = zq_op(conn->zq, false,
                (args->imm ? buf + coff : NULL), lcl_zaddr, op_len, rem_zaddr);
    if (ret < 0)
        goto done;
    ret = sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Wait for server to be ready. */
    ret = sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
    /* Overwrite ramp for get. */
    memset(buf + coff, fill, op_len);
    /* Do get. */
    ret = zq_op(conn->zq, true,
                (args->imm ? buf + coff : NULL), lcl_zaddr, op_len, rem_zaddr);
    if (ret < 0)
        goto done;
    ret = check_buf(buf, buf_len, coff, op_len, fill, sramp);
    if (ret < 0)
        goto done;

 done:

    return ret;
}

int do_zq_setup(struct stuff *conn)
{
    int                 ret;
    struct zhpeq_attr   zq_attr;

    ret = zhpeq_query_attr(&zq_attr);
    if (ret < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_query_attr", "", ret);
        goto done;
    }

    ret = -EINVAL;

    /* Allocate domain. */
    ret = zhpeq_domain_alloc(&conn->zdom);
    if (ret < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_domain_alloc", "", ret);
        goto done;
    }
    /* Allocate zqueue. */
    ret = zhpeq_alloc(conn->zdom, ZQ_LEN, ZQ_LEN, 0, 0, 0,  &conn->zq);
    if (ret < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_qalloc", "", ret);
        goto done;
    }
    /* Get address index. */
    ret = zhpeq_backend_open(conn->zq, conn->sock_fd);
    if (ret < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_open", "", ret);
        goto done;
    }
    conn->open_idx = ret;
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
        .open_idx       = -1,
    };
    struct cli_wire_msg cli_msg;

    /* Let's take a moment to get the client parameters over the socket. */
    ret = sock_recv_fixed_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    args->buf_len = be64toh(cli_msg.buf_len);
    args->once_mode = cli_msg.once_mode;

    /* Dummy for ordering. */
    ret = sock_send_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    ret = do_zq_setup(&conn);
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
        print_func_err(__FUNCTION__, __LINE__, "socket", "", ret);
        goto done;
    }
    if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEPORT,
                   &oflags, sizeof(oflags)) == -1) {
        ret = -errno;
        print_func_err(__FUNCTION__, __LINE__, "setsockopt", "", ret);
        goto done;
    }
    /* None of the usual: no polling; no threads; no cloexec; no nonblock. */
    if (bind(listener_fd, resp->ai_addr, resp->ai_addrlen) == -1) {
        ret = -errno;
        print_func_err(__FUNCTION__, __LINE__, "bind", "", ret);
        goto done;
    }
    if (listen(listener_fd, BACKLOG) == -1) {
        ret = -errno;
        print_func_err(__FUNCTION__, __LINE__, "listen", "", ret);
        goto done;
    }
    for (ret = 0; !ret;) {
        conn_fd = accept(listener_fd, NULL, NULL);
        if (conn_fd == -1) {
            ret = -errno;
            print_func_err(__FUNCTION__, __LINE__, "accept", "", ret);
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
        .open_idx       = -1,
    };
    struct cli_wire_msg cli_msg;
    uint64_t            op_len;
    uint64_t            coff;
    uint64_t            soff;


    ret = connect_sock(args->node, args->service);
    if (ret < 0)
        goto done;
    conn.sock_fd = ret;

    /* Write the ring parameters to the server. */
    cli_msg.buf_len = htobe64(args->buf_len);
    cli_msg.once_mode = args->once_mode;

    ret = sock_send_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    /* Dummy for ordering. */
    ret = sock_recv_fixed_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    ret = do_zq_setup(&conn);
    if (ret < 0)
        goto done;

    for (op_len = args->write_min; op_len <= args->write_max; op_len++) {
        for (coff = args->coff_min; coff <= args->coff_max; coff++) {
            for (soff = args->soff_min; soff <= args->soff_max; soff++) {
                ret = do_client_op(&conn, coff, soff, op_len);
                if (ret < 0)
                    goto done;
            }
        }
    }
    /* Send zero length to cause server exit. */
    ret = do_client_op(&conn, 0, 0, 0);

 done:
    stuff_free(&conn);

    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s [-o] <port> [<node> <buf_len>\n"
        "    [<write_max> <cli_off_max> <svr_off_max>\n"
        "     [<write_min> <cli_off_min> <svr_off_min>]]\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "Server requires just port; client requires 6 or 9 arguments.\n"
        "Client only options:\n"
        " -i : use immediate ops, write_max <= 32\n"
        " -o : run once and then server will exit\n"
        "Uses ASIC backend unless environment variable\n"
        "ZHPE_BACKEND_LIBFABRIC_PROV is set.\n"
        "ZHPE_BACKEND_LIBFABRIC_DOM can be used to set a specific domain\n",
        appname);

    if (help)
        zhpeq_print_info(NULL);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = { NULL };
    bool                client_opt = false;
    int                 opt;
    int                 rc;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION);
    if (rc < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "io")) != -1) {

        /* All opts are client only, now. */
        client_opt = true;

        switch (opt) {

        case 'i':
            if (args.imm)
                usage(false);
            args.imm = true;
            break;

        case 'o':
            if (args.once_mode)
                usage(false);
            args.once_mode = true;
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
        if (parse_kb_uint64_t(__FUNCTION__, __LINE__, "buf_len",
                              argv[optind++], &args.buf_len, 0, 1,
                              SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 ||
            parse_kb_uint64_t(__FUNCTION__, __LINE__, "write_max",
                              argv[optind++], &args.write_max, 0, 1,
                              (args.imm ? ZHPEQ_IMM_MAX : args.buf_len),
                              PARSE_KB | PARSE_KIB) < 0 ||
            parse_kb_uint64_t(__FUNCTION__, __LINE__, "cli_off_max",
                              argv[optind++], &args.coff_max, 0, 0,
                              args.buf_len - args.write_max,
                              PARSE_KB | PARSE_KIB) < 0 ||
            parse_kb_uint64_t(__FUNCTION__, __LINE__, "svr_off_max",
                              argv[optind++], &args.soff_max, 0, 0,
                              args.buf_len - args.write_max,
                              PARSE_KB | PARSE_KIB) < 0)
            usage(false);
        if (opt == 9) {
            if (parse_kb_uint64_t(__FUNCTION__, __LINE__, "write_min",
                                  argv[optind++], &args.write_min, 0, 1,
                                  args.write_max, PARSE_KB | PARSE_KIB) < 0 ||
                parse_kb_uint64_t(__FUNCTION__, __LINE__, "cli_off_min",
                                  argv[optind++], &args.coff_min, 0, 0,
                                  args.coff_max, PARSE_KB | PARSE_KIB) < 0 ||
                parse_kb_uint64_t(__FUNCTION__, __LINE__, "svr_off_min",
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
