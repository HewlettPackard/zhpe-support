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

#include <zhpeq_util_fab.h>

#define BACKLOG         (10)
#ifdef DEBUG
#define TIMEOUT         (-1)
#else
#define TIMEOUT         (10000)
#endif

/* As global variables for debugger */
static int              timeout = TIMEOUT;

struct cli_wire_msg {
    uint64_t            len;
    uint8_t             ep_type;
    bool                once_mode;
};

struct mem_wire_msg {
    uint64_t            remote_key;
    uint64_t            remote_addr;
};

struct args {
    const char          *provider;
    const char          *domain;
    const char          *node;
    const char          *service;
    uint64_t            len;
    uint64_t            ops;
    uint64_t            warmup;
    uint8_t             ep_type;
    bool                once_mode;
};

struct stuff {
    const struct args   *args;
    struct fab_dom      fab_dom;
    struct fab_conn     fab_conn;
    struct fab_conn     fab_listener;
    int                 sock_fd;
    fi_addr_t           dest_av;
    struct fi_context2  *ctx;
    uint64_t            tot;
    uint64_t            remote_key;
    uint64_t            remote_addr;
    bool                allocated;
};

static void stuff_free(struct stuff *stuff)
{
    if (!stuff)
        return;

    fab_conn_free(&stuff->fab_conn);
    fab_conn_free(&stuff->fab_listener);
    fab_dom_free(&stuff->fab_dom);

    free(stuff->ctx);

    FD_CLOSE(stuff->sock_fd);

    if (stuff->allocated)
        free(stuff);
}

static int do_mem_setup(struct stuff *conn)
{
    int                 ret = -EEXIST;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    const struct args   *args = conn->args;
    size_t              req;

    ret = fab_mrmem_alloc(fab_conn, &fab_conn->mrmem, args->len, 0);
    if (ret < 0)
        goto done;

    req = sizeof(*conn->ctx) * conn->tot;
    ret = -posix_memalign((void **)&conn->ctx, page_size, req);
    if (ret < 0) {
        conn->ctx = NULL;
        print_func_errn(__func__, __LINE__, "posix_memalign", true,
                        req, ret);
        goto done;
    }

 done:
    return ret;
}

static int do_mem_xchg(struct stuff *conn)
{
    int                 ret;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    struct mem_wire_msg mem_msg;

    mem_msg.remote_key = htobe64(fi_mr_key(fab_conn->mrmem.mr));
    mem_msg.remote_addr = htobe64((uintptr_t)fab_conn->mrmem.mem);

    ret = sock_send_blob(conn->sock_fd, &mem_msg, sizeof(mem_msg));
    if (ret < 0)
        goto done;
    ret = sock_recv_fixed_blob(conn->sock_fd, &mem_msg, sizeof(mem_msg));
    if (ret < 0)
        goto done;

    conn->remote_key = be64toh(mem_msg.remote_key);
    conn->remote_addr = be64toh(mem_msg.remote_addr);

 done:
    return ret;
}

static ssize_t do_progress(struct fab_conn *fab_conn,
                           size_t *tx_cmp, size_t *rx_cmp)
{
    ssize_t             ret = 0;
    ssize_t             rc;

    /* Check both tx and rx sides to make progress.
     * FIXME: Should rx be necessary for one-sided?
     */
    rc = fab_completions(fab_conn->tx_cq, 0, NULL, NULL);
    if (rc >= 0) {
        if (tx_cmp)
            *tx_cmp += rc;
        else
            assert(!rc);
    } else if (ret >= 0)
        ret = rc;

    rc = fab_completions(fab_conn->rx_cq, 0, NULL, NULL);
    if (rc >= 0) {
        if (rx_cmp)
            *rx_cmp += rc;
        else
            assert(!rc);
    } else if (ret >= 0)
        ret = rc;

    return ret;
}

static int do_server_burst(struct stuff *conn)
{
    int                 ret = 0;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    struct fi_context2  ctx;
    uint64_t            i;

    /* Do a send-receive for the final handshake. */
    ret = fi_recv(fab_conn->ep, NULL, 0, NULL, FI_ADDR_UNSPEC, &ctx);
    if (ret < 0) {
        print_func_fi_err(__func__, __LINE__, "fi_recv", "", ret);
        goto done;
    }
    for (i = 0 ; !i;) {
        ret = do_progress(fab_conn, NULL, &i);
        if (ret < 0)
            goto done;
    }

    fab_print_info(fab_conn);
 done:

    return ret;
}

struct lat {
    uint64_t            tot;
    uint64_t            min;
    uint64_t            max;
};

static inline int do_op_one(struct stuff *conn, void *ctxt, bool write)
{
    int                 ret;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    const struct args   *args = conn->args;

    if (write)
        ret = fi_write(fab_conn->ep, fab_conn->mrmem.mem, args->len,
                       fi_mr_desc(fab_conn->mrmem.mr), conn->dest_av,
                       conn->remote_addr, conn->remote_key, ctxt);
    else
        ret = fi_read(fab_conn->ep, fab_conn->mrmem.mem, args->len,
                      fi_mr_desc(fab_conn->mrmem.mr), conn->dest_av,
                      conn->remote_addr, conn->remote_key, ctxt);
    if (ret < 0)
        print_func_fi_err(__func__, __LINE__,
                          (write ? "fi_write" : "fi_read"), "", ret);

    return ret;
}

static int do_op(struct stuff *conn, struct lat *lat, bool write)
{
    int                 ret = 0;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    const struct args   *args = conn->args;
    uint64_t            i;
    uint64_t            start;
    uint64_t            delta;

    lat->tot = 0;
    lat->min = ~(uint64_t)0;
    lat->max = 0;

    for (i = 0; i < args->warmup; i++) {
        ret = do_op_one(conn, &conn->ctx[i], write);
        if (ret < 0)
            goto done;
    }
    for (i = 0; i < args->ops; i++) {
        start = get_cycles(NULL);
        ret = do_op_one(conn, &conn->ctx[i + args->warmup], write);
        delta = get_cycles(NULL) - start;

        lat->tot += delta;
        if (delta > lat->max)
            lat->max = delta;
        if (delta < lat->min)
            lat->min = delta;
    }
    for (i = 0; i != conn->tot;) {
        ret = do_progress(fab_conn, &i, NULL);
        if (ret < 0)
            goto done;
    }

 done:
    return ret;
}

static void printf_lat(const struct args *args, const char *lbl,
                       struct lat *lat)
{
    printf("%s:%s ave/min/max %.3lf/%.3lf/%.3lf\n",
           appname, lbl,
           cycles_to_usec(lat->tot, args->ops),
           cycles_to_usec(lat->min, 1), cycles_to_usec(lat->max, 1));
}

static int do_client_burst(struct stuff *conn)
{
    int                 ret;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    const struct args   *args = conn->args;
    uint64_t            i;
    struct lat          latw;
    struct lat          latr;

    /* Do one operation and wait to make sure the key info is local. */
    ret = do_op_one(conn, &conn->ctx[0], true);
    if (ret < 0)
        goto done;
    for (i = 0; !i;) {
        ret = do_progress(fab_conn, &i, NULL);
        if (ret < 0)
            goto done;
    }
    /* Do timed operations. */
    ret = do_op(conn, &latw, true);
    if (ret < 0)
        goto done;
    ret = do_op(conn, &latr, false);
    if (ret < 0)
        goto done;

    /* Do a send-receive for the final handshake. */
    ret = fi_send(fab_conn->ep, NULL, 0, NULL, conn->dest_av, &conn->ctx[0]);
    if (ret < 0) {
        print_func_fi_err(__func__, __LINE__, "fi_send", "", ret);
        goto done;
    }
    for (i = 0; !i;) {
        ret = do_progress(fab_conn, &i, NULL);
        if (ret < 0)
            goto done;
    }

    fab_print_info(fab_conn);
    printf("%s:op_cnt/warmup %lu/%lu\n", appname,
           args->ops, args->warmup);
    printf_lat(args, "latw", &latw);
    printf_lat(args, "latr", &latr);

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
        .dest_av        = FI_ADDR_UNSPEC
    };
    struct fab_dom      *fab_dom = &conn.fab_dom;
    struct fab_conn     *fab_conn = &conn.fab_conn;
    struct fab_conn     *fab_listener = &conn.fab_listener;
    union sockaddr_in46 addr;
    size_t              addr_len;
    struct cli_wire_msg cli_msg;
    char                *s;

    fab_dom_init(fab_dom);
    fab_conn_init(fab_dom, fab_conn);
    fab_conn_init(fab_dom, fab_listener);

    /* Get the client parameters over the socket. */
    ret = sock_recv_fixed_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;
    ret = sock_recv_string(conn.sock_fd, &s);
    if (ret < 0)
        goto done;
    args->provider = s;
    ret = sock_recv_string(conn.sock_fd, &s);
    if (ret < 0)
        goto done;
    args->domain = s;

    args->len = be64toh(cli_msg.len);
    args->ep_type = cli_msg.ep_type;
    args->once_mode = !!cli_msg.once_mode;

    ret = fab_dom_setup(NULL, NULL, true,
                        args->provider, args->domain, args->ep_type, fab_dom);
    if (ret < 0)
        goto done;

    if (args->ep_type == FI_EP_RDM) {
        ret = fab_ep_setup(fab_conn, NULL, 0, 0);
        if (ret < 0)
            goto done;
        ret = fab_av_xchg(fab_conn, conn.sock_fd, timeout, &conn.dest_av);
        if (ret < 0)
            goto done;
    } else {
        ret = fab_listener_setup(BACKLOG, fab_listener);
        if (ret < 0)
            goto done;

        /* And send our port to the client. */
        addr_len = sizeof(addr);
        ret = fi_getname(&fab_listener->pep->fid, &addr, &addr_len);
        if (ret >= 0 && !sockaddr_valid(&addr, addr_len, true))
            ret = -EAFNOSUPPORT;
        if (ret < 0) {
            print_func_fi_err(__func__, __LINE__, "fi_getname", "", ret);
            goto done;
        }
        ret = sock_send_blob(conn.sock_fd, &addr, sizeof(addr));
        if (ret < 0)
            goto done;

        /* Now let's wait for a connection request at the libfabric level. */
        ret = fab_listener_wait_and_accept(fab_listener, timeout,
                                           0, 0, fab_conn);
        if (ret < 0)
            goto done;
    }

    /* Now let's exchange the memory parameters to the other side. */
    ret = do_mem_setup(&conn);
    if (ret < 0)
        goto done;
    ret = do_mem_xchg(&conn);
    if (ret < 0)
        goto done;

    ret = do_server_burst(&conn);

 done:
    stuff_free(&conn);
    free((void *)args->provider);
    free((void *)args->domain);

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
            .args = args,
            .sock_fd = -1,
            .dest_av = FI_ADDR_UNSPEC,
            .tot = args->warmup + args->ops,
        };
    struct fab_dom      *fab_dom = &conn.fab_dom;
    struct fab_conn     *fab_conn = &conn.fab_conn;
    struct fab_conn     *fab_listener = &conn.fab_listener;
    union sockaddr_in46 addr;
    struct cli_wire_msg cli_msg;

    fab_dom_init(fab_dom);
    fab_conn_init(fab_dom, fab_conn);
    fab_conn_init(fab_dom, fab_listener);

    ret = connect_sock(args->node, args->service);
    if (ret < 0)
        goto done;
    conn.sock_fd = ret;

    /* Write the ring parameters to the server. */
    cli_msg.len = htobe64(args->len);
    cli_msg.ep_type = args->ep_type;
    cli_msg.once_mode = args->once_mode;

    ret = sock_send_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;
    ret = sock_send_string(conn.sock_fd, args->provider);
    if (ret < 0)
        goto done;
    ret = sock_send_string(conn.sock_fd, args->domain);
    if (ret < 0)
        goto done;

    ret = fab_dom_setup(NULL, NULL, true,
                        args->provider, args->domain, args->ep_type, fab_dom);
    if (ret < 0)
        goto done;

    if (args->ep_type == FI_EP_RDM) {
        ret = fab_ep_setup(fab_conn, NULL, conn.tot, conn.tot);
        if (ret < 0)
            goto done;
        ret = fab_av_xchg(fab_conn, conn.sock_fd, timeout, &conn.dest_av);
        if (ret < 0)
            goto done;
    } else {
        ret = sock_recv_fixed_blob(conn.sock_fd, &addr, sizeof(addr));
        if (ret < 0)
            goto done;

        fab_conn_info(fab_conn)->dest_addr = sockaddr_dup(&addr);
        if (!fab_conn_info(fab_conn)->dest_addr) {
            ret = -FI_ENOMEM;
            goto done;
        }

        /* Connect at the libfabric level. */
        ret = fab_connect(timeout, 0, 0, fab_conn);
        if (ret < 0)
            goto done;
    }

    /* Now let's exchange the memory parameters to the other side. */
    ret = do_mem_setup(&conn);
    if (ret < 0)
        goto done;
    ret = do_mem_xchg(&conn);
    if (ret < 0)
        goto done;

    ret = do_client_burst(&conn);

 done:
    stuff_free(&conn);

    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s [-or] [-d <domain>] [-p <provider>]\n"
        "    [-w <ops>] <port> [<node> <len> <ops>]\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "Server requires just port; client requires all 4 arguments.\n"
        "Client only options:\n"
        " -d <domain> : domain/device to bind to (eg. mlx5_0)\n"
        " -o : run once and then server will exit\n"
        " -p <provider> : provider to use\n"
        " -r : use RDM endpoints\n"
        " -w <ops> : number of warmup operations\n"
        "If provider is zhpe, uses ASIC backend unless environment variable\n"
        "ZHPE_BACKEND_LIBFABRIC_PROV is set.\n"
        "ZHPE_BACKEND_LIBFABRIC_DOM can be used to set a specific domain\n",
        appname);

    if (help) {
        printf("\n");
        fab_print_info(NULL);
    }

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = {
        .ep_type        = FI_EP_MSG,
    };
    bool                client_opt = false;
    int                 opt;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "d:op:rw:")) != -1) {

        /* All opts are client only, now. */
        client_opt = true;

        switch (opt) {

        case 'd':
            if (args.domain)
                usage(false);
            args.domain = optarg;
            break;

        case 'o':
            if (args.once_mode)
                usage(false);
            args.once_mode = true;
            break;

        case 'p':
            if (args.provider)
                usage(false);
            args.provider = optarg;
            break;

        case 'r':
            if (args.ep_type != FI_EP_MSG)
                usage(false);
            args.ep_type = FI_EP_RDM;
            break;

        case 'w':
            if (args.warmup != SIZE_MAX)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "warmup",
                                  optarg, &args.warmup, 0, 1,
                                  SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
                usage(false);
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
    } else if (opt == 4) {
        args.service = argv[optind++];
        args.node = argv[optind++];
        if (parse_kb_uint64_t(__func__, __LINE__, "len",
                              argv[optind++], &args.len, 0, 1,
                              SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 ||
            parse_kb_uint64_t(__func__, __LINE__, "ops",
                              argv[optind++], &args.ops, 0, 1,
                              SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
            usage(false);
        if (do_client(&args) < 0)
            goto done;
    } else
        usage(false);

    ret = 0;
 done:

    return ret;
}
