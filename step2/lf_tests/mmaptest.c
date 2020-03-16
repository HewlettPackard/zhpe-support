/*
 * Copyright (C) 2019-2020 Hewlett Packard Enterprise Development LP.
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

#include <sys/mman.h>

#include <rdma/fi_ext_zhpe.h>

#define PROVIDER        "zhpe"
#define EP_TYPE         FI_EP_RDM

#define BACKLOG         (10)
#ifdef DEBUG
#define TIMEOUT         (-1)
#else
#define TIMEOUT         (10000)
#endif
#define WARMUP_MIN      (1024)
#define RX_WINDOW       (64)
#define TX_WINDOW       (64)
#define L1_CACHELINE    ((size_t)64)

/* As global variables for debugger */
static int              timeout = TIMEOUT;

struct cli_wire_msg {
    uint64_t            mmap_len;
    uint64_t            threads;
    bool                once_mode;
};

struct mem_wire_msg {
    uint64_t            remote_key;
};

struct args {
    const char          *node;
    const char          *service;
    uint64_t            mmap_len;
    uint64_t            threads;
    bool                once_mode;
};

struct thread_data {
    struct stuff        *conn;
    pthread_t           thread;
    uint64_t            tidx;
    int                 status;
};

struct stuff {
    const struct args   *args;
    struct fab_dom      fab_dom;
    struct fab_conn     fab_conn;
    struct fab_conn     fab_listener;
    int                 sock_fd;
    fi_addr_t           dest_av;
    uint64_t            remote_key;
    struct fi_zhpe_ext_ops_v1 *ext_ops;
    struct fi_zhpe_mmap_desc *mdesc;
};

static pthread_mutex_t  thread_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   thread_cond0 = PTHREAD_COND_INITIALIZER;
static pthread_cond_t   thread_cond = PTHREAD_COND_INITIALIZER;
uint64_t                thread_count;
static int              thread_state;

enum {
        STATE_WAIT1,
        STATE_WAIT2,
        STATE_DONE,
};

static int update_error(int old, int new)
{
    if (new < 0 && old >= 0)
        old = new;

    return old;
}

static void stuff_free(struct stuff *stuff)
{
    int                 rc;

    if (!stuff)
        return;

    /* Unmap. */
    if (stuff->mdesc) {
        rc = stuff->ext_ops->munmap(stuff->mdesc);
        if (rc < 0)
            print_func_fi_err(__func__, __LINE__, "ext_munmap", "", rc);
    }

    fab_conn_free(&stuff->fab_conn);
    fab_conn_free(&stuff->fab_listener);
    fab_dom_free(&stuff->fab_dom);

    FD_CLOSE(stuff->sock_fd);
}

static int do_mem_setup(struct stuff *conn)
{
    int                 ret = -EEXIST;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    const struct args   *args = conn->args;
    size_t              req = args->mmap_len * args->threads + page_size;

    ret = fab_mrmem_alloc(fab_conn, &fab_conn->mrmem, req, 0);
    if (ret < 0)
        goto done;
    memset(fab_conn->mrmem.mem, 0, req);
    /* Make sure there are no dirty lines in cache. */
    conn->ext_ops->commit(NULL, fab_conn->mrmem.mem, req, true, true, true);

 done:
    return ret;
}

static int do_mem_xchg(struct stuff *conn, bool client)
{
    int                 ret;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    struct mem_wire_msg mem_msg;

    if (client) {
        ret = sock_recv_fixed_blob(conn->sock_fd, &mem_msg, sizeof(mem_msg));
        if (ret < 0)
            goto done;
        conn->remote_key = be64toh(mem_msg.remote_key);
    } else {
        mem_msg.remote_key = htobe64(fi_mr_key(fab_conn->mrmem.mr));
        ret = sock_send_blob(conn->sock_fd, &mem_msg, sizeof(mem_msg));
        if (ret < 0)
            goto done;
    }

 done:
    return ret;
}

static void *do_server_thread(void *targ)
{
    int                 ret = 0;
    struct thread_data  *thread = targ;
    struct stuff        *conn = thread->conn;
    struct fab_conn     *fab_conn = &conn->fab_conn;
    const struct args   *args = conn->args;
    void                *buf = ((char *)fab_conn->mrmem.mem + page_size +
                                args->mmap_len * thread->tidx);
    uint16_t            *p;
    size_t              i;

    /* Only one thread synchronizes across the wire. */
    mutex_lock(&thread_mutex);
    thread_count++;
    if (thread->tidx) {
        if (thread_count == args->threads)
            cond_broadcast(&thread_cond0);
        while (thread_state == STATE_WAIT1)
            cond_wait(&thread_cond, &thread_mutex);
    } else if (thread_count != args->threads)
            cond_wait(&thread_cond0, &thread_mutex);
    thread_count--;
    mutex_unlock(&thread_mutex);

    if (!thread->tidx) {
        /* Wait for ramps. */
        ret = sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
        if (ret < 0)
            goto done;

        /* Let the threads run. */
        mutex_lock(&thread_mutex);
        thread_state = STATE_WAIT2;
        mutex_unlock(&thread_mutex);
        cond_broadcast(&thread_cond);
    }

    /* Invalidate any prefetched cache lines. */
    conn->ext_ops->commit(NULL, buf, args->mmap_len, true, true, false);
    /* Compare ramp. */
    for (i = 0, p =  buf; i < args->mmap_len; i += sizeof(*p), p++) {
        if (*p != (typeof(*p))(i | 1))
            print_err("t %3" PRIu64 " svr off 0x%08lx saw 0x%04x\n",
                      thread->tidx, i, *p);
    }
    /* Rewrite ramp. */
    for (i = 0, p = buf; i < args->mmap_len; i+= sizeof(*p), p++)
        *p = i;

    /* Only one thread synchronizes across the wire. */
    mutex_lock(&thread_mutex);
    thread_count++;
    if (thread->tidx) {
        if (thread_count == args->threads)
            cond_broadcast(&thread_cond0);
        while (thread_state == STATE_WAIT2)
            cond_wait(&thread_cond, &thread_mutex);
    } else if (thread_count != args->threads)
            cond_wait(&thread_cond0, &thread_mutex);
    thread_count--;
    mutex_unlock(&thread_mutex);

    if (!thread->tidx) {
        /* Tell client ramps are ready. */
        ret = sock_send_blob(conn->sock_fd, NULL, 0);
        if (ret < 0)
            goto done;

        /* Final handshake. */
        ret = sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
        if (ret < 0)
            goto done;

        /* Let the threads run. */
        mutex_lock(&thread_mutex);
        thread_state = STATE_DONE;
        mutex_unlock(&thread_mutex);
        cond_broadcast(&thread_cond);
    }

 done:
    thread->status = ret;

    return NULL;
}

static void *do_client_thread(void *targ)
{
    int                 ret = 0;
    struct thread_data  *thread = targ;
    struct stuff        *conn = thread->conn;
    const struct args   *args = conn->args;
    void                *buf = ((char *)conn->mdesc->addr +
                                args->mmap_len * thread->tidx);
    uint16_t            *p;
    size_t              i;
    uint64_t            lat_write;
    uint64_t            lat_commit;
    uint64_t            lat_flush;
    uint64_t            lat_read;
    uint64_t            start;
    uint64_t            now;

    /* Write ramp. */
    start = get_cycles(NULL);
    for (i = 0, p = buf; i < args->mmap_len; i += sizeof(*p), p++)
        *p = (i | 1);
    now = get_cycles(NULL);
    lat_write = now - start;

    /* Commit buffer. */
    start = now;
    ret = conn->ext_ops->commit(conn->mdesc, buf, args->mmap_len,
                                true, false, true);
    if (ret < 0) {
        print_func_fi_err(__func__, __LINE__, "ext_commit", "", ret);
        goto done;
    }
    now = get_cycles(NULL);
    lat_commit = now - start;

    /* Only one thread synchronizes across the wire. */
    mutex_lock(&thread_mutex);
    thread_count++;
    if (thread->tidx) {
        if (thread_count == args->threads)
            cond_broadcast(&thread_cond0);
        while (thread_state == STATE_WAIT1)
            cond_wait(&thread_cond, &thread_mutex);
    } else if (thread_count != args->threads)
            cond_wait(&thread_cond0, &thread_mutex);
    thread_count--;
    mutex_unlock(&thread_mutex);

    if (!thread->tidx) {
        /* Tell server ramps are ready. */
        ret = sock_send_blob(conn->sock_fd, NULL, 0);
        if (ret < 0)
            goto done;

        /* Wait for ramps. */
        ret = sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
        if (ret < 0)
            goto done;

        /* Let the threads run. */
        mutex_lock(&thread_mutex);
        thread_state = STATE_WAIT2;
        mutex_unlock(&thread_mutex);
        cond_broadcast(&thread_cond);
    }

    /* Invalidate any prefetched cache lines. */
    start = get_cycles(NULL);
    conn->ext_ops->commit(conn->mdesc, buf, args->mmap_len, true, true, false);
    now = get_cycles(NULL);
    lat_flush = now - start;

    /* Compare ramp. */
    start = now;
    for (i = 0, p = conn->mdesc->addr; i < args->mmap_len;
         i += sizeof(*p), p++) {
        if (*p != (typeof(*p))i)
            print_err("t %3" PRIu64 " cli off 0x%08lx saw 0x%04x\n",
                      thread->tidx, i, *p);
    }
    now = get_cycles(NULL);
    lat_read = now - start;

    /* Only one thread synchronizes across the wire. */
    mutex_lock(&thread_mutex);
    thread_count++;
    if (thread->tidx) {
        if (thread_count == args->threads)
            cond_broadcast(&thread_cond0);
        while (thread_state == STATE_WAIT2)
            cond_wait(&thread_cond, &thread_mutex);
    } else if (thread_count != args->threads)
            cond_wait(&thread_cond0, &thread_mutex);
    thread_count--;
    mutex_unlock(&thread_mutex);

    if (!thread->tidx) {
        /* Final handshake. */
        ret = sock_send_blob(conn->sock_fd, NULL, 0);
        if (ret < 0)
            goto done;

        /* Let the threads run. */
        mutex_lock(&thread_mutex);
        thread_state = STATE_DONE;
        mutex_unlock(&thread_mutex);
        cond_broadcast(&thread_cond);
    }

    printf("%s:t %" PRIu64 " mmap_len 0x%lx lat write/commit/flush/read"
           " %.3lf/%.3lf/%.3lf/%.3lf\n",
           appname, thread->tidx, args->mmap_len,
           cycles_to_usec(lat_write, 1),
           cycles_to_usec(lat_commit, 1),
           cycles_to_usec(lat_flush, 1),
           cycles_to_usec(lat_read, 1));

 done:
    thread->status = ret;

    return NULL;
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
    struct thread_data  *threads = NULL;
    struct cli_wire_msg cli_msg;
    size_t              i;
    void                *retval;
    int                 rc;

    fab_dom_init(fab_dom);
    fab_conn_init(fab_dom, fab_conn);
    fab_conn_init(fab_dom, fab_listener);

    /* Get the client parameters over the socket. */
    ret = sock_recv_fixed_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    args->mmap_len = be64toh(cli_msg.mmap_len);
    args->threads = be64toh(cli_msg.threads);
    args->once_mode = !!cli_msg.once_mode;

    ret = fab_dom_setup(NULL, NULL, true, PROVIDER, NULL, EP_TYPE, fab_dom);
    if (ret < 0)
        goto done;

    /* Get ext ops and mmap remote region. */
    ret = fi_open_ops(&fab_dom->fabric->fid, FI_ZHPE_OPS_V1, 0,
                      (void **)&conn.ext_ops, NULL);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "fi_open_ops", FI_ZHPE_OPS_V1, ret);
        goto done;
    }

    ret = fab_ep_setup(fab_conn, NULL, 0, 0);
    if (ret < 0)
        goto done;
    ret = fab_av_xchg(fab_conn, conn.sock_fd, timeout, &conn.dest_av);
    if (ret < 0)
        goto done;

    /* Now let's exchange the memory parameters to the other side. */
    ret = do_mem_setup(&conn);
    if (ret < 0)
        goto done;
    ret = do_mem_xchg(&conn, false);
    if (ret < 0)
        goto done;

    threads = calloc(args->threads, sizeof(*threads));
    if (!threads) {
        ret = - ENOMEM;
        goto done;
    }

    ret = 0;
    thread_state = STATE_WAIT1;

    for (i = 0; i < args->threads; i++) {
        threads[i].conn = &conn;
        threads[i].tidx = i;
        ret = -pthread_create(&threads[i].thread, NULL, do_server_thread,
                              &threads[i]);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "pthread_create", "", ret);
            break;
        }
    }
    for (i = 0; i < args->threads; i++) {
        if (!threads[i].conn)
            break;
        if (ret < 0)
            (void)pthread_cancel(threads[i].thread);
        rc = -pthread_join(threads[i].thread, &retval);
        ret = update_error(ret, rc);
        if (rc < 0)
            continue;
        if (retval == PTHREAD_CANCELED) {
            ret = update_error(ret, -EINTR);
            continue;
        }
        ret = update_error(ret, threads[i].status);
    }

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
            .args = args,
            .sock_fd = -1,
            .dest_av = FI_ADDR_UNSPEC,
        };
    struct fab_dom      *fab_dom = &conn.fab_dom;
    struct fab_conn     *fab_conn = &conn.fab_conn;
    struct fab_conn     *fab_listener = &conn.fab_listener;
    struct thread_data  *threads = NULL;
    struct cli_wire_msg cli_msg;
    size_t              i;
    void                *retval;
    int                 rc;

    fab_dom_init(fab_dom);
    fab_conn_init(fab_dom, fab_conn);
    fab_conn_init(fab_dom, fab_listener);

    ret = connect_sock(args->node, args->service);
    if (ret < 0)
        goto done;
    conn.sock_fd = ret;

    /* Write the ring parameters to the server. */
    cli_msg.mmap_len = htobe64(args->mmap_len);
    cli_msg.threads = htobe64(args->threads);
    cli_msg.once_mode = args->once_mode;

    ret = sock_send_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    ret = fab_dom_setup(NULL, NULL, true, PROVIDER, NULL, EP_TYPE, fab_dom);
    if (ret < 0)
        goto done;

    /* Get ext ops and mmap remote region. */
    ret = fi_open_ops(&fab_dom->fabric->fid, FI_ZHPE_OPS_V1, 0,
                      (void **)&conn.ext_ops, NULL);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "fi_open_ops", FI_ZHPE_OPS_V1, ret);
        goto done;
    }

    ret = fab_ep_setup(fab_conn, NULL, 0, 0);
    if (ret < 0)
        goto done;
    ret = fab_av_xchg(fab_conn, conn.sock_fd, timeout, &conn.dest_av);
    if (ret < 0)
        goto done;

    /* Now let's exchange the memory parameters to the other side. */
    ret = do_mem_xchg(&conn, true);
    if (ret < 0)
        goto done;

    ret = conn.ext_ops->mmap(NULL, args->mmap_len * args->threads,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED, page_size, fab_conn->ep, conn.dest_av,
                             conn.remote_key, FI_ZHPE_MMAP_CACHE_WB,
                             &conn.mdesc);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "ext_mmap", FI_ZHPE_OPS_V1, ret);
        goto done;
    }

    /* Write/read mmap region  */
    threads = calloc(args->threads, sizeof(*threads));
    if (!threads) {
        ret = - ENOMEM;
        goto done;
    }

    ret = 0;
    thread_state = STATE_WAIT1;

    for (i = 0; i < args->threads; i++) {
        threads[i].conn = &conn;
        threads[i].tidx = i;
        ret = -pthread_create(&threads[i].thread, NULL, do_client_thread,
                              &threads[i]);
        if (ret < 0) {
            print_func_err(__func__, __LINE__, "pthread_create", "", ret);
            break;
        }
    }
    for (i = 0; i < args->threads; i++) {
        if (!threads[i].conn)
            break;
        if (ret < 0)
            (void)pthread_cancel(threads[i].thread);
        rc = -pthread_join(threads[i].thread, &retval);
        ret = update_error(ret, rc);
        if (rc < 0)
            continue;
        if (retval == PTHREAD_CANCELED) {
            ret = update_error(ret, -EINTR);
            continue;
        }
        ret = update_error(ret, threads[i].status);
    }

 done:
    stuff_free(&conn);

    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s [-o] [-t threads] <port> [<node> <mmap_len>]\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "Server requires just port; client requires all 3 arguments.\n"
        "Client only options:\n"
        " -o : run once and then server will exit\n"
        " -t <threads> : number of simultaneous threads,"
        " <mmap_len> buffer for each\n",
        appname);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = {
    };
    bool                client_opt = false;
    int                 opt;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "ot:")) != -1) {

        /* All opts are client only, now. */
        client_opt = true;

        switch (opt) {

        case 'o':
            if (args.once_mode)
                usage(false);
            args.once_mode = true;
            break;

        case 't':
            if (args.threads)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "threads",
                                  optarg, &args.threads, 0,
                                  1, SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        default:
            usage(false);

        }
    }

    if (!args.threads)
        args.threads = 1;
    args.mmap_len = page_up(args.mmap_len + page_size);

    opt = argc - optind;

    if (opt == 1) {
        args.service = argv[optind++];
        if (client_opt)
            usage(false);
        if (do_server(&args) < 0)
            goto done;
    } else if (opt == 3) {
        args.service = argv[optind++];
        args.node = argv[optind++];
        if (parse_kb_uint64_t(__func__, __LINE__, "mmap_len",
                              argv[optind++], &args.mmap_len, 0,
                              sizeof(uint16_t), SIZE_MAX,
                              PARSE_KB | PARSE_KIB) < 0)
            usage(false);
        if (do_client(&args) < 0)
            goto done;
    } else
        usage(false);

    ret = 0;

 done:
    return ret;
}
