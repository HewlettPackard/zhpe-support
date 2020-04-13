/*
 * Copyright (C) 2020 Hewlett Packard Enterprise Development LP.
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

#undef _ZHPEQ_TEST_COMPAT_
#include <zhpeq.h>
#include <zhpeq_util.h>

static_assert(ZHPE_HW_CQ_STATUS_SUCCESS == 0, "SUCCESS");

#define BACKLOG         (10)
#ifdef DEBUG
#define TIMEOUT         (-1)
#else
#define TIMEOUT         (10000)
#endif
#define DEFAULT_EPOLL_THRESHOLD (200U)
#define DEFAULT_RQLEN   (2047U)
#define DEFAULT_TQLEN   (1023U)
#define DEFAULT_EPOLL   (100U)

static struct zhpeq_attr zhpeq_attr;

struct cli_wire_msg {
    uint64_t            epoll_threshold_usec;
    uint64_t            rqlen;
    uint64_t            tqlen;
    uint32_t            slice_mask;
    bool                once_mode;
};

struct q_wire_msg {
    /* Actual queue lengths. */
    uint64_t            rqlen;
    uint64_t            tqlen;
};

struct args {
    const char          *node;
    const char          *service;
    uint64_t            epoll_threshold_usec;
    uint32_t            slice_mask;
    bool                once_mode;
};

struct stuff {
    const struct args   *args;
    struct zhpeq_dom    *zqdom;
    struct zhpeq_tq     *ztq;
    struct zhpeq_rq     *zrq;
    const char          *lbl;
    int                 sock_fd;
    size_t              epoll_cnt;
    struct zhpeq_rq_epoll *zepoll;
    size_t              tx_avail;
    size_t              tx_max;
    size_t              rqlen;
    size_t              tqlen;
    void                *addr_cookie;
    uint32_t            dgcid;
    uint32_t            rspctxid;
    uint32_t            cq_count;
    uint8_t             qd_last;
    uint8_t             cq_last;
    bool                epoll;
};

static void conn_stats_print(struct stuff *conn)
{
    if (conn->cq_count)
        zhpeu_print_info("%s:%s:status 0x%x %u\n",
                         zhpeu_appname, conn->lbl, conn->cq_last,
                         conn->cq_count);
    conn->cq_last = 0;
    conn->cq_count = 0;

    zhpeu_print_info("%s:%s:tx/tc/rx %u/%u/%u epoll %lu\n",
                     zhpeu_appname, conn->lbl, conn->ztq->cq_head,
                     conn->ztq->cmd_queued, (conn->zrq ? conn->zrq->head : 0),
                     conn->epoll_cnt);
}

static void stuff_free(struct stuff *stuff)
{
    if (!stuff)
        return;

    zhpeq_rq_epoll_free(stuff->zepoll);
    zhpeq_domain_remove_addr(stuff->zqdom, stuff->addr_cookie);
    zhpeq_rq_free(stuff->zrq);
    zhpeq_tq_free(stuff->ztq);
    zhpeq_domain_free(stuff->zqdom);

    FD_CLOSE(stuff->sock_fd);
}

static int conn_tx_msg(struct stuff *conn)
{
    int32_t             ret;
    struct zhpeq_tq     *ztq = conn->ztq;
    union zhpe_hw_wq_entry *wqe;

    ret = zhpeq_tq_reserve(ztq);
    if (ret < 0) {
        if (ret != -EAGAIN)
            zhpeu_print_func_err(__func__, __LINE__, "zhpeq_tq_reserve", "",
                                 ret);
        goto done;
    }
    wqe = zhpeq_tq_get_wqe(ztq, ret);
    zhpeq_tq_enqa(wqe, 0, conn->dgcid, conn->rspctxid);
    zhpeq_tq_insert(ztq, ret);
    zhpeq_tq_commit(ztq);
    conn->tx_avail--;
    ret = 0;

 done:
    return ret;
}

#define _conn_tx_msg(...)                                       \
    zhpeu_call_neg_errorok(zhpeu_err, conn_tx_msg,  int, -EAGAIN, __VA_ARGS__)

static int conn_tx_completions(struct stuff *conn)
{
    ssize_t             ret = 0;
    struct zhpeq_tq     *ztq = conn->ztq;
    struct zhpe_cq_entry *cqe;

    if ((cqe = zhpeq_tq_cq_entry(ztq))) {
        conn->tx_avail++;
        /* unlikely() to optimize the no-error case. */
        if (unlikely(cqe->status != ZHPE_HW_CQ_STATUS_SUCCESS))
            ret = -EIO;
        if (unlikely(cqe->status != conn->cq_last)) {
            if (conn->cq_count)
                zhpeu_print_info("%s:%s:status 0x%x %u\n",
                                 zhpeu_appname, conn->lbl, conn->cq_last,
                                 conn->cq_count);
            conn->cq_last = cqe->status;
            conn->cq_count = 1;
        } else
            conn->cq_count++;
        if (unlikely(cqe->qd != conn->qd_last)) {
            conn->qd_last = cqe->qd;
            zhpeu_print_info("%s:%s:qd 0x%x\n",
                             zhpeu_appname, conn->lbl, conn->qd_last);
        }
        zhpeq_tq_cq_entry_done(ztq, cqe);
    }

    return ret;
}

#define _conn_tx_completions(...)                               \
    zhpeu_call_neg(zhpeu_err, conn_tx_completions,  int, __VA_ARGS__)

static ssize_t conn_tx_completions_wait(struct stuff *conn)
{
    int                 ret = 0;

    while (conn->tx_avail != conn->tx_max && !ret)
        ret = conn_tx_completions(conn);

    return ret;
}

#define _conn_tx_completions_wait(...)                          \
    zhpeu_call_neg(zhpeu_err, conn_tx_completions_wait, int,  __VA_ARGS__)

static uint64_t cycles_delay(uint64_t start_cyc, uint64_t delay_cyc)
{
    delay_cyc += start_cyc;
    for (;;) {
        start_cyc = get_cycles(NULL);
        if ((int64_t)(start_cyc - delay_cyc) >= 0)
            break;
        yield();
    }

    return start_cyc;
}

static int conn_rx_msg(struct stuff *conn, bool wait_ok)
{
    int                 ret = 0;
    struct zhpeq_rq     *zrq = conn->zrq;
    struct zhpe_rdm_entry *rqe;
    uint64_t            now;

    for (;;) {
        if (unlikely(conn->epoll)) {
            ret = zhpeq_rq_epoll(conn->zepoll, (wait_ok ? -1 : 0), NULL, true);
            if (ret < 0)
                break;
            if (!ret) {
                if (wait_ok)
                    continue;
                break;
            }
            assert(!conn->epoll);
        }
        if ((rqe = zhpeq_rq_entry(zrq))) {
            ret = 1;
            zhpeq_rq_entry_done(zrq, rqe);
            zhpeq_rq_head_update(zrq, 0);
            break;
        }
        /* Start epolling? */
        now = get_cycles_approx();
        if (zhpeq_rq_epoll_check(conn->zrq, now) &&
            zhpeq_rq_epoll_enable(conn->zrq)) {
            /* Yes. */
            conn->epoll = true;
            conn->epoll_cnt++;
        }
        if (!wait_ok) {
            ret = 0;
            break;
        }
    }

    return ret;
}

#define _conn_rx_msg(...)                                       \
    zhpeu_call_neg(zhpeu_err, conn_rx_msg,  int, __VA_ARGS__)

static int do_server_tests(struct stuff *conn)
{
    int                 ret;
    uint64_t            i;

    zhpeq_print_tq_info(conn->ztq);

    /*
     * First, the client will send conn->rqlen  + 1 messages to overrun the
     * receive queue. We will not read the receive queue until the server
     * handshakes over the socket.
     */
    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Receive all the pending entries. */
    conn->lbl = "qdov";
    for (i = 0; i < conn->rqlen; i++) {
        ret = _conn_rx_msg(conn, true);
        assert_always(ret == 1);
    }
    ret = _conn_rx_msg(conn, false);
    assert_always(ret == 0);

    conn_stats_print(conn);

    /* Second, an epoll test. Server rate limits to force epoll. */
    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Receive all pending entries. */
    conn->lbl = "epoll";
    for (i = 0; i < DEFAULT_EPOLL; i++) {
        ret = _conn_rx_msg(conn, true);
        assert_always(ret == 1);
    }

    conn_stats_print(conn);

    /* Third, a queue stop test: what errors are returned when rq stopped. */
    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Accept the first command buffers and then stop. */
    conn->lbl = "stop";
    ret = _conn_rx_msg(conn, true);
    assert_always(ret == 1);
    qcmwrite64(1, conn->zrq->qcm, ZHPE_RDM_QCM_STOP_OFFSET);

    conn_stats_print(conn);

    /* Fourth, a queue free test: what errors are returned when rq freed. */
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    qcmwrite64(0, conn->zrq->qcm, ZHPE_RDM_QCM_STOP_OFFSET);
    while (_conn_rx_msg(conn, false) > 0);

    zhpeq_rq_free(conn->zrq);
    conn->zrq = NULL;

    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    conn_stats_print(conn);

    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

 done:
    return ret;
}

static int do_client_tests(struct stuff *conn)
{
    int                 ret;
    struct zhpeq_tq     *ztq = conn->ztq;
    uint64_t            i;
    uint64_t            c;
    uint64_t            start;

    zhpeq_print_tq_info(ztq);

    /*
     * First, the client will send conn->rqlen + 1 messages and then
     * handshake across the socket until the server empties the RDM
     * queue.
     *
     * The final message should result in status 0x93 and the queue
     * should not be stopped if the bridge is properly configured.
     *
     * The client will wait for each send, so they should complete
     * on both sides in order. The QD bits should be appearing in the
     * XDM reponses as the RDM queue fills up, but this seems not to be
     * working.
     */
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    conn->lbl = "qdov";
    for (i = 0; i < conn->rqlen; i++) {
        ret = _conn_tx_msg(conn);
        assert_always(ret == 0);
        ret = _conn_tx_completions_wait(conn);
        assert_always(ret == 0);
    }
    /* Expected to fail. */
    ret = _conn_tx_msg(conn);
    assert_always(ret == 0);
    ret = conn_tx_completions_wait(conn);
    assert_always(ret == -EIO);
    ret = conn_tx_completions_wait(conn);
    assert_always(ret == 0);

    conn_stats_print(conn);

    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /*
     * Second, a test of polling behavor: the client will send 10000 messages
     * with a minimum delay of 2 * zrq->poll_threshold_cycles between them.
     * This should cause the should cause the server to use epoll for each
     * message.
     */
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    conn->lbl = "epoll";
    start = get_cycles(NULL);
    for (i = 0; i < DEFAULT_EPOLL; i++) {
        start = cycles_delay(start, conn->zrq->epoll_threshold_cycles * 2);
        ret = _conn_tx_msg(conn);
        assert_always(ret == 0);
        ret = _conn_tx_completions_wait(conn);
        assert_always(ret == 0);
    }

    conn_stats_print(conn);

    /* Third, a queue stop test: what errors are returned when rq stopped. */
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    conn->lbl = "stop";
    for (i = conn->tqlen ; i > 0; ) {
        c = min((uint64_t)ZHPE_XDM_QCM_CMD_BUF_COUNT, i);
        for (; c > 0; c--, i--) {
            ret = conn_tx_msg(conn);
            assert_always(ret == 0);
            (void)conn_tx_completions(conn);
        }
    }
    while ((ret = conn_tx_completions_wait(conn)) < 0);
    assert_always(ret == 0);

    conn_stats_print(conn);

    /* Fourth, a queue free test: what errors are returned when rq freed. */
    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    conn->lbl = "tear";
    for (i = conn->tqlen ; i > 0; ) {
        c = min((uint64_t)ZHPE_XDM_QCM_CMD_BUF_COUNT, i);
        for (; c > 0; c--, i--) {
            ret = conn_tx_msg(conn);
            assert_always(ret == 0);
            (void)conn_tx_completions(conn);
        }
    }
    while ((ret = conn_tx_completions_wait(conn)) < 0);
    assert_always(ret == 0);

    conn_stats_print(conn);

    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

 done:
    return ret;
}

static void zrq_epoll_handler(struct zhpeq_rq *zrq, void *vconn)
{
    struct stuff        *conn = vconn;

    conn->epoll = false;
}

static int do_q_setup(struct stuff *conn)
{
    int                 ret;
    const struct args   *args = conn->args;
    union sockaddr_in46 sa;
    size_t              sa_len = sizeof(sa);
    struct q_wire_msg   q_msg;

    ret = -EINVAL;
    conn->tqlen = DEFAULT_TQLEN;

    conn->rqlen = DEFAULT_RQLEN;

    /* Allocate domain. */
    ret = zhpeq_domain_alloc(&conn->zqdom);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", ret);
        goto done;
    }
    /* Allocate zqueues. */
    ret = zhpeq_tq_alloc(conn->zqdom, conn->tqlen, conn->tqlen,
                         0, 0, args->slice_mask,  &conn->ztq);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_tq_alloc", "", ret);
        goto done;
    }
    /*
     * conn->tqlen is the actual size of the tx queue; conn->tx_max is the
     * requested size of the tx queue. This will allow the user to
     * specify 16 and use only command buffers.
     */
    conn->tx_max = conn->tx_avail = conn->tqlen;
    conn->tqlen = conn->ztq->tqinfo.cmdq.ent - 1;

    ret = zhpeq_rq_alloc(conn->zqdom, conn->rqlen, args->slice_mask,
                         &conn->zrq);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_rq_alloc", "", ret);
        goto done;
    }
    conn->rqlen = conn->zrq->rqinfo.cmplq.ent - 1;
    if (!zhpeu_expected_saw("qlen1", conn->ztq->tqinfo.cmdq.ent,
                            conn->ztq->tqinfo.cmplq.ent)) {
        ret = -EIO;
        goto done;
    }
    ret = zhpeq_rq_epoll_alloc(&conn->zepoll);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_rq_epoll_alloc", "",
                             ret);
        goto done;
    }
    ret = zhpeq_rq_epoll_add(conn->zepoll, conn->zrq, zrq_epoll_handler, conn,
                             args->epoll_threshold_usec, false);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_rq_epoll_add", "", ret);
        goto done;
    }
    conn->epoll = true;

    /* Paranoia:exchange and compare queue lengths between client and server. */
    q_msg.rqlen = htobe64(conn->rqlen);
    q_msg.tqlen = htobe64(conn->tqlen);
    ret = _zhpeu_sock_send_blob(conn->sock_fd, &q_msg, sizeof(q_msg));
    if (ret < 0)
        goto done;
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, &q_msg, sizeof(q_msg));
    if (ret < 0)
        goto done;
    q_msg.rqlen = be64toh(q_msg.rqlen);
    q_msg.tqlen = be64toh(q_msg.tqlen);
    if (!zhpeu_expected_saw("qlen2", conn->rqlen, q_msg.rqlen) ||
        !zhpeu_expected_saw("qlen3", conn->rqlen, q_msg.rqlen)) {
        ret = -EIO;
        goto done;
    }

    /* Exchange addresses and insert the remote address in the domain. */
    ret = zhpeq_rq_xchg_addr(conn->zrq, conn->sock_fd, &sa, &sa_len);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_tq_xchg_addr", "", ret);
        goto done;
    }
    if (!zhpeu_expected_saw("sa_family", zhpeu_sockaddr_family(&sa), AF_ZHPE)) {
        ret = -EIO;
        goto done;
    }
    conn->dgcid = zhpeu_uuid_to_gcid(sa.zhpe.sz_uuid);
    conn->rspctxid = ntohl(sa.zhpe.sz_queue);
    ret = zhpeq_domain_insert_addr(conn->zqdom, &sa, &conn->addr_cookie);
    if (ret < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_domain_insert_addr",
                             "", ret);
        goto done;
    }

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

    /* Receive parameters from client. */
    ret = _zhpeu_sock_recv_fixed_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    args->epoll_threshold_usec = be64toh(cli_msg.epoll_threshold_usec);
    args->slice_mask = ntohl(cli_msg.slice_mask);
    args->once_mode = cli_msg.once_mode;

    ret = do_q_setup(&conn);
    if (ret < 0)
        goto done;

    /* Run tests. */
    ret = do_server_tests(&conn);
    if (ret < 0)
        goto done;

    /* Completion handshake. */
    ret = _zhpeu_sock_recv_fixed_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
    ret = _zhpeu_sock_send_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

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

    ret = _zhpeu_sock_getaddrinfo(NULL, args->service,
                                  AF_INET6, SOCK_STREAM, true, &resp);
    if (ret < 0)
        goto done;
    listener_fd = socket(resp->ai_family, resp->ai_socktype,
                         resp->ai_protocol);
    if (listener_fd == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "socket", "", ret);
        goto done;
    }
    if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR,
                   &oflags, sizeof(oflags)) == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "setsockopt", "", ret);
        goto done;
    }
    /* None of the usual: no polling; no threads; no cloexec; no nonblock. */
    if (bind(listener_fd, resp->ai_addr, resp->ai_addrlen) == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "bind", "", ret);
        goto done;
    }
    if (listen(listener_fd, BACKLOG) == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "listen", "", ret);
        goto done;
    }
    for (ret = 0; !ret;) {
        conn_fd = accept(listener_fd, NULL, NULL);
        if (conn_fd == -1) {
            ret = -errno;
            zhpeu_print_func_err(__func__, __LINE__, "accept", "", ret);
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
    struct cli_wire_msg cli_msg;

    ret = _zhpeu_sock_connect(args->node, args->service);
    if (ret < 0)
        goto done;
    conn.sock_fd = ret;

    /* Send arguments to the server. */
    cli_msg.epoll_threshold_usec = htobe64(args->epoll_threshold_usec);
    cli_msg.slice_mask = htonl(args->slice_mask);
    cli_msg.once_mode = args->once_mode;

    ret = _zhpeu_sock_send_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    /* Build the queues before sending parameters to server. */
    ret = do_q_setup(&conn);
    if (ret < 0)
        goto done;

    /* Run tests. */
    ret = do_client_tests(&conn);
    if (ret < 0)
        goto done;

    /* Completion handshake. */
    ret = _zhpeu_sock_send_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;
    ret = _zhpeu_sock_recv_fixed_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

 done:
    stuff_free(&conn);

    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    zhpeu_print_usage(
        help,
        "Usage:%s [-e <epoll_threshold_usec> ] [-S <slice>]\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "Server requires just port; client requires port and node.\n"
        "Client only options:\n"
        " -e <epoll_threshold_usec> : usec before using epoll\n"
        " -S <slice> : 0 - %u\n",
        zhpeu_appname, (uint)ZHPE_MAX_SLICES - 1);

    if (help)
        zhpeq_print_tq_info(NULL);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = {
        .slice_mask     = 0,
    };
    bool                client_opt = false;
    int                 opt;
    int                 rc;
    uint64_t            v64;

    zhpeu_util_init(argv[0], LOG_INFO, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
    if (rc < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "e:oS:")) != -1) {

        /* All opts are client only, now. */
        client_opt = true;

        switch (opt) {

        case 'e':
            if (args.epoll_threshold_usec)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("epoll_threshold_usec", optarg,
                                         &args.epoll_threshold_usec,
                                         0, 1, UINT64_MAX,
                                         PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        case 'o':
            if (args.once_mode)
                usage(false);
            args.once_mode = true;
            break;

        case 'S':
            if (args.slice_mask != 0)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("slice", optarg, &v64, 0,
                                         0, ZHPE_MAX_SLICES - 1, 0) < 0)
                usage(false);
            args.slice_mask = (1U << v64) | SLICE_DEMAND;
            break;

        default:
            usage(false);

        }
    }

    opt = argc - optind;

    if (!args.epoll_threshold_usec)
        args.epoll_threshold_usec = DEFAULT_EPOLL_THRESHOLD;

    if (opt == 1) {
        args.service = argv[optind++];
        if (client_opt)
            usage(false);
        if (do_server(&args) < 0)
            goto done;
    } else if (opt == 2) {
        args.service = argv[optind++];
        args.node = argv[optind++];
        if (do_client(&args) < 0)
            goto done;
    } else
        usage(false);

    ret = 0;

 done:
    return ret;
}
