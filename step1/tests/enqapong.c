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

#undef _ZHPEQ_TEST_COMPAT_
#include <zhpeq.h>
#include <zhpeq_util.h>

#define BACKLOG         (10)
#ifdef DEBUG
#define TIMEOUT         (-1)
#else
#define TIMEOUT         (10000)
#endif
#define DEFAULT_EPOLL_THRESHOLD (200U)
#define DEFAULT_QLEN   (1023U)
#define DEFAULT_WARMUP  (100U)

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

enum {
    TX_NONE = 0,
    TX_WARMUP,
    TX_RUNNING,
    TX_LAST,
};

struct args {
    const char          *node;
    const char          *service;
    uint64_t            ops;
    uint64_t            warmup;
    uint64_t            rqlen;
    uint64_t            tqlen;
    uint64_t            epoll_threshold_usec;
    uint32_t            slice_mask;
    bool                once_mode;
    bool                points_mode;
    bool                seconds_mode;
};

struct enqa_msg {
    uint64_t            tx_start;
    uint64_t            pp_start;
    uint32_t            msg_seq;
    uint32_t            tx_seq;
    uint8_t             flag;
};

struct stuff {
    const struct args   *args;
    struct zhpeq_dom    *zqdom;
    struct zhpeq_tq     *ztq;
    struct zhpeq_rq     *zrq;
    uint64_t            *times;
    size_t              n_times;
    size_t              cur_times;
    int                 sock_fd;
    size_t              ops;
    size_t              warmup;
    uint32_t            msg_tx_seq;
    uint32_t            tx_seq;
    size_t              tx_oos_cnt;
    uint32_t            tx_oos_max;
    size_t              tx_retry;
    struct zhpeq_rx_seq rx_zseq;
    size_t              epoll_cnt;
    struct zhpeu_timing pp_lat;
    struct zhpeq_rq_epoll *zepoll;
    size_t              tx_avail;
    size_t              tx_max;
    size_t              rqlen;
    size_t              tqlen;
    void                *addr_cookie;
    uint32_t            dgcid;
    uint32_t            rspctxid;
    uint8_t             qd_last;
    bool                epoll;
};

static void conn_tx_stats_reset(struct stuff *conn)
{
    conn->tx_oos_cnt = 0;
    conn->tx_oos_max = 0;
    conn->tx_retry = 0;
}

static void conn_rx_stats_reset(struct stuff *conn)
{
    zhpeu_timing_reset(&conn->pp_lat);
    conn->rx_zseq.rx_oos_cnt = 0;
    conn->rx_zseq.rx_oos_max = 0;
    conn->epoll_cnt = 0;
}

static void conn_stats_print(struct stuff *conn)
{
    zhpeu_timing_print(&conn->pp_lat, "pp_lat", 2);
    zhpeu_print_info("%s:tx/tc/rx %u/%u/%u, tx_oos/max/retry %lu/%u/%lu"
                     " rx_oos/max %lu/%u epoll %lu\n",
                     zhpeu_appname, conn->ztq->cq_head, conn->ztq->cmd_queued,
                     conn->zrq->head,
                     conn->tx_oos_cnt, conn->tx_oos_max, conn->tx_retry,
                     conn->rx_zseq.rx_oos_cnt, conn->rx_zseq.rx_oos_max,
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
    free(stuff->times);

    FD_CLOSE(stuff->sock_fd);
}

static int conn_tx_msg(struct stuff *conn, uint64_t pp_start,
                       uint32_t msg_seq, uint8_t flag)
{
    int32_t             ret;
    struct zhpeq_tq     *ztq = conn->ztq;
    struct enqa_msg     *msg;
    union zhpe_hw_wq_entry *wqe;

    ret = zhpeq_tq_reserve(ztq);
    if (ret < 0) {
        if (ret != -EAGAIN)
            zhpeu_print_func_err(__func__, __LINE__, "zhpeq_tq_reserve", "",
                                 ret);
        goto done;
    }
    wqe = zhpeq_tq_get_wqe(ztq, ret);
    msg = (void *)zhpeq_tq_enqa(wqe, 0, conn->dgcid, conn->rspctxid);
    zhpeq_tq_set_context(ztq, ret, msg);
    msg->pp_start = pp_start;
    msg->msg_seq = msg_seq;
    msg->tx_seq = conn->tx_seq++;
    msg->flag = flag;
    zhpeq_tq_insert(ztq, ret);
    zhpeq_tq_commit(ztq);
    conn->tx_avail--;

 done:
    return ret;
}

#define _conn_tx_msg(...)                                       \
    zhpeu_call_neg_errorok(zhpeu_err, conn_tx_msg,  int, -EAGAIN, __VA_ARGS__)

static int conn_tx_completions(struct stuff *conn, bool qfull_ok, bool qd_check)
{
    ssize_t             ret = 0;
    struct zhpeq_tq     *ztq = conn->ztq;
    struct enqa_msg     *msg;
    struct enqa_msg     msg_copy;
    int32_t             oos;
    struct zhpe_cq_entry *cqe;
    struct zhpe_cq_entry cqe_copy;

    while ((cqe = zhpeq_tq_cq_entry(ztq))) {
        conn->tx_avail++;
        msg = zhpeq_tq_cq_context(ztq, cqe);
        /* unlikely() to optimize the no-error case. */
        if (unlikely(cqe->hdr.status != ZHPE_HW_CQ_STATUS_SUCCESS)) {
            cqe_copy = *cqe;
            msg_copy = *msg;
            zhpeq_tq_cq_entry_done(ztq, cqe);
            ret = -EIO;
            if (cqe_copy.hdr.status != ZHPE_HW_CQ_STATUS_GENZ_RDM_QUEUE_FULL) {
                zhpeu_print_err("%s,%u:cqe %p ctx %p index 0x%x status 0x%x\n",
                                __func__, __LINE__, cqe, msg,
                                cqe_copy.hdr.index, cqe_copy.hdr.status);
            } else if (!qfull_ok) {
                /*
                 * Retry: given that we're single threaded and we just
                 * freed a tx slot, EAGAIN should not be possible.
                 */
                conn->tx_retry++;
                ret = _conn_tx_msg(conn, msg_copy.pp_start, msg_copy.msg_seq,
                                   msg_copy.flag);
            }
            goto done;
        }
        oos = wrap32sub(msg->tx_seq, ztq->cq_head);
        zhpeq_tq_cq_entry_done(ztq, cqe);
        if (unlikely(oos)) {
            conn->tx_oos_cnt++;
            conn->tx_oos_max = max(conn->tx_oos_max, (uint32_t)abs(oos));
        }
    }

 done:
    return ret;
}

#define _conn_tx_completions(...)                               \
    zhpeu_call_neg(zhpeu_err, conn_tx_completions,  int, __VA_ARGS__)

static ssize_t conn_tx_completions_wait(struct stuff *conn, bool qfull_ok,
                                       bool qd_check)
{
    int                 ret = 0;

    while (conn->tx_avail != conn->tx_max && !ret)
        ret = conn_tx_completions(conn, qfull_ok, qd_check);

    return ret;
}

#define _conn_tx_completions_wait(...)                          \
    zhpeu_call_neg(zhpeu_err, conn_tx_completions_wait, int,  __VA_ARGS__)

static struct zhpeq_rx_oos *rx_oos_alloc(struct zhpeq_rx_seq *zseq)
{
    return malloc(sizeof(*zseq->rx_oos_list));
}

static void rx_oos_free(struct zhpeq_rx_seq *zseq, struct zhpeq_rx_oos *rx_oos)
{
    free(rx_oos);
}

static_assert(sizeof(struct enqa_msg) <= sizeof(struct zhpe_enqa_payload),
              "enqa_msg");

static void rx_oos_msg_handler(void *vdata, struct zhpe_rdm_entry *rqe)
{
    struct enqa_msg *msg_out = vdata;

    memcpy(msg_out, (void *)&rqe->payload, sizeof(*msg_out));
}

static int conn_rx_msg(struct stuff *conn, struct enqa_msg *msg_out,
                       bool wait_ok)
{
    int                 ret = 0;
    struct zhpeq_rq     *zrq = conn->zrq;
    struct zhpe_rdm_entry *rqe;
    struct enqa_msg     *msg;
    uint32_t            msg_seq;
    uint64_t            now;

    for (;;) {
        /* Check for available oos packets. */
        if (unlikely(conn->rx_zseq.rx_oos_list)) {
            if (zhpeq_rx_oos_spill(&conn->rx_zseq, 1,
                                   rx_oos_msg_handler, msg_out)) {
                ret = 1;
                break;
            }
        }
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
            msg = (void *)&rqe->payload;
            msg_seq = be32toh(msg->msg_seq);
            if (likely(msg_seq == conn->rx_zseq.seq)) {
                zhpeq_rx_oos_log(__func__, __LINE__, msg_seq, 0, 0, 0, 0);
                *msg_out = *msg;
                conn->rx_zseq.seq++;
                ret = 1;
            } else
                ret = zhpeq_rx_oos_insert(&conn->rx_zseq, rqe, msg_seq);
            zhpeq_rq_entry_done(zrq, rqe);
            zhpeq_rq_head_update(zrq, 0);
            if (ret)
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

static int do_server_pong(struct stuff *conn)
{
    int                 ret = 0;
    uint                tx_flag_in = TX_NONE;
    uint64_t            op_count;
    uint64_t            warmup_count;
    struct enqa_msg     msg;

    zhpeq_print_tq_info(conn->ztq);

    /* Ping-pong test. Handshake before beginning. */
    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Server only sends as many times as it receives. */
    conn_tx_stats_reset(conn);
    conn_rx_stats_reset(conn);
    for (op_count = warmup_count = 0; tx_flag_in != TX_LAST; op_count++) {
        /*
         * Receive a packet, send a packet: we are guaranteed the messages are
         * in sequence; we send an immediate reply to so we don't have to
         * buffer the messages to be able to reflect the pp_start and flag
         * to the client.
         */
        ret = _conn_tx_completions(conn, false, false);
        if (ret < 0)
            break;
        for (;;) {
            ret = _conn_rx_msg(conn, &msg, false);
            if (unlikely(ret < 0))
                goto done;
            if (ret > 0)
                break;
        }
        if (unlikely(msg.flag != tx_flag_in)) {
            if (tx_flag_in == TX_WARMUP)
                warmup_count = op_count;
            tx_flag_in = msg.flag;
        }

        ret = _conn_tx_msg(conn, msg.pp_start, htobe32(conn->msg_tx_seq++),
                           msg.flag);
        if (ret < 0)
            goto done;
    }

    /* Wait for all transmits to complete. */
    ret = _conn_tx_completions_wait(conn, false, false);
    if (ret < 0)
        goto done;

    zhpeu_print_info("%s:op_cnt/warmup %lu/%lu\n",
                     zhpeu_appname, op_count - warmup_count, warmup_count);
    conn_stats_print(conn);

 done:
    return ret;
}

static int do_client_pong(struct stuff *conn)
{
    int                 ret = 0;
    const struct args   *args = conn->args;
    uint                tx_flag_in = TX_NONE;
    uint                tx_flag_out = TX_WARMUP;
    uint64_t            rx_avail = min(conn->tx_max, conn->rqlen);
    uint64_t            tx_count;
    uint64_t            rx_count;
    uint64_t            warmup_count;
    struct enqa_msg     msg;
    uint64_t            start;
    uint64_t            now;
    uint64_t            delta;
    struct timespec     ts_beg;
    struct timespec     ts_end;
    size_t              i;

    zhpeq_print_tq_info(conn->ztq);

    /* Synchronize conn->tx_seq and ztq->cq_head. */
    conn->tx_seq = conn->ztq->cq_head;

    /* Ping-pong test. Handshake before beginning. */
    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /*
     * Client tracks notional numbers of receives available and
     * doesn't overrun the server.
     */
    conn_tx_stats_reset(conn);
    conn_rx_stats_reset(conn);
    /* Warmp the clock path */
    clock_gettime_monotonic(&ts_beg);
    start = get_cycles(NULL);
    for (tx_count = rx_count = warmup_count = 0;
         tx_count != rx_count || tx_flag_out != TX_LAST; ) {
        /* Receive packets up to first miss. */
        for (;tx_flag_in != TX_LAST; rx_count++) {
            ret = _conn_rx_msg(conn, &msg, false);
            if (unlikely(ret < 0))
                goto done;
            if (!ret)
                break;
            /* Messages are in sequence. */
            rx_avail++;
            delta = get_cycles(NULL) - be64toh(msg.pp_start);
            conn->times[conn->cur_times++] = delta;
            zhpeu_timing_update(&conn->pp_lat, delta);
            if (unlikely(msg.flag != tx_flag_in)) {
                if (tx_flag_in == TX_WARMUP) {
                    conn->cur_times = 0;
                    warmup_count = rx_count;
                    conn_tx_stats_reset(conn);
                    conn_rx_stats_reset(conn);
                    clock_gettime_monotonic(&ts_beg);
                }
                tx_flag_in = msg.flag;
            }
        }

        ret = _conn_tx_completions(conn, false, false);
        if (ret < 0)
            goto done;

        /* Send all available buffers. */
        for (; rx_avail > 0 && tx_flag_out != TX_LAST; tx_count++, rx_avail--) {

            now = get_cycles(NULL);
            /* Compute delta based on cycles/ops. */
            if (args->seconds_mode)
                delta = now - start;
            else
                delta = tx_count;

            /* Handle switching between warmup/running/last. */
            switch (tx_flag_out) {

            case TX_WARMUP:
                if (likely(delta < conn->warmup - 1))
                    break;
                /* Need to send this one packet early. */
                tx_flag_out = TX_RUNNING;
                conn_tx_stats_reset(conn);
                /* FALLTHROUGH */

            case TX_RUNNING:
                if  (likely(delta < conn->ops - 1))
                     break;
                tx_flag_out = TX_LAST;
                break;

            default:
                zhpeu_print_err("%s,%u:Unexpected state %d\n",
                                __func__, __LINE__, tx_flag_out);
                ret = -EINVAL;
                goto done;
            }

            ret = _conn_tx_msg(conn, htobe64(now), htobe32(conn->msg_tx_seq),
                               tx_flag_out);
            if (ret < 0) {
                if (ret == -EAGAIN) {
                    if (tx_flag_out == TX_LAST)
                        tx_flag_out = TX_RUNNING;
                    break;
                }
                goto done;
            }
            conn->msg_tx_seq++;
        }
    }
    clock_gettime_monotonic(&ts_end);

    zhpeu_print_info("%s:op_cnt/warmup %lu/%lu lat %.3f\n",
                     zhpeu_appname, tx_count - warmup_count, warmup_count,
                     (((double)ts_delta(&ts_beg, &ts_end) * USEC_PER_SEC) /
                      ((double)NSEC_PER_SEC * (tx_count - warmup_count) * 2)));
    conn_stats_print(conn);
    if (args->points_mode) {
        for (i = 0; i < conn->cur_times; i++)
            printf("%.3f\n", cycles_to_usec(conn->times[i], 2));
    }

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
    conn->tqlen = args->tqlen;
    if (conn->tqlen) {
        if (conn->tqlen > zhpeq_attr.z.max_tx_qlen)
            goto done;
    } else
        conn->tqlen = DEFAULT_QLEN;

    conn->rqlen = args->rqlen;
    if (conn->rqlen) {
        if (conn->rqlen > zhpeq_attr.z.max_rx_qlen)
            goto done;
    } else
        conn->rqlen = DEFAULT_QLEN;

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
        .rx_zseq.alloc  = rx_oos_alloc,
        .rx_zseq.free   = rx_oos_free,
    };
    struct cli_wire_msg cli_msg;

    /* Receive parameters from client. */
    ret = _zhpeu_sock_recv_fixed_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    args->epoll_threshold_usec = be64toh(cli_msg.epoll_threshold_usec);
    args->rqlen = be64toh(cli_msg.rqlen);
    args->tqlen = be64toh(cli_msg.tqlen);
    args->slice_mask = ntohl(cli_msg.slice_mask);
    args->once_mode = cli_msg.once_mode;

    ret = do_q_setup(&conn);
    if (ret < 0)
        goto done;

    /* Run test. */
    ret = do_server_pong(&conn);
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
        .ops       = args->ops,
        .rx_zseq.alloc  = rx_oos_alloc,
        .rx_zseq.free   = rx_oos_free,
    };
    struct cli_wire_msg cli_msg;

    ret = _zhpeu_sock_connect(args->node, args->service);
    if (ret < 0)
        goto done;
    conn.sock_fd = ret;

    /* Send arguments to the server. */
    cli_msg.epoll_threshold_usec = htobe64(args->epoll_threshold_usec);
    cli_msg.rqlen = htobe64(args->rqlen);
    cli_msg.tqlen = htobe64(args->tqlen);
    cli_msg.slice_mask = htonl(args->slice_mask);
    cli_msg.once_mode = args->once_mode;

    ret = _zhpeu_sock_send_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    conn.warmup = args->warmup;
    /* Compute warmup operations. */
    if (args->seconds_mode) {
        if (conn.warmup == UINT64_MAX)
            conn.warmup = 1;
        /*
         * If we exceeed 2 million round-trips per second, we have a
         * "success problem".
         */
        conn.n_times = max(conn.ops, conn.warmup) * 2000000;
        conn.ops += conn.warmup;
        conn.warmup *= get_tsc_freq();
        conn.ops *= get_tsc_freq();
    } else {
        if (conn.warmup == UINT64_MAX) {
            conn.warmup = conn.ops / 10;
            if (conn.warmup < DEFAULT_WARMUP)
                conn.warmup = DEFAULT_WARMUP;
            conn.ops += conn.warmup;
        }
        conn.n_times = max(conn.ops, conn.warmup);
    }
    conn.times = calloc(conn.n_times, sizeof(*conn.times));
    if (!conn.times) {
        ret = -ENOMEM;
        goto done;
    }

    /* Build the queues before sending parameters to server. */
    ret = do_q_setup(&conn);
    if (ret < 0)
        goto done;

    /* Run test. */
    ret = do_client_pong(&conn);
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
        "Usage:%s [-oPs] [-e <epoll_threshold_usec> ] [-r <qlen>]\n"
        "    [-S <slice>] [-t <qlen] [-w <warmup_ops>]\n"
        "    <port> [<node> <op_count/seconds>]\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "Server requires just port; client requires all 3 arguments.\n"
        "Client only options:\n"
        " -e <epoll_threshold_usec> : usec before using epoll\n"
        " -o : run once and then server will exit\n"
        " -P : dump points\n"
        " -r <qlen> : rx queue length (default %u)\n"
        " -S <slice> : 0 - %u\n"
        " -s : treat the final argument as seconds\n"
        " -t <qlen> : tx queue length (default %u)\n"
        " -w <ops> : number of warmup operations\n",
        zhpeu_appname, DEFAULT_QLEN, (uint)ZHPE_MAX_SLICES - 1, DEFAULT_QLEN);

    if (help)
        zhpeq_print_tq_info(NULL);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = {
        .warmup         = UINT64_MAX,
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

    while ((opt = getopt(argc, argv, "e:oPr:S:st:w:")) != -1) {

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

        case 'P':
            if (args.points_mode)
                usage(false);
            args.points_mode = true;
            break;

        case 'r':
            if (args.rqlen)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("rlen", optarg, &args.rqlen, 0, 1,
                                         zhpeq_attr.z.max_rx_qlen,
                                         PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        case 'S':
            if (args.slice_mask != 0)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("slice", optarg, &v64, 0,
                                         0, ZHPE_MAX_SLICES - 1, 0) < 0)
                usage(false);
            args.slice_mask = (1U << v64) | SLICE_DEMAND;
            break;

        case 's':
            if (args.seconds_mode)
                usage(false);
            args.seconds_mode = true;
            break;

        case 't':
            if (args.tqlen)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("tqlen", optarg, &args.tqlen, 0, 1,
                                         zhpeq_attr.z.max_tx_qlen,
                                         PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        case 'w':
            if (args.warmup != UINT64_MAX)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("warmup", optarg, &args.warmup, 0, 0,
                                         UINT64_MAX - 1,
                                         PARSE_KB | PARSE_KIB) < 0)
                usage(false);
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
    } else if (opt == 3) {
        args.service = argv[optind++];
        args.node = argv[optind++];
        if (_zhpeu_parse_kb_uint64_t(
                (args.seconds_mode ? "seconds" : "op_counts"),
                argv[optind++], &args.ops, 0, 1,
                (args.seconds_mode ? 1000000 : UINT64_MAX),
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
