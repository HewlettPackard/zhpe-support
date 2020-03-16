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

#define get_cyc(...)    get_cycles(__VA_ARGS__)

#define BACKLOG         (10)
#ifdef DEBUG
#define TIMEOUT         (-1)
#else
#define TIMEOUT         (10000)
#endif
#define DEFAULT_EPOLL_THRESHOLD (200U)
#define DEFAULT_QLEN    (1023U)
#define DEFAULT_WARMUP  (100U)
#define DEFAULT_EPOLL   (100U)

static struct zhpeq_attr zhpeq_attr;

struct cli_wire_msg {
    uint64_t            epoll_threshold_usec;
    uint64_t            rqlen;
    uint64_t            tqlen;
    bool                once_mode;
    bool                pp_only;
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
    uint64_t            ring_ops;
    uint64_t            warmup;
    uint64_t            rqlen;
    uint64_t            tqlen;
    uint64_t            epoll_threshold_usec;
    bool                once_mode;
    bool                pp_only;
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
    void                (*free)(void *ptr);
    const struct args   *args;
    struct zhpeq_dom    *zqdom;
    struct zhpeq_tq     *ztq;
    struct zhpeq_rq     *zrq;
    int                 sock_fd;
    size_t              ring_ops;
    size_t              ring_warmup;
    uint32_t            msg_tx_seq;
    uint32_t            tx_seq;
    size_t              tx_oos_cnt;
    uint32_t            tx_oos_max;
    size_t              tx_retry;
    struct zhpeq_rx_seq rx_zseq;
    size_t              epoll_cnt;
    struct zhpeu_timing tx_lat;
    struct zhpeu_timing tx_cmp;
    struct zhpeu_timing rx_lat;
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
    zhpeu_timing_reset(&conn->tx_lat);
    zhpeu_timing_reset(&conn->tx_cmp);
    conn->tx_oos_cnt = 0;
    conn->tx_oos_max = 0;
    conn->tx_retry = 0;
}

static void conn_rx_stats_reset(struct stuff *conn)
{
    zhpeu_timing_reset(&conn->rx_lat);
    zhpeu_timing_reset(&conn->pp_lat);
    conn->rx_zseq.rx_oos_cnt = 0;
    conn->rx_zseq.rx_oos_max = 0;
    conn->epoll_cnt = 0;
}

static void conn_stats_print(struct stuff *conn)
{
    zhpeu_timing_print(&conn->pp_lat, "pp_lat", 2);
    zhpeu_timing_print(&conn->tx_lat, "tx_lat", 1);
    zhpeu_timing_print(&conn->tx_cmp, "tx_cmp", 1);
    zhpeu_timing_print(&conn->rx_lat, "rx_lat", 1);
    zhpeu_print_info("%s:tx/rx %u/%u, tx_oos/max/retry %lu/%u/%lu"
                     " rx_oos/max %lu/%u epoll %lu\n",
                     zhpeu_appname, conn->ztq->cq_head, conn->zrq->head,
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

    FD_CLOSE(stuff->sock_fd);
}

static int conn_tx_msg(struct stuff *conn, uint64_t pp_start,
                       uint32_t msg_seq, uint8_t flag)
{
    int32_t             ret;
    struct zhpeq_tq     *ztq = conn->ztq;
    uint64_t            start = get_cyc(NULL);
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
    msg->tx_start = htobe64(start);
    if (!pp_start)
        pp_start = msg->tx_start;
    msg->pp_start = pp_start;
    msg->msg_seq = msg_seq;
    msg->tx_seq = conn->tx_seq++;
    msg->flag = flag;
    zhpeq_tq_insert(ztq, ret);
    zhpeq_tq_commit(ztq);
    conn->tx_avail--;
    zhpeu_timing_update(&conn->tx_lat, get_cyc(NULL) - start);

 done:
    return ret;
}

#define _conn_tx_msg(...)                                       \
    zhpeu_call_neg_errorok(zhpeu_err, conn_tx_msg,  int, -EAGAIN, __VA_ARGS__)

static int conn_tx_completions(struct stuff *conn, bool qfull_ok,
                               bool qd_check);

#define _conn_tx_completions(...)                               \
    zhpeu_call_neg(zhpeu_err, conn_tx_completions,  int, __VA_ARGS__)

static int conn_tx_msg_retry(struct stuff *conn, uint64_t pp_start,
                             uint32_t msg_seq, uint8_t flag)
{
    int                 ret;

    for (;;) {
        ret = _conn_tx_msg(conn, pp_start, msg_seq, flag);
        if (ret >= 0 || ret != -EAGAIN)
            break;
        ret = _conn_tx_completions(conn, false, false);
        if (ret < 0)
            break;
    }

    return ret;
}

#define _conn_tx_msg_retry(...)                                 \
    zhpeu_call_neg(zhpeu_err, conn_tx_msg_retry,  int, __VA_ARGS__)

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
        if (unlikely(cqe->status != ZHPE_HW_CQ_STATUS_SUCCESS)) {
            cqe_copy = *cqe;
            msg_copy = *msg;
            zhpeq_tq_cq_entry_done(ztq, cqe);
            ret = -EIO;
            if (cqe_copy.status != ZHPE_HW_CQ_STATUS_GENZ_RDM_QUEUE_FULL) {
                zhpeu_print_err("%s,%u:cqe %p ctx %p index 0x%x status 0x%x\n",
                                __func__, __LINE__, cqe, msg,
                                cqe_copy.index, cqe_copy.status);
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
        zhpeu_timing_update(&conn->tx_cmp,
                            get_cyc(NULL) - be64toh(msg->tx_start));
        oos = (int32_t)(msg->tx_seq - ztq->cq_head);
        zhpeq_tq_cq_entry_done(ztq, cqe);
        if (unlikely(oos)) {
            conn->tx_oos_cnt++;
            conn->tx_oos_max = max(conn->tx_oos_max, (uint32_t)abs(oos));
        }
    }

 done:
    return ret;
}

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

static void cycles_delay(uint64_t start_cyc, uint64_t delay_cyc)
{
    while (get_cycles(NULL) - start_cyc < delay_cyc)
        yield();

}

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

static void rx_oos_msg_handler(void *vdata, struct zhpe_enqa_payload *pay)
{
    struct enqa_msg *msg_out = vdata;

    memcpy(msg_out, pay, sizeof(*msg_out));
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
                ret = zhpeq_rx_oos_insert(&conn->rx_zseq, msg, msg_seq);
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

static int do_server_tests(struct stuff *conn)
{
    int                 ret;
    uint64_t            i;
    struct enqa_msg     msg;

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
    conn_rx_stats_reset(conn);
    for (i = 0; i < conn->rqlen; i++) {
        ret = _conn_rx_msg(conn, &msg, false);
        if (ret < 0)
            goto done;
        if (!ret)
            continue;
    }

    conn_stats_print(conn);

    /* Second, an epoll test. Server rate limits to force epoll. */
    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    /* Receive all pending entries. */
    conn_rx_stats_reset(conn);
    for (i = 0; i < DEFAULT_EPOLL; i++) {
        ret = _conn_rx_msg(conn, &msg, true);
        if (ret < 0)
            goto done;
        assert(ret == 1);
    }

    conn_stats_print(conn);

    ret = _zhpeu_sock_recv_fixed_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

 done:
    return ret;
}

static int do_server_pong(struct stuff *conn)
{
    int                 ret = 0;
    const struct args   *args = conn->args;
    uint                tx_flag_in = TX_NONE;
    uint64_t            op_count;
    uint64_t            warmup_count;
    struct enqa_msg     msg;

    zhpeq_print_tq_info(conn->ztq);

    /* Tests for QD, overflow, and epoll. */
    if (!args->pp_only) {
        ret = do_server_tests(conn);
        if (ret < 0)
            goto done;
    }

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
        for (;;) {
            ret = _conn_rx_msg(conn, &msg, false);
            if (unlikely(ret < 0))
                goto done;
            if (ret > 0)
                break;
        }
        if (msg.flag != tx_flag_in) {
            if (tx_flag_in == TX_WARMUP) {
                warmup_count = op_count;
                conn_tx_stats_reset(conn);
                conn_rx_stats_reset(conn);
            }
            tx_flag_in = msg.flag;
        }
        zhpeu_timing_update(&conn->rx_lat,
                            get_cyc(NULL) - be64toh(msg.tx_start));

        ret = _conn_tx_msg_retry(conn, msg.pp_start,
                                 htobe32(conn->msg_tx_seq++),  msg.flag);
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

static void do_pci_rd(struct stuff *conn, uint ops)
{
    struct zhpeq_rq     *zrq = conn->zrq;
    uint                i;
    struct zhpeu_timing pci_rd;
    uint64_t            start MAYBE_UNUSED;

    zhpeu_timing_reset(&pci_rd);
    for (i = 0; i < ops; i++) {
        start = get_cyc(NULL);
        qcmread64(zrq->qcm, ZHPE_RDM_QCM_RCV_QUEUE_HEAD_OFFSET);
        zhpeu_timing_update(&pci_rd, get_cyc(NULL) - start);
    }
    zhpeu_timing_print(&pci_rd, "pci_rd", 1);
}

static int do_nop(struct stuff *conn, uint ops)
{
    int                 ret;
    struct zhpeq_tq     *ztq = conn->ztq;
    struct zhpe_cq_entry *cqe;
    uint                i;
    uint64_t            start MAYBE_UNUSED;
    union zhpe_hw_wq_entry *wqe;

    conn_tx_stats_reset(conn);
    for (i = 0; i < ops; i++) {
        ret = zhpeq_tq_reserve(ztq);
        if (ret < 0) {
            if (ret != -EAGAIN)
                zhpeu_print_func_err(__func__, __LINE__, "zhpeq_tq_reserve", "",
                                     ret);
            goto done;
        }
        wqe = zhpeq_tq_get_wqe(ztq, ret);
        zhpeq_tq_nop(wqe, 0);
        start = get_cyc(NULL);
        zhpeq_tq_insert(ztq, ret);
        zhpeq_tq_commit(ztq);
        while (!(cqe = zhpeq_tq_cq_entry(ztq)));
        zhpeu_timing_update(&conn->tx_cmp, get_cyc(NULL) - start);
        zhpeq_tq_cq_entry_done(ztq, cqe);
    }
    conn_stats_print(conn);

 done:
    return ret;
}

static int do_client_tests(struct stuff *conn)
{
    int                 ret;
    uint64_t            i;
    uint64_t            start;

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

    conn_tx_stats_reset(conn);
    for (i = 0; i < conn->rqlen; i++) {
        ret = _conn_tx_msg_retry(conn, 0, htobe32(conn->msg_tx_seq++), 0);
        if (ret < 0)
            goto done;
        ret = _conn_tx_completions_wait(conn, false, true);
        if (ret < 0)
            goto done;
    }
    /* No sequence because it is expected to fail. */
    ret = _conn_tx_msg_retry(conn, 0, 0, 0);
    if (ret < 0)
        goto done;
    ret = conn_tx_completions_wait(conn, true, true);
    assert(ret == -EIO);

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

    conn_tx_stats_reset(conn);
    for (i = 0; i < DEFAULT_EPOLL; i++) {
        start = get_cycles(NULL);
        ret = _conn_tx_msg_retry(conn, 0, htobe32(conn->msg_tx_seq++), 0);
        if (ret < 0)
            goto done;
        ret = _conn_tx_completions_wait(conn, false, false);
        if (ret < 0)
            goto done;
        cycles_delay(start, conn->zrq->epoll_threshold_cycles * 2);
    }

    conn_stats_print(conn);

    ret = _zhpeu_sock_send_blob(conn->sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

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
    uint64_t            now MAYBE_UNUSED;
    uint64_t            delta;
    struct timespec     ts_beg;
    struct timespec     ts_end;

    zhpeq_print_tq_info(conn->ztq);

    /* Measure PCI register read time. */
    do_pci_rd(conn, 5);
    /* Do nops to measure completion write time. */
    ret = do_nop(conn, 5);
    if (ret < 0)
        goto done;
    /* Synchronize conn->tx_seq and ztq->cq_head. */
    conn->tx_seq = conn->ztq->cq_head;

    /* Tests for QD, overflow, and epoll. */
    if (!args->pp_only) {
        ret = do_client_tests(conn);
        if (ret < 0)
            goto done;
    }

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
    start = get_cyc(NULL);
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
            if (msg.flag != tx_flag_in) {
                if (tx_flag_in == TX_WARMUP) {
                    warmup_count = rx_count;
                    conn_tx_stats_reset(conn);
                    conn_rx_stats_reset(conn);
                    clock_gettime_monotonic(&ts_beg);
                }
                tx_flag_in = msg.flag;
            }
            now = get_cyc(NULL);
            zhpeu_timing_update(&conn->rx_lat, now - be64toh(msg.tx_start));
            zhpeu_timing_update(&conn->pp_lat, now - be64toh(msg.pp_start));
        }

        ret = _conn_tx_completions(conn, false, false);
        if (ret < 0)
            goto done;

        /* Send all available buffers. */
        for (; rx_avail > 0 && tx_flag_out != TX_LAST; tx_count++, rx_avail--) {

            /* Compute delta based on cycles/ops. */
            if (args->seconds_mode)
                delta = get_cyc(NULL) - start;
            else
                delta = tx_count;

            /* Handle switching between warmup/running/last. */
            switch (tx_flag_out) {

            case TX_WARMUP:
                if (delta < conn->ring_warmup)
                    break;
                tx_flag_out = TX_RUNNING;
                conn_tx_stats_reset(conn);
                /* FALLTHROUGH */

            case TX_RUNNING:
                if  (delta >= conn->ring_ops - 1)
                    tx_flag_out = TX_LAST;
                break;

            default:
                zhpeu_print_err("%s,%u:Unexpected state %d\n",
                                __func__, __LINE__, tx_flag_out);
                ret = -EINVAL;
                goto done;
            }

            ret = _conn_tx_msg(conn, 0, htobe32(conn->msg_tx_seq), tx_flag_out);
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

 done:
    return ret;
}

struct q_wire_msg {
    /* Actual queue lengths. */
    uint64_t            rqlen;
    uint64_t            tqlen;
};

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
                         0, 0, 0,  &conn->ztq);
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

    ret = zhpeq_rq_alloc(conn->zqdom, conn->rqlen, 0, &conn->zrq);
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
    args->once_mode = cli_msg.once_mode;
    args->pp_only = cli_msg.pp_only;

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
        .ring_ops       = args->ring_ops,
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
    cli_msg.once_mode = args->once_mode;
    cli_msg.pp_only = args->pp_only;

    ret = _zhpeu_sock_send_blob(conn.sock_fd, &cli_msg, sizeof(cli_msg));
    if (ret < 0)
        goto done;

    conn.ring_warmup = args->warmup;
    /* Compute warmup operations. */
    if (args->seconds_mode) {
        if (conn.ring_warmup == SIZE_MAX)
            conn.ring_warmup = 1;
        conn.ring_ops += conn.ring_warmup;
        conn.ring_warmup *= get_tsc_freq();
        conn.ring_ops *= get_tsc_freq();
    } else if (conn.ring_warmup == SIZE_MAX) {
        conn.ring_warmup = conn.ring_ops / 10;
        if (conn.ring_warmup < DEFAULT_WARMUP)
            conn.ring_warmup = DEFAULT_WARMUP;
        conn.ring_ops += conn.ring_warmup;
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
        "Usage:%s [-os] -e <epoll_threshold_usec> ] [-q <qlen>]\n"
        "    [-w <warmup_ops>] <port> [<node> <op_count/seconds>]\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "Server requires just port; client requires all 3 arguments.\n"
        "Client only options:\n"
        " -e <epoll_threshold_usec> : usec before using epoll\n"
        " -o : run once and then server will exit\n"
        " -P : ping-pong test only\n"
        " -r <qlen> : rx queue length (default %u)\n"
        " -s : treat the final argument as seconds\n"
        " -t <qlen> : tx queue length (default %u)\n"
        " -w <ops> : number of warmup operations\n",
        zhpeu_appname, DEFAULT_QLEN, DEFAULT_QLEN);

    if (help)
        zhpeq_print_tq_info(NULL);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct args         args = {
        .warmup         = SIZE_MAX,
    };
    bool                client_opt = false;
    int                 opt;
    int                 rc;

    zhpeu_util_init(argv[0], LOG_INFO, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
    if (rc < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "e:oPr:st:w:")) != -1) {

        /* All opts are client only, now. */
        client_opt = true;

        switch (opt) {

        case 'e':
            if (args.epoll_threshold_usec)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("epoll_threshold_usec", optarg,
                                         &args.epoll_threshold_usec,
                                         0, 1, SIZE_MAX,
                                         PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        case 'o':
            if (args.once_mode)
                usage(false);
            args.once_mode = true;
            break;

        case 'P':
            if (args.pp_only)
                usage(false);
            args.pp_only = true;
            break;

        case 'r':
            if (args.rqlen)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("rlen", optarg, &args.rqlen, 0, 1,
                                         zhpeq_attr.z.max_rx_qlen,
                                         PARSE_KB | PARSE_KIB) < 0)
                usage(false);
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
            if (args.warmup != SIZE_MAX)
                usage(false);
            if (_zhpeu_parse_kb_uint64_t("warmup", optarg, &args.warmup, 0, 0,
                                         SIZE_MAX - 1,
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
                argv[optind++], &args.ring_ops, 0, 1,
                (args.seconds_mode ? 1000000 : SIZE_MAX),
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
