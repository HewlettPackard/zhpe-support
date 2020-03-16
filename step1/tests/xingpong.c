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

#include <zhpeq.h>
#include <zhpeq_util.h>

#include <sys/queue.h>

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
#define ZQ_LEN          (1023)

struct cli_wire_msg {
    uint64_t            ring_entry_len;
    uint64_t            ring_entries;
    uint64_t            tx_avail;
    bool                aligned_mode;
    bool                copy_mode;
    bool                once_mode;
    bool                unidir_mode;
};

struct mem_wire_msg {
    uint64_t            zq_remote_rx_addr;
};

struct rx_queue {
    STAILQ_ENTRY(rx_queue) list;
    union {
        void            *buf;
        uint64_t        idx;
    };
};

enum {
    TX_NONE = 0,
    TX_WARMUP,
    TX_RUNNING,
    TX_LAST,
};

STAILQ_HEAD(rx_queue_head, rx_queue);

struct args {
    const char          *node;
    const char          *service;
    uint64_t            bufaddr;
    uint64_t            ring_entry_len;
    uint64_t            ring_entries;
    uint64_t            ring_ops;
    uint64_t            tx_avail;
    uint64_t            warmup;
    bool                aligned_mode;
    bool                copy_mode;
    bool                once_mode;
    bool                seconds_mode;
    bool                unidir_mode;
};

struct stuff {
    const struct args   *args;
    struct zhpeq_dom    *zdom;
    struct zhpeq        *zq;
    struct zhpeq_key_data *zq_local_kdata;
    struct zhpeq_key_data *zq_remote_kdata;
    uint64_t            zq_local_tx_zaddr;
    uint64_t            zq_remote_rx_zaddr;
    int                 sock_fd;
    void                *tx_addr;
    void                *rx_addr;
    uint64_t            *ring_timestamps;
    struct rx_queue     *rx_rcv;
    void                *rx_data;
    size_t              ring_entry_aligned;
    size_t              ring_ops;
    size_t              ring_warmup;
    size_t              ring_end_off;
    size_t              tx_avail;
    int                 open_idx;
    bool                allocated;
};

static inline uint64_t next_roff(struct stuff *conn, uint64_t cur)
{
    /* Reserve first entry for source on client. */
    cur += conn->ring_entry_aligned;
    if (cur >= conn->ring_end_off)
        cur = 0;

    return cur;
}

static void stuff_free(struct stuff *stuff)
{
    if (!stuff)
        return;

    if (stuff->zq) {
        zhpeq_qkdata_free(stuff->zq_remote_kdata);
        zhpeq_qkdata_free(stuff->zq_local_kdata);
    }
    if (stuff->open_idx != -1)
        zhpeq_backend_close(stuff->zq, stuff->open_idx);
    zhpeq_free(stuff->zq);
    zhpeq_domain_free(stuff->zdom);

    free(stuff->rx_rcv);
    free(stuff->ring_timestamps);
    if (stuff->tx_addr)
        munmap(stuff->tx_addr, stuff->ring_end_off * 2);

    FD_CLOSE(stuff->sock_fd);

    if (stuff->allocated)
        free(stuff);
}

static int do_mem_setup(struct stuff *conn)
{
    int                 ret = -EEXIST;
    const struct args   *args = conn->args;
    size_t              mask = L1_CACHELINE - 1;
    size_t              req;
    size_t              off;

    if (args->aligned_mode)
        conn->ring_entry_aligned = (args->ring_entry_len + mask) & ~mask;
    else
        conn->ring_entry_aligned = args->ring_entry_len;

    /* Size of an array of entries plus a tail index. */
    req = conn->ring_entry_aligned * args->ring_entries;
    off = conn->ring_end_off = req;
    req *= 2;
    conn->tx_addr = mmap((void *)(uintptr_t)args->bufaddr, req,
                         PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED,
                         -1 , 0);
    if (conn->tx_addr == MAP_FAILED) {
         conn->tx_addr = NULL;
         print_func_errn(__func__, __LINE__, "mmap", req, false, ret);
         goto done;
    }
    memset(conn->tx_addr, TX_NONE, req);
    conn->rx_addr = (char *)conn->tx_addr + off;

    ret = zhpeq_mr_reg(conn->zdom, conn->tx_addr, req,
                       (ZHPEQ_MR_GET | ZHPEQ_MR_PUT |
                        ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE),
                       &conn->zq_local_kdata);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_mr_reg", "", ret);
        goto done;
    }
    ret = zhpeq_lcl_key_access(conn->zq_local_kdata, conn->tx_addr,
                               req, 0, &conn->zq_local_tx_zaddr);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_lcl_key_access",
                       "", ret);
        goto done;
    }

    req = sizeof(*conn->ring_timestamps) * args->ring_entries;
    ret = -posix_memalign((void **)&conn->ring_timestamps, page_size, req);
    if (ret < 0) {
        conn->ring_timestamps = NULL;
        print_func_errn(__func__, __LINE__, "posix_memalign", true,
                        req, ret);
        goto done;
    }

    if (!args->copy_mode)
        goto done;

    req = sizeof(*conn->rx_rcv) * args->ring_entries + conn->ring_end_off;
    ret = -posix_memalign((void **)&conn->rx_rcv, page_size, req);
    if (ret < 0) {
        conn->rx_rcv = NULL;
        print_func_errn(__func__, __LINE__, "posix_memalign", true,
                        req, ret);
        goto done;
    }
    conn->rx_data = (void *)(conn->rx_rcv + args->ring_entries);

 done:
    return ret;
}

static int do_mem_xchg(struct stuff *conn)
{
    int                 ret;
    char                blob[ZHPEQ_KEY_BLOB_MAX];
    struct mem_wire_msg mem_msg;
    size_t              blob_len;

    blob_len = sizeof(blob);
    ret = zhpeq_qkdata_export(conn->zq_local_kdata, blob, &blob_len);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_qkdata_export", "", ret);
        goto done;
    }

    mem_msg.zq_remote_rx_addr = htobe64((uintptr_t)conn->rx_addr);

    ret = sock_send_blob(conn->sock_fd, &mem_msg, sizeof(mem_msg));
    if (ret < 0)
        goto done;
    ret = sock_send_blob(conn->sock_fd, blob, blob_len);
    if (ret < 0)
        goto done;
    ret = sock_recv_fixed_blob(conn->sock_fd, &mem_msg, sizeof(mem_msg));
    if (ret < 0)
        goto done;
    ret = sock_recv_fixed_blob(conn->sock_fd, blob, blob_len);
    if (ret < 0)
        goto done;

    mem_msg.zq_remote_rx_addr = be64toh(mem_msg.zq_remote_rx_addr);

    ret = zhpeq_qkdata_import(conn->zdom, conn->open_idx, blob, blob_len,
                              &conn->zq_remote_kdata);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_qkdata_import", "", ret);
        goto done;
    }
    ret = zhpeq_zmmu_reg(conn->zq_remote_kdata);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_zmmu_reg", "", ret);
        goto done;
    }

    ret = zhpeq_rem_key_access(conn->zq_remote_kdata,
                               mem_msg.zq_remote_rx_addr, conn->ring_end_off,
                               0, &conn->zq_remote_rx_zaddr);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_rem_key_access",
                       "", ret);
        goto done;
    }

 done:

    return ret;
}

static inline int zq_completions(struct zhpeq *zq)
{
    ssize_t             ret = 0;
    ssize_t             i;
    struct zhpeq_cq_entry zq_comp[TX_WINDOW];

    ret = zhpeq_cq_read(zq, zq_comp, ARRAY_SIZE(zq_comp));
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_cq_read", "", ret);
        goto done;
    }
    for (i = 0; i < ret; i++) {
        if (zq_comp[i].z.status != ZHPEQ_CQ_STATUS_SUCCESS) {
            print_err("%s,%u:I/O error\n", __func__, __LINE__);
            ret = -EIO;
            break;
        }
    }

 done:

    return ret;
}

static void random_rx_rcv(struct stuff *conn, struct rx_queue_head *rx_head)
{
    const struct args   *args = conn->args;
    struct rx_queue     *tp;
    struct rx_queue     *rp;
    struct rx_queue     *cp;
    uint64_t            t;
    uint64_t            r;

    /* Partition shuffle the list. */

    for (t = 0; t < args->ring_entries; t++) {
        tp = conn->rx_rcv + t;
        tp->idx = t;
    }

    for (t = args->ring_entries; t > 0; t--) {
        tp = conn->rx_rcv + t - 1;
        r = random() * t / ((uint64_t)RAND_MAX + 1);
        rp = conn->rx_rcv + r;

        cp = conn->rx_rcv + rp->idx;
        rp->idx = tp->idx;
        STAILQ_INSERT_TAIL(rx_head, cp, list);
    }

    /* Set buf to equivalent slot in rx_data. */
    t = 0;
    STAILQ_FOREACH(tp, rx_head, list) {
        tp->buf = ((char *)conn->rx_data +
                   (tp - conn->rx_rcv) * args->ring_entry_len);
        t++;
    }
    if (t != args->ring_entries) {
        print_err("list contains %lu/%lu entries\n",
                  t, args->ring_entries);
    }
}

static int zq_write(struct zhpeq *zq, bool fence, uint64_t lcl_zaddr,
                    size_t len, uint64_t rem_zaddr)
{
    int64_t             ret;
    uint32_t            zq_index;

    ret = zhpeq_reserve(zq, 1);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_reserve", "", ret);
        goto done;
    }
    zq_index = ret;
    ret = zhpeq_put(zq, zq_index, fence, lcl_zaddr, len, rem_zaddr, NULL);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_put", "", ret);
        goto done;
    }
    ret = zhpeq_commit(zq, zq_index, 1);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_commit", "", ret);
        goto done;
    }

 done:
    return ret;
}

static ssize_t do_progress(struct zhpeq *zq, size_t *tx_cmp)
{
    ssize_t             ret = 0;
    ssize_t             rc;

    rc = zq_completions(zq);
    if (ret >= 0) {
        if (tx_cmp)
            *tx_cmp += rc;
        else
            assert(!rc);
    } else
        ret = rc;

    return ret;
}

static int do_server_pong(struct stuff *conn)
{
    int                 ret = 0;
    const struct args   *args = conn->args;
    uint                tx_flag_in = TX_NONE;
    size_t              tx_avail = conn->tx_avail;
    size_t              tx_avail_shadow = 0;
    size_t              tx_off = 0;
    size_t              rx_off = 0;
    struct rx_queue_head rx_head = STAILQ_HEAD_INITIALIZER(rx_head);
    struct rx_queue     *rx_ptr;
    uint64_t            tx_count;
    uint64_t            rx_count;
    uint64_t            warmup_count;
    uint64_t            op_count;
    uint64_t            window;
    uint8_t             *tx_addr;
    volatile uint8_t    *rx_addr;
    uint8_t             tx_flag_new;
    uint64_t            zq_tx_addr;
    uint64_t            zq_rx_addr;

    /* Create a random receive list for copy mode */
    if (args->copy_mode)
        random_rx_rcv(conn, &rx_head);

    /* Server starts with no ring entries available to transmit. */

    for (tx_count = rx_count = warmup_count = 0;
         tx_count != rx_count || tx_flag_in != TX_LAST; ) {
        /* Receive packets up to window or first miss. */
        for (window = RX_WINDOW; window > 0 && tx_flag_in != TX_LAST;
             window--, rx_count++, rx_off = next_roff(conn, rx_off)) {
            tx_addr = (void *)((char *)conn->tx_addr + rx_off);
            rx_addr = (void *)((char *)conn->rx_addr + rx_off);
            if (!(tx_flag_new = *rx_addr))
                break;
            if (tx_flag_new != tx_flag_in) {
                if (tx_flag_in == TX_WARMUP)
                    warmup_count = rx_count;
                tx_flag_in = tx_flag_new;
            }
            *tx_addr = tx_flag_new;
            /* If we're copying, grab an entry off the list; copy the
             * ring entry into the data buf; and add it back to the end
             * of the list.
             */
            if (args->copy_mode) {
                rx_ptr = STAILQ_FIRST(&rx_head);
                STAILQ_REMOVE_HEAD(&rx_head, list);
                memcpy(rx_ptr->buf, (void *)rx_addr, args->ring_entry_len);
                STAILQ_INSERT_TAIL(&rx_head, rx_ptr, list);
            }
            *(uint8_t *)rx_addr = 0;
        }
        /*
         * Fix possible issues with out-of-order completion by exhausting
         * tx_avail and then waiting for all outstanding I/Os to complete.
         */
        ret = do_progress(conn->zq, &tx_avail_shadow);
        if (ret < 0)
            goto done;
        if (!tx_avail) {
            if (tx_avail_shadow != conn->tx_avail)
                continue;
            tx_avail = tx_avail_shadow;
            tx_avail_shadow = 0;
        }
        /* Send all available buffers. */
        for (window = TX_WINDOW; window > 0 && rx_count != tx_count && tx_avail;
             (window--, tx_count++, tx_avail--,
              tx_off = next_roff(conn, tx_off))) {
            /* Reflect buffer to same offset in client.*/
            zq_tx_addr = conn->zq_local_tx_zaddr + tx_off;
            zq_rx_addr = conn->zq_remote_rx_zaddr + tx_off;
            ret = zq_write(conn->zq, false, zq_tx_addr, args->ring_entry_len,
                           zq_rx_addr);
            if (ret < 0)
                goto done;
        }
    }
    tx_avail += tx_avail_shadow;
    while (tx_avail != conn->tx_avail) {
        ret = do_progress(conn->zq, &tx_avail);
        if (ret < 0)
            goto done;
    }
    op_count = tx_count - warmup_count;
    zhpeq_print_info(conn->zq);
    printf("%s:op_cnt/warmup %lu/%lu\n", appname, op_count, warmup_count);

 done:

    return ret;
}

static int do_client_pong(struct stuff *conn)
{
    int                 ret = 0;
    const struct args   *args = conn->args;
    uint                tx_flag_in = TX_NONE;
    uint                tx_flag_out = TX_WARMUP;
    size_t              tx_avail = conn->tx_avail;
    size_t              tx_avail_shadow = 0;
    size_t              ring_avail = args->ring_entries;
    size_t              tx_off = 0;
    size_t              rx_off = 0;
    size_t              tx_idx = 0;
    size_t              rx_idx = 0;
    uint64_t            lat_total1 = 0;
    uint64_t            lat_total2 = 0;
    uint64_t            lat_max2 = 0;
    uint64_t            lat_min2 = 0;
    uint64_t            lat_comp = 0;
    uint64_t            lat_write = 0;
    uint64_t            q_max1 = 0;
    uint64_t            tx_count;
    uint64_t            rx_count;
    uint64_t            warmup_count;
    uint64_t            op_count;
    uint64_t            window;
    uint8_t             *tx_addr;
    volatile uint8_t    *rx_addr;
    uint64_t            delta;
    uint64_t            start;
    uint64_t            now;
    uint64_t            zq_tx_addr;
    uint64_t            zq_rx_addr;

    start = get_cycles(NULL);
    for (tx_count = rx_count = warmup_count = 0;
         tx_count != rx_count || tx_flag_out != TX_LAST;) {
        /* Receive packets up to chunk or first miss. */
        for (window = RX_WINDOW; window > 0 && tx_flag_in != TX_LAST;
             (window--, rx_count++, ring_avail++,
              rx_off = next_roff(conn, rx_off))) {
            rx_addr = (void *)((char *)conn->rx_addr + rx_off);
            if (!(tx_flag_in = *rx_addr))
                break;
            *rx_addr = 0;
            if (!rx_off)
                rx_idx = 0;
            /* Reset statistics after warmup. */
            if (rx_count == warmup_count) {
                lat_total2 = 0;
                lat_max2 = 0;
                lat_min2 = ~(uint64_t)0;
            }
            /* Compute timestamp for entries. */
            delta = get_cycles(NULL) - conn->ring_timestamps[rx_idx++];
            lat_total2 += delta;
            if (delta > lat_max2)
                lat_max2 = delta;
            if (delta < lat_min2)
                lat_min2 = delta;
        }
        /*
         * Fix possible issues with out-of-order completion by exhausting
         * tx_avail and then waiting for all outstanding I/Os to complete.
         */
        now = get_cycles(NULL);
        ret = do_progress(conn->zq, &tx_avail_shadow);
        lat_comp += get_cycles(NULL) - now;
        if (ret < 0)
            goto done;
        if (!tx_avail) {
            if (tx_avail_shadow != conn->tx_avail)
                continue;
            tx_avail = tx_avail_shadow;
            tx_avail_shadow = 0;
        }
        /* Send all available buffers. */
        for (window = TX_WINDOW;
             window > 0 && ring_avail > 0 && tx_flag_out != TX_LAST && tx_avail;
             (window--, ring_avail--, tx_count++, tx_avail--,
              tx_off = next_roff(conn, tx_off))) {

            now = get_cycles(NULL);

            /* Compute delta based on cycles/ops. */
            if (args->seconds_mode)
                delta = now - start;
            else
                delta = tx_count;

            /* Handle switching between warmup/running/last. */
            switch (tx_flag_out) {

            case TX_WARMUP:
                if (delta < conn->ring_warmup)
                    break;
                tx_flag_out = TX_RUNNING;
                warmup_count = tx_count;
                /* Reset timers/counters after warmup. */
                lat_total1 = now;
                lat_comp = 0;
                lat_write = 0;
                q_max1 = 0;
                /* FALLTHROUGH */

            case TX_RUNNING:
                if  (delta >= conn->ring_ops - 1)
                    tx_flag_out = TX_LAST;
                break;

            default:
                print_err("%s,%u:Unexpected state %d\n",
                          __func__, __LINE__, tx_flag_out);
                ret = -EINVAL;
                goto done;
            }

            /* Write buffer to same offset in server.*/
            tx_addr = (void *)((char *)conn->tx_addr + tx_off);
            zq_tx_addr = conn->zq_local_tx_zaddr + tx_off;
            zq_rx_addr = conn->zq_remote_rx_zaddr + tx_off;
            if (!tx_off)
                tx_idx = 0;
            /* Write op flag. */
            *tx_addr = tx_flag_out;
            /* Send data. */
            now = get_cycles(NULL);
            conn->ring_timestamps[tx_idx++] = now;
            ret = zq_write(conn->zq, false, zq_tx_addr, args->ring_entry_len,
                           zq_rx_addr);
            lat_write += get_cycles(NULL) - now;
            if (ret < 0)
                goto done;
        }
        delta = tx_count - rx_count;
        if (delta > q_max1)
            q_max1 = delta;
    }
    tx_avail += tx_avail_shadow;
    while (tx_avail != conn->tx_avail) {
        now = get_cycles(NULL);
        ret = do_progress(conn->zq, &tx_avail);
        lat_comp += get_cycles(NULL) - now;
        if (ret < 0)
            goto done;
    }
    lat_total1 = get_cycles(NULL) - lat_total1;
    op_count = tx_count - warmup_count;
    zhpeq_print_info(conn->zq);
    printf("%s:op_cnt/warmup %lu/%lu\n", appname, op_count, warmup_count);
    printf("%s:lat ave1/ave2/min2/max2 %.3lf/%.3lf/%.3lf/%.3lf\n", appname,
           cycles_to_usec(lat_total1, op_count * 2),
           cycles_to_usec(lat_total2, op_count * 2),
           cycles_to_usec(lat_min2, 2), cycles_to_usec(lat_max2, 2));
    printf("%s:lat comp/write %.3lf/%.3lf qmax %lu\n",  appname,
           cycles_to_usec(lat_comp, op_count),
           cycles_to_usec(lat_write, op_count), q_max1);

 done:
    return ret;
}

static int do_server_sink(struct stuff *conn)
{
    int                 ret = 0;
    volatile uint8_t    *rx_addr = conn->rx_addr;

    while (*rx_addr != TX_LAST)
        yield();
    zhpeq_print_info(conn->zq);

    return ret;
}

static int do_client_unidir(struct stuff *conn)
{
    int                 ret = 0;
    const struct args   *args = conn->args;
    uint                tx_flag_out = TX_WARMUP;
    size_t              tx_avail = conn->tx_avail;
    size_t              tx_avail_shadow = 0;
    size_t              tx_off = 0;
    uint64_t            lat_total1 = 0;
    uint64_t            lat_comp = 0;
    uint64_t            lat_write = 0;
    uint64_t            tx_count;
    uint64_t            op_count;
    uint64_t            warmup_count;
    uint8_t             *tx_addr;
    uint64_t            delta;
    uint64_t            start;
    uint64_t            now;
    uint64_t            zq_tx_addr;
    uint64_t            zq_rx_addr;

    start = get_cycles(NULL);
    for (tx_count = warmup_count = 0; tx_flag_out != TX_LAST;
         tx_count++, tx_avail--, tx_off = next_roff(conn, tx_off)) {

        /*
         * Fix possible issues with out-of-order completion by exhausting
         * tx_avail and then waiting for all outstanding I/Os to complete.
         */
        now = get_cycles(NULL);
        ret = do_progress(conn->zq, &tx_avail_shadow);
        lat_comp += get_cycles(NULL) - now;
        if (ret < 0)
            goto done;
        if (!tx_avail) {
            while (tx_avail_shadow != conn->tx_avail) {
                now = get_cycles(NULL);
                ret = do_progress(conn->zq, &tx_avail_shadow);
                lat_comp += get_cycles(NULL) - now;
                if (ret < 0)
                    goto done;
            }
            tx_avail = tx_avail_shadow;
            tx_avail_shadow = 0;
        }

        /* Compute delta based on cycles/ops. */
        if (args->seconds_mode)
            delta = now - start;
        else
            delta = tx_count;

        /* Handle switching between warmup/running/last. */
        switch (tx_flag_out) {

        case TX_WARMUP:
            if (delta < conn->ring_warmup)
                break;
            tx_flag_out = TX_RUNNING;
            warmup_count = tx_count;
            /* Reset timers/counters after warmup. */
            lat_total1 = get_cycles(NULL);
            lat_comp = 0;
            lat_write = 0;
            /* FALLTHROUGH */

        case TX_RUNNING:
            if  (delta >= conn->ring_ops - 1) {
                tx_flag_out = TX_LAST;
                /* Force the last packet to use the first entry. */
                tx_off = 0;
            }
            break;

        default:
            print_err("%s,%u:Unexpected state %d\n",
                      __func__, __LINE__, tx_flag_out);
            ret = -EINVAL;
            goto done;
        }

        /* Write buffer to same offset in server.*/
        tx_addr = (void *)((char *)conn->tx_addr + tx_off);
        zq_tx_addr = conn->zq_local_tx_zaddr + tx_off;
        zq_rx_addr = conn->zq_remote_rx_zaddr + tx_off;
        /* Write op flag. */
        *tx_addr = tx_flag_out;
        ret = zq_write(conn->zq, false, zq_tx_addr, args->ring_entry_len,
                       zq_rx_addr);
        now = get_cycles(NULL);
        lat_write += get_cycles(NULL) - now;
        if (ret < 0)
            goto done;
    }
    tx_avail += tx_avail_shadow;
    while (tx_avail != conn->tx_avail) {
        now = get_cycles(NULL);
        ret = do_progress(conn->zq, &tx_avail);
        lat_comp += get_cycles(NULL) - now;
        if (ret < 0)
            goto done;
    }
    lat_total1 = get_cycles(NULL) - lat_total1;
    op_count = tx_count - warmup_count;
    zhpeq_print_info(conn->zq);
    printf("%s:op_cnt/warmup %lu/%lu\n", appname, op_count, warmup_count);
    printf("%s:lat ave1 %.3lf\n", appname,
           cycles_to_usec(lat_total1, op_count));
    printf("%s:lat comp/write %.3lf/%.3lf\n", appname,
           cycles_to_usec(lat_comp, op_count),
           cycles_to_usec(lat_write, op_count));

 done:
    return ret;
}

int do_zq_setup(struct stuff *conn)
{
    int                 ret;
    const struct args   *args = conn->args;
    union sockaddr_in46 sa;
    size_t              sa_len = sizeof(sa);
    struct zhpeq_attr   zq_attr;

    ret = zhpeq_query_attr(&zq_attr);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_query_attr", "", ret);
        goto done;
    }

    ret = -EINVAL;
    conn->tx_avail = args->tx_avail;
    if (conn->tx_avail) {
        if (conn->tx_avail > zq_attr.z.max_tx_qlen)
            goto done;
    } else
        conn->tx_avail = ZQ_LEN;

    /* Allocate domain. */
    ret = zhpeq_domain_alloc(&conn->zdom);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", ret);
        goto done;
    }
    /* Allocate zqueue. */
    ret = zhpeq_alloc(conn->zdom, conn->tx_avail + 1, conn->tx_avail + 1,
                      0, 0, 0,  &conn->zq);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_qalloc", "", ret);
        goto done;
    }
    /* Get address index. */
    ret = zhpeq_backend_exchange(conn->zq, conn->sock_fd, &sa, &sa_len);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_backend_exchange",
                       "", ret);
        goto done;
    }
    ret = zhpeq_backend_open(conn->zq, &sa);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_backend_open", "", ret);
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

    args->ring_entry_len = be64toh(cli_msg.ring_entry_len);
    args->ring_entries = be64toh(cli_msg.ring_entries);
    args->tx_avail = be64toh(cli_msg.tx_avail);
    args->aligned_mode = !!cli_msg.aligned_mode;
    args->copy_mode = !!cli_msg.copy_mode;
    args->once_mode = !!cli_msg.once_mode;
    args->unidir_mode = !!cli_msg.unidir_mode;

    /* Dummy for ordering. */
    ret = sock_send_blob(conn.sock_fd, NULL, 0);
    if (ret < 0)
        goto done;

    ret = do_zq_setup(&conn);
    if (ret < 0)
        goto done;

    if (args->unidir_mode)
        ret = do_server_sink(&conn);
    else
        ret = do_server_pong(&conn);

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
        .open_idx       = -1,
        .ring_ops       = args->ring_ops,
    };
    struct cli_wire_msg cli_msg;

    ret = connect_sock(args->node, args->service);
    if (ret < 0)
        goto done;
    conn.sock_fd = ret;

    /* Write the ring parameters to the server. */
    cli_msg.ring_entry_len = htobe64(args->ring_entry_len);
    cli_msg.ring_entries = htobe64(args->ring_entries);
    cli_msg.tx_avail = htobe64(args->tx_avail);
    cli_msg.aligned_mode = args->aligned_mode;
    cli_msg.copy_mode = args->copy_mode;
    cli_msg.once_mode = args->once_mode;
    cli_msg.unidir_mode = args->unidir_mode;

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
        if (conn.ring_warmup < args->ring_entries)
            conn.ring_warmup = args->ring_entries;
        if (conn.ring_warmup < WARMUP_MIN)
            conn.ring_warmup = WARMUP_MIN;
        conn.ring_ops += conn.ring_warmup;
    }

    /* Send ops */
    if (args->unidir_mode)
        ret = do_client_unidir(&conn);
    else
        ret = do_client_pong(&conn);

 done:
    stuff_free(&conn);

    return ret;
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s [-acosu] [-t <txqlen>] [-b <address>]\n"
        "    <port> [<node> <entry_len> <ring_entries>"
        " <op_count/seconds>]\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n"
        "Server requires just port; client requires all 5 arguments.\n"
        "Client only options:\n"
        " -a : cache line align entries\n"
        " -b <address> : try to allocate buffer at address\n"
        " -c : copy mode\n"
        " -o : run once and then server will exit\n"
        " -s : treat the final argument as seconds\n"
        " -t <txqlen> : length of tx request queue\n"
        " -u : uni-directional client-to-server traffic (no copy)\n"
        " -w <ops> : number of warmup operations\n"
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
    struct args         args = {
        .warmup         = SIZE_MAX,
    };
    bool                client_opt = false;
    int                 opt;
    int                 rc;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "ab:cost:uw:")) != -1) {

        /* All opts are client only, now. */
        client_opt = true;

        switch (opt) {

        case 'a':
            if (args.aligned_mode)
                usage(false);
            args.aligned_mode = true;
            break;

        case 'b':
            if (args.bufaddr)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "bufaddr",
                                  optarg, &args.bufaddr, 0, 1,
                                  SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        case 'c':
            if (args.copy_mode)
                usage(false);
            args.copy_mode = true;
            break;

        case 'o':
            if (args.once_mode)
                usage(false);
            args.once_mode = true;
            break;

        case 's':
            if (args.seconds_mode)
                usage(false);
            args.seconds_mode = true;
            break;

        case 't':
            if (args.tx_avail)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "tx_avail",
                                  optarg, &args.tx_avail, 0, 1,
                                  SIZE_MAX, PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        case 'u':
            if (args.unidir_mode)
                usage(false);
            args.unidir_mode = true;
            break;

        case 'w':
            if (args.warmup != SIZE_MAX)
                usage(false);
            if (parse_kb_uint64_t(__func__, __LINE__, "warmup",
                                  optarg, &args.warmup, 0, 0,
                                  SIZE_MAX - 1, PARSE_KB | PARSE_KIB) < 0)
                usage(false);
            break;

        default:
            usage(false);

        }
    }

    if (args.copy_mode && args.unidir_mode)
        usage(false);

    opt = argc - optind;

    if (opt == 1) {
        args.service = argv[optind++];
        if (client_opt)
            usage(false);
        if (do_server(&args) < 0)
            goto done;
    } else if (opt == 5) {
        args.service = argv[optind++];
        args.node = argv[optind++];
        if (parse_kb_uint64_t(__func__, __LINE__, "entry_len",
                              argv[optind++], &args.ring_entry_len, 0,
                              sizeof(uint8_t), SIZE_MAX,
                              PARSE_KB | PARSE_KIB) < 0 ||
            parse_kb_uint64_t(__func__, __LINE__, "ring_entries",
                              argv[optind++], &args.ring_entries, 0, 1,
                              SIZE_MAX, PARSE_KB | PARSE_KIB) < 0 ||
            parse_kb_uint64_t(__func__, __LINE__,
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
