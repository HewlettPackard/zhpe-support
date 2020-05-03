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

#ifndef _ZHPEQ_UTIL_FAB_H_
#define _ZHPEQ_UTIL_FAB_H_

#include <zhpeq_util.h>

#include <rdma/fabric.h>
#include <rdma/fi_atomic.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_trigger.h>

_EXTERN_C_BEG

#define FAB_FIVERSION       FI_VERSION(1, 5)

struct fab_mrmem {
    struct fid_mr       *mr;
    void                *mem;
    size_t              len;
    void                *mem_free;
    size_t              len_free;
};

struct fab_info {
    char                *node;
    char                *service;
    uint64_t            flags;
    struct fi_info      *hints;
    struct fi_info      *info;
};

struct fab_dom {
    struct fab_info     finfo;
    struct fid_fabric   *fabric;
    struct fid_domain   *domain;
    struct fid_av       *av;
    void                *av_sa_tree;
    void                *av_fi_tree;
    pthread_mutex_t     av_mutex;
    void                (*onfree)(struct fab_dom *dom, void *data);
    void                *onfree_data;
    int32_t             use_count;
};

struct fab_conn {
    struct fab_dom      *dom;
    struct fab_info     finfo;
    struct fid_eq       *eq;
    struct fid_cq       *tx_cq;
    struct fid_cq       *rx_cq;
    struct fid_ep       *ep;
    struct fid_pep      *pep;
    struct fab_mrmem    mrmem;
    void                (*onfree)(struct fab_conn *conn, void *data);
    void                *onfree_data;
    int32_t             use_count;
};

static inline void fab_print_func_err(const char *callf, uint line,
                                      const char *errf, const char *arg,
                                      int err)
{
    if (err < 0)
        err = -err;

    zhpeu_print_err("%s,%u:%s(%s) returned error %d:%s\n",
                    callf, line, errf, arg, err, fi_strerror(err));
}

static inline void fab_print_func_errn(const char *callf, uint line,
                                       const char *errf, llong arg,
                                       bool arg_hex, int err)
{
    if (arg_hex)
        zhpeu_print_err("%s,%u:%s(0x%Lx) returned error %d:%s\n",
                        callf, line, errf, arg, err, fi_strerror(err));
   else
        zhpeu_print_err("%s,%u:%s(0x%Ld) returned error %d:%s\n",
                        callf, line, errf, arg, err, fi_strerror(err));
}

#define FI_CLOSE(_ptr)                                          \
({                                                              \
    int __ret = 0;                                              \
    typeof(_ptr) __ptr = (_ptr);                                \
                                                                \
    if (__ptr) {                                                \
        __ret = fi_close(&(__ptr)->fid);                        \
        if (__ret < 0)                                          \
            fab_print_func_err(__func__, __LINE__,              \
                               "fi_close", #_ptr, __ret);       \
    }                                                           \
    __ret;                                                      \
})

void fab_dom_init(struct fab_dom *dom);
void fab_conn_init(struct fab_dom *dom, struct fab_conn *conn);

struct fab_dom *fab_dom_alloc(void (*onfree)(struct fab_dom *dom, void *data),
                              void *data);

#define _fab_dom_alloc(...)                                     \
    zhpeu_call_null(zhpeu_err, fab_dom_alloc, struct fab_dom *, __VA_ARGS__)

struct fab_conn *_fab_conn_alloc(struct fab_dom *dom,
                                 void (*onfree)(struct fab_conn *conn,
                                                void *data),
                                 void *data);

#define _fab_conn_alloc(...)                                    \
    zhpeu_call_null(zhpeu_err, fab_conn_alloc, struct fab_conn *, __VA_ARGS__)

int fab_dom_free(struct fab_dom *dom);
int fab_conn_free(struct fab_conn *conn);

int fab_dom_setup(const char *service, const char *node, bool passive,
                  const char *provider, const char *domain,
                  enum fi_ep_type ep_type, struct fab_dom *dom);

#define _fab_dom_setup(...)                                     \
    zhpeu_call_neg(zhpeu_err, fab_dom_setup, int, __VA_ARGS__)

int fab_dom_setupx(const char *service, const char *node, bool passive,
                   const char *provider, const char *domain,
                   enum fi_ep_type ep_type, uint64_t mr_mode,
                   enum fi_progress progress, struct fab_dom *dom);

#define _fab_dom_setupx(...)                                    \
    zhpeu_call_neg(zhpeu_err, fab_dom_setupx, int, __VA_ARGS__)

int fab_dom_getinfo(const char *service, const char *node, bool passive,
                    struct fab_dom *dom, struct fab_info *finfo);

#define _fab_dom_getinfo(...)                                   \
    zhpeu_call_neg(zhpeu_err, fab_dom_getinfo, int, __VA_ARGS__)

int fab_listener_setup(int backlog, struct fab_conn *listener);

#define _fab_listener_setup(...)                                \
    zhpeu_call_neg(zhpeu_err, fab_listener_setup, int, __VA_ARGS__)

int fab_listener_wait_and_accept(struct fab_conn *listener, int timeout,
                                 size_t tx_size, size_t rx_size,
                                 struct fab_conn *conn);

#define _fab_listener_wait_and_accept(...)                      \
    zhpeu_call_neg(zhpeu_err, fab_listener_wait_and_accept, int, __VA_ARGS__)

int fab_connect(int timeout,
                size_t tx_size, size_t rx_size, struct fab_conn *conn);

#define _fab_connect(...)                                       \
    zhpeu_call_neg(zhpeu_err, fab_connect, int, __VA_ARGS__)

int fab_av_xchg_addr(struct fab_conn *conn, int sock_fd,
                     union sockaddr_in46 *ep_addr);

#define _fab_av_xchg_addr(...)                                  \
    zhpeu_call_neg(zhpeu_err, fab_av_xchg_addr, int, __VA_ARGS__)

int fab_av_xchg(struct fab_conn *conn, int sock_fd, int timeout,
                fi_addr_t *fi_addr);

#define _fab_av_xchg(...)                                       \
    zhpeu_call_neg(zhpeu_err, fab_av_xchg, int, __VA_ARGS__)

int fab_av_insert(struct fab_dom *dom, union sockaddr_in46 *saddr,
                  fi_addr_t *fi_addr_out);

#define _fab_av_insert(...)                                     \
    zhpeu_call_neg(zhpeu_err, fab_av_insert, int, __VA_ARGS__)

int fab_av_remove(struct fab_dom *dom, fi_addr_t fi_addr);

#define _fab_av_remove(...)                                     \
    zhpeu_call_neg(zhpeu_err, fab_av_remove, int, __VA_ARGS__)

int fab_av_wait_send(struct fab_conn *conn, fi_addr_t fi_addr,
                     int (*retry)(void *retry_arg), void *retry_arg);

#define _fab_av_wait_send(...)                                  \
    zhpeu_call_neg(zhpeu_err, fab_av_wait_send, int, __VA_ARGS__)

int fab_av_wait_recv(struct fab_conn *conn, fi_addr_t fi_addr,
                     int (*retry)(void *retry_arg), void *retry_arg);

#define _fab_av_wait_recv(...)                                  \
    zhpeu_call_neg(zhpeu_err, fab_av_wait_recv, int, __VA_ARGS__)

int fab_listener_setup(int backlog, struct fab_conn *listener);

#define _fab_listener_setup(...)                                \
    zhpeu_call_neg(zhpeu_err, fab_listener_setup, int, __VA_ARGS__)

int fab_ep_setup(struct fab_conn *conn, struct fid_eq *eq,
                 size_t tx_size, size_t rx_size);

#define _fab_ep_setup(...)                                      \
    zhpeu_call_neg(zhpeu_err, fab_ep_setup, int, __VA_ARGS__)

int fab_eq_cm_event(struct fab_conn *conn, int timeout, uint32_t expected,
                    struct fi_eq_cm_entry *entry);

#define _fab_eq_cm_event(...)                                   \
    zhpeu_call_neg(zhpeu_err, fab_eq_cm_event, int, __VA_ARGS__)

int fab_mrmem_alloc_aligned(struct fab_conn *conn, struct fab_mrmem *mrmem,
                            size_t alignment, size_t len, uint64_t access);

#define _fab_mrmem_alloc_aligned(...)                           \
    zhpeu_call_neg(zhpeu_err, fab_mrmem_alloc_aligned, int, __VA_ARGS__)

static inline
int fab_mrmem_alloc(struct fab_conn *conn, struct fab_mrmem *mrmem, size_t len,
                    uint64_t access)
{
    return fab_mrmem_alloc_aligned(conn, mrmem, zhpeu_init_time->pagesz,
                                   len, access);
}

#define _fab_mrmem_alloc(...)                                   \
    zhpeu_call_neg(zhpeu_err, fab_mrmem_alloc, int, __VA_ARGS__)

int fab_mrmem_free(struct fab_mrmem *mrmem);

#define _fab_mrmem_free(...)                                    \
    zhpeu_call_neg(zhpeu_err, fab_mrmem_free, int, __VA_ARGS__)

ssize_t fab_completions(struct fid_cq *cq, size_t count,
                        void (*cq_update)(void *arg, void *cqe, bool err),
                        void *arg);

#define _fab_completions(...)                                   \
    zhpeu_call_neg(zhpeu_err, fab_completions, int, __VA_ARGS__)

int fab_cq_sread(struct fid_cq *cq, struct fi_cq_tagged_entry *fi_cqe,
                 size_t count, void *cond, int timeout,
                 struct fi_cq_err_entry *fi_cqerr);

#define _fab_cq_sread(...)                                      \
    zhpeu_call_neg(zhpeu_err, fab_cq_sread, int, __VA_ARGS__)

int fab_cq_read(struct fid_cq *cq, struct fi_cq_tagged_entry *fi_cqe,
                size_t count, struct fi_cq_err_entry *fi_cqerr);

#define _fab_cq_read(...)                                       \
    zhpeu_call_neg(zhpeu_err, fab_cq_read, int, __VA_ARGS__)

void fab_print_info(struct fab_conn *conn);

static inline struct fi_info *fab_conn_info(struct fab_conn *conn)
{
    return (conn->finfo.info ?: conn->dom->finfo.info);
}

#ifdef _ZHPEQ_TEST_COMPAT_

#define fab_av_xchg(...)        _fab_av_xchg(__VA_ARGS__)
#define fab_completions(...)    _fab_completions(__VA_ARGS__)
#define fab_connect(...)        _fab_connect(__VA_ARGS__)
#define fab_dom_setup(...)      _fab_dom_setup(__VA_ARGS__)
#define fab_ep_setup(...)       _fab_ep_setup(__VA_ARGS__)
#define fab_listener_setup(...) _fab_listener_setup(__VA_ARGS__)
#define fab_listener_wait_and_accept(...)                       \
    _fab_listener_wait_and_accept(__VA_ARGS__)
#define fab_mrmem_alloc(...)    _fab_mrmem_alloc(__VA_ARGS__)
#define print_func_fi_err       fab_print_func_err
#define print_func_fi_errn      fab_print_func_errn

#endif

_EXTERN_C_END

#endif /* _ZHPEQ_UTIL_FAB_H_ */
