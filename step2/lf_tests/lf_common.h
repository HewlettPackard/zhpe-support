/*
 * Copyright (C) 2019 Hewlett Packard Enterprise Development LP.
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

#ifndef _LF_COMMON_H_
#define _LF_COMMON_H_

#include <zhpeq_util_fab.h>

_EXTERN_C_BEG

struct lf_params {
    const char          *service;
    const char          *node;
    const char          *provider;
    const char          *domain;
    uint64_t            tx_avail;
    uint64_t            rx_avail;
    uint64_t            memsize;
    int                 sock_fd;
    uint8_t             ep_type;
    bool                free_str;
};

union lf_context {
    struct fi_context2  ctx2;
    union ucontext      *next;
};

struct lf_conn {
    struct fab_conn     *fab_conn;
    fi_addr_t           remote_fi_addr;
    uint64_t            remote_addr;
    uint64_t            remote_key;
    uint64_t            remote_size;
    size_t              tx_avail;
    size_t              rx_avail;
    union lf_context    *ctx;
    union lf_context    *ctx_free;
    size_t              ctx_size;
    size_t              ctx_avail;
    size_t              ctx_cur;
    int                 sock_fd;
};

void lf_ctx_free(struct lf_conn *lf_conn, void *vctx);
union lf_context *lf_ctx_next(struct lf_conn *lf_conn);
bool lf_ctx_all_done(struct lf_conn *conn);
int lf_progress(struct lf_conn *lf_conn);
int lf_wait_all(struct lf_conn *lf_conn);
void lf_conn_free(struct lf_conn *lf_conn);
void lf_params_free(struct lf_params *param);
int lf_server_recv_params(int sock_fd, struct lf_params *param);
int lf_client_send_params(int sock_fd, struct lf_params *param);
int lf_conn_alloc(const struct lf_params *param, struct lf_conn **lf_conn_out);
int lf_server_ep_setup(struct lf_conn *lf_conn);
int lf_client_ep_setup(struct lf_conn *lf_conn);

_EXTERN_C_END

#endif /* _LF_COMMON_H_ */
