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

#ifndef _LIBZHPEQ_INTERNAL_H_
#define _LIBZHPEQ_INTERNAL_H_

#define _GNU_SOURCE

#include <zhpeq_util.h>
#include <zhpe.h>

#include <assert.h>
#include <pthread.h>

#include <arpa/inet.h>

#include <sys/mman.h>

typedef size_t __attribute__ ((aligned(64))) cache_size_t;

struct backend_ops {
    int                 (*lib_init)(void);
    int                 (*domain)(const union zhpeq_backend_params *params,
                                  struct zhpeq_dom *zdom);
    int                 (*domain_free)(struct zhpeq_dom *zdom);
    int                 (*qalloc)(struct zhpeq_dom *zdom, struct zhpeq *zq);
    int                 (*qfree)(struct zhpeq *zq);
    int                 (*open)(struct zhpeq *zq, int sock_fd);
    int                 (*close)(struct zhpeq *zq, int open_idx);
    int                 (*wq_signal)(struct zhpeq *zq);
    ssize_t             (*cq_poll)(struct zhpeq *zq, size_t len);
    int                 (*mr_reg)(struct zhpeq_dom *zdom,
                                  const void *buf, size_t len, uint32_t access,
                                  struct zhpeq_key_data **kdata_out);
    int                 (*mr_free)(struct zhpeq_dom *zdom,
                                   struct zhpeq_key_data *kdata);
    int                 (*zmmu_free)(struct zhpeq *zq,
                                     struct zhpeq_key_data *kdata);
    int                 (*zmmu_import)(struct zhpeq *zq, int open_idx,
                                       const void *blob, size_t blob_len,
                                       struct zhpeq_key_data **kdata_out);
    int                 (*zmmu_export)(struct zhpeq *zq,
                                       const struct zhpeq_key_data *kdata,
                                       void **blob_out, size_t *blob_len);
    void                (*print_info)(struct zhpeq *zq);
};

#define FREE_END        (-1)

union free_index {
    struct {
        int32_t         index;
        uint32_t        seq;
    };
    uint64_t            blob;
};

struct zhpeq_dom {
    void                *backend_data;
};

struct zhpeq {
    struct zhpeq_dom    *zdom;
    uint                debug_flags;
    struct zhpe_info    info;
    struct zhpe_hw_reg  *reg;
    union zhpe_hw_wq_entry *wq;
    union zhpe_hw_cq_entry *cq;
    void                **context;
    void                *backend_data;
    uint32_t            q_head;         /* Shadow for wq and cq */
    pthread_spinlock_t __attribute__ ((aligned(64))) tail_lock;
    uint32_t            tail_reserved;
    uint32_t            tail_commit;
    bool                tail_lock_init;
};

static inline uint8_t cq_valid(uint32_t idx, uint32_t qmask)
{
    return ((idx & (qmask + 1)) ? 0 : ZHPE_HW_CQ_VALID);
}

extern struct backend_ops libfabric_ops;

#define likely(x)		__builtin_expect((x), 1)
#define unlikely(x)		__builtin_expect((x), 0)

#endif /* _LIBZHPEQ_INTERNAL_H */
