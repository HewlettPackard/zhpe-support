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

#include <zhpeq.h>
#include <zhpeq_util.h>
#include <zhpe.h>

#include <assert.h>
#include <endian.h>

#include <uuid/uuid.h>

/* Do extern "C" without goofing up emacs. */
#ifndef _EXTERN_C_SET
#define _EXTERN_C_SET
#ifdef  __cplusplus
#define _EXTERN_C_BEG extern "C" {
#define _EXTERN_C_END }
#else
#define _EXTERN_C_BEG
#define _EXTERN_C_END
#endif
#endif

_EXTERN_C_BEG

#define DEV_NAME        "/dev/"DRIVER_NAME

struct backend_ops {
    int                 (*lib_init)(struct zhpeq_attr *attr);
    int                 (*domain)(struct zhpeq_dom *zdom);
    int                 (*domain_free)(struct zhpeq_dom *zdom);
    int                 (*qalloc)(struct zhpeq *zq, int cmd_qlen, int cmp_qlen,
                                  int traffic_class, int priority,
                                  int slice_mask);
    int                 (*qalloc_post)(struct zhpeq *zq);
    int                 (*qfree_pre)(struct zhpeq *zq);
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
    int                 (*zmmu_free)(struct zhpeq_dom *zdom,
                                     struct zhpeq_key_data *kdata);
    int                 (*zmmu_import)(struct zhpeq_dom *zdom, int open_idx,
                                       const void *blob, size_t blob_len,
                                       bool cpu_visible,
                                       struct zhpeq_key_data **kdata_out);
    int                 (*zmmu_export)(struct zhpeq_dom *zdom,
                                       const struct zhpeq_key_data *kdata,
                                       void *blob, size_t *blob_len);
    void                (*print_info)(struct zhpeq *zq);
    int                 (*getaddr)(struct zhpeq *zq, union sockaddr_in46 *sa);
    char                *(*qkdata_id_str)(struct zhpeq_dom *zdom,
                                          const struct zhpeq_key_data *qkdata);
};

extern uuid_t           zhpeq_uuid;

void zhpeq_register_backend(enum zhpe_backend backend, struct backend_ops *ops);
void zhpeq_backend_libfabric_init(int fd);
void zhpeq_backend_zhpe_init(int fd);

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
    struct zhpe_xqinfo  xqinfo;
    volatile void       *qcm;
    union zhpe_hw_wq_entry *wq;
    union zhpe_hw_cq_entry *cq;
    void                **context;
    void                *backend_data;
    int                 fd;
    /* q_head may be updated in progress thread. */
    uint32_t            q_head CACHE_ALIGNED;
    uint32_t            tail_reserved CACHE_ALIGNED;
    uint32_t            tail_commit;
};

static inline uint8_t cq_valid(uint32_t idx, uint32_t qmask)
{
    return ((idx & (qmask + 1)) ? 0 : ZHPE_HW_CQ_VALID);
}

static inline uint64_t ioread64(const volatile void *addr)
{
    return le64toh(*(const volatile uint64_t *)addr);
}

static inline void iowrite64(uint64_t value, volatile void *addr)
{
    *(volatile uint64_t *)addr = htole64(value);
}

struct key_data_packed {
    uint64_t            vaddr;
    uint64_t            zaddr;
    uint64_t            len;
    uint8_t             access;
} __attribute__((packed));

static inline void pack_kdata(const struct zhpeq_key_data *qkdata,
                              struct key_data_packed *pdata,
                              uint64_t zaddr)
{
    const struct zhpe_key_data *kdata = &qkdata->z;

    pdata->vaddr = be64toh(kdata->vaddr);
    pdata->zaddr = be64toh(zaddr);
    pdata->len = be64toh(kdata->len);
    pdata->access = kdata->access;
}

static inline void unpack_kdata(const struct key_data_packed *pdata,
                                struct zhpeq_key_data *qkdata)
{
    struct zhpe_key_data *kdata = &qkdata->z;

    kdata->vaddr = htobe64(pdata->vaddr);
    kdata->zaddr = htobe64(pdata->zaddr);
    kdata->len = htobe64(pdata->len);
    kdata->access = pdata->access;
}

#define ZHPEQ_MR_V1             (1U)
#define ZHPEQ_MR_REMOTE         ((uint32_t)1 << 31)

struct zhpeq_mr_desc_common_hdr {
    uint32_t            magic;
    uint32_t            version;
};

struct zhpeq_mr_desc_v1 {
    struct zhpeq_mr_desc_common_hdr hdr;
    struct zhpeq_key_data qkdata;
    uint32_t            access_plus;
    int                 uuid_idx;
};

union zhpeq_mr_desc {
    struct zhpeq_mr_desc_common_hdr hdr;
    struct zhpeq_mr_desc_v1 v1;
};

/* FIXME: probably works for now, but ditch bit fields. */
union xdm_cmp_tail {
    struct zhpe_xdm_cmpl_queue_tail_toggle bits;
    uint64_t            u64;
};

union xdm_active {
    struct zhpe_xdm_active_status_error bits;
    uint64_t            u64;
};

union rdm_rcv_tail {
    struct zhpe_rdm_rcv_queue_tail_toggle bits;
    uint64_t            u64;
};

_EXTERN_C_END

#ifdef _EXTERN_C_SET
#undef _EXTERN_C_SET
#undef _EXTERN_C_BEG
#undef _EXTERN_C_END
#endif

#endif /* _LIBZHPEQ_INTERNAL_H */
