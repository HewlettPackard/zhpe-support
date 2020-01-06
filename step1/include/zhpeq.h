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

#ifndef _ZHPEQ_H_
#define _ZHPEQ_H_

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <zhpe_uapi.h>

_EXTERN_C_BEG

#define ZHPEQ_API_VERSION       (1)

#define ZHPEQ_MR_GET            ZHPE_MR_GET
#define ZHPEQ_MR_PUT            ZHPE_MR_PUT
#define ZHPEQ_MR_GET_REMOTE     ZHPE_MR_GET_REMOTE
#define ZHPEQ_MR_PUT_REMOTE     ZHPE_MR_PUT_REMOTE
#define ZHPEQ_MR_SEND           ZHPE_MR_SEND
#define ZHPEQ_MR_RECV           ZHPE_MR_RECV

#define ZHPEQ_MR_KEY_ZERO_OFF   ZHPE_MR_FLAG0
#define ZHPEQ_MR_FLAG1          ZHPE_MR_FLAG1
#define ZHPEQ_MR_FLAG2          ZHPE_MR_FLAG2

#define ZHPEQ_MR_REQ_CPU        ZHPE_MR_REQ_CPU
#define ZHPEQ_MR_REQ_CPU_CACHE  ZHPE_MR_REQ_CPU_CACHE
#define ZHPEQ_MR_REQ_CPU_WB     ZHPE_MR_REQ_CPU_WB
#define ZHPEQ_MR_REQ_CPU_WC     ZHPE_MR_REQ_CPU_WC
#define ZHPEQ_MR_REQ_CPU_WT     ZHPE_MR_REQ_CPU_WT
#define ZHPEQ_MR_REQ_CPU_UC     ZHPE_MR_REQ_CPU_UC

enum zhpeq_atomic_size {
    ZHPEQ_ATOMIC_SIZE_NONE      = ZHPE_HW_ATOMIC_RETURN,
    ZHPEQ_ATOMIC_SIZE32         = ZHPE_HW_ATOMIC_SIZE_32,
    ZHPEQ_ATOMIC_SIZE64         = ZHPE_HW_ATOMIC_SIZE_64,
};

enum zhpeq_atomic_op {
    ZHPEQ_ATOMIC_NONE           = ZHPE_HW_OPCODE_NOP,
    ZHPEQ_ATOMIC_SWAP           = ZHPE_HW_OPCODE_ATM_SWAP,
    ZHPEQ_ATOMIC_ADD            = ZHPE_HW_OPCODE_ATM_ADD,
    ZHPEQ_ATOMIC_AND            = ZHPE_HW_OPCODE_ATM_AND,
    ZHPEQ_ATOMIC_OR             = ZHPE_HW_OPCODE_ATM_OR,
    ZHPEQ_ATOMIC_XOR            = ZHPE_HW_OPCODE_ATM_XOR,
    ZHPEQ_ATOMIC_SMIN           = ZHPE_HW_OPCODE_ATM_SMIN,
    ZHPEQ_ATOMIC_SMAX           = ZHPE_HW_OPCODE_ATM_SMAX,
    ZHPEQ_ATOMIC_UMIN           = ZHPE_HW_OPCODE_ATM_UMIN,
    ZHPEQ_ATOMIC_UMAX           = ZHPE_HW_OPCODE_ATM_UMAX,
    ZHPEQ_ATOMIC_CAS            = ZHPE_HW_OPCODE_ATM_CAS,
};

#define ZHPEQ_CQ_STATUS_SUCCESS ZHPE_HW_CQ_STATUS_SUCCESS

enum zhpeq_backend {
    ZHPEQ_BACKEND_NONE,
    ZHPEQ_BACKEND_ZHPE,
    ZHPEQ_BACKEND_LIBFABRIC,
    ZHPEQ_BACKEND_MAX,
};

enum {
    ZHPEQ_PRI_MAX               = 1,
    ZHPEQ_TC_MAX                = 15,
    ZHPEQ_IMM_MAX               = ZHPE_MAX_IMM,
    ZHPEQ_KEY_BLOB_MAX          = 32,
};

struct zhpeq_attr {
    enum zhpeq_backend  backend;
    struct zhpe_attr    z;
};

struct zhpeq_key_data {
    struct zhpe_key_data z;
    union {
        uint64_t        laddr;
        uint64_t        rsp_zaddr;
    };
};

struct zhpeq_cq_entry {
    struct zhpe_cq_entry z;
};

/* Public portions of structures. */
struct zhpeq_mmap_desc {
    struct zhpeq_key_data *qkdata;
    void                *addr;
};

/* Forward references to shut the compiler up. */
struct zhpeq;
struct zhpeq_dom;

static inline int zhpeq_rem_key_access(struct zhpeq_key_data *qkdata,
                                       uint64_t start, uint64_t len,
                                       uint32_t qaccess, uint64_t *zaddr)
{
    struct zhpe_key_data *kdata = &qkdata->z;

    if (!qkdata)
        return -EINVAL;
    if (kdata->access & ZHPEQ_MR_KEY_ZERO_OFF)
        start += kdata->vaddr;
    if ((qaccess & kdata->access) != qaccess ||
        start < kdata->vaddr || start + len > kdata->vaddr + kdata->len)
        return -EINVAL;
    *zaddr = (start - kdata->vaddr) + kdata->zaddr;

    return 0;
}

static inline int zhpeq_lcl_key_access(struct zhpeq_key_data *qkdata,
                                       void *buf, uint64_t len,
                                       uint32_t qaccess, uint64_t *zaddr)
{
    uintptr_t           start = (uintptr_t)buf;
    struct zhpe_key_data *kdata = &qkdata->z;

    if (!qkdata)
        return -EINVAL;
    if ((qaccess & kdata->access) != qaccess ||
        start < kdata->vaddr || start + len > kdata->vaddr + kdata->len)
        return -EINVAL;
    *zaddr = (start - kdata->vaddr) + qkdata->laddr;

    return 0;
}

int zhpeq_init(int api_version);

int zhpeq_query_attr(struct zhpeq_attr *attr);

int zhpeq_domain_alloc(struct zhpeq_dom **zdom_out);

int zhpeq_domain_free(struct zhpeq_dom *zdom);

int zhpeq_alloc(struct zhpeq_dom *zdom, int cmd_qlen, int cmp_qlen,
                int traffic_class, int priority, int slice_mask,
                struct zhpeq **zq_out);

int zhpeq_free(struct zhpeq *zq);

int zhpeq_backend_exchange(struct zhpeq *zq, int sock_fd,
                           void *sa, size_t *sa_len);

int zhpeq_backend_open(struct zhpeq *zq, void *sa);

int zhpeq_backend_close(struct zhpeq *zq, int open_idx);

ssize_t zhpeq_cq_read(struct zhpeq *zq, struct zhpeq_cq_entry *entries,
                      size_t n_entries);

int zhpeq_mr_reg(struct zhpeq_dom *zdom, const void *buf, size_t len,
                 uint32_t access, struct zhpeq_key_data **qkdata_out);

int zhpeq_qkdata_free(struct zhpeq_key_data *qkdata);

int zhpeq_qkdata_export(const struct zhpeq_key_data *qkdata,
                        void *blob, size_t *blob_len);

int zhpeq_qkdata_import(struct zhpeq_dom *zdom, int open_idx,
                        const void *blob, size_t blob_len,
                        struct zhpeq_key_data **qkdata_out);

int zhpeq_fam_qkdata(struct zhpeq_dom *zdom, int open_idx,
                     struct zhpeq_key_data **qkdata_out, size_t *n_qkdata);

int zhpeq_zmmu_reg(struct zhpeq_key_data *qkdata);

int zhpeq_mmap(const struct zhpeq_key_data *qkdata,
               uint32_t cache_mode, void *addr, size_t length, int prot,
               int flags, off_t offset, struct zhpeq_mmap_desc **zmdesc);

int zhpeq_mmap_unmap(struct zhpeq_mmap_desc *zmdesc);

int zhpeq_mmap_commit(struct zhpeq_mmap_desc *zmdesc,
                      const void *addr, size_t length, bool fence,
                      bool invalidate, bool wait);

int64_t zhpeq_reserve(struct zhpeq *zq, uint32_t n_entries);

int64_t zhpeq_reserve_next(struct zhpeq *zq, int64_t last);

int zhpeq_commit(struct zhpeq *zq, uint32_t qindex, uint32_t n_entries);

int zhpeq_signal(struct zhpeq *zq);

int zhpeq_check_stopped(struct zhpeq *zq);

int zhpeq_restart(struct zhpeq *zq, uint32_t head_idx, uint32_t tail_idx);

int zhpeq_put(struct zhpeq *zq, uint32_t qindex, bool fence,
              uint64_t local_addr, size_t len, uint64_t remote_addr,
              void *context);

int zhpeq_puti(struct zhpeq *zq, uint32_t qindex, bool fence,
               const void *buf, size_t len, uint64_t remote_addr,
               void *context);

int zhpeq_get(struct zhpeq *zq, uint32_t qindex, bool fence,
              uint64_t local_addr, size_t len, uint64_t remote_addr,
              void *context);

int zhpeq_geti(struct zhpeq *zq, uint32_t qindex, bool fence,
               size_t len, uint64_t remote_addr, void *context);

int zhpeq_nop(struct zhpeq *zq, uint32_t qindex, bool fence,
              void *context);

int zhpeq_atomic(struct zhpeq *zq, uint32_t qindex, bool fence, bool retval,
                 enum zhpeq_atomic_size datasize, enum zhpeq_atomic_op op,
                 uint64_t remote_addr, const uint64_t *operands,
                 void *context);

void zhpeq_print_info(struct zhpeq *zq);

struct zhpeq_dom *zhpeq_dom(struct zhpeq *zq);

void zhpeq_print_qkdata(const char *func, uint line,
                        const struct zhpeq_key_data *qkdata);

void zhpeq_print_qcm(const char *func, uint line, const struct zhpeq *zq);

void zhpeq_print_wq(struct zhpeq *zq, int offset, int cnt);

void zhpeq_print_cq(struct zhpeq *zq, int offset, int cnt);

bool zhpeq_is_asic(void);

int zhpeq_getaddr(struct zhpeq *zq, void *sa, size_t *sa_len);

_EXTERN_C_END

#endif /* _ZHPEQ_H_ */
