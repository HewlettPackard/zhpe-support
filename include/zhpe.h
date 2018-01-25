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

#ifndef _ZHPE_H_
#define _ZHPE_H_

#ifdef __KERNEL__

#include <linux/uio.h>
#include <asm/byteorder.h>

#define htobe64 cpu_to_be64
#define be64toh be64_to_cpu
#define htobe32 cpu_to_be32
#define be32toh be32_to_cpu

typedef long long       llong;
typedef unsigned long long ullong;

#else

#include <endian.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/uio.h>

#endif

#include <zhpeq.h>

#define DRIVER_NAME     "zhpe"

enum {
    ZHPE_OP_INIT,
    ZHPE_OP_MR_REG,
    ZHPE_OP_MR_DEREG,
    ZHPE_OP_NOP,
    ZHPE_OP_QALLOC,
    ZHPE_OP_QFREE,
    ZHPE_OP_ZMMU_REG,
    ZHPE_OP_ZMMU_DEREG,
    ZHPE_OP_HELPER_INIT,
    ZHPE_OP_HELPER_NOP,
    ZHPE_OP_HELPER_EXIT,
    ZHPE_OP_RESPONSE = 0x80,
    ZHPE_OP_VERSION = 1,
};

enum {
    DEBUG_TESTMODE      = 0x00000001,
    DEBUG_MEM           = 0x00000002,
    DEBUG_COUNT         = 0x00000004,
    DEBUG_IO            = 0x00000008,
    DEBUG_RELEASE       = 0x00000018,
};

#define ZHPE_HELPER_OPEN_SLEEP (1)

/* ZHPE_MAGIC == 'ZHPE' */
#define ZHPE_MAGIC      (0x47454E5A)

#define ZHPE_ENTRY_LEN  (64U)

#define ZHPE_MR_V1      (1U)
#define ZHPE_MR_REMOTE  ((uint32_t)1 << 31)

struct zhpe_mr_desc_common_hdr {
    uint32_t            magic;
    uint32_t            version;
};

struct zhpe_mr_desc_v1 {
    struct zhpe_mr_desc_common_hdr hdr;
    struct zhpeq_key_data kdata;
};

union zhpe_mr_desc {
    struct zhpe_mr_desc_common_hdr hdr;
    struct zhpe_mr_desc_v1 v1;
};

struct zhpe_info {
    uint32_t            qlen;
    uint32_t            rsize;
    uint32_t            qsize;
    uint64_t            reg_off;
    uint64_t            wq_off;
    uint64_t            cq_off;
};

struct zhpe_common_hdr {
    uint8_t             version;
    uint8_t             opcode;
    uint16_t            index;
    int                 status;
};

struct zhpe_req_INIT {
    struct zhpe_common_hdr hdr;
};

struct zhpe_rsp_INIT {
    struct zhpe_common_hdr hdr;
    uint64_t            shared_offset;
    uint32_t            shared_size;
};

struct zhpe_req_MR_REG {
    struct zhpe_common_hdr hdr;
    struct zhpeq_key_data kdata;
};

struct zhpe_rsp_MR_REG {
    struct zhpe_common_hdr hdr;
    union zhpe_mr_desc  desc;
};

struct zhpe_req_MR_DEREG {
    struct zhpe_common_hdr hdr;
    union zhpe_mr_desc  desc;
};

struct zhpe_rsp_MR_DEREG {
    struct zhpe_common_hdr hdr;
};

struct zhpe_req_NOP {
    struct zhpe_common_hdr hdr;
    uint64_t            seq;
};

struct zhpe_rsp_NOP {
    struct zhpe_common_hdr hdr;
    uint64_t            seq;
};

struct zhpe_req_QALLOC {
    struct zhpe_common_hdr hdr;
    uint32_t            qlen;
};

struct zhpe_rsp_QALLOC {
    struct zhpe_common_hdr hdr;
    struct zhpe_info   info;
};

struct zhpe_req_QFREE {
    struct zhpe_common_hdr hdr;
    struct zhpe_info   info;
};

struct zhpe_rsp_QFREE {
    struct zhpe_common_hdr hdr;
};

struct zhpe_req_ZMMU_REG {
    struct zhpe_common_hdr hdr;
    union zhpe_mr_desc  desc;
};

struct zhpe_rsp_ZMMU_REG {
    struct zhpe_common_hdr hdr;
    union zhpe_mr_desc  desc;
};

struct zhpe_req_ZMMU_DEREG {
    struct zhpe_common_hdr hdr;
    union zhpe_mr_desc  desc;
};

struct zhpe_rsp_ZMMU_DEREG {
    struct zhpe_common_hdr hdr;
};

struct zhpe_req_HELPER_EXIT {
    struct zhpe_common_hdr hdr;
};

struct zhpe_rsp_HELPER_EXIT {
    struct zhpe_common_hdr hdr;
};

struct zhpe_req_HELPER_INIT {
    struct zhpe_common_hdr hdr;
    uint64_t            shared_offset;
    uint64_t            shared_size;
};

struct zhpe_rsp_HELPER_INIT {
    struct zhpe_common_hdr hdr;
};

struct zhpe_req_HELPER_NOP {
    struct zhpe_common_hdr hdr;
    uint64_t            seq;
};

struct zhpe_rsp_HELPER_NOP {
    struct zhpe_common_hdr hdr;
    uint64_t            seq;
};

union zhpe_req {
    struct zhpe_common_hdr hdr;
    struct zhpe_req_INIT init;
    struct zhpe_req_MR_REG mr_reg;
    struct zhpe_req_MR_DEREG mr_dereg;
    struct zhpe_req_NOP nop;
    struct zhpe_req_QALLOC qalloc;
    struct zhpe_req_QFREE qfree;
    struct zhpe_req_ZMMU_REG zmmu_reg;
    struct zhpe_req_ZMMU_DEREG zmmu_dereg;
    struct zhpe_req_HELPER_EXIT helper_exit;
    struct zhpe_req_HELPER_INIT helper_init;
    struct zhpe_req_HELPER_NOP helper_nop;
};

union zhpe_rsp {
    struct zhpe_common_hdr hdr;
    struct zhpe_rsp_INIT init;
    struct zhpe_rsp_MR_REG mr_reg;
    struct zhpe_rsp_MR_DEREG mr_dereg;
    struct zhpe_rsp_NOP nop;
    struct zhpe_rsp_QALLOC qalloc;
    struct zhpe_rsp_QFREE qfree;
    struct zhpe_rsp_ZMMU_REG zmmu_reg;
    struct zhpe_rsp_ZMMU_DEREG zmmu_dereg;
    struct zhpe_rsp_HELPER_EXIT helper_exit;
    struct zhpe_rsp_HELPER_INIT helper_init;
    struct zhpe_rsp_HELPER_NOP helper_nop;
};

union zhpe_op {
    struct zhpe_common_hdr hdr;
    union zhpe_req     req;
    union zhpe_rsp     rsp;
};

#define ZHPE_SHARED_VERSION    (1)

struct zhpe_shared_data {
    uint                magic;
    uint                version;
    uint                debug_flags;
    struct zhpeq_attr   default_attr;
};

#define ZHPE_HW_ENTRY_LEN (64)

enum {
    ZHPE_HW_OPCODE_NONE = 0,
    ZHPE_HW_OPCODE_NOP,
    ZHPE_HW_OPCODE_ENQA,
    ZHPE_HW_OPCODE_PUT,
    ZHPE_HW_OPCODE_GET,
    ZHPE_HW_OPCODE_PUTIMM,
    ZHPE_HW_OPCODE_GETIMM,
    ZHPE_HW_OPCODE_ATM_SWAP = 0x20,
    ZHPE_HW_OPCODE_ATM_ADD = 0x22,
    ZHPE_HW_OPCODE_ATM_AND = 0x24,
    ZHPE_HW_OPCODE_ATM_OR = 0x25,
    ZHPE_HW_OPCODE_ATM_XOR = 0x26,
    ZHPE_HW_OPCODE_ATM_SMIN = 0x28,
    ZHPE_HW_OPCODE_ATM_SMAX = 0x29,
    ZHPE_HW_OPCODE_ATM_UMIN = 0x2a,
    ZHPE_HW_OPCODE_ATM_UMAX = 0x2b,
    ZHPE_HW_OPCODE_ATM_CAS = 0x2c,
    ZHPE_HW_OPCODE_FENCE = 0x100,

    ZHPE_HW_ATOMIC_RETURN = 0x01,
    ZHPE_HW_ATOMIC_SIZE_MASK = 0x0E,
    ZHPE_HW_ATOMIC_SIZE_32 = 0x04,
    ZHPE_HW_ATOMIC_SIZE_64 = 0x0C,
};

/* Timestamps are for SW timing use. */

struct zhpe_hw_wq_hdr {
    uint16_t            opcode;
    uint16_t            cmp_index;
};

struct zhpe_hw_wq_nop {
    struct zhpe_hw_wq_hdr hdr;
    struct zhpeq_timing_stamp timestamp;
};

struct zhpe_hw_wq_dma {
    struct zhpe_hw_wq_hdr hdr;
    uint32_t            len;
    uint64_t            lcl_addr;
    uint64_t            rem_addr;
    struct zhpeq_timing_stamp timestamp;
};

struct zhpe_hw_wq_imm {
    struct zhpe_hw_wq_hdr hdr;
    uint32_t            len;
    uint64_t            rem_addr;
    struct zhpeq_timing_stamp timestamp;
    uint8_t             filler[4];
    uint8_t             data[ZHPEQ_IMM_MAX];
};

struct zhpe_hw_wq_atomic {
    struct zhpe_hw_wq_hdr hdr;
    uint8_t             size;
    uint8_t             filler1[3];
    uint64_t            rem_addr;
    struct zhpeq_timing_stamp timestamp;
    uint8_t             filler2[4];
    union zhpeq_atomic  operands[2];
};

union zhpe_hw_wq_entry {
    struct zhpe_hw_wq_hdr hdr;
    struct zhpe_hw_wq_nop nop;
    struct zhpe_hw_wq_dma dma;
    struct zhpe_hw_wq_imm imm;
    struct zhpe_hw_wq_atomic atm;
    uint8_t             filler[ZHPE_HW_ENTRY_LEN];
};

enum {
    ZHPE_HW_CQ_VALID = 1,
};

union zhpe_hw_cq_entry {
    struct zhpeq_cq_entry entry;
    uint8_t             filler[ZHPE_HW_ENTRY_LEN];
};

typedef volatile uint16_t __attribute__ ((aligned(64))) zhpe_hw_reg16_t;

struct zhpe_hw_reg {
    zhpe_hw_reg16_t     stop;
    zhpe_hw_reg16_t     wq_tail;
    zhpe_hw_reg16_t     wq_head;
    zhpe_hw_reg16_t     cq_tail;
};

int zhpe_driver_cmd(union zhpe_op *buf, size_t req_len, size_t rsp_len);

#endif /* _ZHPE_H_ */
