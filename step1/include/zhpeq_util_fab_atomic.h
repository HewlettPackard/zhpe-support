/*
 * Copyright (c) 2020 Hewlett Packard Enterprise Development LP.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _ZHPEQ_UTIL_FAB_ATOMIC_H_
#define _ZHPEQ_UTIL_FAB_ATOMIC_H_

#include <zhpe_externc.h>
#include <zhpeq_util.h>
#include <rdma/fi_domain.h>

_EXTERN_C_BEG

/*
 * For one operand ops, operand1 is ignored.
 *
 * For two operand ops, operand0 and operand1 usage conforms
 * to the way the zhpe bridge works.
 *
 * FI_CSWAP: 0 is old; 1 is new.
 * FI_MSWAP: 0 is mask; 1 is new.
 */

static inline int zhpeu_fab_atomic_op_u8(enum fi_op op,
                                         uint8_t operand0, uint8_t operand1,
                                         uint8_t *dst, uint64_t *original)
{
    int                 ret = 0;
    uint8_t             old;
    uint8_t             new;

    switch (op) {

    case FI_ATOMIC_READ:
        *original = atm_load_rlx(dst);
        break;

    case FI_ATOMIC_WRITE:
        *original = atm_xchg(dst, operand0);
        break;

    case FI_BAND:
        *original = atm_and(dst, operand0);
        break;

    case FI_BOR:
        *original = atm_or(dst, operand0);
        break;

    case FI_BXOR:
        *original = atm_xor(dst, operand0);
        break;

    case FI_CSWAP:
        atm_cmpxchg(dst, &operand0, operand1);
        *original = operand0;
        break;

    case FI_SUM:
        *original = atm_add(dst, operand0);
        break;

    case FI_MSWAP:
        old = atm_load_rlx(dst);
        for (;;) {
            new = (operand1 & operand0) | (old & ~operand0);
            if (atm_cmpxchg(dst, &old, new))
                break;
        }
        *original = old;
        break;

    default:
        *original = 0;
        ret = -FI_EINVAL;
        break;
    }

    return ret;
}

static inline int zhpeu_fab_atomic_op_u16(enum fi_op op,
                                          uint16_t operand0, uint16_t operand1,
                                          uint16_t *dst, uint64_t *original)
{
    int                 ret = 0;
    uint16_t            old;
    uint16_t            new;

    switch (op) {

    case FI_ATOMIC_READ:
        *original = atm_load_rlx(dst);
        break;

    case FI_ATOMIC_WRITE:
        *original = atm_xchg(dst, operand0);
        break;

    case FI_BAND:
        *original = atm_and(dst, operand0);
        break;

    case FI_BOR:
        *original = atm_or(dst, operand0);
        break;

    case FI_BXOR:
        *original = atm_xor(dst, operand0);
        break;

    case FI_CSWAP:
        atm_cmpxchg(dst, &operand0, operand1);
        *original = operand0;
        break;

    case FI_SUM:
        *original = atm_add(dst, operand0);
        break;

    case FI_MSWAP:
        old = atm_load_rlx(dst);
        for (;;) {
            new = (operand1 & operand0) | (old & ~operand0);
            if (atm_cmpxchg(dst, &old, new))
                break;
        }
        *original = old;
        break;

    default:
        *original = 0;
        ret = -FI_EINVAL;
        break;
    }

    return ret;
}

static inline int zhpeu_fab_atomic_op_u32(enum fi_op op,
                                          uint32_t operand0, uint32_t operand1,
                                          uint32_t *dst, uint64_t *original)
{
    int                 ret = 0;
    uint32_t            old;
    uint32_t            new;

    switch (op) {

    case FI_ATOMIC_READ:
        *original = atm_load_rlx(dst);
        break;

    case FI_ATOMIC_WRITE:
        *original = atm_xchg(dst, operand0);
        break;

    case FI_BAND:
        *original = atm_and(dst, operand0);
        break;

    case FI_BOR:
        *original = atm_or(dst, operand0);
        break;

    case FI_BXOR:
        *original = atm_xor(dst, operand0);
        break;

    case FI_CSWAP:
        atm_cmpxchg(dst, &operand0, operand1);
        *original = operand0;
        break;

    case FI_SUM:
        *original = atm_add(dst, operand0);
        break;

    case FI_MSWAP:
        old = atm_load_rlx(dst);
        for (;;) {
            new = (operand1 & operand0) | (old & ~operand0);
            if (atm_cmpxchg(dst, &old, new))
                break;
        }
        *original = old;
        break;

    default:
        *original = 0;
        ret = -FI_EINVAL;
        break;
    }

    return ret;
}

static inline int zhpeu_fab_atomic_op_u64(enum fi_op op,
                                          uint64_t operand0, uint64_t operand1,
                                          uint64_t *dst, uint64_t *original)
{
    int                 ret = 0;
    uint64_t            old;
    uint64_t            new;

    switch (op) {

    case FI_ATOMIC_READ:
        *original = atm_load_rlx(dst);
        break;

    case FI_ATOMIC_WRITE:
        *original = atm_xchg(dst, operand0);
        break;

    case FI_BAND:
        *original = atm_and(dst, operand0);
        break;

    case FI_BOR:
        *original = atm_or(dst, operand0);
        break;

    case FI_BXOR:
        *original = atm_xor(dst, operand0);
        break;

    case FI_CSWAP:
        atm_cmpxchg(dst, &operand0, operand1);
        *original = operand0;
        break;

    case FI_SUM:
        *original = atm_add(dst, operand0);
        break;

    case FI_MSWAP:
        old = atm_load_rlx(dst);
        for (;;) {
            new = (operand1 & operand0) | (old & ~operand0);
            if (atm_cmpxchg(dst, &old, new))
                break;
        }
        *original = old;
        break;

    default:
        *original = 0;
        ret = -FI_EINVAL;
        break;
    }

    return ret;
}

static inline int zhpeu_fab_atomic_op(enum fi_datatype type, enum fi_op op,
                                      uint64_t operand0, uint64_t operand1,
                                      void *dst, uint64_t *original)
{
    int                 ret;

    switch (type) {

    case FI_UINT8:
        ret = zhpeu_fab_atomic_op_u8(op, operand0, operand1, dst, original);
        break;

    case FI_UINT16:
        ret = zhpeu_fab_atomic_op_u16(op, operand0, operand1, dst, original);
        break;

    case FI_UINT32:
        ret = zhpeu_fab_atomic_op_u32(op, operand0, operand1, dst, original);
        break;

    case FI_UINT64:
        ret = zhpeu_fab_atomic_op_u64(op, operand0, operand1, dst, original);
        break;

    default:
        *original = 0;
        ret = -FI_EINVAL;
        break;
    }

    return ret;
}

static inline int zhpeu_fab_atomic_load(enum fi_datatype type,
                                        const void *src, uint64_t *value)
{
    int                 ret = 0;

    switch (type) {

    case FI_UINT8:
        *value = atm_load_rlx((const uint8_t *)src);
        break;

    case FI_UINT16:
        *value = atm_load_rlx((const uint16_t *)src);
        break;

    case FI_UINT32:
        *value = atm_load_rlx((const uint32_t *)src);
        break;

    case FI_UINT64:
        *value = atm_load_rlx((const uint64_t *)src);
        break;

    default:
        ret = -FI_EINVAL;
        break;
    }

    return ret;
}

static inline int zhpeu_fab_atomic_store(enum fi_datatype type,
                                         void *dst, uint64_t value)
{
    int                 ret = 0;

    switch (type) {

    case FI_UINT8:
        atm_store_rlx((uint8_t *)dst, (uint8_t)value);
        break;

    case FI_UINT16:
        atm_store_rlx((uint16_t *)dst, (uint16_t)value);
        break;

    case FI_UINT32:
        atm_store_rlx((uint32_t *)dst, (uint32_t)value);
        break;

    case FI_UINT64:
        atm_store_rlx((uint64_t *)dst, (uint64_t)value);
        break;

    default:
        ret = -FI_EINVAL;
        break;
    }

    return ret;
}

static inline int zhpeu_fab_atomic_copy(enum fi_datatype type,
                                        const void *src, void *dst)
{
    int                 ret = 0;
    uint64_t            value;

    switch (type) {

    case FI_UINT8:
        value = atm_load_rlx((const uint8_t *)src);
        atm_store_rlx((uint8_t *)dst, (uint8_t)value);
        break;

    case FI_UINT16:
        value = atm_load_rlx((const uint16_t *)src);
        atm_store_rlx((uint16_t *)dst, (uint16_t)value);
        break;

    case FI_UINT32:
        value = atm_load_rlx((const uint32_t *)src);
        atm_store_rlx((uint32_t *)dst, (uint32_t)value);
        break;

    case FI_UINT64:
        value = atm_load_rlx((const uint64_t *)src);
        atm_store_rlx((uint64_t *)dst, (uint64_t)value);
        break;

    default:
        ret = -FI_EINVAL;
        break;
    }

    return ret;
}

_EXTERN_C_END

#endif /* _ZHPEQ_UTIL_FAB_ATOMIC_H_ */
