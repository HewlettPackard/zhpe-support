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

#define ZHPEU_FAB_ATOMIC_OP_SIZE(_size, _op, _operand0, _operand1,      \
                                 _dst, _original, _status)              \
do {                                                                    \
    uint ## _size ## _t *__dst = (_dst);                                \
    uint ## _size ## _t __operand0 = (_operand0);                       \
    uint ## _size ## _t __operand1 = (_operand1);                       \
    uint ## _size ## _t __old;                                          \
    uint ## _size ## _t __new;                                          \
                                                                        \
    (_status) = 0;                                                      \
                                                                        \
    switch(_op) {                                                       \
                                                                        \
    case FI_ATOMIC_READ:                                                \
        (_original) = atm_load_rlx(__dst);                              \
        break;                                                          \
                                                                        \
    case FI_ATOMIC_WRITE:                                               \
        (_original) = atm_xchg(__dst, __operand0);                      \
        break;                                                          \
                                                                        \
    case FI_BAND:                                                       \
        (_original) = atm_and(__dst, __operand0);                       \
        break;                                                          \
                                                                        \
    case FI_BOR:                                                        \
        (_original) = atm_or(__dst, __operand0);                        \
        break;                                                          \
                                                                        \
    case FI_BXOR:                                                       \
        (_original) = atm_xor(__dst, __operand0);                       \
        break;                                                          \
                                                                        \
    case FI_CSWAP:                                                      \
        atm_cmpxchg(__dst, &__operand0, __operand1);                    \
        (_original) = __operand0;                                       \
        break;                                                          \
                                                                        \
    case FI_SUM:                                                        \
        (_original) = atm_add(__dst, __operand0);                       \
        break;                                                          \
                                                                        \
    case FI_MSWAP:                                                      \
        __old = atm_load_rlx(__dst);                                    \
        for (;;) {                                                      \
            __new = (__operand1 & __operand0) | (__old & ~__operand0);  \
            if (atm_cmpxchg(__dst, &__old, __new))                      \
                break;                                                  \
        }                                                               \
        (_original) = __old;                                            \
        break;                                                          \
                                                                        \
    default:                                                            \
        (_original) = 0;                                                \
        (_status) = -FI_EINVAL;                                         \
        break;                                                          \
    }                                                                   \
} while(0)

#define ZHPEU_FAB_ATOMIC_LOAD_SIZE(_size, _src, _value)                 \
do {                                                                    \
    const uint ## _size ## _t   *__src = (_src);                        \
                                                                        \
    (_value) = atm_load_rlx(__src);                                     \
} while(0)

#define ZHPEU_FAB_ATOMIC_STORE_SIZE(_size, _dst, _value)                \
do {                                                                    \
    uint ## _size ## _t *__dst = (_dst);                                \
    uint ## _size ## _t __value = (_value);                             \
                                                                        \
    atm_store_rlx(__dst, __value);                                      \
} while(0)

#define ZHPEU_FAB_ATOMIC_COPY_SIZE(_size, _src, _dst)                   \
do {                                                                    \
    const uint ## _size ## _t   *__src = (_src);                        \
    uint ## _size ## _t *__dst = (_dst);                                \
    uint ## _size ## _t __value;                                        \
                                                                        \
    __value = atm_load_rlx(__src);                                      \
    atm_store_rlx(__dst, __value);                                      \
} while(0)

static inline int
zhpeu_fab_atomic_op(enum fi_datatype type, enum fi_op op, uint64_t operand,
                    uint64_t compare, void *dst, uint64_t *original)
{
    int                 ret = 0;
    uint64_t            orig;

    switch (type) {

    case FI_UINT8:
        ZHPEU_FAB_ATOMIC_OP_SIZE(8,  op, operand, compare, dst, orig, ret);
        break;

    case FI_UINT16:
        ZHPEU_FAB_ATOMIC_OP_SIZE(16, op, operand, compare, dst, orig, ret);
        break;

    case FI_UINT32:
        ZHPEU_FAB_ATOMIC_OP_SIZE(32, op, operand, compare, dst, orig, ret);
        break;

    case FI_UINT64:
        ZHPEU_FAB_ATOMIC_OP_SIZE(64, op, operand, compare, dst, orig, ret);
        break;

    default:
        orig = 0;
        ret = -FI_EINVAL;
        break;
    }

    if (original)
        *original = orig;

    return ret;
}

static inline int zhpeu_fab_atomic_load(enum fi_datatype type,
                                        const void *dst, uint64_t *value)
{
    int                 ret = 0;

    switch (type) {

    case FI_UINT8:
        ZHPEU_FAB_ATOMIC_LOAD_SIZE(8,  dst, *value);
        break;

    case FI_UINT16:
        ZHPEU_FAB_ATOMIC_LOAD_SIZE(16, dst, *value);
        break;

    case FI_UINT32:
        ZHPEU_FAB_ATOMIC_LOAD_SIZE(32, dst, *value);
        break;

    case FI_UINT64:
        ZHPEU_FAB_ATOMIC_LOAD_SIZE(64, dst, *value);
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
        ZHPEU_FAB_ATOMIC_STORE_SIZE(8,  dst, value);
        break;

    case FI_UINT16:
        ZHPEU_FAB_ATOMIC_STORE_SIZE(16, dst, value);
        break;

    case FI_UINT32:
        ZHPEU_FAB_ATOMIC_STORE_SIZE(32, dst, value);
        break;

    case FI_UINT64:
        ZHPEU_FAB_ATOMIC_STORE_SIZE(64, dst, value);
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

    switch (type) {

    case FI_UINT8:
        ZHPEU_FAB_ATOMIC_COPY_SIZE(8,  src, dst);
        break;

    case FI_UINT16:
        ZHPEU_FAB_ATOMIC_COPY_SIZE(16, src, dst);
        break;

    case FI_UINT32:
        ZHPEU_FAB_ATOMIC_COPY_SIZE(32, src, dst);
        break;

    case FI_UINT64:
        ZHPEU_FAB_ATOMIC_COPY_SIZE(64, src, dst);
        break;

    default:
        ret = -FI_EINVAL;
        break;
    }

    return ret;
}

_EXTERN_C_END

#endif /* _ZHPEQ_UTIL_FAB_ATOMIC_H_ */
