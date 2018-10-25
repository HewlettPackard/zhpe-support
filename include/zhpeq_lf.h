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

#ifndef _ZHPEQ_LF_H_
#define _ZHPEQ_LF_H_

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

#include <zhpeq_util_fab.h>

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

void zhpel_mpi_exit(int status) __attribute__ ((__noreturn__));

#define MPI_ERRCHK(_func, _args)                                        \
({                                                                      \
    int                 __rc = _func _args;                             \
                                                                        \
    if (__rc != MPI_SUCCESS) {                                          \
        print_err("%s,%u:%s returned %d\n",                             \
                  __func__, __LINE__, #_func, __rc);                    \
        zhpel_mpi_exit(1);                                              \
    }                                                                   \
    __rc;                                                               \
})

#define FI_ERRCHK(_func, _args)                                         \
({                                                                      \
    int                 __rc = _func _args;                             \
                                                                        \
    if (__rc < 0) {                                                     \
        print_err("%s,%u:%s returned %d:%s\n",                          \
                  __func__, __LINE__, #_func, __rc,                     \
                  fi_strerror(-__rc));                                  \
        zhpel_mpi_exit(1);                                              \
    }                                                                   \
    __rc;                                                               \
})

#define FI_EAGAINOK(_func, _args, _cntr)                                \
({                                                                      \
    struct fid_cntr     *__cntr = (_cntr);                              \
    uint64_t            __cval;                                         \
    int                 __rc;                                           \
                                                                        \
    for (;;) {                                                          \
        __rc = _func _args;                                             \
        if (__rc >= 0)                                                  \
            break;                                                      \
        if (__rc != -FI_EAGAIN) {                                       \
            print_err("%s,%u:%s returned %d:%s\n",                      \
                      __func__, __LINE__, #_func, __rc,                 \
                      fi_strerror(-__rc));                              \
            zhpel_mpi_exit(1);                                          \
        }                                                               \
        __cval = fi_cntr_read(__cntr);                                  \
        /* Try to drive progress forward. */                            \
        __rc = fi_cntr_wait(__cntr, __cval + 1, 1);                     \
        if (__rc < 0 && __rc != -FI_ETIMEDOUT) {                        \
            __rc = fi_cntr_wait(__cntr, __cval + 1, 1);                 \
            print_err("%s,%u:%s returned %d:%s\n",                      \
                      __func__, __LINE__, "fi_cntr_wait", __rc,         \
                      fi_strerror(-__rc));                              \
            zhpel_mpi_exit(1);                                          \
        }                                                               \
    }                                                                   \
    __rc;                                                               \
})

#define ERRCHK(_func, _args)                                            \
({                                                                      \
    long         __rc = _func _args;                                    \
                                                                        \
    if (__rc == -1) {                                                   \
        __rc = errno;                                                   \
        print_err("%s,%u:%s errno %ld:%s\n",                            \
                  __func__, __LINE__, #_func, __rc, strerror(__rc));    \
        zhpel_mpi_exit(1);                                              \
    }                                                                   \
    __rc;                                                               \
})

#define NULLCHK(_func, _args)                                           \
({                                                                      \
    void        *__rp = _func _args;                                    \
                                                                        \
    if (__rp == NULL) {                                                 \
        print_err("%s,%u:%s returned NULL\n",                           \
                  __func__, __LINE__, #_func);                          \
        zhpel_mpi_exit(1);                                              \
    }                                                                   \
    __rp;                                                               \
})

#define POSIX_ERRCHK(_func, _args)                                      \
({                                                                      \
    int         __rc = _func _args;                                     \
                                                                        \
    if (__rc > 0) {                                                     \
        print_err("%s,%u:%s errno %d:%s\n",                             \
                  __func__, __LINE__, #_func, __rc, strerror(__rc));    \
        zhpel_mpi_exit(1);                                              \
    }                                                                   \
    __rc;                                                               \
})

#define ZHPEL_RKEY              (65536)

struct zhpel_eps {
    size_t              n_eps;
    size_t              per_thr_size;
    void                *mem;
    struct fid_ep       **eps;
    struct fid_cntr     **rcnts;
    struct fid_cntr     **wcnts;
    bool                tx;
};


struct zhpel_data {
    struct fi_info      *fi;
    struct fid_fabric   *fabric;
    struct fid_domain   *domain;
    struct fid_av       *av;
    struct fid_ep       *sep;
    void                *mem;
    size_t              mem_size;
    size_t              mem_off;
    struct fid_mr       *mr;
    struct zhpel_eps    cli;
    struct zhpel_eps    svr;
    size_t              rank;
    bool                use_rma_events;
};

void zhpel_init(struct zhpel_data *lf_data, const char *provider,
                const char *domain, bool use_sep, bool use_rma_events,
                size_t rank, size_t n_ranks, size_t cli_per_thr_size,
                size_t svr_per_thr_size);

void zhpel_destroy(struct zhpel_data *lf_data);

_EXTERN_C_END

#ifdef _EXTERN_C_SET
#undef _EXTERN_C_SET
#undef _EXTERN_C_BEG
#undef _EXTERN_C_END
#endif

#endif /* _ZHPEQ_LF_H_ */
