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

#define _GNU_SOURCE
#include <internal.h>

#include <cpuid.h>
#include <ctype.h>
#include <dlfcn.h>
#include <jansson.h>
#include <limits.h>

#define LIBNAME         "libzhpeq"

static_assert(sizeof(union zhpe_hw_wq_entry) ==  ZHPE_ENTRY_LEN,
              "zhpe_hw_wq_entry");
static_assert(sizeof(union zhpe_hw_cq_entry) ==  ZHPE_ENTRY_LEN,
              "zhpe_hw_cq_entry");
static_assert(sizeof(union zhpe_hw_rdm_entry) ==  ZHPE_ENTRY_LEN,
              "zhpe_hw_cq_entry");
static_assert(__BYTE_ORDER == __LITTLE_ENDIAN, "Only little endian supported");
static_assert(__x86_64__, "x86-64");

/* Set to 1 to dump qkdata when registered/exported/imported/freed. */
#define QKDATA_DUMP     (0)

static pthread_mutex_t  init_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t  zaddr_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct zhpeq_attr b_attr;

static void insert_none(struct zhpeq_tq *ztq, uint16_t reservation16)
{
}

zhpeq_tq_entry_insert_fn zhpeq_insert_fn[ZHPEQ_INSERT_LEN] = {
    [ZHPEQ_INSERT_NONE] = insert_none,
};

void                    (*zhpeq_mcommit)(void);
uuid_t                  zhpeq_uuid;

static inline union zhpe_hw_wq_entry *tq_get_wq(struct zhpeq_tq *ztq)
{
    size_t              i = ztq->wq_tail++ & (ztq->tqinfo.cmdq.ent - 1);

    return &ztq->wq[i];
}

static void cmd_insert64(struct zhpeq_tq *ztq, uint16_t reservation16)
{
    union zhpe_hw_wq_entry *src = &ztq->mem[reservation16];
    union zhpe_hw_wq_entry *dst = &ztq->cmd[reservation16];
    size_t              i;

    src->hdr.cmp_index = reservation16;
    assert(!(src->hdr.opcode & ZHPE_HW_OPCODE_FENCE));
    for (i = 1; i < ARRAY_SIZE(dst->bytes8); i++)
        iowrite64(src->bytes8[i], &dst->bytes8[i]);
    iowrite64(src->bytes8[0], &dst->bytes8[0]);
    ztq->cmd_queued++;
}

static void mem_insert64(struct zhpeq_tq *ztq, uint16_t reservation16)
{
    union zhpe_hw_wq_entry *src = &ztq->mem[reservation16];
    union zhpe_hw_wq_entry *dst = tq_get_wq(ztq);

    src->hdr.cmp_index = reservation16;
    memcpy(dst, src, sizeof(*dst));
}

static void cmd_insert128(struct zhpeq_tq *ztq, uint16_t reservation16)
{
    union zhpe_hw_wq_entry *src = &ztq->mem[reservation16];
    union zhpe_hw_wq_entry *dst = &ztq->cmd[reservation16];

    src->hdr.cmp_index = reservation16;
    assert(!(src->hdr.opcode & ZHPE_HW_OPCODE_FENCE));
    asm volatile (
        "vmovdqa   (%[s]), %%xmm0\n"
        "vmovdqa 16(%[s]), %%xmm1\n"
        "vmovdqa 32(%[s]), %%xmm2\n"
        "vmovdqa 48(%[s]), %%xmm3\n"
        "vmovdqa   %%xmm1, 16(%[d])\n"
        "vmovdqa   %%xmm2, 32(%[d])\n"
        "vmovdqa   %%xmm3, 48(%[d])\n"
        "vmovdqa   %%xmm0,   (%[d])\n"
        : "=m" (*dst): [s] "r" (src), [d] "r" (dst)
        : "%xmm0", "%xmm1", "%xmm2", "%xmm3");
    ztq->cmd_queued++;
}

static void cmd_insert256(struct zhpeq_tq *ztq, uint16_t reservation16)
{
    union zhpe_hw_wq_entry *src = &ztq->mem[reservation16];
    union zhpe_hw_wq_entry *dst = &ztq->cmd[reservation16];

    src->hdr.cmp_index = reservation16;
    assert(!(src->hdr.opcode & ZHPE_HW_OPCODE_FENCE));
    asm volatile (
        "vmovdqa   (%[s]), %%ymm0\n"
        "vmovdqa 32(%[s]), %%ymm1\n"
        "vmovdqa   %%ymm1, 32(%[d])\n"
        "vmovdqa   %%ymm0,   (%[d])\n"
        : "=m" (*dst) : [s] "r" (src), [d] "r" (dst) : "%ymm0", "%ymm1");
    ztq->cmd_queued++;
}

static void mem_insert256(struct zhpeq_tq *ztq, uint16_t reservation16)
{
    union zhpe_hw_wq_entry *src = &ztq->mem[reservation16];
    union zhpe_hw_wq_entry *dst = tq_get_wq(ztq);

    src->hdr.cmp_index = reservation16;
    asm volatile (
        "vmovdqa   (%[s]), %%ymm0\n"
        "vmovdqa 32(%[s]), %%ymm1\n"
        "vmovntdq  %%ymm0,   (%[d])\n"
        "vmovntdq  %%ymm1, 32(%[d])\n"
        : "=m" (*dst) : [s] "r" (src), [d] "r" (dst) : "%ymm0", "%ymm1");
}

static void do_mcommit(void)
{
    mcommit();
}

static void no_mcommit(void)
{
}

#ifdef ZHPEQ_DIRECT

#define CPUID_0000_0007                 (0x00000007)
#define CPUID_0000_0007_SUB_0           (0x0)
#define CPUID_0000_0007_SUB_0_EBX_AVX2  (0x20)

static void __attribute__((constructor)) lib_init(void)
{
    uint                eax;
    uint                ebx;
    uint                ecx;
    uint                edx;

    /* Defaults for Carbon. */
    zhpeq_insert_fn[ZHPEQ_INSERT_CMD] = cmd_insert64;
    zhpeq_insert_fn[ZHPEQ_INSERT_MEM] = mem_insert64;
    zhpeq_mcommit = no_mcommit;

    /*
     * Both Naples and Rome support AVX2, Carbon does not. Naples
     * supports 16 byte UC writes, Rome supports 32. I will assume
     * MCOMMIT cannot be enabled if AVX2 isn't supported and that
     * MCOMMIT is a good proxy for 32 byte UC writes.
     *
     * The driver won't load on Intel platforms, so I'm not going
     * to bother verifying AMD CPUs, here.
     */
    if (__get_cpuid_count(CPUID_0000_0007, CPUID_0000_0007_SUB_0,
                          &eax, &ebx, &ecx, &edx) &&
        (ebx & CPUID_0000_0007_SUB_0_EBX_AVX2)) {
        zhpeq_insert_fn[ZHPEQ_INSERT_MEM] = mem_insert256;
        /*
         * We assume the driver enabled mcommit if it is possible.
         * Since mcommit is supported on Rome and not on Naples, I'll
         * use that as test the PCI 32-byte writes work.
         */
        if (__get_cpuid(CPUID_8000_0008, &eax, &ebx, &ecx, &edx) &&
            (ebx & CPUID_8000_0008_EBX_MCOMMIT)) {
            zhpeq_mcommit = do_mcommit;
            zhpeq_insert_fn[ZHPEQ_INSERT_CMD] = cmd_insert256;
        } else
            zhpeq_insert_fn[ZHPEQ_INSERT_CMD] = cmd_insert128;
    }
    if (getenv("ZHPEQ_DISABLE_CMD_BUF"))
        zhpeq_insert_fn[ZHPEQ_INSERT_CMD] = zhpeq_insert_fn[ZHPEQ_INSERT_MEM];
}

#include "../step2/libzhpeq_backend/backend_zhpe.c"

#else

#error optional indirect support unfinished

#define BACKNAME        "libzhpeq_backend.so"

static bool             b_zhpe;
static struct backend_ops *b_ops;

static void __attribute__((constructor)) lib_init(void)
{
    void                *dlhandle = dlopen(BACKNAME, RTLD_NOW);

    if (!dlhandle) {
        zhpeu_print_err("Failed to load %s:%s\n", BACKNAME, dlerror());
        abort();
    }
}

void zhpeq_register_backend(enum zhpeq_backend backend, struct backend_ops *ops)
{
    /* For the moment, the zhpe backend will only register if the zhpe device
     * can be opened and the libfabric backend will only register if the zhpe
     * device can't be opened.
     */

    switch (backend) {

    case ZHPEQ_BACKEND_LIBFABRIC:
        b_ops = ops;
        break;

    case ZHPEQ_BACKEND_ZHPE:
        b_zhpe = true;
        b_ops = ops;
        break;

    default:
        zhpeu_print_err("Unexpected backed %d\n", backend);
        break;
    }
}

#endif

int zhpeq_init(int api_version, struct zhpeq_attr *attr)
{
    int                 ret = -EINVAL;
    static int          init_status = 1;

    if (!zhpeu_expected_saw("api_version", ZHPEQ_API_VERSION, api_version))
        goto done;

    if (init_status > 0) {
        mutex_lock(&init_mutex);
        if (init_status > 0) {
            ret = zhpe_lib_init(&b_attr);
            init_status = (ret <= 0 ? ret : 0);
        }
        mutex_unlock(&init_mutex);
    }
    ret = init_status;
    if (!ret && attr)
        *attr = b_attr;

 done:
    return ret;
}

int zhpeq_query_attr(struct zhpeq_attr *attr)
{
    int                 ret = -EINVAL;

    /* Compatibility handling is left for another day. */
    if (!attr)
        goto done;

    *attr = b_attr;
    ret = 0;

 done:
    return ret;
}

int zhpeq_domain_free(struct zhpeq_dom *zqdom)
{
    int                 ret = 0;
    struct zhpeq_domi   *zqdomi = container_of(zqdom, struct zhpeq_domi, zqdom);

    if (!zqdom)
        goto done;

    ret = zhpe_domain_free(zqdomi);
    free(zqdomi);

 done:
    return ret;
}

int zhpeq_domain_alloc(struct zhpeq_dom **zqdom_out)
{
    int                 ret = -EINVAL;
    struct zhpeq_domi   *zqdomi = NULL;

    if (!zqdom_out)
        goto done;
    *zqdom_out = NULL;

    zqdomi = xcalloc_cachealigned(1, sizeof(*zqdomi));

    ret = zhpe_domain(zqdomi);

 done:
    if (ret >= 0)
        *zqdom_out = &zqdomi->zqdom;
    else
        free(zqdomi);

    return ret;
}

int zhpeq_domain_insert_addr(struct zhpeq_dom *zqdom, void *sa,
                             void **addr_cookie)
{
    int                 ret = -EINVAL;
    struct zhpeq_domi   *domi = container_of(zqdom, struct zhpeq_domi, zqdom);

    if (!addr_cookie)
        goto done;
    *addr_cookie = NULL;
    if (!zqdom)
        goto done;

    ret = zhpe_domain_insert_addr(domi, sa, addr_cookie);

 done:
    return ret;
}

int zhpeq_domain_remove_addr(struct zhpeq_dom *zqdom, void *addr_cookie)
{
    int                 ret = -EINVAL;
    struct zhpeq_domi   *domi = container_of(zqdom, struct zhpeq_domi, zqdom);

    if (!zqdom)
        goto done;
    if (!addr_cookie) {
        ret = 0;
        goto done;
    }

    ret = zhpe_domain_remove_addr(domi, addr_cookie);

 done:
    return ret;
}

static union xdm_active ztq_stopped_wait(struct zhpeq_tq *ztq)
{
    union xdm_active    active;

    for (;;) {
        active.u64 = qcmread64(ztq->qcm,
                               ZHPE_XDM_QCM_ACTIVE_STATUS_ERROR_OFFSET);
        if (!active.bits.active)
            break;
        yield();
    }

    return active;
}

static union xdm_active ztq_stop(struct zhpeq_tq *ztq)
{
    qcmwrite64(1, ztq->qcm, ZHPE_XDM_QCM_STOP_OFFSET);

    return ztq_stopped_wait(ztq);
}

int zhpeq_tq_restart(struct zhpeq_tq *ztq)
{
    int                 ret = -EINVAL;
    union xdm_active    active;

    if (!ztq)
        goto done;

    ret = 0;
    active = ztq_stop(ztq);
    if (active.bits.error) {
        ret = -EIO;
        if (active.bits.status != ZHPE_XDM_QCM_STATUS_CMD_ERROR)
            zhpeu_print_err("%s,%u:status %u\n",
                            __func__, __LINE__, active.bits.status);
    }
    qcmwrite64(0, ztq->qcm, ZHPE_XDM_QCM_STOP_OFFSET);

 done:
    return ret;
}

int zhpeq_tq_free(struct zhpeq_tq *ztq)
{
    int                 ret = 0;
    struct zhpeq_tqi    *tqi = container_of(ztq, struct zhpeq_tqi, ztq);
    int                 rc;

    if (!ztq)
        goto done;

    /* Stop the queue. */
    if (ztq->qcm)
        ztq_stop(ztq);

    ret = zhpeu_update_error(ret, zhpe_tq_free_pre(tqi));

    /* Unmap qcm, wq, and cq. */
    rc = _zhpeu_munmap((void *)ztq->qcm, ztq->tqinfo.qcm.size);
    ret = zhpeu_update_error(ret, rc);
    rc = _zhpeu_munmap(ztq->wq, ztq->tqinfo.cmdq.size);
    ret = zhpeu_update_error(ret, rc);
    rc = _zhpeu_munmap((void *)ztq->cq, ztq->tqinfo.cmplq.size);
    ret = zhpeu_update_error(ret, rc);

    /* Call the driver to free the queue. */
    if (ztq->tqinfo.qcm.size)
        ret = zhpeu_update_error(ret, zhpe_tq_free(tqi));

    /* Free queue memory. */
    free(ztq->ctx);
    free(ztq->mem);
    free(ztq->free_bitmap);
    free(tqi);

 done:
    return ret;
}

int zhpeq_tq_alloc(struct zhpeq_dom *zqdom, int cmd_qlen, int cmp_qlen,
                   int traffic_class, int priority, int slice_mask,
                   struct zhpeq_tq **ztq_out)
{
    int                 ret = -EINVAL;
    struct zhpeq_tqi    *tqi = NULL;
    struct zhpeq_tq     *ztq = NULL;
    union xdm_cmp_tail  tail = {
        .bits.toggle_valid = 1,
    };
    int                 flags;
    size_t              i;
    size_t              e;
    size_t              orig;

    if (!ztq_out)
        goto done;
    *ztq_out = NULL;
    if (!zqdom || cmp_qlen < cmd_qlen ||
        cmd_qlen < 1 || cmd_qlen > b_attr.z.max_tx_qlen ||
        cmp_qlen < 1 || cmp_qlen > b_attr.z.max_tx_qlen ||
        traffic_class < 0 || traffic_class > ZHPEQ_MAX_TC ||
        priority < 0 || priority > ZHPEQ_MAX_PRIO ||
        (slice_mask & ~(ALL_SLICES | SLICE_DEMAND)))
        goto done;

    ret = -ENOMEM;
    tqi = calloc_cachealigned(1, sizeof(*tqi));
    if (!tqi)
        goto done;
    ztq = &tqi->ztq;
    ztq->zqdom = zqdom;
    tqi->dev_fd = -1;

    /*
     * Questions:
     * 1.) Code is much cleaner if I actually allocate to a power of 2,
     * but I could still honor the actual size and I am not.
     * A comment:
     * I really can't allocate less than a page the queue, 64 entries, and my
     * bitmap chunks are 64 bits, so it really seems easiest just to force
     * 64 as the minimum allocation.
     */
    orig = cmd_qlen;
    cmd_qlen = max(roundup_pow_of_2(cmd_qlen), (uint64_t)ZHPEQ_BITMAP_BITS);
    if (cmd_qlen == orig)
        cmd_qlen *= 2;
    orig = cmp_qlen;
    cmp_qlen = max(roundup_pow_of_2(cmp_qlen), (uint64_t)ZHPEQ_BITMAP_BITS);
    if (cmp_qlen == orig)
        cmp_qlen *= 2;

    ret = zhpe_tq_alloc(tqi, cmd_qlen, cmp_qlen, traffic_class,
                        priority, slice_mask);
    if (ret < 0)
        goto done;

    ret = -ENOMEM;
    e = ztq->tqinfo.cmdq.ent - 1;
    ztq->ctx = calloc_cachealigned(e, sizeof(*ztq->ctx));
    if (!ztq->ctx)
        goto done;
    ztq->mem = calloc_cachealigned(e, sizeof(*ztq->mem));
    if (!ztq->mem)
        goto done;
    e = (e >> ZHPEQ_BITMAP_SHIFT) + 1;
    ztq->free_bitmap = calloc_cachealigned(e, sizeof(*ztq->free_bitmap));
    if (!ztq->free_bitmap)
        goto done;

    /* Initial free_bitmap. */
    for (i = 0; i < e; i++)
        ztq->free_bitmap[i] = ~(uint64_t)0;
    ztq->free_bitmap[e - 1] &= ~((uint64_t)1 << (ZHPEQ_BITMAP_BITS - 1));

    /* tqi->dev_fd == -1 means we're faking things out. */
    flags = (tqi->dev_fd == -1 ? MAP_ANONYMOUS | MAP_PRIVATE : MAP_SHARED);

    /* Map qcm, wq, and cq. */
    ztq->qcm = _zhpeu_mmap(NULL, ztq->tqinfo.qcm.size, PROT_READ | PROT_WRITE,
                           flags, tqi->dev_fd, ztq->tqinfo.qcm.off);
    if (!ztq->qcm) {
        ret = -errno;
        goto done;
    }
    ztq->cmd = VPTR(ztq->qcm, ZHPE_XDM_QCM_CMD_BUF_OFFSET);

    ztq->wq = _zhpeu_mmap(NULL, ztq->tqinfo.cmdq.size, PROT_READ | PROT_WRITE,
                          flags, tqi->dev_fd, ztq->tqinfo.cmdq.off);
    if (!ztq->wq) {
        ret = -errno;
        goto done;
    }

    ztq->cq = _zhpeu_mmap(NULL, ztq->tqinfo.cmplq.size, PROT_READ | PROT_WRITE,
                          flags, tqi->dev_fd, ztq->tqinfo.cmplq.off);
    if (!ztq->cq) {
        ret = -errno;
        goto done;
    }

    ret = zhpe_tq_alloc_post(tqi);
    if (ret < 0)
        goto done;

    /* Initialize completion tail to zero and set toggle bit. */
    qcmwrite64(tail.u64, ztq->qcm,
               ZHPE_XDM_QCM_CMPL_QUEUE_TAIL_TOGGLE_OFFSET);
    /* Intialize command head and tail to zero. */
    qcmwrite64(0, ztq->qcm, ZHPE_XDM_QCM_CMD_QUEUE_HEAD_OFFSET);
    qcmwrite64(0, ztq->qcm, ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
    /* Start the queue. */
    qcmwrite64(0, ztq->qcm, ZHPE_XDM_QCM_STOP_OFFSET);
    ret = 0;

 done:
    if (ret >= 0)
        *ztq_out = ztq;
    else
        (void)zhpeq_tq_free(ztq);

    return ret;
}

int32_t zhpeq_tq_reserve_type(struct zhpeq_tq *ztq, uint64_t type_mask)
{
    int32_t             ret;
    uint                i;

    if (unlikely(!ztq)) {
        ret = -EINVAL;
        goto done;
    }

    ret = ffs64(ztq->free_bitmap[0] & type_mask);
    if (likely(ret)) {
        ret--;
        ztq->free_bitmap[0] &= ~((uint64_t)1 << ret);
        if (likely(ret < ZHPE_XDM_QCM_CMD_BUF_COUNT))
            ret |= (ZHPEQ_INSERT_CMD << 16);
        else
            ret |= (ZHPEQ_INSERT_MEM << 16);
    } else {
        for (i = 1; i < (ztq->tqinfo.cmdq.ent >> ZHPEQ_BITMAP_SHIFT); i++) {
            ret = ffs64(ztq->free_bitmap[i]);
            if (ret) {
                ret--;
                ztq->free_bitmap[i] &= ~((uint64_t)1 << ret);
                ret += (i << ZHPEQ_BITMAP_SHIFT);
                ret |= (ZHPEQ_INSERT_MEM << 16);
                goto done;
            }
        }
        ret = -EAGAIN;
    }

 done:
    return ret;
}

void zhpeq_tq_commit(struct zhpeq_tq *ztq)
{
    uint32_t            qmask;

    if (unlikely(ztq->wq_tail != ztq->wq_tail_commit)) {
        qmask = ztq->tqinfo.cmdq.ent - 1;
        ztq->wq_tail_commit = ztq->wq_tail;
        qcmwrite64(ztq->wq_tail_commit & qmask,
                   ztq->qcm, ZHPE_XDM_QCM_CMD_QUEUE_TAIL_OFFSET);
    }
}

int zhpeq_rq_free(struct zhpeq_rq *zrq)
{
    int                 ret = 0;
    struct zhpeq_rqi    *rqi = container_of(zrq, struct zhpeq_rqi, zrq);
    int                 rc;
    union rdm_active    active;

    if (!zrq)
        goto done;

    /* Remove queue from epoll. */
    ret = zhpeu_update_error(ret, zhpeq_rq_epoll_del(zrq));
    /* Stop the queue. */
    if (zrq->qcm) {
        qcmwrite64(1, zrq->qcm, ZHPE_RDM_QCM_STOP_OFFSET);
        for (;;) {
            active.u64 = qcmread64(zrq->qcm, ZHPE_RDM_QCM_ACTIVE_OFFSET);
            if (!active.bits.active)
                break;
            yield();
        }
    }

    ret = 0;
    /* Unmap qcm and rq. */
    rc = _zhpeu_munmap((void *)zrq->qcm, zrq->rqinfo.qcm.size);
    ret = zhpeu_update_error(ret, rc);

    rc = _zhpeu_munmap((void *)zrq->rq, zrq->rqinfo.cmplq.size);
    ret = zhpeu_update_error(ret, rc);

    /* Call the driver to free the queue. */
    if (zrq->rqinfo.qcm.size)
        ret = zhpeu_update_error(ret, zhpe_rq_free(rqi));

    /* Free queue memory. */
    free(rqi);

 done:
    return ret;
}

static int rq_alloc(struct zhpeq_dom *zqdom, int rx_qlen, int slice_mask,
                    int qspecific, struct zhpeq_rq **zrq_out)
{
    int                 ret;
    struct zhpeq_rqi    *rqi = NULL;
    struct zhpeq_rq     *zrq = NULL;
    union rdm_rcv_tail  tail = {
        .bits.toggle_valid = 1,
    };
    int                 flags;
    size_t              orig;
    ret = -ENOMEM;
    rqi = calloc_cachealigned(1, sizeof(*rqi));
    if (!rqi)
        goto done;
    zrq = &rqi->zrq;
    zrq->zqdom = zqdom;
    rqi->dev_fd = -1;

    /* Same questions/comments as above. */
    orig = rx_qlen;
    rx_qlen = roundup_pow_of_2(rx_qlen);
    if (rx_qlen == orig)
        rx_qlen *= 2;

    if (qspecific == 0)
        ret = zhpe_rq_alloc(rqi, rx_qlen, slice_mask);
    else
        ret = zhpe_rq_alloc_specific(rqi, rx_qlen, qspecific);
    if (ret < 0)
        goto done;

    /* rqi->dev_fd == -1 means we're faking things out. */
    flags = (rqi->dev_fd == -1 ? MAP_ANONYMOUS | MAP_PRIVATE : MAP_SHARED);

    /* Map qcm, wq, and cq. */
    zrq->qcm = _zhpeu_mmap(NULL, zrq->rqinfo.qcm.size, PROT_READ | PROT_WRITE,
                           flags, rqi->dev_fd, zrq->rqinfo.qcm.off);
    if (!zrq->qcm) {
        ret = -errno;
        goto done;
    }

    zrq->rq = _zhpeu_mmap(NULL, zrq->rqinfo.cmplq.size, PROT_READ | PROT_WRITE,
                          flags, rqi->dev_fd, zrq->rqinfo.cmplq.off);
    if (!zrq->rq) {
        ret = -errno;
        goto done;
    }

    /* Initialize receive tail to zero and set toggle bit. */
    qcmwrite64(tail.u64, zrq->qcm,
               ZHPE_RDM_QCM_RCV_QUEUE_TAIL_TOGGLE_OFFSET);
    /* Intialize receive head to zero. */
    qcmwrite64(0, zrq->qcm, ZHPE_RDM_QCM_RCV_QUEUE_HEAD_OFFSET);
    /* Start the queue. */
    qcmwrite64(0, zrq->qcm, ZHPE_RDM_QCM_STOP_OFFSET);
    ret = 0;

 done:
    if (ret >= 0)
        *zrq_out = zrq;
    else
        (void)zhpeq_rq_free(zrq);

    return ret;
}

int zhpeq_rq_alloc(struct zhpeq_dom *zqdom, int rx_qlen, int slice_mask,
                   struct zhpeq_rq **zrq_out)
{
    int                 ret = -EINVAL;

    if (!zrq_out)
        goto done;
    *zrq_out = NULL;
    if (!zqdom || rx_qlen < 1 || rx_qlen > b_attr.z.max_rx_qlen ||
        (slice_mask & ~(ALL_SLICES | SLICE_DEMAND)))
        goto done;

    ret = rq_alloc(zqdom, rx_qlen, slice_mask, 0, zrq_out);

 done:
    return ret;
}

int zhpeq_rq_alloc_specific(struct zhpeq_dom *zqdom, int rx_qlen,
                            int qspecific, struct zhpeq_rq **zrq_out)
{
    int                 ret = -EINVAL;

    if (!zrq_out)
        goto done;
    *zrq_out = NULL;
    if (!zqdom || rx_qlen < 1 || rx_qlen > b_attr.z.max_rx_qlen ||
        qspecific < 0 || (qspecific & ZHPE_SZQ_FLAGS_MASK))
        goto done;

    /* qspecific == 0 => any */
    ret = rq_alloc(zqdom, rx_qlen, 0, qspecific, zrq_out);

 done:
    return ret;
}

int zhpeq_rq_epoll_alloc(struct zhpeq_rq_epoll **zepoll_out)
{
    int                 ret = -EINVAL;
    struct zhpeq_rq_epolli *epolli = NULL;

    if (!zepoll_out)
        goto done;
    *zepoll_out = NULL;

    epolli = calloc(1, sizeof(*epolli));
    if (!epolli) {
        ret = -ENOMEM;
        goto done;
    }
    mutex_init(&epolli->mutex, NULL);
    epolli->ref = 1;

    ret = zhpe_rq_epoll_alloc(epolli);
    if (ret < 0)
        /* epolli freed by zhpe_rq_epoll_alloc(). */
        goto done;
    *zepoll_out = &epolli->zepoll;

 done:
    return ret;
}

void __zhpeq_rq_epolli_free(struct zhpeq_rq_epolli *epolli)
{
    mutex_destroy(&epolli->mutex);
    free(epolli);
}

int zhpeq_rq_epoll_free(struct zhpeq_rq_epoll *zepoll)
{
    int                 ret = 0;
    struct zhpeq_rq_epolli *epolli =
        container_of(zepoll, struct zhpeq_rq_epolli, zepoll);

    if (!zepoll)
        goto done;

    ret = zhpe_rq_epoll_free(epolli);
    /* epolli may be freed. */

 done:
    return ret;
}

int zhpeq_rq_epoll_add(struct zhpeq_rq_epoll *zepoll, struct zhpeq_rq *zrq,
                       void (*epoll_handler)(struct zhpeq_rq *zrq,
                                             void *epoll_handler_data),
                       void *epoll_handler_data, uint32_t epoll_threshold_us,
                       bool disabled)
{
    int                 ret = -EINVAL;
    struct zhpeq_rq_epolli *epolli =
        container_of(zepoll, struct zhpeq_rq_epolli, zepoll);
    struct zhpeq_rqi    *rqi = container_of(zrq, struct zhpeq_rqi, zrq);

    if (!zepoll || !zrq || !epoll_handler || !epoll_threshold_us)
        goto done;

    rqi->epoll_handler = epoll_handler;
    rqi->epoll_handler_data = epoll_handler_data;
    zrq->epoll_threshold_cycles = usec_to_cycles(epoll_threshold_us);
    ret = zhpe_rq_epoll_add(epolli, rqi, disabled);

 done:
    return ret;
}

int zhpeq_rq_epoll_del(struct zhpeq_rq *zrq)
{
    int                 ret = 0;
    struct zhpeq_rqi    *rqi = container_of(zrq, struct zhpeq_rqi, zrq);

    if (!zrq || !rqi->epolli)
        goto done;

    ret = zhpe_rq_epoll_del(rqi);
    /* rqi->epolli may be freed. */

 done:
    return ret;
}

int zhpeq_rq_epoll(struct zhpeq_rq_epoll *zepoll, int timeout_ms,
                   const sigset_t *sigmask, bool eintr_ok)
{
    int                 ret = -EINVAL;
    struct zhpeq_rq_epolli *epolli =
        container_of(zepoll, struct zhpeq_rq_epolli, zepoll);

    if (!zepoll)
        goto done;

    ret = zhpe_rq_epoll(epolli, timeout_ms, sigmask, eintr_ok);

 done:
    return ret;
}

int zhpeq_rq_epoll_signal(struct zhpeq_rq_epoll *zepoll)
{
    int                 ret = -EINVAL;
    struct zhpeq_rq_epolli *epolli =
        container_of(zepoll, struct zhpeq_rq_epolli, zepoll);

    if (!zepoll)
        goto done;

    ret = zhpe_rq_epoll_signal(epolli);

 done:
    return ret;
}

bool zhpeq_rq_epoll_enable(struct zhpeq_rq *zrq)
{
    struct zhpeq_rqi    *rqi = container_of(zrq, struct zhpeq_rqi, zrq);

    if (!zrq || !rqi->epolli)
        return false;

    return zhpe_rq_epoll_enable(rqi);
}

int zhpeq_rq_get_addr(struct zhpeq_rq *zrq, void *sa, size_t *sa_len)
{
    ssize_t             ret = -EINVAL;
    struct zhpeq_rqi    *rqi = container_of(zrq, struct zhpeq_rqi, zrq);

    if (!zrq || !sa_len)
        goto done;

    ret = zhpe_rq_get_addr(rqi, sa, sa_len);

 done:
    return ret;
}

int zhpeq_rq_xchg_addr(struct zhpeq_rq *zrq, int sock_fd,
                       void *sa, size_t *sa_len)
{
    int                 ret = -EINVAL;

    if (!zrq || sock_fd == -1 || !sa || !sa_len)
        goto done;

    ret = zhpeq_rq_get_addr(zrq, sa, sa_len);
    if (ret < 0)
        goto done;
    ret = _zhpeu_sock_send_blob(sock_fd, sa, *sa_len);
    if (ret < 0)
        goto done;
    ret = _zhpeu_sock_recv_fixed_blob(sock_fd, sa, *sa_len);
    if (ret < 0)
        goto done;

 done:
    return ret;
}

/* Sequence/Out-Of-Sequence handling. */

#ifndef NDEBUG

static ZHPEU_DECLARE_DEBUG_LOG(rx_oos_log, 20);

void zhpeq_rx_oos_log(const char *func, uint line,
                      uint64_t v0, uint64_t v1, uint64_t v2, uint64_t v3,
                      uint64_t v4)
{
    zhpeu_debug_log(&rx_oos_log, func, line, v0, v1, v2, v3, v4,
                    get_cycles_approx());
}

#endif

#define RX_OOS_ARRAY_SIZE (64)

static void rx_oos_insert1(struct zhpeq_rx_seq *zseq,
                           struct zhpe_rdm_entry *rqe,
                           uint32_t oos, struct zhpeq_rx_oos *rx_oos)
{
    uint32_t            off;

    zseq->rx_oos_cnt++;
    zseq->rx_oos_max = max(zseq->rx_oos_max, oos);
    off = mask2_off(oos, ARRAY_SIZE(rx_oos->rqe));
    rx_oos->rqe[off] = *rqe;
    rx_oos->valid_bits |= ((uint64_t)1 << off);
    zhpeq_rx_oos_log(__func__, __LINE__, zseq->rx_oos_base_seq + oos,
                     (uintptr_t)rx_oos, rx_oos->base_off, rx_oos->valid_bits,
                     0);
}

static int rx_oos_alloc(struct zhpeq_rx_seq *zseq, struct zhpe_rdm_entry *rqe,
                        uint32_t oos, struct zhpeq_rx_oos **prev)
{
    struct zhpeq_rx_oos *rx_oos;

    rx_oos = zseq->alloc(zseq);
    if (unlikely(!rx_oos))
        return -ENOMEM;
    rx_oos->base_off = mask2_down(oos, ARRAY_SIZE(rx_oos->rqe));
    rx_oos->valid_bits = 0;
    rx_oos_insert1(zseq, rqe, oos, rx_oos);
    rx_oos->next = *prev;
    zhpeq_rx_oos_log(__func__, __LINE__, zseq->rx_oos_base_seq + oos,
                     (uintptr_t)rx_oos, (uintptr_t)prev,
                     (uintptr_t)rx_oos->next, 0);
    *prev = rx_oos;

    return 0;
}

int zhpeq_rx_oos_insert(struct zhpeq_rx_seq *zseq, struct zhpe_rdm_entry *rqe,
                        uint32_t seen)
{
    struct zhpeq_rx_oos	*rx_oos;
    struct zhpeq_rx_oos **prev;
    uint32_t            oos;

    if (!zseq->rx_oos_list)
        zseq->rx_oos_base_seq = zseq->seq;
    oos = seen - zseq->rx_oos_base_seq;

    for (prev = &zseq->rx_oos_list, rx_oos = *prev; rx_oos;
         prev = &rx_oos->next, rx_oos = *prev) {
        if (oos >= rx_oos->base_off + ARRAY_SIZE(rx_oos->rqe))
            continue;
        if (oos < rx_oos->base_off)
            break;
        rx_oos_insert1(zseq, rqe, oos, rx_oos);
        return 0;
    }

    return rx_oos_alloc(zseq, rqe, oos, prev);
}

bool zhpeq_rx_oos_spill(struct zhpeq_rx_seq *zseq, uint32_t msgs,
                        void (*handler)(void *handler_data,
                                        struct zhpe_rdm_entry *rqe),
                        void *handler_data)
{
    uint32_t            msgs_orig = msgs;
    struct zhpeq_rx_oos *rx_oos = zseq->rx_oos_list;
    uint64_t            valid_mask;
    uint32_t            oos;
    uint32_t            off;

    for (; rx_oos && msgs; msgs--, zseq->seq++) {
        oos = zseq->seq - zseq->rx_oos_base_seq;
        if (oos < rx_oos->base_off)
            break;
        assert(oos < rx_oos->base_off + ARRAY_SIZE(rx_oos->rqe));
        off = mask2_off(oos, ARRAY_SIZE(rx_oos->rqe));
        valid_mask = ((uint64_t)1 << off);
        if (!(rx_oos->valid_bits & valid_mask))
                break;
        rx_oos->valid_bits &= ~valid_mask;
        handler(handler_data, &rx_oos->rqe[off]);
        zhpeq_rx_oos_log(__func__, __LINE__, zseq->rx_oos_base_seq + oos,
                         (uintptr_t)rx_oos, rx_oos->base_off,
                         rx_oos->valid_bits, 0);
        if (rx_oos->valid_bits)
                continue;
        zhpeq_rx_oos_log(__func__, __LINE__, zseq->rx_oos_base_seq + oos,
                         (uintptr_t)rx_oos, (uintptr_t)&zseq->rx_oos_list,
                         (uintptr_t)rx_oos->next, 0);
        zseq->rx_oos_list = rx_oos->next;
        zseq->free(zseq, rx_oos);
        rx_oos = zseq->rx_oos_list;
    }

    return (msgs != msgs_orig);
}

int zhpeq_mr_reg(struct zhpeq_dom *zqdom, const void *buf, size_t len,
                 uint32_t access, struct zhpeq_key_data **qkdata_out)
{
    zhpe_stats_start(zhpe_stats_subid(ZHPQ, 0));

    int                 ret = -EINVAL;
    struct zhpeq_domi   *zqdomi = container_of(zqdom, struct zhpeq_domi, zqdom);

    if (!qkdata_out)
        goto done;
    *qkdata_out = NULL;
    if (!len || page_up((uintptr_t)buf + len)  <= (uintptr_t)buf ||
        (access & ~ZHPEQ_MR_VALID_MASK))
        goto done;

    ret = zhpe_mr_reg(zqdomi, buf, len, access, qkdata_out);
#if QKDATA_DUMP
    if (ret >= 0)
        zhpeq_print_qkdata(__func__, __LINE__, *qkdata_out);
#endif

 done:
    zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 0));

    return ret;
}

int zhpeq_qkdata_free(struct zhpeq_key_data *qkdata)
{
    int                 ret = 0;
    struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, struct zhpeq_mr_desc_v1, qkdata);

    if (!qkdata)
        goto done;

    ret = -EINVAL;
    if (desc->hdr.magic != ZHPE_MAGIC ||
        (desc->hdr.version & ZHPEQ_MR_VMASK) != ZHPEQ_MR_V1)
        goto done;

#if QKDATA_DUMP
    zhpeq_print_qkdata(__func__, __LINE__, qkdata);
#endif
    if (desc->hdr.version & ZHPEQ_MR_VREG) {
        if (desc->hdr.version & ZHPEQ_MR_VREMOTE) {
            zhpe_stats_start(zhpe_stats_subid(ZHPQ, 50));
            ret = zhpe_zmmu_free(desc);
            zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 50));
        } else {
            zhpe_stats_start(zhpe_stats_subid(ZHPQ, 10));
            ret = zhpe_mr_free(desc);
            zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 10));
        }
    }
    free(desc);

 done:
    return ret;
}

int zhpeq_zmmu_reg(struct zhpeq_key_data *qkdata)
{
    zhpe_stats_start(zhpe_stats_subid(ZHPQ, 40));

    int                 ret = -EINVAL;
    struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, struct zhpeq_mr_desc_v1, qkdata);

    if (!qkdata || desc->hdr.magic != ZHPE_MAGIC ||
        desc->hdr.version != ZHPEQ_MR_V1REMOTE)
        goto done;

#if QKDATA_DUMP
    zhpeq_print_qkdata(__func__, __LINE__, qkdata);
#endif
    ret = zhpe_zmmu_reg(desc);

 done:
    zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 40));

    return ret;
}

int zhpeq_fam_qkdata(struct zhpeq_dom *zqdom, void *addr_cookie,
                     struct zhpeq_key_data **qkdata_out, size_t *n_qkdata_out)
{
    int                 ret = -EINVAL;
    struct zhpeq_domi   *zqdomi = container_of(zqdom, struct zhpeq_domi, zqdom);

    zhpe_stats_start(zhpe_stats_subid(ZHPQ, 20));

    if (!zqdom || !addr_cookie || !qkdata_out ||
        !n_qkdata_out || !*n_qkdata_out)
        goto done;

    ret = zhpe_fam_qkdata(zqdomi, addr_cookie, qkdata_out, n_qkdata_out);

#if QKDATA_DUMP
    if (ret >= 0) {
        size_t          i;

        for (i = 0; i < *n_qkdata_out; i++)
            zhpeq_print_qkdata(__func__, __LINE__, qkdata_out[i]);
    }
#endif

 done:
    zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 20));
    if (ret < 0 && n_qkdata_out)
        *n_qkdata_out = 0;

    return ret;
}

int zhpeq_qkdata_export(const struct zhpeq_key_data *qkdata, uint32_t qaccmask,
                        void *blob, size_t *blob_len)
{
    zhpe_stats_start(zhpe_stats_subid(ZHPQ, 30));

    int                 ret = -EINVAL;
    const struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, const struct zhpeq_mr_desc_v1, qkdata);

    if (!qkdata || !blob || !blob_len ||
        *blob_len < sizeof(struct key_data_packed) ||
        desc->hdr.magic != ZHPE_MAGIC ||
        desc->hdr.version != (ZHPEQ_MR_V1 | ZHPEQ_MR_VREG))
        goto done;

#if QKDATA_DUMP
    zhpeq_print_qkdata(__func__, __LINE__, qkdata);
#endif
    *blob_len = sizeof(struct key_data_packed);
    ret = zhpe_qkdata_export(qkdata, blob, qaccmask);

 done:
    zhpe_stats_stop(zhpe_stats_subid(ZHPQ, 30));

    return ret;
}

int zhpeq_qkdata_import(struct zhpeq_dom *zqdom, void *addr_cookie,
                        const void *blob, size_t blob_len,
                        struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -EINVAL;
    struct zhpeq_domi   *zqdomi = container_of(zqdom, struct zhpeq_domi, zqdom);
    const struct key_data_packed *pdata = blob;
    struct zhpeq_mr_desc_v1 *desc = NULL;
    struct zhpeq_key_data *qkdata;

    if (!qkdata_out)
        goto done;
    *qkdata_out = NULL;
    if (!zqdom || !blob || blob_len != sizeof(*pdata))
        goto done;

    desc = xmalloc_cachealigned(sizeof(*desc));
    qkdata = &desc->qkdata;

    desc->hdr.magic = ZHPE_MAGIC;
    desc->hdr.version = ZHPEQ_MR_V1REMOTE;
    desc->addr_cookie = addr_cookie;
    unpack_kdata(pdata, qkdata);
    qkdata->zqdom = &zqdomi->zqdom;
    qkdata->cache_entry = NULL;
    desc->rsp_zaddr = qkdata->z.zaddr;
    qkdata->z.zaddr = 0;
    *qkdata_out = qkdata;
    ret = 0;

 done:
    return ret;
}

int zhpeq_mmap(const struct zhpeq_key_data *qkdata,
               uint32_t cache_mode, void *addr, size_t length, int prot,
               int flags, off_t offset, struct zhpeq_mmap_desc **zmdesc)
{
    int                 ret = -EINVAL;
    const struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, const struct zhpeq_mr_desc_v1, qkdata);

    if (!zmdesc)
        goto done;
    *zmdesc = NULL;
    if (!qkdata || !zmdesc || (cache_mode & ~ZHPEQ_MR_REQ_CPU_CACHE) ||
        desc->hdr.magic != ZHPE_MAGIC ||
        (desc->hdr.version & ~ZHPEQ_MR_VREG) != ZHPEQ_MR_V1REMOTE ||
        !length || page_off(offset) ||
        page_off(qkdata->z.vaddr) || page_off(qkdata->z.len) ||
        offset + length > desc->qkdata.z.len || (prot & PROT_EXEC) ||
        ((prot & PROT_READ) && !(qkdata->z.access & ZHPEQ_MR_GET_REMOTE)) ||
        ((prot & PROT_WRITE) && !(qkdata->z.access & ZHPEQ_MR_PUT_REMOTE)))
        goto done;

    cache_mode |= ZHPEQ_MR_REQ_CPU;

    ret = zhpe_mmap(desc, cache_mode, addr, length, prot,
                    flags, offset, zmdesc);

#if QKDATA_DUMP
    if (ret >= 0)
        zhpeq_print_qkdata(__func__, __LINE__, qkdata);
#endif

 done:
    return ret;
}

int zhpeq_mmap_unmap(struct zhpeq_mmap_desc *zmdesc)
{
    int                 ret = -EINVAL;

    if (!zmdesc)
        goto done;

#if QKDATA_DUMP
    zhpeq_print_qkdata(__func__, __LINE__, zmdesc->qkdata);
#endif
    ret = zhpe_mmap_unmap(zmdesc);

 done:
    return ret;
}

int zhpeq_mmap_commit(struct zhpeq_mmap_desc *zmdesc,
                      const void *addr, size_t length, bool fence,
                      bool invalidate, bool wait)
{
    return zhpe_mmap_commit(zmdesc, addr, length, fence, invalidate, wait);
}

void zhpeq_print_tq_info(struct zhpeq_tq *ztq)
{
    const char          *b_str = "unknown";
    struct zhpe_attr    *attr = &b_attr.z;
    struct zhpeq_tqi    *tqi = container_of(ztq, struct zhpeq_tqi, ztq);

    if (!ztq)
        return;

    switch (b_attr.backend) {

    case ZHPEQ_BACKEND_ZHPE:
        b_str = "zhpe";
        break;

    case ZHPEQ_BACKEND_LIBFABRIC:
        b_str = "libfabric";
        break;

    default:
        break;
    }

    printf("%s:attributes\n", LIBNAME);
    printf("backend       : %s\n", b_str);
    printf("max_tx_queues : %u\n", attr->max_tx_queues);
    printf("max_rx_queues : %u\n", attr->max_rx_queues);
    printf("max_tx_qlen   : %u\n", attr->max_tx_qlen);
    printf("max_rx_qlen   : %u\n", attr->max_rx_qlen);
    printf("max_dma_len   : %" PRIu64 "\n", attr->max_dma_len);
    printf("num_slices    : %u\n", attr->num_slices);

    printf("\n");
    zhpe_print_tq_info(tqi);
}

static json_t           *saved_json = NULL;

static uint str_to_uint(const char *str, ulong mask, int *ret)
{
    uint		num;
    char                *e;

    *ret = -EINVAL;
    errno = 0;
    num = (uint)strtoul(str, &e, 0);
    if (errno != 0) {
        *ret = -errno;
        goto done;
    }
    if (*e != '\0')
        goto done;
    if (num & ~mask)
        goto done;

    *ret = 0;

done:
    return num;
}

int zhpeq_get_zaddr(const char *node, const char *service,
                    bool source, struct sockaddr_zhpe *sz)
{
    int			ret = -EINVAL;
    char                *node_cp = NULL;
    uint                index = 0;
    const char		*gcid_fname;
    uint		gcid;
    ulong               ctxid;
    const char		*name, *gcid_str, *slash;
    json_t              *nodes, *kind, *comp, *gcids, *gcid_json;
    json_error_t        err;

    if (!sz)
        goto done;
    if (!node && !source)
        goto done;

    memset(sz, 0, sizeof(*sz));
    ctxid = (source ? 0 : ZHPE_SZQ_INVAL);
    if (service) {
        ctxid = str_to_uint(service, ZHPE_CTXID_MASK, &ret);
        if (ret < 0)
            goto done;
    }
    sz->sz_family = AF_ZHPE;
    sz->sz_queue = htonl(ctxid);
    if (!node || !strcmp(node, "localhost")) {
        if (source)
            memcpy(sz->sz_uuid, zhpeq_uuid, sizeof(sz->sz_uuid));
        else {
            gcid = zhpeu_uuid_to_gcid(zhpeq_uuid);
            zhpeu_install_gcid_in_uuid(sz->sz_uuid, gcid);
        }
        ret = 0;
        goto done;
    }
    if (isdigit(node[0])) {
        gcid = str_to_uint(node, ZHPE_GCID_MASK, &ret);
        if (ret < 0)
            goto done;
        zhpeu_install_gcid_in_uuid(sz->sz_uuid, gcid);
        goto done;
    }

    mutex_lock(&zaddr_mutex);
    if (!saved_json) {
        gcid_fname = getenv(ZHPEQ_HOSTS_ENV);
        if (!gcid_fname)
	    gcid_fname = ZHPEQ_HOSTS_FILE;
        saved_json = json_load_file(gcid_fname, 0, &err);
	if (!saved_json) {
            mutex_unlock(&zaddr_mutex);
	    ret = -EINVAL;
	    goto done;
	}
    }
    mutex_unlock(&zaddr_mutex);

    nodes = json_object_get(saved_json, "Nodes");
    if (!nodes) {
        ret = -EINVAL;
        goto done;
    }

    slash = strchr(node, '/');
    if (slash) {  /* node string contains a GCID index */
        /* make writable copy of node string */
        node_cp = strdup(node);
        if (!node_cp) {
            ret = -ENOMEM;
            goto done;
        }
        *(node_cp + (slash - node)) = '\0';
        index = str_to_uint(slash + 1, -1ul, &ret);
        if (ret < 0)
            goto done;
        node = node_cp;
    }

    ret = -ENOENT;
    json_object_foreach(nodes, name, kind) {
        comp = json_object_get(kind, node);
        if (json_is_array(comp) && json_array_size(comp) == 5) {
            // Revisit: should we care about the Enabled state?
            gcids = json_array_get(comp, 4);
            if (json_is_array(gcids) && index < json_array_size(gcids)) {
                gcid_json = json_array_get(gcids, index);
                if (json_is_string(gcid_json)) {
                    gcid_str = json_string_value(gcid_json);
                    gcid = str_to_uint(gcid_str, ZHPE_GCID_MASK, &ret);
                    if (ret < 0)
                        goto done;
                    zhpeu_install_gcid_in_uuid(sz->sz_uuid, gcid);
                }
            }
            break;
        }
    }

done:
    free(node_cp);

    return ret;
}

int zhpeq_feature_enable(uint64_t features)
{
    return zhpe_feature_enable(features);
}

void zhpeq_print_qkdata(const char *func, uint line,
                        const struct zhpeq_key_data *qkdata)
{
    char                *id_str = NULL;
    const struct zhpeq_mr_desc_v1 *desc =
        container_of(qkdata, const struct zhpeq_mr_desc_v1, qkdata);

    if (!qkdata)
        return;

    id_str = zhpe_qkdata_id_str(desc);
    fprintf(stderr, "%s,%u:%p %s\n", func, line, qkdata, (id_str ?: ""));
    fprintf(stderr, "%s,%u:v/z/l 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64
            "0x%x \n", func, line,
            qkdata->z.vaddr, qkdata->z.zaddr, qkdata->z.len, qkdata->z.access);
}

static void print_qcm1(const char *func, uint line, const volatile void *qcm,
                      uint offset)
{
    printf("%s,%u:qcm[0x%03x] = 0x%lx\n",
           func, line, offset, qcmread64(qcm, offset));
}

void zhpeq_print_tq_qcm(const char *func, uint line, const struct zhpeq_tq *ztq)
{
    uint                i;

    if (!ztq)
        return;

    printf("%s,%u:%s %p\n", func, line, __func__, ztq->qcm);
    for (i = 0x00; i < 0x30; i += 0x08)
        print_qcm1(func, line, ztq->qcm, i);
    for (i = 0x40; i < 0x108; i += 0x40)
        print_qcm1(func, line, ztq->qcm, i);
}

static uint wq_opcode(union zhpe_hw_wq_entry *wqe)
{
    return (wqe->hdr.opcode & ZHPE_HW_OPCODE_MASK);
}

static uint wq_fence(union zhpe_hw_wq_entry *wqe)
{
    return !!(wqe->hdr.opcode & ZHPE_HW_OPCODE_FENCE);
}

static uint wq_index(union zhpe_hw_wq_entry *wqe)
{
    return wqe->hdr.cmp_index;
}

static void wq_print_enq(union zhpe_hw_wq_entry *wqe, uint i, const char *opstr)
{
    struct zhpe_hw_wq_enqa *enq = &wqe->enqa;

    fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x dgcid 0x%x rspctxid 0x%x\n",
            i, opstr, wq_fence(wqe), wq_index(wqe),
            enq->dgcid, enq->rspctxid);
}

static void wq_print_imm(union zhpe_hw_wq_entry *wqe, uint i, const char *opstr)
{
    struct zhpe_hw_wq_imm *imm = &wqe->imm;

    fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x len 0x%x rem 0x%lx\n",
            i, opstr, wq_fence(wqe), wq_index(wqe),
            imm->len, imm->rem_addr);
}

static void wq_print_dma(union zhpe_hw_wq_entry *wqe, uint i, const char *opstr)
{
    struct zhpe_hw_wq_dma *dma = &wqe->dma;

    fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x len 0x%x rd 0x%lx wr 0x%lx\n",
            i, opstr, wq_fence(wqe), wq_index(wqe),
            dma->len, dma->rd_addr, dma->wr_addr);
}

static void wq_print_atm(union zhpe_hw_wq_entry *wqe, uint i, const char *opstr)
{
    struct zhpe_hw_wq_atomic *atm = &wqe->atm;
    uint64_t            operands[2];

    if ((atm->size & ZHPE_HW_ATOMIC_SIZE_MASK) == ZHPE_HW_ATOMIC_SIZE_32) {
        operands[0] = atm->operands32[0];
        operands[1] = atm->operands32[1];
    } else {
        operands[0] = atm->operands64[0];
        operands[1] = atm->operands64[1];
    }
    fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x size 0x%x rem 0x%lx"
            " operands 0x%lx 0x%lx\n",
            i, opstr, wq_fence(wqe), wq_index(wqe),
            atm->size, atm->rem_addr, operands[0], operands[1]);
}

static void wq_print(union zhpe_hw_wq_entry *wqe, uint i)
{
    switch (wq_opcode(wqe)) {

    case ZHPE_HW_OPCODE_NOP:
        fprintf(stderr, "%7d:%-7s:f %u idx 0x%04x\n",
                i, "NOP", wq_fence(wqe), wq_index(wqe));
        break;

    case ZHPE_HW_OPCODE_ENQA:
        wq_print_enq(wqe, i, "ENQA");
        break;

    case ZHPE_HW_OPCODE_GETIMM:
        wq_print_imm(wqe, i, "GETIMM");
        break;

    case ZHPE_HW_OPCODE_PUTIMM:
        wq_print_imm(wqe, i, "PUTIMM");
        break;

    case ZHPE_HW_OPCODE_GET:
        wq_print_dma(wqe, i, "GET");
        break;

    case ZHPE_HW_OPCODE_PUT:
        wq_print_dma(wqe, i, "PUT");
        break;

    case ZHPE_HW_OPCODE_ATM_ADD:
        wq_print_atm(wqe, i, "ATMADD");
        break;

    case ZHPE_HW_OPCODE_ATM_CAS:
        wq_print_atm(wqe, i, "ATMCAS");
        break;

    case ZHPE_HW_OPCODE_ATM_SWAP:
        wq_print_atm(wqe, i, "ATMSWAP");
        break;

    default:
        fprintf(stderr, "%7d:OP 0x%02x:f %u idx %0x04x\n",
                i, wq_opcode(wqe), wq_fence(wqe), wq_index(wqe));
        break;
    }
}

void zhpeq_print_tq_wq(struct zhpeq_tq *ztq, int cnt)
{
    uint32_t            qmask = ztq->tqinfo.cmdq.ent - 1;
    uint                i;

    if (!ztq)
        return;
    if (!cnt || cnt > qmask)
        cnt = qmask;
    if (cnt > ztq->wq_tail)
        cnt = ztq->wq_tail;
    for (i = ztq->wq_tail - cnt ; cnt > 0; i++, cnt--)
        wq_print(&ztq->wq[i & qmask], i);
}

void zhpeq_print_tq_cq(struct zhpeq_tq *ztq, int cnt)
{
    uint32_t            qmask = ztq->tqinfo.cmplq.ent - 1;
    uint                i;
    union zhpe_hw_cq_entry *cqe;
    char                *d;

    if (!ztq)
        return;
    if (!cnt || cnt > qmask)
        cnt = qmask;
    if (cnt > ztq->cq_head)
        cnt = ztq->cq_head;
    for (i = ztq->cq_head - cnt ; cnt > 0; i++, cnt--) {
        cqe = (void *)&ztq->cq[i & qmask];
        /* Print the first 8 bytes of the result */
        d = cqe->entry.result.data;
        fprintf(stderr, "%7d:v %u idx 0x%04x status 0x%02x"
                " data %02x%02x%x02%02x%02x%02x%02x%02x\n",
                i, cqe->entry.valid, cqe->entry.index, cqe->entry.status,
                d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]);
    }
}

void zhpeq_print_rq_qcm(const char *func, uint line, const struct zhpeq_rq *zrq)
{
    uint                i;

    if (!zrq)
        return;

    printf("%s,%u:%s %p\n", func, line, __func__, zrq->qcm);
    for (i = 0x00; i < 0x20; i += 0x08)
        print_qcm1(func, line, zrq->qcm, i);
    for (i = 0x40; i < 0x100; i += 0x40)
        print_qcm1(func, line, zrq->qcm, i);
}
