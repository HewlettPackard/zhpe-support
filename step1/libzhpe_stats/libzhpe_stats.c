/*
 * Copyright (C) 2019-2020 Hewlett Packard Enterprise Development LP.
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

#include <zhpeq_util.h>

#include <zhpe_stats.h>
#include <zhpe_stats_types.h>

#include <sys/syscall.h>

#include <asm/bitsperlong.h>

#include <linux/perf_event.h>
#include <sys/prctl.h>

#include <math.h>

/*
 * zhpe_stats_profile is a global variable.
 * zhpe_stats_init sets it based on the ZHPE_STATS_PROFILE.
 * zhpe_stats_finalize sets it back to 0.
 * Once initialized, zhpe_stats_profile != 0.
 *
 * zhpe_stats is a thread-local variable.
 * It is initially set to &dummy.
 * We can only set up the counters once, so
 * zhpe_stats_init callocs and sets up zhpe_stats.
 * zhpe_stats_finalize frees zhpe_stats.
 *
 * stats_cmn_closed frees zhpe_stats->buffer and sets it to NULL.
 *
 */

#ifdef HAVE_ZHPE_STATS

#ifdef HAVE_ZHPE_SIM

#include <hpe_sim_api_linux64.h>

#endif // HAVE_ZHPE_SIM

static_assert(sizeof(struct zhpe_stats_record)%64 == 0, "foo");

/* copied from perf_event_open man page */
static int my_perf_event_open(struct perf_event_attr *pea, pid_t pid,
                              int cpu, int group_fd, unsigned long flags)
{
    int ret;

    ret = syscall(__NR_perf_event_open, pea, pid, cpu,
                  group_fd, flags);
    return ret;
}

/* John Byrne's asm magic */
#define __XMMCLOBBER03  : "%xmm0", "%xmm1", "%xmm2", "%xmm3"
#define __XMMCLOBBERA   __XMMCLOBBER03, "%xmm4", "%xmm5", "%xmm6", "%xmm7"

#define __XMM_XFER_ALIGN        (16)
#define __XMM_CACHE_SIZE        (64)
#define __XMM_XFER_LOOP         (128)

#define __vmemcpy(_d, _s, _to, _from, _len)                             \
do {                                                                    \
    for (; _len >= __XMM_XFER_LOOP; _len -= __XMM_XFER_LOOP) {          \
        asm volatile (                                                  \
            #_s "    (%0),  %%xmm0\n"                                   \
            #_s "  16(%0),  %%xmm1\n"                                   \
            #_s "  32(%0),  %%xmm2\n"                                   \
            #_s "  48(%0),  %%xmm3\n"                                   \
            #_s "  64(%0),  %%xmm4\n"                                   \
            #_s "  80(%0),  %%xmm5\n"                                   \
            #_s "  96(%0),  %%xmm6\n"                                   \
            #_s " 112(%0),  %%xmm7\n"                                   \
            #_d "  %%xmm0,    (%1)\n"                                   \
            #_d "  %%xmm1,  16(%1)\n"                                   \
            #_d "  %%xmm2,  32(%1)\n"                                   \
            #_d "  %%xmm3,  48(%1)\n"                                   \
            #_d "  %%xmm4,  64(%1)\n"                                   \
            #_d "  %%xmm5,  80(%1)\n"                                   \
            #_d "  %%xmm6,  96(%1)\n"                                   \
            #_d "  %%xmm7, 112(%1)\n"                                   \
            : : "r" (_from), "r" (_to) __XMMCLOBBERA);                  \
        _from += __XMM_XFER_LOOP;                                       \
        _to += __XMM_XFER_LOOP;                                         \
    }                                                                   \
    for (; _len >= __XMM_CACHE_SIZE; _len -= __XMM_CACHE_SIZE) {        \
        asm volatile (                                                  \
            #_s "    (%0),  %%xmm0\n"                                   \
            #_s "  16(%0),  %%xmm1\n"                                   \
            #_s "  32(%0),  %%xmm2\n"                                   \
            #_s "  48(%0),  %%xmm3\n"                                   \
            #_d "  %%xmm0,    (%1)\n"                                   \
            #_d "  %%xmm1,  16(%1)\n"                                   \
            #_d "  %%xmm2,  32(%1)\n"                                   \
            #_d "  %%xmm3,  48(%1)\n"                                   \
            : : "r" (_from), "r" (_to) __XMMCLOBBER03);                 \
        _from += __XMM_CACHE_SIZE;                                      \
        _to += __XMM_CACHE_SIZE;                                        \
    }                                                                   \
    if (_len)                                                           \
         memcpy(_to, _from, _len);                                      \
} while(0)                                                              \

#endif // HAVE_ZHPE_STATS

static void stats_nop_stamp(struct zhpe_stats *zstats,  uint32_t dum,
                            uint64_t dum1, uint64_t dum2, uint64_t dum3,
                            uint64_t dum4, uint64_t dum5, uint64_t dum6)
{
}

static void stats_nop_setvals(struct zhpe_stats *zstats,
                              struct zhpe_stats_record *rec)
{
}

static void stats_nop_zstats_uint32(struct zhpe_stats *zstats, uint32_t dum)
{
}

static void stats_nop_zstats(struct zhpe_stats *zstats)
{
};

static struct zhpe_stats_ops zhpe_stats_nops = {
    .close              = stats_nop_zstats,
    .enable             = stats_nop_zstats,
    .disable            = stats_nop_zstats,
    .pause_all          = stats_nop_zstats,
    .restart_all        = stats_nop_zstats,
    .stop_all           = stats_nop_zstats,
    .start              = stats_nop_zstats_uint32,
    .stop               = stats_nop_zstats_uint32,
    .stamp              = stats_nop_stamp,
    .setvals            = stats_nop_setvals,
};

static struct zhpe_stats dummy =
{
    .zhpe_stats_ops= &zhpe_stats_nops,
};

__thread struct zhpe_stats *zhpe_stats = &dummy;

#ifdef HAVE_ZHPE_STATS

#define ZHPE_STATS_BUF_COUNT_MAX (MiB)

/* Common definitions/code */
static char             *zhpe_stats_dir;
static char             *zhpe_stats_unique;
static pthread_mutex_t  zhpe_stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t         zhpe_stats_buf_count;
static size_t           zhpe_stats_profile;
static struct zhpe_stats *zhpe_stats_list;
static struct zhpe_stats_ops stats_ops_enabled;
static struct zhpe_stats_ops stats_ops_disabled;

static int              zhpe_stats_num_counters = 0;
static __u32            perf_typeid = 0;

static void __attribute__((constructor)) lib_init(void)
{
    if (getenv("ZHPE_STATS_INIT")) {
        zhpe_stats_init("libzhpe_stats");
        zhpe_stats_test(0);
        zhpe_stats_open(1);
    }
}

static void __attribute__((destructor)) lib_fini(void)
{
    if (getenv("ZHPE_STATS_INIT")) {
        zhpe_stats_close();
        zhpe_stats_finalize();
    }
}

/* forward declarations */
static void stats_flush(struct zhpe_stats *zstats);

static void stats_cmn_enable(struct zhpe_stats *zstats)
{
    if(zstats->enabled == ZHPE_STATS_ENABLED)
        return;

    zstats->enabled = ZHPE_STATS_ENABLED;
    zstats->zhpe_stats_ops = &stats_ops_enabled;
    zstats->zhpe_stats_ops->restart_all(zstats);
}

static void stats_cmn_disable(struct zhpe_stats *zstats)
{
    zstats->zhpe_stats_ops->pause_all(zstats);
    zstats->enabled = ZHPE_STATS_DISABLED;
    zstats->zhpe_stats_ops = &stats_ops_disabled;
}

/* don't free zstats */
static void stats_cmn_close(struct zhpe_stats *zstats)
{
    struct zhpe_stats   **zsprev;

    zstats->zhpe_stats_ops->recordme(zstats, 0, ZHPE_STATS_OP_CLOSE);

    stats_flush(zstats);
    if (zstats->fd != -1)
        close(zstats->fd);

    mutex_lock(&zhpe_stats_mutex);
    for (zsprev = &zhpe_stats_list; *zsprev; zsprev = &(*zsprev)->next) {
        if (*zsprev == zstats) {
            *zsprev = zstats->next;
            break;
        }
    }
    mutex_unlock(&zhpe_stats_mutex);

    free(zstats->buffer);
    free(zstats);
    zhpe_stats = &dummy;

    return;
}

static void gdb_find_timestamp(struct zhpe_stats *zstats, uint64_t timestamp)
{
    uint64_t            cur = zstats->head;
    uint64_t            delta;

    if (!zstats->head)
        return;

    for (delta = cur / 2, cur = delta; delta;) {
        if (zstats->buffer[cur].val0 > timestamp)
            cur -= delta;
        else if (zstats->buffer[cur].val0 < timestamp)
            cur -= delta;
        else {
            zstats->head_gdb = cur + 1;
            return;
        }
    }
    /* Edge, doesn't have to be perfect. */
    if (zstats->buffer[cur].val0 < timestamp)
        cur = min(cur + 2, zstats->head - 1);
    zstats->head_gdb = cur + 1;
}

void zhpe_stats_gdb_tidx(pid_t tid, size_t idx)
{
    struct zhpe_stats   *zstats_tid = NULL;
    struct zhpe_stats   *zstats;
    uint64_t            timestamp;

    for (zstats = zhpe_stats_list; zstats; zstats = zstats->next) {
        if (tid == zstats->tid) {
            zstats_tid = zstats;
            break;
        }
        zstats->head_gdb = 0;
    }
    if (!zstats)
        return;

    if (idx >= zstats_tid->head) {
        if (zstats_tid->head > 0)
            idx = zstats_tid->head;
    }

    zstats_tid->head_gdb = idx + 1;
    timestamp = zstats_tid->buffer[idx].val0;

    for (zstats = zhpe_stats_list; zstats; zstats = zstats->next) {
        if (zstats == zstats_tid)
            continue;
        gdb_find_timestamp(zstats, timestamp);
    }
}

static void stats_flush_all(void)
{
    struct zhpe_stats   *zstats;

    /* No locking so it called from the debugger when things are stuck. */
    for (zstats = zhpe_stats_list; zstats; zstats = zstats->next)
        stats_flush(zstats);
}

void zhpe_stats_finalize(void)
{
    struct zhpe_stats   *zstats = zhpe_stats;
    int                 open_count;

    /* Close the current thread. */
    zstats->zhpe_stats_ops->close(zstats);

    mutex_lock(&zhpe_stats_mutex);
    for (zstats = zhpe_stats_list, open_count = 0; zstats;
         zstats = zstats->next, open_count++);
    if (open_count) {
        print_err("%s:%d threads remain open, flushing\n",
                  __func__, open_count);
        stats_flush_all();
    }
    free(zhpe_stats_dir);
    zhpe_stats_dir = NULL;
    free(zhpe_stats_unique);
    zhpe_stats_unique = NULL;
    zhpe_stats_profile = 0;
    mutex_unlock(&zhpe_stats_mutex);

    return;
}

static void stats_write_metadata(struct zhpe_stats *zstats)
{
    int i, bufsize, res;

    struct zhpe_stats_metadata metadata;
    metadata.profileid = zhpe_stats_profile;
    metadata.perf_typeid = perf_typeid;
    metadata.config_count =  zhpe_stats_num_counters;
    for (i=0;i< zhpe_stats_num_counters;i++){
        metadata.config_list[i] = zstats->zhpe_stats_config_list[i];
    }

    bufsize = sizeof(struct zhpe_stats_metadata);
    res = write(zstats->fd, &metadata, bufsize);
    if (check_func_ion(__func__, __LINE__, "write", bufsize, false,
                       bufsize, res, 0) < 0)
        abort();
}

/* overwrite when full */
/* todo: check compilation output for NDEBUG option when compile with 5 */
static struct zhpe_stats_record *
stats_nextslot_noflush(struct zhpe_stats *zstats)
{
    struct zhpe_stats_record *rec;

    assert(zstats->buffer);

    rec = &(zstats->buffer[(zstats->head++ & zstats->slots_mask)]);

    return rec;
}

static struct zhpe_stats_record *
stats_nextslot_flush(struct zhpe_stats *zstats)
{
    struct zhpe_stats_record *rec;

    assert(zstats->buffer);
    if (unlikely((zstats->head & zstats->slots_mask) == zstats->slots_mask))
        stats_flush(zstats);

    rec = &(zstats->buffer[(zstats->head++ & zstats->slots_mask)]);

    return rec;
}

static uint64_t do_rdtscp(void)
{
    uint32_t            lo;
    uint32_t            hi;
    uint32_t            cpu;

    asm volatile("rdtscp\n" : "=a" (lo), "=d" (hi), "=c" (cpu) : :);

    return ((uint64_t)hi << 32 | lo);
}

static uint64_t do_rdpmc(struct zhpe_stats *zstats, uint index)
{
    uint32_t            pmc;
    uint32_t            lo;
    uint32_t            hi;

    pmc = zstats->zhpe_stats_mmap_list[index]->index;
    assert(pmc > 0);
    pmc--;
    asm volatile("rdpmc\n" : "=a" (lo), "=d" (hi) : "c" (pmc) :);

    return ((uint64_t)hi << 32 | lo);
}

static void stats_setvals_1_rdpmc(struct zhpe_stats *zstats,
                                  struct zhpe_stats_record *rec)
{

    rec->val0 = do_rdtscp();
    rec->val1 = do_rdpmc(zstats, 0);
    rec->val2 = 0;
    rec->val3 = 0;
    rec->val4 = 0;
    rec->val5 = 0;
    rec->val6 = 0;
}

static void stats_setvals_2_rdpmc(struct zhpe_stats *zstats,
                                  struct zhpe_stats_record *rec)
{

    rec->val0 = do_rdtscp();
    rec->val1 = do_rdpmc(zstats, 0);
    rec->val2 = do_rdpmc(zstats, 1);
    rec->val3 = 0;
    rec->val4 = 0;
    rec->val5 = 0;
    rec->val6 = 0;
}

static void stats_setvals_6_rdpmc(struct zhpe_stats *zstats,
                                  struct zhpe_stats_record *rec)
{

    rec->val0 = do_rdtscp();
    rec->val1 = do_rdpmc(zstats, 0);
    rec->val2 = do_rdpmc(zstats, 1);
    rec->val3 = do_rdpmc(zstats, 2);
    rec->val4 = do_rdpmc(zstats, 3);
    rec->val5 = do_rdpmc(zstats, 4);
    rec->val6 = do_rdpmc(zstats, 5);
}

static void stats_setvals_stamp(struct zhpe_stats *zstats,
                                struct zhpe_stats_record *rec)
{

    rec->val0 = do_rdtscp();
    rec->val1 = 0;
    rec->val2 = 0;
    rec->val3 = 0;
    rec->val4 = 0;
    rec->val5 = 0;
    rec->val6 = 0;
}

#ifdef HAVE_ZHPE_SIM
static void stats_setvals_hpe_sim(struct zhpe_stats *zstats,
                                  struct zhpe_stats_record *rec)
{
    ProcCtlData *simdata = (void *)zstats->sim_buf;
    int64_t             rc;

    rec->val0 = do_rdtscp();

    assert(zstats->sim_buf);

    rc = sim_api_data_rec(DATA_REC_PAUSE, (uint16_t)zstats->uid,
                          (uintptr_t)simdata);
    if (rc) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_PAUSE", -rc);
        abort();
    }

    rec->val1 = simdata->cpl0ExecInstTotal;
    rec->val2 = simdata->cpl3ExecInstTotal;
    rec->val3 = 0;
    rec->val4 = 0;
    rec->val5 = 0;
    rec->val6 = 0;

    rc = sim_api_data_rec(DATA_REC_START, (uint16_t)zstats->uid,
                          (uintptr_t)zstats->sim_buf);
    if (rc) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_START", -rc);
        abort();
    }
}

#else // HAVE_ZHPE_SIM
/*
 * Compiling sim_ops needs things from the hpe_stats include file.
 * We could have stubbed out the needed things, but instead we
 * define sim nops.
 *
 */
static void stats_setvals_hpe_sim(struct zhpe_stats *zstats,
                                  struct zhpe_stats_record *rec)
{
}

#endif // HAVE_ZHPE_SIM


#if 0
static void stats_recordme_vmemcpy(struct zhpe_stats *zstats, uint32_t subid,
                                   uint32_t opflag)
{
    struct zhpe_stats_record *dest;
    struct zhpe_stats_record tmp;

    tmp.subid = subid;
    tmp.op_flag = opflag;

    dest = zstats->zhpe_stats_ops->nextslot(zstats);
    zstats->zhpe_stats_ops->setvals(zstats, &tmp);
    __vmemcpy(movntdq, movntdqa, dest, &tmp, sizeof(*dest));
}
#endif

static void stats_recordme_memcpy(struct zhpe_stats *zstats, uint32_t subid,
                                  uint32_t opflag)
{
    struct zhpe_stats_record *dest;
    struct zhpe_stats_record tmp;

    tmp.subid = subid;
    tmp.op_flag = opflag;

    dest = zstats->zhpe_stats_ops->nextslot(zstats);
    zstats->zhpe_stats_ops->setvals(zstats, &tmp);
    memcpy(dest, &tmp, sizeof(*dest));
}

static void stats_recordme(struct zhpe_stats *zstats, uint32_t subid,
                           uint32_t opflag)
{
    struct zhpe_stats_record *dest;

    dest = zstats->zhpe_stats_ops->nextslot(zstats);
    dest->subid = subid;
    dest->op_flag = opflag;
    zstats->zhpe_stats_ops->setvals(zstats, dest);
}

#define SS1                                             \
do {                                                    \
    zhpe_stats_start(ZHPE_STATS_SUBID_STARTSTOP);       \
    zhpe_stats_stop(ZHPE_STATS_SUBID_STARTSTOP);        \
} while (0)

#define SS10                                            \
do {                                                    \
    SS1;                                                \
    SS1;                                                \
    SS1;                                                \
    SS1;                                                \
    SS1;                                                \
    SS1;                                                \
    SS1;                                                \
    SS1;                                                \
    SS1;                                                \
    SS1;                                                \
} while (0)

#define SS100                                           \
do {                                                    \
    SS10;                                               \
    SS10;                                               \
    SS10;                                               \
    SS10;                                               \
    SS10;                                               \
    SS10;                                               \
    SS10;                                               \
    SS10;                                               \
    SS10;                                               \
    SS10;                                               \
} while (0)

#define S_STAMP_S1                                      \
do {                                                    \
    zhpe_stats_start(ZHPE_STATS_SUBID_S_STAMP_S);       \
    zhpe_stats_stamp(89888786, 89, 88, 87, 86, 54, 32); \
    zhpe_stats_stop(ZHPE_STATS_SUBID_S_STAMP_S);        \
} while (0)

#define S_STAMP_S10                                     \
do {                                                    \
    S_STAMP_S1;                                         \
    S_STAMP_S1;                                         \
    S_STAMP_S1;                                         \
    S_STAMP_S1;                                         \
    S_STAMP_S1;                                         \
    S_STAMP_S1;                                         \
    S_STAMP_S1;                                         \
    S_STAMP_S1;                                         \
    S_STAMP_S1;                                         \
    S_STAMP_S1;                                         \
} while (0)

#define S_STAMP_S100                                    \
do {                                                    \
    S_STAMP_S10;                                        \
    S_STAMP_S10;                                        \
    S_STAMP_S10;                                        \
    S_STAMP_S10;                                        \
    S_STAMP_S10;                                        \
    S_STAMP_S10;                                        \
    S_STAMP_S10;                                        \
    S_STAMP_S10;                                        \
    S_STAMP_S10;                                        \
    S_STAMP_S10;                                        \
} while (0)

#define S_STARTSTOP_S1                                  \
do {                                                    \
    zhpe_stats_start(ZHPE_STATS_SUBID_S_SS_S);          \
    zhpe_stats_start(0);                                \
    zhpe_stats_stop(0);                                 \
    zhpe_stats_stop(ZHPE_STATS_SUBID_S_SS_S);           \
} while (0)

#define S_STARTSTOP_S10                                 \
do {                                                    \
    S_STARTSTOP_S1;                                     \
    S_STARTSTOP_S1;                                     \
    S_STARTSTOP_S1;                                     \
    S_STARTSTOP_S1;                                     \
    S_STARTSTOP_S1;                                     \
    S_STARTSTOP_S1;                                     \
    S_STARTSTOP_S1;                                     \
    S_STARTSTOP_S1;                                     \
    S_STARTSTOP_S1;                                     \
    S_STARTSTOP_S1;                                     \
} while (0)

#define S_STARTSTOP_S100                                \
do {                                                    \
    S_STARTSTOP_S10;                                    \
    S_STARTSTOP_S10;                                    \
    S_STARTSTOP_S10;                                    \
    S_STARTSTOP_S10;                                    \
    S_STARTSTOP_S10;                                    \
    S_STARTSTOP_S10;                                    \
    S_STARTSTOP_S10;                                    \
    S_STARTSTOP_S10;                                    \
    S_STARTSTOP_S10;                                    \
    S_STARTSTOP_S10;                                    \
} while (0)

void zhpe_stats_test(uint16_t uid)
{
    zhpe_stats_open(uid);
    SS100;
    S_STAMP_S100;
    S_STARTSTOP_S100;
    zhpe_stats_close();
}

uint64_t dest1[8] CACHE_ALIGNED;

uint64_t src1[8] CACHE_ALIGNED;

/* single thread, no need to lock */
static void stats_flush(struct zhpe_stats *zstats)
{
    size_t              req = (zstats->head & zstats->slots_mask);
    ssize_t             res;

    assert(zstats->buffer);
    assert(req < zstats->slots_num);
    if (!req)
        return;
    io_wmb();
    req *= sizeof(struct zhpe_stats_record);
    res = write(zstats->fd, zstats->buffer, req);
    if (check_func_ion(__func__, __LINE__, "write", req, false,
                       req, res, 0) < 0)
        abort();
}

static void rdpmc_stats_close(struct zhpe_stats *zstats)
{
    int                 i;
    int                 err;

    if (prctl(PR_TASK_PERF_EVENTS_DISABLE) == -1) {
        err = -errno;
        print_func_err(__func__, __LINE__, "prctl", "DISABLE", err);
        abort();
    }
    for (i = 0; i < zhpe_stats_num_counters; i++) {
        if (zstats->zhpe_stats_mmap_list[i])
            munmap(zstats->zhpe_stats_mmap_list[i], page_size);
    }
    free(zstats->zhpe_stats_mmap_list);
    free(zstats->zhpe_stats_config_list);

    stats_cmn_close(zstats);
}

#ifdef HAVE_ZHPE_SIM
static void sim_stats_close(struct zhpe_stats *zstats)
{
    int64_t             ret;

    ret = sim_api_data_rec(DATA_REC_END, zstats->uid,
                           (uintptr_t)zstats->sim_buf);
    if (ret)
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_END", -ret);

    stats_cmn_close(zstats);
}

#else

static void sim_stats_close(struct zhpe_stats *zstats)
{
}

#endif // HAVE_ZHPE_SIM

static void stats_start(struct zhpe_stats *zstats, uint32_t subid)
{
//printf("IN stats_start\n");
    zstats->zhpe_stats_ops->recordme(zstats, subid, ZHPE_STATS_OP_START);
}

static void stats_stop(struct zhpe_stats *zstats, uint32_t subid)
{
//printf("IN stats_stop\n");
    zstats->zhpe_stats_ops->recordme(zstats, subid, ZHPE_STATS_OP_STOP);
}

static void stats_pause_all(struct zhpe_stats *zstats)
{
//printf("IN stats_pause_all\n");
    zstats->zhpe_stats_ops->recordme(zstats, 0, ZHPE_STATS_OP_PAUSE_ALL);
}

static void stats_restart_all(struct zhpe_stats *zstats)
{
//printf("IN stats_restart_all\n");
    zstats->zhpe_stats_ops->recordme(zstats, 0, ZHPE_STATS_OP_RESTART_ALL);
}

static void stats_stop_all(struct zhpe_stats *zstats)
{
//printf("IN stats_stop_all\n");
    zstats->zhpe_stats_ops->recordme(zstats, 0, ZHPE_STATS_OP_STOP_ALL);
}

/* generic */
static void stats_stamp(struct zhpe_stats *zstats, uint32_t subid,
                        uint64_t d1, uint64_t d2, uint64_t d3,
                        uint64_t d4, uint64_t d5, uint64_t d6)
{
    struct zhpe_stats_record    *dest;

    dest = zstats->zhpe_stats_ops->nextslot(zstats);
    dest->subid = subid;
    dest->op_flag = ZHPE_STATS_OP_STAMP;

    dest->val0 = do_rdtscp();
    dest->val1 = d1;
    dest->val2 = d2;
    dest->val3 = d3;
    dest->val4 = d4;
    dest->val5 = d5;
    dest->val6 = d6;
}

static struct zhpe_stats_ops stats_ops_enabled = {
    .close              = stats_cmn_close,
    .enable             = stats_cmn_enable,
    .disable            = stats_cmn_disable,
    .pause_all          = stats_pause_all,
    .restart_all        = stats_restart_all,
    .stop_all           = stats_stop_all,
    .start              = stats_start,
    .stop               = stats_stop,
    .stamp              = stats_stamp,
};

static struct zhpe_stats_ops stats_ops_disabled = {
    .close              = stats_cmn_close,
    .enable             = stats_cmn_enable,
    .disable            = stats_cmn_disable,
    .pause_all          = stats_nop_zstats,
    .restart_all        = stats_nop_zstats,
    .stop_all           = stats_nop_zstats,
    .start              = stats_nop_zstats_uint32,
    .stop               = stats_nop_zstats_uint32,
    .stamp              = stats_nop_stamp,
};

static void init_rdpmc_profile(struct zhpe_stats *zstats, __u32 petype,
                               int count, ...)
{
    int                 group_fd = -1;
    int                 fd = -1;
    va_list             args;
    int                 err;
    __u64               peconfig;
    int                 i;
    struct perf_event_attr pe;
    struct perf_event_mmap_page *buf;

    zhpe_stats_num_counters = count;

    va_start(args, count);

    zstats->zhpe_stats_mmap_list =
        xcalloc(count, sizeof(*zstats->zhpe_stats_mmap_list));
    zstats->zhpe_stats_config_list =
        xcalloc(count, sizeof(*zstats->zhpe_stats_config_list));

    for (i = 0; i < count; i++) {
        peconfig = va_arg(args, __u64);

        memset(&pe, 0, sizeof(pe));
        pe.size = sizeof(pe);
        pe.type = petype;
        pe.config = peconfig;
        pe.disabled = 1;
        pe.exclude_kernel = 1;

        zstats->zhpe_stats_config_list[i] = peconfig;

        fd = my_perf_event_open(&pe, 0, -1, group_fd, 0);
        if (fd == -1) {
            err = -errno;
            print_func_err(__func__, __LINE__, "perf_event_open", "", err);
            abort();
        }

        buf = _zhpeu_mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, 0);
        /* Once the mmap exists, close the fd unless group leader. */
        if (i == 0)
            group_fd = fd;
        else
            close(fd);

        if (!buf)
            abort();
        zstats->zhpe_stats_mmap_list[i] = buf;
    }
    va_end(args);
    close(group_fd);

    if (prctl(PR_TASK_PERF_EVENTS_ENABLE) == -1) {
        err = -errno;
        print_func_err(__func__, __LINE__, "prctl", "ENABLE", err);
        abort();
    }
    for (i = 0; i < count; i++) {
        buf = zstats->zhpe_stats_mmap_list[i];
        if (!buf->index) {
            print_err("Error: %s, %d, buf: %p, bad buf->index\n",
                      __func__, __LINE__, buf);
            abort();
        }
    }
}

#ifdef HAVE_ZHPE_SIM

/* create recording entry and start collecting data for uid */
static void stats_sim_open(struct zhpe_stats *zstats, uint16_t uid)
{
    uint64_t                    len;
    int64_t ret;

    ret = sim_api_data_rec(DATA_REC_CREAT, uid, (uintptr_t)&len);
    if (ret) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_CREAT", -ret);
        abort();
    }

    if (zstats->sim_buf == NULL)
        zstats->sim_buf = calloc(1,len);

    ret = sim_api_data_rec(DATA_REC_START, uid, (uintptr_t)zstats->sim_buf);
    if (ret) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_START", -ret);
        abort();
    }
}

#else

static void stats_sim_open(struct zhpe_stats *zstats, uint16_t uid)
{
}

#endif // HAVE_ZHPE_SIM

static void stats_cmn_open(struct zhpe_stats *zstats, uint16_t uid)
{
    char                *fname = NULL;
    int                 err;

    if (zhpe_stats_profile == 0 ||
        zhpe_stats_profile == ZHPE_STATS_PROFILE_DISABLED)
        return;

    if (zstats != &dummy) {
        print_err("%s:zhpe_stats_open(%u) called on opened thread\n",
                  __func__, uid);
        return;
    }

    /* create zstats */
    zstats = xcalloc(1, sizeof(*zstats));

    zstats->zhpe_stats_ops = &stats_ops_enabled;
    zstats->uid = uid;
    zstats->slots_num = zhpe_stats_buf_count;
    zstats->slots_mask = zhpe_stats_buf_count - 1;
    zstats->buffer = xmalloc_cachealigned(zstats->slots_num *
                                          sizeof(struct zhpe_stats_record));
    zstats->tid = syscall(SYS_gettid);

    xasprintf(&fname, "%s/%s.%d.%d", zhpe_stats_dir, zhpe_stats_unique,
              zstats->tid, uid);
    zstats->fd = open(fname, O_RDWR | O_CREAT | O_APPEND,
                      S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (zstats->fd == -1) {
        err = -errno;
        print_func_err(__func__, __LINE__, "open", fname, err);
        abort();
    }
    free(fname);

    switch (zhpe_stats_profile) {

    case ZHPE_STATS_PROFILE_CARBON:
        stats_sim_open(zstats, uid);
        break;

    case ZHPE_STATS_PROFILE_STAMPS:
        break;

    case ZHPE_STATS_PROFILE_CPU_JUST1:
        init_rdpmc_profile(zstats, PERF_TYPE_RAW, 1,
                           RAW_PERF_HW_RETIRED_INSTRUCTIONS);
        break;

    case ZHPE_STATS_PROFILE_HW_JUST1:
        init_rdpmc_profile(zstats, PERF_TYPE_HARDWARE, 1,
                           PERF_COUNT_HW_INSTRUCTIONS);
        break;

    case ZHPE_STATS_PROFILE_HW:
        init_rdpmc_profile(zstats, PERF_TYPE_HARDWARE, 2,
                           PERF_COUNT_HW_INSTRUCTIONS,
                           PERF_COUNT_HW_CPU_CYCLES);
        break;

    case ZHPE_STATS_PROFILE_CPU:
        init_rdpmc_profile(zstats, PERF_TYPE_RAW, 6,
                           RAW_PERF_HW_RETIRED_INSTRUCTIONS,
                           RAW_PERF_HW_CPU_CYCLES,
                           DISPATCH_RESOURCE_STALL_CYCLES0,
                           DISPATCH_RESOURCE_STALL_CYCLES1,
                           RAW_PERF_HW_RETIRED_CONDITIONAL_BRANCH_INSTRUCTIONS,
                           RAW_PERF_HW_BRANCH_MISSES);
        break;

    case ZHPE_STATS_PROFILE_CPU2:
        init_rdpmc_profile(zstats, PERF_TYPE_RAW, 6,
                           RAW_PERF_HW_RETIRED_INSTRUCTIONS,
                           RAW_PERF_HW_CPU_CYCLES,
                           DISPATCH_RESOURCE_STALL_CYCLES0,
                           RAW_PERF_HW_RETIRED_CONDITIONAL_BRANCH_INSTRUCTIONS,
                           RAW_PERF_HW_RETIRED_BRANCH_INSTRUCTIONS,
                           RAW_PERF_HW_BRANCH_MISSES);
        break;

    case ZHPE_STATS_PROFILE_CACHE:
    case ZHPE_STATS_PROFILE_CACHE2:
        init_rdpmc_profile(zstats, perf_typeid, 6,
                           ALL_DC_ACCESSES,
                           L2_CACHE_MISS_FROM_DC_MISS,
                           L2_CACHE_HIT_FROM_DC_MISS,
                           L2_CACHE_MISS_FROM_L2_HWPF1,
                           L2_CACHE_MISS_FROM_L2_HWPF2,
                           L2_CACHE_HIT_FROM_L2_HWPF);
        break;

    }

    zhpe_stats = zstats;
    mutex_lock(&zhpe_stats_mutex);
    zstats->next = zhpe_stats_list;
    zhpe_stats_list = zstats;
    mutex_unlock(&zhpe_stats_mutex);

    stats_write_metadata(zstats);
}

/* sets global data */
bool zhpe_stats_init(const char *stats_unique)
{
    bool                ret = true;
    char                *tmp;
    char                *stats_dir;

    stats_dir = getenv("ZHPE_STATS_DIR");

    mutex_lock(&zhpe_stats_mutex);

    if (!stats_dir) {
        ret = false;
        print_err("%s:missing ZHPE_STATS_DIR\n", __func__);
    }

    tmp = getenv("ZHPE_STATS_PROFILE");

    if (!tmp) {
        ret = false;
        print_err("%s:missing ZHPE_STATS_PROFILE\n", __func__);
    }

    if (!stats_unique) {
        ret = false;
        print_err("%s:missing stats_unique\n", __func__);
    }

    if (!ret)
        goto done;

    if (zhpe_stats_profile != 0) {
        ret = false;
        print_err("%s: zhpe_stats_init called twice\n", __func__);
        goto done;
    }

    ret = false;

    stats_ops_enabled.recordme = stats_recordme;
    stats_ops_enabled.nextslot = stats_nextslot_noflush;

    print_err("Setting ZHPE_STATS_PROFILE to %s.\n", tmp);

    if (!strcmp("carbon", tmp)) {
        zhpe_stats_profile = ZHPE_STATS_PROFILE_CARBON;
        stats_ops_enabled.close = sim_stats_close;
        stats_ops_enabled.setvals = stats_setvals_hpe_sim;
    } else if (!strcmp("stamps", tmp)) {
        zhpe_stats_profile = ZHPE_STATS_PROFILE_STAMPS;
        stats_ops_enabled.setvals = stats_setvals_stamp;
        stats_ops_enabled.nextslot = stats_nextslot_flush;
    } else if (!strcmp("just1cpu", tmp)) {
        zhpe_stats_profile = ZHPE_STATS_PROFILE_CPU_JUST1;
        perf_typeid = PERF_TYPE_RAW;
        stats_ops_enabled.close = rdpmc_stats_close;
        stats_ops_enabled.setvals = stats_setvals_1_rdpmc;
    } else if (!strcmp("just1hw", tmp)) {
        zhpe_stats_profile = ZHPE_STATS_PROFILE_HW_JUST1;
        perf_typeid = PERF_TYPE_HARDWARE;
        stats_ops_enabled.close = rdpmc_stats_close;
        stats_ops_enabled.setvals = stats_setvals_1_rdpmc;
    } else if (!strcmp("hw", tmp)) {
        zhpe_stats_profile = ZHPE_STATS_PROFILE_HW;
        perf_typeid = PERF_TYPE_HARDWARE;
        stats_ops_enabled.close = rdpmc_stats_close;
        stats_ops_enabled.setvals = stats_setvals_2_rdpmc;
    } else if (!strcmp("cpu", tmp)) {
        zhpe_stats_profile = ZHPE_STATS_PROFILE_CPU;
        perf_typeid = PERF_TYPE_RAW;
        stats_ops_enabled.close = rdpmc_stats_close;
        stats_ops_enabled.setvals = stats_setvals_6_rdpmc;
    } else if (!strcmp("cpu2", tmp)) {
        zhpe_stats_profile = ZHPE_STATS_PROFILE_CPU2;
        perf_typeid = PERF_TYPE_RAW;
        stats_ops_enabled.close = rdpmc_stats_close;
        stats_ops_enabled.setvals = stats_setvals_6_rdpmc;
    } else if (!strcmp("cache", tmp)) {
        zhpe_stats_profile = ZHPE_STATS_PROFILE_CACHE;
        perf_typeid = PERF_TYPE_RAW;
        stats_ops_enabled.close = rdpmc_stats_close;
        stats_ops_enabled.setvals = stats_setvals_6_rdpmc;
    } else if (!strcmp("cache2", tmp)) {
        zhpe_stats_profile = ZHPE_STATS_PROFILE_CACHE2;
        perf_typeid = PERF_TYPE_RAW;
        stats_ops_enabled.close = rdpmc_stats_close;
        stats_ops_enabled.setvals = stats_setvals_6_rdpmc;
        stats_ops_enabled.recordme = stats_recordme_memcpy;
    }

    if (zhpe_stats_profile == 0)
        goto done;

    stats_ops_disabled.close = stats_ops_enabled.close;
    stats_ops_disabled.recordme = stats_ops_enabled.recordme;
    stats_ops_disabled.nextslot = stats_ops_enabled.nextslot;
    stats_ops_disabled.setvals = stats_ops_enabled.setvals;

#ifdef HAVE_ZHPE_SIM
    if (sim_api_is_sim()) {
        if (zhpe_stats_profile != ZHPE_STATS_PROFILE_CARBON) {
            print_err("%s:Only carbon profile allowed on Carbon\n", __func__);
            goto done;
        }
    } else {
        if (zhpe_stats_profile == ZHPE_STATS_PROFILE_CARBON) {
            print_err("%s:carbon profile only allowed on Carbon\n", __func__);
            goto done;
        }
    }
#else // HAVE_ZHPE_SIM
    if (zhpe_stats_profile == ZHPE_STATS_PROFILE_CARBON) {
        print_err("%s:carbon profile not supported\n", __func__);
        goto done;
    }
#endif // HAVE_ZHPE_SIM

    zhpe_stats_buf_count = ZHPE_STATS_BUF_COUNT_MAX;
    tmp = getenv("ZHPE_STATS_BUF_COUNT");
    if (tmp != NULL)
        zhpe_stats_buf_count = atoi(tmp);

    if (zhpe_stats_buf_count & (zhpe_stats_buf_count - 1)) {
        zhpe_stats_buf_count = (uint64_t)1 << fls64(zhpe_stats_buf_count);
        print_err("%s,%u: rounded up ZHPE_STATS_BUF_COUNT to: %lu\n",
                  __func__, __LINE__, zhpe_stats_buf_count);
    }

    if ((zhpe_stats_buf_count <= 0) ||
        (zhpe_stats_buf_count > ZHPE_STATS_BUF_COUNT_MAX))
    {
        zhpe_stats_buf_count = ZHPE_STATS_BUF_COUNT_MAX;
        print_err("%s,%u: Setting ZHPE_STATS_BUF_COUNT to %lu.\n",
        __func__, __LINE__, zhpe_stats_buf_count);
    }

    zhpe_stats_dir = xstrdup_or_null(stats_dir);
    zhpe_stats_unique = xstrdup_or_null(stats_unique);

    ret = true;

 done:
    if (!ret) {
        print_err("%s:zhpe-stats disabled\n", __func__);
        zhpe_stats_profile = ZHPE_STATS_PROFILE_DISABLED;
    }
    mutex_unlock(&zhpe_stats_mutex);

    return ret;
}

/* minimal_open sets up thread-specific data and calls profile-specific open */
void zhpe_stats_open(uint16_t uid)
{
    struct zhpe_stats *zstats = zhpe_stats;

    stats_cmn_open(zstats, uid);
}

#else

void zhpe_stats_test(uint16_t uid)
{
}

bool zhpe_stats_init(const char *stats_unique)
{
    return true;
}

void zhpe_stats_open(uint16_t uid)
{
}

void zhpe_stats_finalize(void)
{
}
#endif // HAVE_ZHPE_STATS
