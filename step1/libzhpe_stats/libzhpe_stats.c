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
 * stats_common_closed frees zhpe_stats->buffer and sets it to NULL.
 *
 */

#ifdef HAVE_ZHPE_STATS

#ifdef HAVE_HPE_SIM

#include <hpe_sim_api_linux64.h>

#endif // HAVE_HPE_SIM

static_assert(sizeof(struct zhpe_stats_record)%64 == 0, "foo");

#define rdpmc(counter,low, high) \
     __asm__ __volatile__("rdpmc" \
        : "=a" (low), "=d" (high) \
        : "c" (counter))

/* copied from perf_event_open man page */
int my_perf_event_open(struct perf_event_attr *pea, pid_t pid,
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

static void stats_nop_stamp(struct zhpe_stats *zstats,
                            uint32_t dum,
                            uint64_t dum1,
                            uint64_t dum2,
                            uint64_t dum3,
                            uint64_t dum4,
                            uint64_t dum5,
                            uint64_t dum6)
{
}

static void stats_nop_setvals(struct zhpe_stats *zstats,
                              struct zhpe_stats_record *rec)
{
}

static void stats_nop_saveme(struct zhpe_stats *zstats, char *dest, char *src)
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
    .saveme             = stats_nop_saveme,
};

static struct zhpe_stats dummy =
{
    .zhpe_stats_ops= &zhpe_stats_nops
};

__thread struct zhpe_stats *zhpe_stats = &dummy;

#ifdef HAVE_ZHPE_STATS

#define ZHPE_STATS_BUF_COUNT_MAX 1048576


/* Common definitions/code */
static char             *zhpe_stats_dir;
static char             *zhpe_stats_unique;
static pthread_mutex_t  zhpe_stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t         zhpe_stats_buf_count;
static uint64_t         zhpe_stats_buf_mask;
static size_t           zhpe_stats_profile=0;

int zhpe_stats_num_counters=0;
__u32 perf_typeid=0;


/* forward declarations */
void zhpe_stats_flush();

static void stats_cmn_enable(struct zhpe_stats * zstats)
{
    if(zstats->enabled == ZHPE_STATS_ENABLED)
        return;

    zstats->enabled = ZHPE_STATS_ENABLED;
    zstats->zhpe_stats_ops = zstats->saved_zhpe_stats_ops;
    zstats->zhpe_stats_ops->restart_all(zstats);
}

static void stats_cmn_disable(struct zhpe_stats *zstats)
{
    zstats->zhpe_stats_ops->pause_all(zstats);
    zstats->enabled = ZHPE_STATS_DISABLED;
    zstats->zhpe_stats_ops = zstats->disabled_zhpe_stats_ops;
}

/* don't free zstats */
static void stats_common_close(struct zhpe_stats *zstats)
{
    if ( zstats->fd > 0 )
        close(zstats->fd);
    zstats->fd = -1;

    free(zstats->buffer);
    zstats->buffer = NULL;
    return;
}

static void rdpmc_stats_finalize(struct zhpe_stats *zstats)
{
    if (zstats == &dummy)
        return;

    for (int i=0;i<zhpe_stats_num_counters;i++)
    {
        if (zstats->zhpe_stats_fd_list[i] != -1)
        {
           close(zstats->zhpe_stats_fd_list[i]);
           zstats->zhpe_stats_fd_list[i]=-1;
        }
    }
    free(zstats->zhpe_stats_fd_list);
    free(zstats->zhpe_stats_cntr_list);
    free(zstats->zhpe_stats_config_list);
    return;
}


void zhpe_stats_finalize()
{
    struct zhpe_stats *zstats = zhpe_stats;

    if (zstats == &dummy)
        return;

    if (zhpe_stats_dir)
        free(zhpe_stats_dir);
    zhpe_stats_dir = NULL;

    if (zhpe_stats_unique)
        free(zhpe_stats_unique);
    zhpe_stats_unique = NULL;

    /* custom finalize here */
    if (zhpe_stats_profile > 100)
        rdpmc_stats_finalize(zstats);

    stats_common_close(zstats);
    zhpe_stats_profile = 0;
    return;
}

static void stats_write_metadata(struct zhpe_stats * zstats)
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
static struct zhpe_stats_record *stats_simple_nextslot(struct zhpe_stats *zstats)
{
    assert(zstats->buffer);
    struct zhpe_stats_record *rec;

    assert(zstats->head < zstats->num_slots - 1);

    rec = &(zstats->buffer[(zhpe_stats_buf_mask & zstats->head++)]);

    return rec;
}

static uint64_t do_rdtscp(void)
{
    uint32_t            lo;
    uint32_t            hi;
    uint32_t            cpu;

    asm volatile("rdtscp\n\t": "=a" (lo), "=d" (hi), "=c" (cpu) : :);

    return ((uint64_t)hi << 32 | lo);
}

static void stats_setvals_just1_rdpmc(struct zhpe_stats *zstats,
                                      struct zhpe_stats_record *rec)
{
    unsigned int cnt1low, cnt1high;

    rec->val0 = do_rdtscp();
    rdpmc(zstats->zhpe_stats_cntr_list[0], cnt1low, cnt1high);
    rec->val1 = (((long long)cnt1low) | ((long long)cnt1high ) << 32);
}

static void stats_setvals_2_rdpmc(struct zhpe_stats *zstats,
                                  struct zhpe_stats_record *rec)
{
    unsigned int cnt1low, cnt1high;
    unsigned int cnt2low, cnt2high;

    rec->val0 = do_rdtscp();
    rdpmc(zstats->zhpe_stats_cntr_list[0], cnt1low, cnt1high);
    rec->val1 = (((long long)cnt1low) | ((long long)cnt1high ) << 32);
    rdpmc(zstats->zhpe_stats_cntr_list[1], cnt2low, cnt2high);
    rec->val2 = (((long long)cnt2low) | ((long long)cnt2high ) << 32);
}

static void stats_setvals_6_rdpmc(struct zhpe_stats *zstats,
                                  struct zhpe_stats_record *rec)
{
    unsigned int cnt1low, cnt1high;
    unsigned int cnt2low, cnt2high;
    unsigned int cnt3low, cnt3high;
    unsigned int cnt4low, cnt4high;
    unsigned int cnt5low, cnt5high;
    unsigned int cnt6low, cnt6high;

    rec->val0 = do_rdtscp();
    rdpmc(zstats->zhpe_stats_cntr_list[0], cnt1low, cnt1high);
    rec->val1 = (((long long)cnt1low) | ((long long)cnt1high ) << 32);
    rdpmc(zstats->zhpe_stats_cntr_list[1], cnt2low, cnt2high);
    rec->val2 = (((long long)cnt2low) | ((long long)cnt2high ) << 32);
    rdpmc(zstats->zhpe_stats_cntr_list[2], cnt3low, cnt3high);
    rec->val3 = (((long long)cnt3low) | ((long long)cnt3high ) << 32);
    rdpmc(zstats->zhpe_stats_cntr_list[3], cnt4low, cnt4high);
    rec->val4 = (((long long)cnt4low) | ((long long)cnt4high ) << 32);
    rdpmc(zstats->zhpe_stats_cntr_list[4], cnt5low, cnt5high);
    rec->val5 = (((long long)cnt5low) | ((long long)cnt5high ) << 32);
    rdpmc(zstats->zhpe_stats_cntr_list[5], cnt6low, cnt6high);
    rec->val6 = (((long long)cnt6low) | ((long long)cnt6high ) << 32);
}

#ifdef HPE_SIM
static void stats_setvals_hpe_sim(struct zhpe_stats *zstats,
                                  struct zhpe_stats_record *rec)
{
    //uint64_t len =  sizeof(uint64_t);
    ProcCtlData *foo;
    rec->val0 = do_rdtscp();
    foo = (void *)zstats->sim_buf;

    assert(zstats->sim_buf);
    int64_t ret;

    ret = sim_api_data_rec(DATA_REC_PAUSE, (uint16_t)zstats->uid,
                                        (uintptr_t)zstats->sim_buf);
    if (ret)
    {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_PAUSE", -ret);
        abort();
    }

    rec->val1 = foo->cpl0ExecInstTotal;
    rec->val2 = foo->cpl3ExecInstTotal;

    ret = sim_api_data_rec(DATA_REC_START, (uint16_t)zstats->uid,
                                        (uintptr_t)zstats->sim_buf);
    if (ret)
    {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_START", -ret);
        abort();
    }
}

#else // HPE_SIM
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

#endif // HPE_SIM


static inline void stats_vmemcpy_saveme(struct zhpe_stats *zstats,
                                        char * dest, char * src)
{
    uint64_t len =  sizeof(struct zhpe_stats_record);
    __vmemcpy(movntdq, movntdqa, dest, src, len);
}

static inline void stats_memcpy_saveme(struct zhpe_stats *zstats,
                                       char * dest, char * src)
{
    uint64_t len =  sizeof(struct zhpe_stats_record);
    memcpy(dest, src, len);
}

static void stats_recordme_memcpy(struct zhpe_stats *zstats,
                                  uint32_t subid, uint32_t opflag)
{
    struct zhpe_stats_record *dest;
    struct zhpe_stats_record tmp;

    tmp.subid = subid;
    tmp.op_flag = opflag;

    dest = stats_simple_nextslot(zstats);
    zstats->zhpe_stats_ops->setvals(zstats, &tmp);
    stats_memcpy_saveme(zstats, (char *)dest, (char *)&tmp);
}

static void stats_recordme(struct zhpe_stats *zstats, uint32_t subid,
                           uint32_t opflag)
{
    struct zhpe_stats_record *dest;

    dest = stats_simple_nextslot(zstats);
    dest->subid = subid;
    dest->op_flag = opflag;

    zstats->zhpe_stats_ops->setvals(zstats, dest);
}

#define SS1    \
do {            \
    zhpe_stats_start(ZHPE_STATS_SUBID_STARTSTOP);      \
    zhpe_stats_stop(ZHPE_STATS_SUBID_STARTSTOP);      \
} while (0)

#define SS10    \
do {            \
    SS1;       \
    SS1;       \
    SS1;       \
    SS1;       \
    SS1;       \
    SS1;       \
    SS1;       \
    SS1;       \
    SS1;       \
    SS1;       \
} while (0)

#define SS100    \
do {            \
    SS10;       \
    SS10;       \
    SS10;       \
    SS10;       \
    SS10;       \
    SS10;       \
    SS10;       \
    SS10;       \
    SS10;       \
    SS10;       \
} while (0)

#define S_STAMP_S1    \
do {            \
    zhpe_stats_start(ZHPE_STATS_SUBID_S_STAMP_S);      \
    zhpe_stats_stamp(89888786, 89, 88, 87, 86, 54, 32);       \
    zhpe_stats_stop(ZHPE_STATS_SUBID_S_STAMP_S);      \
} while (0)

#define S_STAMP_S10    \
do {            \
    S_STAMP_S1;       \
    S_STAMP_S1;       \
    S_STAMP_S1;       \
    S_STAMP_S1;       \
    S_STAMP_S1;       \
    S_STAMP_S1;       \
    S_STAMP_S1;       \
    S_STAMP_S1;       \
    S_STAMP_S1;       \
    S_STAMP_S1;       \
} while (0)

#define S_STAMP_S100    \
do {            \
    S_STAMP_S10;       \
    S_STAMP_S10;       \
    S_STAMP_S10;       \
    S_STAMP_S10;       \
    S_STAMP_S10;       \
    S_STAMP_S10;       \
    S_STAMP_S10;       \
    S_STAMP_S10;       \
    S_STAMP_S10;       \
    S_STAMP_S10;       \
} while (0)

#define S_STARTSTOP_S1    \
do {            \
    zhpe_stats_start(ZHPE_STATS_SUBID_S_SS_S);      \
    zhpe_stats_start(0);      \
    zhpe_stats_stop(0);      \
    zhpe_stats_stop(ZHPE_STATS_SUBID_S_SS_S);      \
} while (0)

#define S_STARTSTOP_S10    \
do {            \
    S_STARTSTOP_S1;       \
    S_STARTSTOP_S1;       \
    S_STARTSTOP_S1;       \
    S_STARTSTOP_S1;       \
    S_STARTSTOP_S1;       \
    S_STARTSTOP_S1;       \
    S_STARTSTOP_S1;       \
    S_STARTSTOP_S1;       \
    S_STARTSTOP_S1;       \
    S_STARTSTOP_S1;       \
} while (0)

#define S_STARTSTOP_S100    \
do {            \
    S_STARTSTOP_S10;       \
    S_STARTSTOP_S10;       \
    S_STARTSTOP_S10;       \
    S_STARTSTOP_S10;       \
    S_STARTSTOP_S10;       \
    S_STARTSTOP_S10;       \
    S_STARTSTOP_S10;       \
    S_STARTSTOP_S10;       \
    S_STARTSTOP_S10;       \
    S_STARTSTOP_S10;       \
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
void zhpe_stats_flush(struct zhpe_stats *zstats)
{
    assert(zstats->buffer);

    ssize_t     res;
    uint64_t    bufsize;

    assert(zstats->head < zstats->num_slots - 1);
    bufsize = (zhpe_stats_buf_mask & zstats->head)
                * (sizeof(struct zhpe_stats_record));
    io_wmb();
    res = write(zstats->fd, zstats->buffer, bufsize);
    if (check_func_ion(__func__, __LINE__, "write", bufsize, false,
                       bufsize, res, 0) < 0)
        abort();

    zstats->head = 0;
}

static void rdpmc_stats_close(struct zhpe_stats *zstats)
{
//printf("In rdpmc_stats_close\n");
    stats_recordme(zstats, 0, ZHPE_STATS_OP_CLOSE);

    zhpe_stats_flush(zstats);

    stats_common_close(zstats);
}


#ifdef HPE_SIM
static void sim_stats_close(struct zhpe_stats *zstats)
{
    int64_t ret;
//printf("IN sim_stats_close\n");
    ret=sim_api_data_rec(DATA_REC_END, zstats->uid,
                                       (uintptr_t)zstats->sim_buf);
    if (ret)
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_END", -ret);
    zhpe_stats_flush(zstats);
    stats_common_close(zstats);
}

#else

static void sim_stats_close(struct zhpe_stats *zstats)
{
}

#endif //HPE_SIM

/* cache2 profile */
static void stats_start_memcpy(struct zhpe_stats *zstats, uint32_t subid)
{
    stats_recordme_memcpy(zstats, subid, ZHPE_STATS_OP_START);
}

static void stats_stop_memcpy(struct zhpe_stats *zstats, uint32_t subid)
{
    stats_recordme_memcpy(zstats, subid, ZHPE_STATS_OP_STOP);
}

static void stats_stop_all_memcpy(struct zhpe_stats *zstats)
{
    stats_recordme(zstats, 0, ZHPE_STATS_OP_RESTART_ALL);
}


static void stats_start(struct zhpe_stats *zstats, uint32_t subid)
{
//printf("IN stats_start\n");
    stats_recordme(zstats, subid, ZHPE_STATS_OP_START);
}

static void stats_stop(struct zhpe_stats *zstats, uint32_t subid)
{
//printf("IN stats_stop\n");
    stats_recordme(zstats, subid, ZHPE_STATS_OP_STOP);
}

static void stats_pause_all(struct zhpe_stats *zstats)
{
//printf("IN stats_pause_all\n");
    stats_recordme(zstats, 0, ZHPE_STATS_OP_PAUSE_ALL);
}

static void stats_restart_all(struct zhpe_stats *zstats)
{
//printf("IN stats_restart_all\n");
    stats_recordme(zstats, 0, ZHPE_STATS_OP_RESTART_ALL);
}

static void stats_stop_all(struct zhpe_stats *zstats)
{
//printf("IN stats_stop_all\n");
    stats_recordme(zstats, 0, ZHPE_STATS_OP_STOP_ALL);
}

/* generic */
static void stats_stamp(struct zhpe_stats *zstats, uint32_t subid,
                                    uint64_t d1,
                                    uint64_t d2,
                                    uint64_t d3,
                                    uint64_t d4,
                                    uint64_t d5,
                                    uint64_t d6)

{
    struct zhpe_stats_record    *dest;

    dest = stats_simple_nextslot(zstats);
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

static struct zhpe_stats_ops stats_ops_rdpmc = {
    .close              = rdpmc_stats_close,
    .enable             = stats_cmn_enable,
    .disable            = stats_cmn_disable,
    .pause_all          = stats_pause_all,
    .restart_all        = stats_restart_all,
    .stop_all           = stats_stop_all,
    .start              = stats_start,
    .stop               = stats_stop,
    .stamp              = stats_stamp,
    .setvals            = stats_setvals_6_rdpmc,
    .saveme             = stats_memcpy_saveme,
};

static struct zhpe_stats_ops stats_ops_rdpmc_just1val = {
    .close              = rdpmc_stats_close,
    .enable             = stats_cmn_enable,
    .disable            = stats_cmn_disable,
    .pause_all          = stats_pause_all,
    .restart_all        = stats_restart_all,
    .stop_all           = stats_stop_all,
    .start              = stats_start,
    .stop               = stats_stop,
    .stamp              = stats_stamp,
    .setvals            = stats_setvals_just1_rdpmc,
    .saveme             = stats_memcpy_saveme,
};

static struct zhpe_stats_ops stats_ops_rdpmc_2vals = {
    .close              = rdpmc_stats_close,
    .enable             = stats_cmn_enable,
    .disable            = stats_cmn_disable,
    .pause_all          = stats_pause_all,
    .restart_all        = stats_restart_all,
    .stop_all           = stats_stop_all,
    .start              = stats_start,
    .stop               = stats_stop,
    .stamp              = stats_stamp,
    .setvals            = stats_setvals_2_rdpmc,
    .saveme             = stats_memcpy_saveme,
};

static struct zhpe_stats_ops stats_ops_rdpmc_disabled = {
    .close              = rdpmc_stats_close,
    .enable             = stats_cmn_enable,
    .disable            = stats_cmn_disable,
    .pause_all          = stats_nop_zstats,
    .restart_all        = stats_nop_zstats,
    .stop_all           = stats_nop_zstats,
    .start              = stats_nop_zstats_uint32,
    .stop               = stats_nop_zstats_uint32,
    .stamp              = stats_nop_stamp,
    .setvals            = stats_nop_setvals,
    .saveme             = stats_nop_saveme,
};

static struct zhpe_stats_ops stats_ops_rdpmc_memcpy = {
    .close              = rdpmc_stats_close,
    .enable             = stats_cmn_enable,
    .disable            = stats_cmn_disable,
    .pause_all          = stats_pause_all,
    .restart_all        = stats_restart_all,
    .stop_all           = stats_stop_all_memcpy,
    .start              = stats_start_memcpy,
    .stop               = stats_stop_memcpy,
    .stamp              = stats_stamp,
    .setvals            = stats_setvals_6_rdpmc,
    .saveme             = stats_memcpy_saveme,
};

static struct zhpe_stats_ops stats_ops_hpe_sim_disabled = {
    .close              = sim_stats_close,
    .enable             = stats_cmn_enable,
    .disable            = stats_cmn_disable,
    .pause_all          = stats_nop_zstats,
    .restart_all        = stats_nop_zstats,
    .stop_all           = stats_nop_zstats,
    .start              = stats_nop_zstats_uint32,
    .stop               = stats_nop_zstats_uint32,
    .stamp              = stats_stamp,
    .setvals            = stats_setvals_hpe_sim,
    .saveme             = stats_memcpy_saveme,
};

static struct zhpe_stats_ops stats_ops_hpe_sim = {
    .close              = sim_stats_close,
    .enable             = stats_cmn_enable,
    .disable            = stats_cmn_disable,
    .pause_all          = stats_pause_all,
    .restart_all        = stats_restart_all,
    .stop_all           = stats_stop_all,
    .start              = stats_start,
    .stop               = stats_stop,
    .stamp              = stats_stamp,
    .setvals            = stats_setvals_hpe_sim,
    .saveme             = stats_memcpy_saveme,
};

static void init_rdpmc_profile(struct zhpe_stats *zstats, __u32 petype,
                               int count, ...)
{
    va_list args;
    va_start(args, count);
    int ret;

    zstats->zhpe_stats_fd_list = calloc(count, sizeof(int));
    zstats->zhpe_stats_cntr_list = calloc(count, sizeof(uint64_t));
    zstats->zhpe_stats_config_list = calloc(count, sizeof(uint64_t));

    struct perf_event_attr pe;

    int         err;
    void        *addr;
    uint64_t    index;
    __u64       peconfig;

    struct perf_event_mmap_page * buf;

    for (int i=0; i<count; i++)
    {
        peconfig = va_arg(args, __u64);

        memset(&pe, 0, sizeof(struct perf_event_attr));
        pe.size = sizeof(struct perf_event_attr);
        pe.type = petype;
        pe.config = peconfig;
        pe.exclude_kernel = 1;

        zstats->zhpe_stats_config_list[i] = peconfig;

        zstats->zhpe_stats_fd_list[i] = my_perf_event_open(&pe, 0, -1, -1, 0);
        if (zstats->zhpe_stats_fd_list[i] < 0) {
            err = -errno;
            print_func_err(__func__, __LINE__, "perf_event_open fail", "", err);
            exit(EXIT_FAILURE);
        }

        addr = mmap(NULL, 4096, PROT_READ, MAP_SHARED,
                    zstats->zhpe_stats_fd_list[i], 0);
        if (addr == MAP_FAILED) {
            err = -errno;
            print_func_err(__func__, __LINE__, "mmap() syscall fail", "", err);
            exit(EXIT_FAILURE);
        }

        buf = (struct perf_event_mmap_page *) addr;
        index = buf->index;
        if (index == 0) {
            print_err("Error: %s, %d, buf: %lxu, bad buf->index\n",
                              __func__, __LINE__, (uintptr_t)addr);
            exit(EXIT_FAILURE);
        }
        zstats->zhpe_stats_cntr_list[i] = index - 1;
        printf("At open: zhpe_stats_cntr_list[%d] = %lxu\n",i, index);
    }
    va_end(args);
    ret = prctl(PR_TASK_PERF_EVENTS_ENABLE);
    if (ret) {
        err = -errno;
        print_func_err(__func__, __LINE__, "prctl fail", "", err);
        exit(EXIT_FAILURE);
    }
}

#ifdef HPE_SIM

/* create recording entry and start collecting data for uid */
static void stats_sim_open(struct zhpe_stats *zstats, uint16_t uid)
{
    uint64_t                    len;
    int64_t ret;

    ret=sim_api_data_rec(DATA_REC_CREAT, uid, (uintptr_t)&len);
    if (ret) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_CREAT", -ret);
        abort();
    }

    if (zstats->sim_buf == NULL)
        zstats->sim_buf = calloc(1,len);

    ret=sim_api_data_rec(DATA_REC_START, uid, (uintptr_t)zstats->sim_buf);
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

#endif // HPE_SIM



static void stats_common_open(struct zhpe_stats *zstats, uint16_t uid)
{
//printf("in stats_common_open\n");
    char *fname = NULL;
    if (zhpe_stats_profile == ZHPE_STATS_PROFILE_DISABLED)
        return;

    if (zhpe_stats_profile == 0)
    {
        print_err("%s:%d %s\n",__func__, __LINE__,
                       "zhpe_stats_profile is NULL");
        abort();
    }

    if (zstats->buffer != 0)
    {
        if (zstats->uid == uid)
            return;

        /* could just close existing file and start new one. */
        print_err("%s:%d %s\n",__func__, __LINE__,
                       "zhpe_stats already open");
        abort();
    }

    zstats->uid = uid;
    zstats->num_slots = zhpe_stats_buf_count;
    zstats->head = 0;
    zstats->buffer = malloc_cachealigned(zstats->num_slots *
                                         sizeof(struct zhpe_stats_record));

    if (zhpeu_asprintf(&fname, "%s/%s.%ld.%d",
                           zhpe_stats_dir, zhpe_stats_unique,
                           syscall(SYS_gettid), uid) == -1)
    {
        print_func_err(__func__, __LINE__, "zhpeu_asprintf", "", -ENOMEM);
        abort();
    }

    printf("new output file%s\n",fname);
    zstats->fd = open(fname, O_RDWR | O_CREAT | O_APPEND,
                     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (zstats->fd == -1) {
        print_func_err(__func__, __LINE__, "open", fname, -errno);
        abort();
    }
    //printf("Just opened %s: %d\n",fname,zstats->fd);
    free(fname);
        switch(zhpe_stats_profile) {

            case ZHPE_STATS_PROFILE_DISABLED:
                break;

            case ZHPE_STATS_PROFILE_CARBON:
                zstats->zhpe_stats_ops = &stats_ops_hpe_sim;
                zstats->saved_zhpe_stats_ops = &stats_ops_hpe_sim;
                zstats->disabled_zhpe_stats_ops = &stats_ops_hpe_sim_disabled;
                stats_sim_open(zstats, uid);
                break;

            case ZHPE_STATS_PROFILE_CPU_JUST1:
            case ZHPE_STATS_PROFILE_HW_JUST1:
                zstats->zhpe_stats_ops = &stats_ops_rdpmc_just1val;
                zstats->saved_zhpe_stats_ops = &stats_ops_rdpmc_just1val;
                zstats->disabled_zhpe_stats_ops = &stats_ops_rdpmc_disabled;
                break;

            case ZHPE_STATS_PROFILE_HW:
                zstats->zhpe_stats_ops = &stats_ops_rdpmc_2vals;
                zstats->saved_zhpe_stats_ops = &stats_ops_rdpmc_2vals;
                zstats->disabled_zhpe_stats_ops = &stats_ops_rdpmc_disabled;
                break;

            case ZHPE_STATS_PROFILE_CPU:
            case ZHPE_STATS_PROFILE_CACHE:
                zstats->zhpe_stats_ops = &stats_ops_rdpmc;
                zstats->saved_zhpe_stats_ops = &stats_ops_rdpmc;
                zstats->disabled_zhpe_stats_ops = &stats_ops_rdpmc_disabled;
                break;

            case ZHPE_STATS_PROFILE_CACHE2:
                zstats->zhpe_stats_ops = &stats_ops_rdpmc_memcpy;
                zstats->saved_zhpe_stats_ops = &stats_ops_rdpmc_memcpy;
                zstats->disabled_zhpe_stats_ops = &stats_ops_rdpmc_disabled;
                break;

            default:
                  print_err("%s:%d Error: invalid stats profile %zu \n",
                                                        __func__, __LINE__,
                                                        zhpe_stats_profile);
                  abort();
        }
        stats_write_metadata(zstats);
}

/* sets global data */
bool zhpe_stats_init(const char *stats_unique)
{
    struct zhpe_stats *zstats;

    bool                ret = false;
    char                *tmp;
    char                *stats_dir;

    stats_dir = getenv("ZHPE_STATS_DIR");

    if (!stats_dir && !stats_unique) {
        print_err("%s,%u:missing %s and %s\n", __func__, __LINE__,
                  "stats_unique", "stats_dir");
        return ret;
    }

    if (!stats_dir || !stats_unique) {
        print_err("%s,%u:missing %s\n", __func__, __LINE__,
                  stats_dir ? "stats_unique" : "stats_dir");
        return ret;
    }

    tmp = getenv("ZHPE_STATS_PROFILE");

    if (tmp == NULL)
        tmp = "";

    print_err("Setting ZHPE_STATS_PROFILE to %s.\n",tmp);

    mutex_lock(&zhpe_stats_mutex);

    if (zhpe_stats_profile != 0) {
        print_err("%s,%u: zhpe_stats_init called twice\n",
            __func__, __LINE__);
        return ret;
    }

    if (!strcmp(tmp, "carbon"))
    {
        if (!strcmp("carbon",tmp)) {
            zhpe_stats_profile = ZHPE_STATS_PROFILE_CARBON;
        } else {
            print_err("%s:%d: Invalid profile: %s", __func__, __LINE__, tmp);
            goto done;
        }
    } else if (!strcmp("just1cpu",tmp)) {
            zhpe_stats_profile = ZHPE_STATS_PROFILE_CPU_JUST1;
            perf_typeid = PERF_TYPE_RAW;
    } else if (!strcmp("just1hw",tmp)) {
                zhpe_stats_profile = ZHPE_STATS_PROFILE_HW_JUST1;
                perf_typeid = PERF_TYPE_HARDWARE;
    } else if (!strcmp("hw",tmp)) {
                zhpe_stats_profile = ZHPE_STATS_PROFILE_HW;
                perf_typeid = PERF_TYPE_HARDWARE;
    } else if (!strcmp("cpu",tmp)) {
                zhpe_stats_profile = ZHPE_STATS_PROFILE_CPU;
                perf_typeid = PERF_TYPE_RAW;
    } else if (!strcmp("cpu2",tmp)) {
                zhpe_stats_profile = ZHPE_STATS_PROFILE_CPU2;
                perf_typeid = PERF_TYPE_RAW;
    } else if (!strcmp("cache",tmp)) {
            zhpe_stats_profile = ZHPE_STATS_PROFILE_CACHE;
            perf_typeid = PERF_TYPE_RAW;
    } else if (!strcmp("cache2",tmp)) {
            zhpe_stats_profile = ZHPE_STATS_PROFILE_CACHE2;
            perf_typeid = PERF_TYPE_RAW;
    } else {
            print_err("%s,%u: Disabling zhpe-stats.\n", __func__, __LINE__);
            zhpe_stats_profile = ZHPE_STATS_PROFILE_DISABLED;
    }

    zhpe_stats_buf_count=0;
    tmp = getenv("ZHPE_STATS_BUF_COUNT");
    if (tmp != NULL)
        zhpe_stats_buf_count=atoi(tmp);

    if (zhpe_stats_buf_count & (zhpe_stats_buf_count -1)) {
        zhpe_stats_buf_count = pow(2,ceil(log(zhpe_stats_buf_count)/log(2)));
        print_err("%s,%u: rounded up ZHPE_STATS_BUF_COUNT to: %lu\n",
                  __func__, __LINE__, zhpe_stats_buf_count);
    }

    if ((zhpe_stats_buf_count <= 0) ||
            (zhpe_stats_buf_count > ZHPE_STATS_BUF_COUNT_MAX))
    {
        zhpe_stats_buf_count=ZHPE_STATS_BUF_COUNT_MAX;
        print_err("%s,%u: Setting ZHPE_STATS_BUF_COUNT to %lu.\n",
                     __func__, __LINE__, zhpe_stats_buf_count);
    }

    zhpe_stats_buf_mask=zhpe_stats_buf_count - 1;

    /* create zstats */
    zstats = calloc(1, sizeof(struct zhpe_stats));
    zhpe_stats = zstats;
    zstats->enabled = 0;
    assert (zstats);
    zstats->zhpe_stats_ops = &zhpe_stats_nops;

    if (zhpe_stats_profile !=  ZHPE_STATS_PROFILE_CARBON)
    {
        switch(zhpe_stats_profile) {
            case ZHPE_STATS_PROFILE_CPU_JUST1:
                zhpe_stats_num_counters = 1;
                init_rdpmc_profile(zstats, PERF_TYPE_RAW, 1,
                                    RAW_PERF_HW_RETIRED_INSTRUCTIONS);
                break;
            case ZHPE_STATS_PROFILE_HW_JUST1:
                zhpe_stats_num_counters = 1;
                init_rdpmc_profile(zstats, PERF_TYPE_HARDWARE, 1,
                                    PERF_COUNT_HW_INSTRUCTIONS
                                    );
                break;

            case ZHPE_STATS_PROFILE_HW:
                zhpe_stats_num_counters = 2;
                init_rdpmc_profile(zstats, PERF_TYPE_HARDWARE, 2,
                                    PERF_COUNT_HW_INSTRUCTIONS,
                                    PERF_COUNT_HW_CPU_CYCLES
                                    );
                break;

            case ZHPE_STATS_PROFILE_CPU:
                zhpe_stats_num_counters = 6;
                init_rdpmc_profile(zstats, PERF_TYPE_RAW, 6,
                            RAW_PERF_HW_RETIRED_INSTRUCTIONS,
                            RAW_PERF_HW_RETIRED_CONDITIONAL_BRANCH_INSTRUCTIONS,
                            RAW_PERF_HW_CPU_CYCLES,
                            DISPATCH_RESOURCE_STALL_CYCLES0,
                            DISPATCH_RESOURCE_STALL_CYCLES1,
                            RAW_PERF_HW_BRANCH_MISSES);
                break;
            case ZHPE_STATS_PROFILE_CPU2:
                zhpe_stats_num_counters = 6;
                init_rdpmc_profile(zstats, PERF_TYPE_RAW, 6,
                            RAW_PERF_HW_RETIRED_INSTRUCTIONS,
                            RAW_PERF_HW_RETIRED_CONDITIONAL_BRANCH_INSTRUCTIONS,
                            RAW_PERF_HW_RETIRED_BRANCH_INSTRUCTIONS,
                            RAW_PERF_HW_CPU_CYCLES,
                            DISPATCH_RESOURCE_STALL_CYCLES0,
                            RAW_PERF_HW_BRANCH_MISSES);
                break;

            case ZHPE_STATS_PROFILE_CACHE:
                zhpe_stats_num_counters = 6;
                init_rdpmc_profile(zstats, perf_typeid, 6,
                                    ALL_DC_ACCESSES,
                                    L2_CACHE_MISS_FROM_DC_MISS,
                                    L2_CACHE_HIT_FROM_DC_MISS,
                                    L2_CACHE_MISS_FROM_L2_HWPF1,
                                    L2_CACHE_MISS_FROM_L2_HWPF2,
                                    L2_CACHE_HIT_FROM_L2_HWPF);
                break;

            case ZHPE_STATS_PROFILE_CACHE2:
                zhpe_stats_num_counters = 6;
                init_rdpmc_profile(zstats, perf_typeid, 6,
                                        ALL_DC_ACCESSES,
                                        L2_CACHE_MISS_FROM_DC_MISS,
                                        L2_CACHE_HIT_FROM_DC_MISS,
                                        L2_CACHE_MISS_FROM_L2_HWPF1,
                                        L2_CACHE_MISS_FROM_L2_HWPF2,
                                        L2_CACHE_HIT_FROM_L2_HWPF);
                break;
        }
    }

    zhpe_stats_dir = strdup_or_null(stats_dir);
    if (!zhpe_stats_dir)
        goto done;
    zhpe_stats_unique = strdup_or_null(stats_unique);
    if (!zhpe_stats_unique)
        goto done;

    ret = true;
 done:
    mutex_unlock(&zhpe_stats_mutex);

    return ret;
}

/* minimal_open sets up thread-specific data and calls profile-specific open */
void zhpe_stats_open(uint16_t uid)
{
    struct zhpe_stats *zstats = zhpe_stats;
    stats_common_open(zstats, uid);
}

#else

void zhpe_stats_test(uint16_t uid)
{
}

void zhpe_stats_flush()
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
