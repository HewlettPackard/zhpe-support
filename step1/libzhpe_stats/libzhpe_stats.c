/*
 * Copyright (C) 2018-2019 Hewlett Packard Enterprise Development LP.
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

#include <zhpe_stats_types.h>

#include <sys/syscall.h>

struct zhpe_stats_extra {
    uint32_t            starts;
    uint32_t            pauses;
    uint32_t            subid;
    uint32_t            nesting;
};

struct zhpe_stats_delta {
    bool                paused;
    struct zhpe_stats_delta *next;
    char                buf[0];
};

struct zhpe_stats {
    char                likwid_name[16];
    uint32_t            likwid_sample;
    uint32_t            run_count;
    int                 fd;
    uint16_t            uid;
    uint8_t             state;
    bool                pause_all;
    struct zhpe_stats_delta *delta;
    struct zhpe_stats_delta *delta_free;
    uint64_t            buf_len;
    char                buf[0];
};

enum {
    ZHPE_STATS_INIT,
    ZHPE_STATS_DISABLED,
    ZHPE_STATS_STOPPED,
    ZHPE_STATS_RUNNING,
    ZHPE_STATS_PAUSED,
};

static struct zhpe_stats *stats_nop_null(void)
{
    return NULL;
}

static void stats_nop_stats(struct zhpe_stats *stats)
{
}

static void stats_nop_stats_uint32(struct zhpe_stats *stats, uint32_t dum)
{
}

static void stats_nop_uint16(uint16_t dum)
{
}

static void stats_nop_void(void)
{
};

static void stats_nop_voidp(void *dum)
{
};

static struct zhpe_stats_ops zhpe_stats_nops = {
    .open               = stats_nop_uint16,
    .close              = stats_nop_void,
    .enable             = stats_nop_void,
    .disable            = stats_nop_void,
    .stop_counters      = stats_nop_null,
    .stop_all           = stats_nop_stats,
    .pause_all          = stats_nop_stats,
    .restart_all        = stats_nop_void,
    .start              = stats_nop_stats_uint32,
    .stop               = stats_nop_stats_uint32,
    .pause              = stats_nop_stats_uint32,
    .finalize           = stats_nop_void,
    .key_destructor     = stats_nop_voidp,
};

struct zhpe_stats_ops *zhpe_stats_ops = &zhpe_stats_nops;

#ifdef HAVE_ZHPE_SIM

#include <zhpe_stats.h>

#include <hpe_sim_api_linux64.h>

#ifdef LIKWID_PERFMON
#include <likwid.h>
#else
#define LIKWID_MARKER_INIT
#define LIKWID_MARKER_CLOSE
#define LIKWID_MARKER_START(_x)
#define LIKWID_MARKER_STOP(_x)
#endif

/* Common defintions/code */

static char             *zhpe_stats_dir;
static char             *zhpe_stats_unique;
static pthread_key_t    zhpe_stats_key;
static pthread_mutex_t  zhpe_stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool             zhpe_stats_init_once;

static inline struct zhpe_stats_extra *
stats_cmn_extra(struct zhpe_stats *stats, void *buf)
{
    return (void *)((char *)buf + stats->buf_len -
                    sizeof(struct zhpe_stats_extra));
}

#if 0
#define STATS_STATE_CASE(_name) \
    case ZHPE_STATS_ ## _name:  \
        return # _name

static const char *stats_cmn_state_str(uint8_t state)
{
    switch (state) {

    STATS_STATE_CASE(INIT);
    STATS_STATE_CASE(DISABLED);
    STATS_STATE_CASE(RUNNING);
    STATS_STATE_CASE(STOPPED);
    STATS_STATE_CASE(PAUSED);

    default:
        return "invalid";
    }
}
#endif

static void stats_cmn_update_stats(struct zhpe_stats *stats)
{
    char                *new = stats->buf;
    char                *old = stats->buf + stats->buf_len;
    size_t              o;
    size_t              n;
    uint64_t            *u64op;
    uint64_t            *u64np;
    uint32_t            *u32op;
    uint32_t            *u32np;
    struct zhpe_stats_delta *delta;

    /* compute delta stats: old = new - old */
    o = offsetof(ProcCtlData, execInstTotal);
    n = ((sizeof(ProcCtlData) - o) / sizeof(*u64op));
    u64op = (void *)(old + o);
    u64np = (void *)(new + o);
    for (; n > 0; n--, u64op++, u64np++)
        *u64op = *u64np - *u64op;

    o = offsetof(CacheData, coherencyCastoutDataL1);
    n = ((sizeof(CacheData) - o) / sizeof(*u64op));
    u64op = (void *)(old + sizeof(ProcCtlData) + o);
    u64np = (void *)(new + sizeof(ProcCtlData) + o);
    for (; n > 0; n--, u64op++, u64np++)
        *u64op = *u64np - *u64op;

    n = offsetof(struct zhpe_stats_extra, subid) / sizeof(*u32op);
    u32op = (void *)stats_cmn_extra(stats, old);
    u32np = (void *)stats_cmn_extra(stats, new);
    for (; n > 0; n--, u32op++, u32np++)
        *u32op = *u32np - *u32op;

    /* Update all active deltas with new data: delta += old */
    for (delta = stats->delta; delta; delta = delta->next) {
        if (delta->paused)
            continue;
        /* compute delta stats: new += old */
        o = offsetof(ProcCtlData, execInstTotal);
        n = ((sizeof(ProcCtlData) - o) / sizeof(*u64op));
        u64op = (void *)(old + o);
        u64np = (void *)(delta->buf + o);
        for (; n > 0; n--, u64op++, u64np++)
            *u64np += *u64op;

        o = offsetof(CacheData, coherencyCastoutDataL1);
        n = ((sizeof(CacheData) - o) / sizeof(*u64op));
        u64op = (void *)(old + sizeof(ProcCtlData) + o);
        u64np = (void *)(delta->buf + sizeof(ProcCtlData) + o);
        for (; n > 0; n--, u64op++, u64np++)
            *u64np += *u64op;

        n = offsetof(struct zhpe_stats_extra, subid) / sizeof(*u32op);
        u32op = (void *)stats_cmn_extra(stats, old);
        u32np = (void *)stats_cmn_extra(stats, delta->buf);
        for (; n > 0; n--, u32op++, u32np++)
            *u32np += *u32op;
    }
    /* Save current state. */
    memcpy(stats->buf + stats->buf_len, stats->buf, stats->buf_len);
}

static struct zhpe_stats_delta *
stats_cmn_delta_find(struct zhpe_stats *stats,
                     struct zhpe_stats_delta *list, uint32_t subid)
{
    struct zhpe_stats_delta *ret;

    for (ret = list; ret; ret = ret->next) {
        if (stats_cmn_extra(stats, ret->buf)->subid == subid) {
            break;
        }
    }

    return ret;
}

static inline void stats_cmn_delta_write(struct zhpe_stats *stats,
                                         struct zhpe_stats_delta *delta)
{
    ssize_t             res;

    res = write(stats->fd, delta->buf, stats->buf_len);
    if (check_func_ion(__func__, __LINE__, "write", stats->buf_len, false,
                       stats->buf_len, res, 0) < 0)
        abort();
}

static inline void stats_cmn_delta_free_head(struct zhpe_stats *stats)
{
    struct zhpe_stats_delta *delta;

    delta = stats->delta;
    stats->delta = delta->next;
    delta->next = stats->delta_free;
    stats->delta_free = delta;
}

static struct zhpe_stats_delta *
stats_cmn_delta_alloc(struct zhpe_stats *stats, uint32_t subid)
{
    struct zhpe_stats_delta *ret = stats->delta_free;
    size_t              req = sizeof(*ret) + stats->buf_len;
    struct zhpe_stats_delta *next;
    struct zhpe_stats_extra *extra;

    if (ret)
        stats->delta_free = ret->next;
    else {
        ret = malloc(req);
        if (!ret)
            abort();
    }
    memset(ret, 0, req);

    extra = stats_cmn_extra(stats, ret->buf);
    extra->subid = subid;
    next = stats->delta;
    if (next)
        extra->nesting = stats_cmn_extra(stats, next->buf)->nesting + 1;

    ret->next = stats->delta;
    stats->delta = ret;

    return ret;
}

static void stats_cmn_finalize(void)
{
    free(zhpe_stats_dir);
    zhpe_stats_dir = NULL;
    free(zhpe_stats_unique);
    zhpe_stats_unique = NULL;
    zhpe_stats_ops = &zhpe_stats_nops;
}

static void stats_cmn_close(struct zhpe_stats *stats)
{
    struct zhpe_stats_delta *delta;
    struct zhpe_stats_delta *next;

    abort_posix(pthread_setspecific, zhpe_stats_key, NULL);

    if (stats->fd != -1)
        close(stats->fd);

    while (stats->delta)
        stats_cmn_delta_free_head(stats);
    stats->delta = NULL;

    for (delta = stats->delta_free; delta; delta = next) {
        next = delta->next;
        free(delta);
    }
    stats->delta_free = NULL;
    free(stats);
}

static void stats_cmn_open(uint16_t uid, size_t buf_len)
{
    char                *fname = NULL;
    struct zhpe_stats   *stats;

    buf_len += sizeof(struct zhpe_stats_extra);
    stats = calloc(1, sizeof(*stats) + 2 * buf_len);
    if (!stats)
        abort();
    stats->uid = uid;
    stats->buf_len = buf_len;
    stats->fd = -1;

    if (zhpeu_asprintf(&fname, "%s/%s.%ld.%d",
                       zhpe_stats_dir, zhpe_stats_unique,
                       syscall(SYS_gettid), uid) == -1) {
        print_func_err(__func__, __LINE__, "zhpeu_asprintf", "", -ENOMEM);
        abort();
    }

    stats->fd = open(fname, O_RDWR | O_CREAT | O_TRUNC,
                     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (stats->fd == -1) {
        print_func_err(__func__, __LINE__, "open", fname, -errno);
        abort();
    }

    abort_posix(pthread_setspecific, zhpe_stats_key, stats);
    stats->state = ZHPE_STATS_DISABLED;

    free(fname);
}

static void stats_cmn_enable(void)
{
    struct zhpe_stats   *stats;

    stats = pthread_getspecific(zhpe_stats_key);
    if (!stats)
        return;

    switch (stats->state)
    {
    case ZHPE_STATS_DISABLED:
        stats->state = ZHPE_STATS_STOPPED;
        break;

    default:
        break;
    }
}

static void stats_cmn_disable(void)
{
    struct zhpe_stats   *stats;

    stats = pthread_getspecific(zhpe_stats_key);
    if (!stats)
        return;

    switch (stats->state)
    {
    case ZHPE_STATS_RUNNING:
        zhpe_stats_stop_all();
        /* FALLTHROUGH */

    case ZHPE_STATS_STOPPED:
        stats->state = ZHPE_STATS_DISABLED;
        break;

    default:
        break;
    }
}

/* Carbon code */

static void sim_check_rec(struct zhpe_stats *stats)
{
    static bool         once = false;
    size_t              rlen;
    ProcCtlData         *procp;
    CacheData           *cachep;

    if (once)
        return;

    rlen = sizeof(*procp) + sizeof(*cachep) + sizeof(struct zhpe_stats_extra);
    if (stats->buf_len != rlen) {
        print_err("%s,%u:Unexpected record length %lu != %lu\n",
                  __func__, __LINE__, stats->buf_len, rlen);
        abort();
    }

    procp = (void *)stats->buf;
    if (procp->header.version != DATA_REC_VER ||
        procp->header.id.val != PROC_DATA_ID) {
        print_err("%s,%u:ProcCtlData version/id 0x%02x/0x%04x "
                  "!= 0x%02x/0x%04x\n", __func__, __LINE__,
                  procp->header.version, procp->header.id.val,
                  DATA_REC_VER, PROC_DATA_ID);
        abort();
    }

    cachep = (void *)(stats->buf + sizeof(*procp));
    if (cachep->header.version != DATA_REC_VER ||
        cachep->header.id.val != DATA_REC_CACHE_ID) {
        print_err("%s,%u:CacheData version/id 0x%02x/0x%04x "
                  "!= 0x%02x/0x%04x\n", __func__, __LINE__,
                  cachep->header.version, cachep->header.id.val,
                  DATA_REC_VER, DATA_REC_CACHE_ID);
        abort();
    }
}

static void sim_start(struct zhpe_stats *stats)
{
    /* Init/save snapshot for next time. */
    if (stats->state == ZHPE_STATS_STOPPED)
        memset(stats->buf, 0, 2 * stats->buf_len);
   if (sim_api_data_rec(DATA_REC_START, stats->uid, (uintptr_t)stats->buf)) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_START", -EINVAL);
        abort();
    }
    stats_cmn_extra(stats, stats->buf)->starts++;
    stats->state = ZHPE_STATS_RUNNING;
}

static void sim_stop(struct zhpe_stats *stats)
{
    if (sim_api_data_rec(DATA_REC_STOP, stats->uid, (uintptr_t)stats->buf)) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_STOP", -EINVAL);
        abort();
    }
    stats->state = ZHPE_STATS_STOPPED;

    sim_check_rec(stats);
    stats_cmn_update_stats(stats);
}

#if 0
static void sim_pause(struct zhpe_stats *stats)
{
    if (sim_api_data_rec(DATA_REC_PAUSE, stats->uid, (uintptr_t)stats->buf)) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_STOP", -EINVAL);
        abort();
    }
    stats->state = ZHPE_STATS_PAUSED;
    stats_cmn_extra(stats, stats->buf)->pauses++;
}
#endif

static void sim_close(struct zhpe_stats *stats)
{
    if (sim_api_data_rec(DATA_REC_END, stats->uid, (uintptr_t)stats->buf))
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_END", -EINVAL);
    stats_cmn_close(stats);
}

static void stats_sim_close(void)
{
    struct zhpe_stats   *stats;

    stats = pthread_getspecific(zhpe_stats_key);
    if (!stats)
        return;
    sim_close(stats);
}

static void stats_sim_open(uint16_t uid)
{
    uint64_t            buf_len;
    struct zhpe_stats   *stats;

    stats = pthread_getspecific(zhpe_stats_key);
    if (stats) {
        print_err("%s,%u:tid %ld, uid 0x%03x active, cannot open 0x%03x\n",
                  __func__, __LINE__, syscall(SYS_gettid), stats->uid, uid);
        abort();
    }
    if (sim_api_data_rec(DATA_REC_CREAT, uid, (uintptr_t)&buf_len)) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_CREAT", -EINVAL);
        abort();
    }
    stats_cmn_open(uid, buf_len);
}

static void stats_sim_pause_all(struct zhpe_stats *stats)
{
    stats->pause_all = true;
}

static void stats_sim_restart_all(void)
{
    struct zhpe_stats   *stats;

    stats = pthread_getspecific(zhpe_stats_key);
    if (!stats)
        return;

    if (stats->state <= ZHPE_STATS_DISABLED)
        return;
    if (!stats->pause_all)
        return;
    stats->pause_all = false;

    sim_start(stats);
}

static struct zhpe_stats *stats_sim_stop_counters(void)
{
    struct zhpe_stats   *stats;

    stats = pthread_getspecific(zhpe_stats_key);
    if (!stats)
        return NULL;
    if (stats->state <= ZHPE_STATS_DISABLED)
        return NULL;

    if (stats->state != ZHPE_STATS_STOPPED)
        sim_stop(stats);

    return stats;
}

static void stats_sim_start(struct zhpe_stats *stats, uint32_t subid)
{
    struct zhpe_stats_delta *active;
    struct zhpe_stats_delta *delta;
    struct zhpe_stats_delta *next;

    /* subid already active? */
    active = stats_cmn_delta_find(stats, stats->delta, subid);
    if (!active) {
        stats_cmn_delta_alloc(stats, subid);
        goto do_start;
    }

    for (delta = stats->delta; delta; delta = next) {
        next = delta->next;
        delta->paused = false;
        if (delta == active)
            break;
    }
do_start:
    sim_start(stats);
}

static void stats_sim_stop(struct zhpe_stats *stats, uint32_t subid)
{
    struct zhpe_stats_delta *active;
    struct zhpe_stats_delta *delta;
    struct zhpe_stats_delta *next;

    /* Active? */
    active = stats_cmn_delta_find(stats, stats->delta, subid);
    if (!active)
        goto do_start;

    for (delta = stats->delta; delta; delta = next) {
        next = delta->next;
        stats_cmn_delta_write(stats, delta);
        stats_cmn_delta_free_head(stats);
        if (delta == active)
            break;
    }

 do_start:
    for (delta = stats->delta; delta; delta = next) {
        next = delta->next;
        if (!delta->paused) {
            sim_start(stats);
            return;
        }
    }
}

static void stats_sim_stop_all(struct zhpe_stats *stats)
{
    struct zhpe_stats_delta *delta;
    struct zhpe_stats_delta *next;

    for (delta = stats->delta; delta; delta = next) {
        next = delta->next;
        stats_cmn_delta_write(stats, delta);
        stats_cmn_delta_free_head(stats);
    }
}

static void stats_sim_pause(struct zhpe_stats *stats, uint32_t subid)
{
    struct zhpe_stats_delta *active;
    struct zhpe_stats_delta *delta;
    struct zhpe_stats_delta *next;

    /* Active? */
    active = stats_cmn_delta_find(stats, stats->delta, subid);
    if (!active)
        goto do_start;

    for (delta = stats->delta; delta; delta = next) {
        next = delta->next;
        delta->paused = true;
        if (delta == active)
            break;
    }

 do_start:
    for (delta = stats->delta; delta; delta = next) {
        next = delta->next;
        if (!delta->paused) {
            sim_start(stats);
            return;
        }
    }
}

static void stats_sim_finalize(void)
{
    stats_sim_close();
    mutex_lock(&zhpe_stats_mutex);
    stats_cmn_finalize();
    mutex_unlock(&zhpe_stats_mutex);
}

static void stats_sim_key_destructor(void *vstats)
{
    struct zhpe_stats   *stats = vstats;

    if (!stats)
        return;

    if (stats->state <= ZHPE_STATS_DISABLED)
        return;

    sim_close(stats);
}

static struct zhpe_stats_ops stats_ops_sim = {
    .open               = stats_sim_open,
    .close              = stats_sim_close,
    .enable             = stats_cmn_enable,
    .disable            = stats_cmn_disable,
    .stop_counters      = stats_sim_stop_counters,
    .stop_all           = stats_sim_stop_all,
    .pause_all          = stats_sim_pause_all,
    .restart_all        = stats_sim_restart_all,
    .start              = stats_sim_start,
    .stop               = stats_sim_stop,
    .pause              = stats_sim_pause,
    .finalize           = stats_sim_finalize,
    .key_destructor     = stats_sim_key_destructor,
};

/* LIKWID code */

#ifdef LIKWID_PERFMON

static void stats_finalize_likwid(void)
{
    LIKWID_MARKER_CLOSE;
}

static void stats_open_likwid(struct zhpe_stats *stats)
{
    if (!zhpe_stats_dir || stats->state != ZHPE_STATS_INIT)
        return;
    if (stats->buf) {
        print_err("%s,%u:uid 0x%03x already opened\n",
                  __func__, __LINE__, stats->uid);
        return;
    }
    stats->likwid_sample = 0;
    stats->buf_len = sizeof(ProcCtlData) + sizeof(CacheData);
    stats_open_common(stats);
}

void stats_start_likwid(struct zhpe_stats *stats)
{
    if (stats->state == ZHPE_STATS_STOPPED) {
        memset(stats->extra, 0, sizeof(*stats->extra));
        snprintf(stats->likwid_name, sizeof(stats->likwid_name), "%u:%u",
                stats->uid, stats->likwid_sample++);
    } else if (stats->state != ZHPE_STATS_PAUSED)
        return;
    LIKWID_MARKER_START(stats->likwid_name);
    stats->extra->starts++;
    stats->state = ZHPE_STATS_RUNNING;
    return;
}

static void stats_stop_likwid(struct zhpe_stats *stats)
{
    ssize_t                     res;

    if (stats->state == ZHPE_STATS_RUNNING)
        LIKWID_MARKER_STOP(stats->likwid_name);
    else if (stats->state != ZHPE_STATS_PAUSED)
        return;
    stats->state = ZHPE_STATS_STOPPED;
    res = write(stats->fd, stats->buf, stats->buf_len);
    if (check_func_ion(__func__, __LINE__, "write", stats->buf_len, false,
                       stats->buf_len, res, 0) < 0)
        return;
}

static void stats_pause_likwid(struct zhpe_stats *stats)
{
    if (stats->state != ZHPE_STATS_RUNNING)
        return;
    LIKWID_MARKER_STOP(stats->likwid_name);
    stats->extra->pauses++;
    stats->state = ZHPE_STATS_PAUSED;
}

static struct zhpe_stats_ops stats_ops_likwid = {
    .finalize           = stats_finalize_likwid,
    .open               = stats_open_likwid,
    .close              = stats_close_common,
    .start              = stats_start_likwid,
    .stop               = stats_stop_likwid,
    .pause              = stats_pause_likwid,
    /* Unimplemented, yet */
    .delta_start        = stats_nop_delta,
    .delta_stop         = stats_nop_delta,
    .pause_all          = stats_nop_void,
    .restart_all        = stats_nop_void,
};

#endif

void zhpe_stats_init(const char *stats_dir, const char *stats_unique)
{
    if (!stats_dir && !stats_unique)
        return;
    if (!stats_dir || !stats_unique) {
        print_err("%s,%u:missing %s\n", __func__, __LINE__,
                  stats_dir ? "stats_unique" : "stats_dir");
        abort();
    }
    mutex_lock(&zhpe_stats_mutex);
    if (zhpe_stats_ops != &zhpe_stats_nops) {
        print_err("%s,%u:already initialized\n", __func__, __LINE__);
        abort();
    }
#ifdef HAVE_ZHPE_SIM
    if (sim_api_is_sim())
        zhpe_stats_ops = &stats_ops_sim;
#endif
#ifdef LIKWID_PERFMON
    if (zhpe_stats_ops == &zhpe_stats_nops) {
        zhpe_stats_ops = &stats_ops_likwid;
        LIKWID_MARKER_INIT;
    }
#endif
    if (zhpe_stats_ops == &zhpe_stats_nops) {
        print_err("%s,%u:no statistics support available\n",
                  __func__, __LINE__);
        abort();
    }

    zhpe_stats_dir = strdup_or_null(stats_dir);
    if (!zhpe_stats_dir)
        abort();
    zhpe_stats_unique = strdup_or_null(stats_unique);
    if (!zhpe_stats_unique)
        abort();

    if (!zhpe_stats_init_once) {
        abort_posix(pthread_key_create, &zhpe_stats_key,
                    zhpe_stats_ops->key_destructor);
        zhpe_stats_init_once = true;
    }

    mutex_unlock(&zhpe_stats_mutex);
}

void zhpe_stats_test(uint16_t uid)
{

    zhpe_stats_open(uid);
    zhpe_stats_enable();

    zhpe_stats_start(0);
    zhpe_stats_stop(0);

    zhpe_stats_start(0);
    zhpe_stats_stop(0);

    zhpe_stats_start(0);
    zhpe_stats_pause(0);
    zhpe_stats_stop(0);

    zhpe_stats_start(0);
    zhpe_stats_pause(0);
    zhpe_stats_start(0);
    zhpe_stats_stop(0);

    zhpe_stats_start(0);
    zhpe_stats_pause_all();
    nop();
    zhpe_stats_stop_all();

    zhpe_stats_start(0);
    zhpe_stats_pause_all();
    zhpe_stats_restart_all();
    nop();
    zhpe_stats_stop_all();

    zhpe_stats_start(0);
    nop();
    zhpe_stats_stop(0);

    zhpe_stats_start(0);
    zhpe_stats_start(1);
    zhpe_stats_stop(1);
    zhpe_stats_stop(0);

    zhpe_stats_start(0);
    nop();
    zhpe_stats_start(1);
    nop();
    nop();
    zhpe_stats_stop(1);
    nop();
    zhpe_stats_stop(0);

    zhpe_stats_start(0);
    nop();
    nop();
    zhpe_stats_start(1);
    nop();
    zhpe_stats_pause_all();
    nop();
    zhpe_stats_restart_all();
    nop();
    zhpe_stats_stop_all();

    zhpe_stats_start(0);
    zhpe_stats_start(1);
    nop();
    nop();

    zhpe_stats_start(2);
    nop();
    zhpe_stats_start(3);
    nop();
    zhpe_stats_pause(2);
    nop();
    zhpe_stats_start(3);
    nop();
    zhpe_stats_stop(3);
    zhpe_stats_stop(2);

    zhpe_stats_start(4);
    zhpe_stats_start(5);
    nop();
    zhpe_stats_stop(5);
    zhpe_stats_stop(4);

    zhpe_stats_stop(1);
    zhpe_stats_stop(0);

    zhpe_stats_close();
}

#else

void zhpe_stats_init(const char *stats_dir, const char *stats_unique)
{
    if (!stats_dir && !stats_unique)
        return;
    print_err("%s,%u:libzhpe_stats built without stats support\n",
              __func__, __LINE__);
}

void zhpe_stats_test(uint16_t uid)
{
}

#endif
