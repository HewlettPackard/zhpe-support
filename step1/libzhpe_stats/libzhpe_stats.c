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

static void stats_nop_finalize(void)
{
};

static void stats_nop(struct zhpe_stats *stats)
{
};

static struct zhpe_stats_ops stats_nops = {
    .finalize           = stats_nop_finalize,
    .open               = stats_nop,
    .close              = stats_nop,
    .start              = stats_nop,
    .stop               = stats_nop,
    .pause              = stats_nop,
};

struct zhpe_stats_ops *zhpe_stats_ops = &stats_nops;

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

static char                     *zhpe_stats_dir;
static char                     *zhpe_stats_unique;

static void stats_finalize_sim(void)
{
}

static void stats_open_common(struct zhpe_stats *stats)
{
    bool                do_close = true;
    char                *fname = NULL;

    if (zhpeu_asprintf(&fname, "%s/%s.%d", zhpe_stats_dir, zhpe_stats_unique,
                       stats->uid) == -1) {
        print_func_err(__func__, __LINE__, "zhpeu_asprintf", "", -ENOMEM);
        goto done;
    }
    stats->buf_len += sizeof(*stats->extra);
    stats->buf = malloc(stats->buf_len);
    if (!stats->buf)
        goto done;
    memset(stats->buf, 0, stats->buf_len);
    stats->extra = (void *)((char *)stats->buf + stats->buf_len -
                            sizeof(*stats->extra));
    stats->fd = open(fname, O_RDWR | O_CREAT | O_TRUNC,
                     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (stats->fd == -1) {
        print_func_err(__func__, __LINE__, "open", fname, -errno);
        goto done;
    }
    stats->state = ZHPE_STATS_DISABLED;
    do_close = false;
 done:
    free(fname);
    if (do_close)
        zhpe_stats_close(stats);
}

static void stats_open_sim(struct zhpe_stats *stats)
{
    if (!zhpe_stats_dir || stats->state != ZHPE_STATS_INIT)
        return;
    if (stats->buf) {
        print_err("%s,%u:stats %p already opened\n", __func__, __LINE__, stats);
        return;
    }
    if (sim_api_data_rec(DATA_REC_CREAT, stats->uid,
                         (uintptr_t)&stats->buf_len)) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_CREAT", -EINVAL);
        stats->buf_len = 0;
        return;
    }
    stats_open_common(stats);
}

static void stats_close_common(struct zhpe_stats *stats)
{
    stats->buf_len = 0;
    if (stats->fd != -1)
        close(stats->fd);
    stats->fd = -1;
    free(stats->buf);
    stats->buf = NULL;
}

static void stats_close_sim(struct zhpe_stats *stats)
{
    if (stats->buf_len &&
        sim_api_data_rec(DATA_REC_END, stats->uid, (uintptr_t)stats->buf))
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_END", -EINVAL);
    stats_close_common(stats);
}

static void stats_start_sim(struct zhpe_stats *stats)
{
    if (stats->state == ZHPE_STATS_STOPPED)
        memset(stats->extra, 0, sizeof(*stats->extra));
    else if (stats->state != ZHPE_STATS_PAUSED)
        return;
    if (sim_api_data_rec(DATA_REC_START, stats->uid, (uintptr_t)stats->buf)) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_START", -EINVAL);
        return;
    }
    stats->extra->starts++;
    stats->state = ZHPE_STATS_RUNNING;
    return;
}

static void stats_stop_sim(struct zhpe_stats *stats)
{
    ssize_t                     res;

    if (stats->state != ZHPE_STATS_RUNNING && stats->state != ZHPE_STATS_PAUSED)
        return;
    if (sim_api_data_rec(DATA_REC_STOP, stats->uid, (uintptr_t)stats->buf)) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_STOP", -EINVAL);
        return;
    }
    stats->state = ZHPE_STATS_STOPPED;
    res = write(stats->fd, stats->buf, stats->buf_len);
    if (check_func_ion(__func__, __LINE__, "write", stats->buf_len, false,
                       stats->buf_len, res, 0) < 0)
        return;
}

static void stats_pause_sim(struct zhpe_stats *stats)
{
    if (stats->state != ZHPE_STATS_RUNNING)
        return;
    if (sim_api_data_rec(DATA_REC_PAUSE, stats->uid, (uintptr_t)stats->buf)) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_PAUSE", -EINVAL);
        return;
    }
    stats->extra->pauses++;
    stats->state = ZHPE_STATS_PAUSED;
}

static struct zhpe_stats_ops stats_ops_sim = {
    .finalize           = stats_finalize_sim,
    .open               = stats_open_sim,
    .close              = stats_close_sim,
    .start              = stats_start_sim,
    .stop               = stats_stop_sim,
    .pause              = stats_pause_sim,
};

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
        print_err("%s,%u:stats %p already opened\n", __func__, __LINE__, stats);
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
};

#endif

void zhpe_stats_init(const char *stats_dir, const char *stats_unique)
{
    if (!stats_dir && !stats_unique)
        return;
    if (!stats_dir || !stats_unique) {
        print_err("%s,%u:missing %s\n", __func__, __LINE__,
                  stats_dir ? "stats_unique" : "stats_dir");
        return;
    }
    if (zhpe_stats_dir) {
        print_err("%s,%u:already initialized\n", __func__, __LINE__);
        return;
    }
    zhpe_stats_dir = strdup_or_null(stats_dir);
    if (!zhpe_stats_dir)
        return;
    zhpe_stats_unique = strdup_or_null(stats_unique);
    if (!zhpe_stats_unique) {
        free(zhpe_stats_dir);
        zhpe_stats_dir = NULL;
        return;
    }
#ifdef HAVE_ZHPE_SIM
    if (sim_api_is_sim()) {
        zhpe_stats_ops = &stats_ops_sim;
        return;
    }
#endif
#ifdef LIKWID_PERFMON
    zhpe_stats_ops = &stats_ops_likwid;
    LIKWID_MARKER_INIT;
#else
    print_err("%s,%u:not on simulator and no LIKWID support\n",
              __func__, __LINE__);
#endif
}

void zhpe_stats_test(uint16_t uid)
{
    DEFINE_ZHPE_STATS(stats_test, uid);

    zhpe_stats_open(&stats_test);
    zhpe_stats_enable(&stats_test);

    zhpe_stats_start(&stats_test);
    zhpe_stats_stop(&stats_test);

    zhpe_stats_start(&stats_test);
    zhpe_stats_stop(&stats_test);

    zhpe_stats_start(&stats_test);
    zhpe_stats_pause(&stats_test);
    zhpe_stats_start(&stats_test);
    zhpe_stats_stop(&stats_test);

    zhpe_stats_start(&stats_test);
    zhpe_stats_pause(&stats_test);
    zhpe_stats_stop(&stats_test);

    zhpe_stats_close(&stats_test);
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
