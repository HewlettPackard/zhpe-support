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

#ifdef HAVE_ZHPE_SIM
#include <zhpe_stats.h>
#include <hpe_sim_api_linux64.h>

static char                     *zhpe_stats_dir;
static char                     *zhpe_stats_unique;

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
    if (!sim_api_is_sim()) {
        print_err("%s,%u:not on simulator\n", __func__, __LINE__);
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
}

void zhpe_stats_open(struct zhpe_stats *stats)
{
    bool                do_close = true;
    char                *fname = NULL;

    if (!zhpe_stats_dir || stats->state != ZHPE_STATS_INIT)
        return;
    if (stats->buf) {
        print_err("%s,%u:stats %p already opened\n", __func__, __LINE__, stats);
        return;
    }
    if (zhpeu_asprintf(&fname, "%s/%s.%d", zhpe_stats_dir, zhpe_stats_unique,
                       stats->uid) == -1) {
        print_func_err(__func__, __LINE__, "zhpeu_asprintf", "", -ENOMEM);
        return;
    }
    if (sim_api_data_rec(DATA_REC_CREAT, stats->uid,
                         (uintptr_t)&stats->buf_len)) {
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_CREAT", -EINVAL);
        stats->buf_len = 0;
        goto done;
    }
    stats->buf_len += sizeof(*stats->extra);
    stats->buf = malloc(stats->buf_len);
    if (!stats->buf)
        goto done;
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

void zhpe_stats_close(struct zhpe_stats *stats)
{
    if (stats->buf_len &&
        sim_api_data_rec(DATA_REC_END, stats->uid, (uintptr_t)stats->buf))
        print_func_err(__func__, __LINE__, "sim_api_data_rec",
                       "DATA_REC_END", -EINVAL);
    stats->buf_len = 0;
    if (stats->fd != -1)
        close(stats->fd);
    stats->fd = -1;
    free(stats->buf);
    stats->buf = NULL;
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
    zhpe_stats_close(&stats_test);
}

void zhpe_stats_start(struct zhpe_stats *stats)
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
    stats->state = ZHPE_STATS_RUNNING;
    return;
}

void zhpe_stats_stop(struct zhpe_stats *stats)
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

void zhpe_stats_pause(struct zhpe_stats *stats)
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

#else

struct zhpe_stats;

void zhpe_stats_init(const char *stats_dir, const char *stats_unique)
{
    if (!stats_dir && !stats_unique)
        return;
    print_err("%s,%u:libzhpe_stats built without stats support\n",
              __func__, __LINE__);
}

void zhpe_stats_open(struct zhpe_stats *stats)
{
}

void zhpe_stats_close(struct zhpe_stats *stats)
{
}

void zhpe_stats_test(uint16_t uid)
{
}

void zhpe_stats_start(struct zhpe_stats *stats)
{
}

void zhpe_stats_stop(struct zhpe_stats *stats, bool do_write)
{
}

void zhpe_stats_pause(struct zhpe_stats *stats)
{
}

#endif
