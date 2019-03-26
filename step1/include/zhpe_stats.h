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

#ifndef _ZHPE_STATS_H_
#define _ZHPE_STATS_H_

#include <stdbool.h>
#include <stdint.h>

#include <zhpe_stats_types.h>

_EXTERN_C_BEG

#ifdef HAVE_ZHPE_STATS

void zhpe_stats_init(const char *stats_dir, const char *stats_unique);
void zhpe_stats_test(uint16_t uid);

static inline void zhpe_stats_finalize(void)
{
    zhpe_stats_ops->finalize();
}

static inline void zhpe_stats_open(struct zhpe_stats *stats)
{
    zhpe_stats_ops->open(stats);
}

static inline void zhpe_stats_close(struct zhpe_stats *stats)
{
    zhpe_stats_ops->close(stats);
}

static inline void zhpe_stats_start(struct zhpe_stats *stats)
{
    zhpe_stats_ops->start(stats);
}

static inline void zhpe_stats_stop(struct zhpe_stats *stats)
{
    zhpe_stats_ops->stop(stats);
}

static inline void zhpe_stats_pause(struct zhpe_stats *stats)
{
    zhpe_stats_ops->pause(stats);
}

static inline void zhpe_stats_enable(struct zhpe_stats *stats)
{
    switch (stats->state)
    {
    case ZHPE_STATS_INIT:
        zhpe_stats_open(stats);
        /* FALLTHROUGH */

    case ZHPE_STATS_DISABLED:
        stats->state = ZHPE_STATS_STOPPED;
        break;

    default:
        break;
    }
}

static inline void zhpe_stats_disable(struct zhpe_stats *stats)
{
    switch (stats->state)
    {
    case ZHPE_STATS_RUNNING:
    case ZHPE_STATS_PAUSED:
        zhpe_stats_stop(stats);
        /* FALLTHROUGH */

    case ZHPE_STATS_STOPPED:
        stats->state = ZHPE_STATS_DISABLED;
        break;

    default:
        break;
    }
}

#else

#define zhpe_stats_init(stats_dir, stats_unique)
#define zhpe_stats_finalize()
#define zhpe_stats_test(uid)
#define zhpe_stats_open(stats)
#define zhpe_stats_close(stats)
#define zhpe_stats_start(stats)
#define zhpe_stats_stop(stats)
#define zhpe_stats_pause(stats)
#define zhpe_stats_enable(stats)
#define zhpe_stats_disable(stats)

#endif

_EXTERN_C_END

#endif /* _ZHPE_STATS_H_ */
