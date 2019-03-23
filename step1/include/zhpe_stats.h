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

#include <zhpe_externc.h>

_EXTERN_C_BEG

struct zhpe_stats_extra {
    uint32_t            pauses;
};

struct zhpe_stats {
    void                *buf;
    struct zhpe_stats_extra *extra;
    uint64_t            buf_len;
    int                 fd;
    uint16_t            uid;
    uint8_t             state;
};

enum {
    ZHPE_STATS_INIT,
    ZHPE_STATS_DISABLED,
    ZHPE_STATS_STOPPED,
    ZHPE_STATS_RUNNING,
    ZHPE_STATS_PAUSED,
};

#define DEFINE_ZHPE_STATS(_name, _uid)          \
    struct zhpe_stats _name = {                 \
        .uid            = _uid,                 \
        .fd             = -1,                   \
        .state          = ZHPE_STATS_INIT,      \
}

#if defined(DEFAULT_SYMVER)
#define DEFINE_ZHPE_STATS_FABRIC(_name, _uid)   \
    struct zhpe_stats DEFAULT_SYMVER_PRE(_name) \
    __attribute__((visibility ("default"),      \
                   EXTERNALLY_VISIBLE)) = {     \
        .uid            = _uid,                 \
        .fd             = -1,                   \
        .state          = ZHPE_STATS_INIT,      \
    };                                          \
    CURRENT_SYMVER(_name##_, _name)
#endif

#ifdef HAVE_ZHPE_STATS

#define EXTERN_ZHPE_STATS(_name)                \
        extern struct zhpe_stats _name

void zhpe_stats_init(const char *stats_dir, const char *stats_unique);
void zhpe_stats_test(uint16_t uid);
void zhpe_stats_open(struct zhpe_stats *stats);
void zhpe_stats_close(struct zhpe_stats *stats);
void zhpe_stats_start(struct zhpe_stats *stats);
void zhpe_stats_stop(struct zhpe_stats *stats);
void zhpe_stats_pause(struct zhpe_stats *stats);

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

#define EXTERN_ZHPE_STATS(_name)

#define zhpe_stats_init(stats_dir, stats_unique)
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
