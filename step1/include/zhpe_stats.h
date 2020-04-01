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

#ifndef _ZHPE_STATS_H_
#define _ZHPE_STATS_H_

#include <zhpeq_util.h>
#include <zhpe_stats_types.h>

_EXTERN_C_BEG

struct zhpe_stats_record {
    uint32_t    op_flag;
    uint32_t    subid;
    uint64_t    val0;
    uint64_t    val1;
    uint64_t    val2;
    uint64_t    val3;
    uint64_t    val4;
    uint64_t    val5;
    uint64_t    val6;
} CACHE_ALIGNED;

struct zhpe_stats;

struct zhpe_stats_ops {
    void   (*close)(struct zhpe_stats *zstats);
    void   (*enable)(struct zhpe_stats *zstats);
    void   (*disable)(struct zhpe_stats *zstats);
    void   (*pause_all)(struct zhpe_stats *zstats);
    void   (*restart_all)(struct zhpe_stats *zstats);
    void   (*stop_all)(struct zhpe_stats *zstats);
    void   (*start)(struct zhpe_stats *zstats, uint32_t subid);
    void   (*stop)(struct zhpe_stats *zstats, uint32_t subid);
    void   (*stamp)(struct zhpe_stats *zstats, uint32_t subid,
                                            uint64_t d1, uint64_t d2,
                                            uint64_t d3, uint64_t d4,
                                            uint64_t d5, uint64_t d6);
    void   (*setvals)(struct zhpe_stats *zstats, struct zhpe_stats_record *rec);
    struct zhpe_stats_record    *(*nextslot)(struct zhpe_stats *zstats);
    void   (*saveme)(struct zhpe_stats *zstats, char *dest, char *src);
};

struct zhpe_stats {
    struct zhpe_stats_record    *buffer;
    uint64_t                    *sim_buf;
    struct zhpe_stats_ops       *zhpe_stats_ops;
    struct zhpe_stats_ops       *saved_zhpe_stats_ops;
    struct zhpe_stats_ops       *disabled_zhpe_stats_ops;
    int                         *zhpe_stats_fd_list;
    uint64_t                    *zhpe_stats_cntr_list;
    uint64_t                    *zhpe_stats_config_list;
    uint32_t                    num_slots;
    int                         fd;
    uint16_t                    uid;
    size_t                      head;
    uint8_t                     enabled;
};

void zhpe_stats_finalize();
bool zhpe_stats_init(const char *stats_unique);
void zhpe_stats_open(uint16_t uid);
void zhpe_stats_test(uint16_t uid);
uint16_t zhpe_stats_subid(uint16_t uid, uint16_t id);

extern __thread struct zhpe_stats *zhpe_stats;

#ifdef HAVE_ZHPE_STATS


#define zhpe_stats_subid(_name, _id)            \
    ((ZHPE_STATS_SUBID_##_name * 1000) + _id)

#else

#define zhpe_stats_subid(_name, _id) 0

#endif


#ifdef HAVE_ZHPE_STATS
static inline void zhpe_stats_close(void)
{
    struct zhpe_stats *zstats = zhpe_stats;
    zstats->zhpe_stats_ops->close(zstats);
}

static inline void zhpe_stats_pause_all(void)
{
    struct zhpe_stats *zstats = zhpe_stats;
    zstats->zhpe_stats_ops->pause_all(zstats);
}

static inline void zhpe_stats_restart_all(void)
{
    struct zhpe_stats *zstats = zhpe_stats;
    zstats->zhpe_stats_ops->restart_all(zstats);
}

static inline void zhpe_stats_stop_all(void)
{
    struct zhpe_stats *zstats = zhpe_stats;
    zstats->zhpe_stats_ops->stop_all(zstats);
}

static inline void zhpe_stats_start(uint32_t subid)
{
    struct zhpe_stats *zstats = zhpe_stats;
    zstats->zhpe_stats_ops->start(zstats, subid);
}

static inline void zhpe_stats_stop(uint32_t subid)
{
    struct zhpe_stats *zstats = zhpe_stats;
    zstats->zhpe_stats_ops->stop(zstats, subid);
}

static inline void zhpe_stats_enable(void)
{
    struct zhpe_stats *zstats = zhpe_stats;
    zstats->zhpe_stats_ops->enable(zstats);
}

static inline void zhpe_stats_disable(void)
{
    struct zhpe_stats *zstats = zhpe_stats;
    zstats->zhpe_stats_ops->disable(zstats);
}

static inline void zhpe_stats_stamp(uint32_t subid,
                                    uint64_t d1,
                                    uint64_t d2,
                                    uint64_t d3,
                                    uint64_t d4,
                                    uint64_t d5,
                                    uint64_t d6)
{
    struct zhpe_stats *zstats = zhpe_stats;
    zstats->zhpe_stats_ops->stamp(zstats, subid, d1, d2, d3, d4, d5, d6);
}


#else // HAVE_ZHPE_STATS

static inline void zhpe_stats_close(void)
{
}

static inline void zhpe_stats_pause_all(void)
{
}

static inline void zhpe_stats_restart_all(void)
{
}

static inline void zhpe_stats_stop_all(void)
{
}

static inline void zhpe_stats_start(uint32_t subid)
{
}

static inline void zhpe_stats_stop(uint32_t subid)
{
}

static inline void zhpe_stats_enable(void)
{
}

static inline void zhpe_stats_disable(void)
{
}

static inline void zhpe_stats_stamp(uint32_t subid,
                                    uint64_t d1,
                                    uint64_t d2,
                                    uint64_t d3,
                                    uint64_t d4,
                                    uint64_t d5,
                                    uint64_t d6)
{
}

#endif // HAVE_ZHPE_STATS
_EXTERN_C_END

#endif /* _ZHPE_STATS_H_ */
