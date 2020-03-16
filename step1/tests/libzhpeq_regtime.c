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

#include <zhpeq.h>

#include <limits.h>

static struct zhpeq_attr zhpeq_attr;

static void usage(bool help) __attribute__ ((__noreturn__));

#define COUNTERS        (4)

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s <min_size>[K|M|G] <max_size>[K|M|G] <ops>[k|m|g|K|M|G]]\n"
        "Create a region of <max_size>, must be power of 2, and run <ops>.\n"
        "tests for each size from <min_size>, 2 * <min_size>, ...,\n"
        "<max_size>.\n",
        appname);

    exit(255);
}

void dump_data(const char *label, uint64_t *delta, uint64_t ops, uint64_t size)
{
    uint64_t            tot = 0;
    uint64_t            min = ~(uint64_t)0;
    uint64_t            max = 0;
    uint64_t            i;
    uint64_t            j;

    for (i = 0, j = 0; i < ops; i++, j += COUNTERS) {
        tot += delta[j];
        if (delta[j] < min)
            min = delta[j];
        if (delta[j] > max)
            max = delta[j];
    }
    printf("*%7s avg/min/max/ops/opbytes %.3lf/%.3lf/%.3lf/%" PRIu64
           "/%" PRIu64 "\n",
           label, cycles_to_usec(tot, ops), cycles_to_usec(min, 1),
           cycles_to_usec(max, 1), ops, size);
    for (i = 0, j = 0; i < ops; i++, j += COUNTERS)
        printf("%" PRIu64 " %.3lf\n", i, cycles_to_usec(delta[j], 1));
}

int main(int argc, char **argv)
{
    int                 ret = 255;
    struct zhpeq_dom    *zqdom = NULL;
    char                *map = NULL;
    uint64_t            i;
    uint64_t            j;
    uint64_t            min_size;
    uint64_t            max_size;
    uint64_t            size;
    uint64_t            ops;
    uint64_t            start;
    uint64_t            *delta;
    size_t              req;
    size_t              delta_req;
    struct zhpeq_key_data *kdata;
    int                 rc;

    zhpeq_util_init(argv[0], LOG_DEBUG, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    if (argc != 4)
        usage(false);

    if (parse_kb_uint64_t(__func__, __LINE__,
                          "min_size", argv[1], &min_size,
                          0, 1, SIZE_MAX, PARSE_KIB) < 0)
        usage(false);
    if (parse_kb_uint64_t(__func__, __LINE__,
                          "max_size", argv[2], &max_size,
                          0, 1, SIZE_MAX, PARSE_KIB) < 0)
        usage(false);
    if (parse_kb_uint64_t(__func__, __LINE__,
                          "ops", argv[3], &ops,
                          0, 1, SIZE_MAX, PARSE_KIB | PARSE_KB) < 0)
        usage(false);
    if (min_size & (min_size - 1)) {
        fprintf(stderr, "%s:min_size must be a power of 2\n", appname);
        goto done;
    }
    if (max_size & (max_size - 1)) {
        fprintf(stderr, "%s:max_size must be a power of 2\n", appname);
        goto done;
    }

    ret = 1;

    rc = zhpeq_domain_alloc(&zqdom);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", rc);
        goto done;
    }

    req = (max_size + page_size - 1) & ~(page_size - 1);
    delta_req = ops * sizeof(*delta) * COUNTERS;
    delta_req = (delta_req + page_size - 1) & ~(page_size - 1);

    map = mmap(NULL, req + delta_req, PROT_READ | PROT_WRITE,
               MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (map == MAP_FAILED) {
        map = NULL;
        print_func_err(__func__, __LINE__, "mmap", "", errno);
        goto done;
    }
    delta = (void *)(map + req);
    /* mlock and munlock to fault everything in */
    if (mlock(map, req + delta_req) == -1) {
        print_func_err(__func__, __LINE__, "mlock", "", errno);
        goto done;
    }
    if (munlock(map, req + delta_req) == -1) {
        print_func_err(__func__, __LINE__, "munlock", "", errno);
        goto done;
    }

    /* Now the test loop. */
    for (size = min_size; size <= max_size; size *= 2) {
        for (i = 0, j = 0; i < ops; i++, j += COUNTERS) {
            start = get_cycles(NULL);
            rc = zhpeq_mr_reg(zqdom, map, size,
                              (ZHPEQ_MR_GET | ZHPEQ_MR_PUT |
                               ZHPEQ_MR_SEND | ZHPEQ_MR_RECV |
                               ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE),
                              &kdata);
            if (rc < 0) {
                print_func_err(__func__, __LINE__, "zhpeq_mr_reg", "", rc);
                goto done;
            }
            delta[j] = get_cycles(NULL) - start;
            start = get_cycles(NULL);
            rc = zhpeq_qkdata_free(kdata);
            if (rc < 0) {
                print_func_err(__func__, __LINE__, "zhpeq_mr_free",
                               "", rc);
                goto done;
            }
            delta[j + 1] = get_cycles(NULL) - start;
        }
        for (i = 0, j = 0; i < ops; i++, j += COUNTERS) {
            start = get_cycles(NULL);
            if (mlock(map, size) == -1) {
                print_func_err(__func__, __LINE__, "mlock", "", errno);
                goto done;
            }
            delta[j + 2] = get_cycles(NULL) - start;
            start = get_cycles(NULL);
            if (munlock(map, size) == -1) {
                print_func_err(__func__, __LINE__, "munlock", "", errno);
                goto done;
            }
            delta[j + 3] = get_cycles(NULL) - start;
        }
        dump_data("mr_reg", delta, ops, size);
        dump_data("mr_free", delta + 1, ops, size);
        dump_data("mlock", delta + 2, ops, size);
        dump_data("munlock", delta + 3, ops, size);
    }
    ret = 0;

 done:
    if (map)
        munmap(map, req + delta_req);
    zhpeq_domain_free(zqdom);

    printf("%s:done, ret = %d\n", appname, ret);

    return ret;
}
