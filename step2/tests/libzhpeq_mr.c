/*
 * Copyright (C) 2017-2019 Hewlett Packard Enterprise Development LP.
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

#include <internal.h>

#include <limits.h>

static char buf[4];

struct test {
    void                *buf;
    size_t              len;
    uint32_t            match;
    uint32_t            qaccess;
    struct zhpeq_key_data *qk;
};

static struct test tests[] = {
    { buf,     2, 0x0000, ZHPEQ_MR_PUT },
    { buf,     2, 0x0001, ZHPEQ_MR_PUT },
    { buf,     2, 0x0000, ZHPEQ_MR_PUT | ZHPEQ_MR_GET },
    { buf,     1, 0x0000, ZHPEQ_MR_PUT },
    { buf + 1, 1, 0x0000, ZHPEQ_MR_PUT },
    { NULL },
};

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(help, "Usage:%s\n", appname);

    exit(255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct zhpeq_dom    *zdom = NULL;
    int                 rc;
    uint32_t            match;
    uint                i;
    uint                j;
    struct zhpeq_attr   attr;
    bool                zhpe;

    zhpeq_util_init(argv[0], LOG_DEBUG, false);

    if (argc != 1)
        usage(false);

    rc = zhpeq_init(ZHPEQ_API_VERSION);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    rc = zhpeq_query_attr(&attr);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_query_attr", "", rc);
        goto done;
    }
    zhpe = (attr.backend == ZHPEQ_BACKEND_ZHPE);

    rc = zhpeq_domain_alloc(&zdom);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", rc);
        goto done;
    }
    for (i = 0; tests[i].buf; i++) {
        rc = zhpeq_mr_reg(zdom, tests[i].buf, tests[i].len,
                          tests[i].qaccess, &tests[i].qk);
        if (rc < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_mr_reg", "", rc);
            goto done;
        }
        for (j = 0, match = 0; j < i; j++) {
            if (tests[j].qk == tests[i].qk)
                match |= (1U << j);
        }
        if ((zhpe && tests[i].match != match) || (!zhpe && match)) {
            print_err("test %u 0x%04x != 0x%04x\n",
                      i, match, tests[i].match);
            goto done;
        }
    }
    for (i = 0; tests[i].buf; i++) {
        rc = zhpeq_qkdata_free(tests[i].qk);
        if (rc < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_mr_free", "", rc);
            goto done;
        }
    }

    ret = 0;

 done:
    zhpeq_domain_free(zdom);

    printf("%s:done, ret = %d\n", appname, ret);

    return ret;
}
