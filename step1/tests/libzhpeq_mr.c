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
    { buf,     1, 0x0003, ZHPEQ_MR_PUT },
    { buf + 1, 1, 0x000B, ZHPEQ_MR_PUT },
    { NULL },
};

#define QACCESS_RD	(ZHPEQ_MR_PUT | ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_SEND)
#define QACCESS_WR	(ZHPEQ_MR_GET | ZHPEQ_MR_PUT_REMOTE | ZHPEQ_MR_RECV)
#define QACCESS_RW	(QACCESS_RD | QACCESS_WR)

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(help, "Usage:%s\n", appname);

    exit(255);
}

static int do_policy_reg(struct zhpeq_dom *zqdom, char *pbuf,
                         struct zhpeq_key_data *qk[6])
{
    int                 ret;
    int                 i = 0;

    ret = zhpeq_mr_reg(zqdom, pbuf, page_size * 7,
                       QACCESS_RW, &qk[i++]);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_mr_reg", "", ret);
        goto done;
    }
    ret = zhpeq_mr_reg(zqdom, pbuf + page_size, page_size * 2,
                       QACCESS_RW, &qk[i++]);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_mr_reg", "", ret);
        goto done;
    }
    ret = zhpeq_mr_reg(zqdom, pbuf + page_size * 4, page_size * 2,
                       QACCESS_RW, &qk[i++]);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_mr_reg", "", ret);
        goto done;
    }
    ret = zhpeq_mr_reg(zqdom, pbuf + page_size * 2, page_size * 3,
                       QACCESS_RW, &qk[i++]);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_mr_reg", "", ret);
        goto done;
    }
    ret = zhpeq_mr_reg(zqdom, pbuf + page_size * 3, page_size,
                       QACCESS_RW, &qk[i++]);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_mr_reg", "", ret);
        goto done;
    }

 done:
    return ret;
}

static int do_policy_tests(struct zhpeq_dom *zqdom)
{
    int                 ret;
    int                 rc;
    int                 i;
    char                *pbuf = NULL;
    const size_t        buf_size = page_size * 7;
    struct zhpeq_key_data *qk[6] = { NULL };

    pbuf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (buf == MAP_FAILED) {
        ret = -errno;
        pbuf = NULL;
        print_func_errn(__func__, __LINE__, "mmap", buf_size, false, ret);
        goto done;
    }

    ret = do_policy_reg(zqdom, pbuf, qk);
    for (i = 0; i < ARRAY_SIZE(qk); i++) {
        if (qk[i])
            zhpeq_qkdata_free(qk[i]);
        qk[i] = NULL;
    }
    ret = do_policy_reg(zqdom, pbuf, qk);
    for (i = 0; i < ARRAY_SIZE(qk); i++) {
        if (qk[i]) {
            rc = zhpeq_qkdata_free(qk[i]);
            if (rc < 0) {
                print_func_err(__func__, __LINE__, "zhpeq_qkdata_free",
                               "", ret);
                if (ret >= 0)
                    ret = rc;
            }
        }
        qk[i] = NULL;
    }
    ret = do_policy_reg(zqdom, pbuf, qk);
    for (i = ARRAY_SIZE(qk) - 1; i >= 0; i--) {
        if (qk[i]) {
            rc = zhpeq_qkdata_free(qk[i]);
            if (rc < 0) {
                print_func_err(__func__, __LINE__, "zhpeq_qkdata_free",
                               "", ret);
                if (ret >= 0)
                    ret = rc;
            }
        }
        qk[i] = NULL;
    }

 done:
    if (pbuf)
        munmap(pbuf, buf_size);

    return ret;
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    struct zhpeq_dom    *zqdom = NULL;
    int                 rc;
    uint32_t            match;
    uint                i;
    uint                j;
    bool                zhpe;

    zhpeq_util_init(argv[0], LOG_DEBUG, false);

    if (argc != 1)
        usage(false);

    rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    zhpe = zhpeq_is_asic();

    rc = zhpeq_domain_alloc(&zqdom);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", rc);
        goto done;
    }
    rc = do_policy_tests(zqdom);
    if (rc < 0)
        goto done;

    for (i = 0; tests[i].buf; i++) {
        rc = zhpeq_mr_reg(zqdom, tests[i].buf, tests[i].len,
                          tests[i].qaccess, &tests[i].qk);
        if (rc < 0) {
            print_func_err(__func__, __LINE__, "zhpeq_mr_reg", "", rc);
            goto done;
        }
        for (j = 0, match = 0; j < i; j++) {
            if (tests[j].qk->active_uptr == tests[i].qk->active_uptr)
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
    zhpeq_domain_free(zqdom);

    printf("%s:done, ret = %d\n", appname, ret);

    return ret;
}
