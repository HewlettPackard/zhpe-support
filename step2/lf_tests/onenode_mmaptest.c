/*
 * Copyright (C) 2019 Hewlett Packard Enterprise Development LP.
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

/*
 * This is a self-contained hello world that takes one argument: a memory length.
*/

#define _GNU_SOURCE

#include <zhpe_mmap.h>
#include <zhpeq_util_fab.h>

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s <mmap_len>\n"
        "All sizes may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "Lower case is base 10; upper case is base 2.\n",
        appname);

    exit(help ? 0 : 255);
}

int main(int argc, char **argv)
{
    size_t                 i;
    int                 ret = 1;

    /* params for mmap */
    uint64_t            mmap_len;
    uint64_t            length;
    void                *buf=NULL;

    uint16_t *p;

    if (argc != 1)
        usage(true);

    ret = zhpe_mmap_init();
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpe_mmap_init", FI_ZHPE_OPS_V1, ret);
        goto done;
    }

    /* set length */
    if (parse_kb_uint64_t(__func__, __LINE__, "mmap_len",
        argv[1], &mmap_len, 0,
        sizeof(uint16_t), SIZE_MAX,
        PARSE_KB | PARSE_KIB))
            usage(false);
    length = page_up(mmap_len);

    ret = zhpe_mmap_alloc(length, buf);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpe_mmap_alloc", FI_ZHPE_OPS_V1, ret);
        goto done;
    }

    printf("Writing to new buf:\n");
    for (i = 0, p = buf; i < mmap_len; i += sizeof (*p), p++)
        *p = (i | 1);


    printf("Checking contents of buf:\n");
    ret=0;
    for (i = 0, p = buf; i < mmap_len;
         i += sizeof(*p), p++) {
        if (*p != (typeof(*p))(i | 1)) {
            if (!ret)
                print_err("first error: off 0x%08lx saw 0x%04x\n", i, *p);
            ret++;
        }
    }
    print_err("Saw %d errors\n", ret);
    ret = zhpe_mmap_free(buf);
    if (ret < 0) {
        print_func_err(__func__, __LINE__, "zhpe_mmap_free", FI_ZHPE_OPS_V1, ret);
        goto done;
    }


done:
    return ret;
}
