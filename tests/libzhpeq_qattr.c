/*
 * Copyright (C) 2017-2018 Hewlett Packard Enterprise Development LP.
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
#include <zhpeq_util.h>

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(help, "Usage:%s\n", appname);

    exit(255);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    int                 rc;
    struct zhpeq_attr   attr;

    zhpeq_util_init(argv[0], LOG_DEBUG, false);

    if (argc > 1)
        usage(false);

    rc = zhpeq_init(ZHPEQ_API_VERSION);
    if (rc < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    rc = zhpeq_query_attr(&attr);
    if (rc < 0) {
        print_func_err(__FUNCTION__, __LINE__, "zhpeq_query_attr", "", rc);
        goto done;
    }
    printf("%s:max_tx_queues : %u\n", appname, attr.z.max_tx_queues);
    printf("%s:max_rx_queues : %u\n", appname, attr.z.max_rx_queues);
    printf("%s:max_hw_qlen   : %u\n", appname, attr.z.max_hw_qlen);
    printf("%s:max_sw_qlen   : %u\n", appname, attr.z.max_sw_qlen);
    printf("%s:max_dma_len   : %Lu\n", appname, (ullong)attr.z.max_dma_len);

 done:
    return ret;
}
