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

static struct zhpeq_attr zhpeq_attr;


static void usage(bool help) __attribute__ ((__noreturn__));

static void print_attr(const char *lbl, struct zhpeq_attr *attr)
{
    print_info("%s:max_tx_queues : %u\n", lbl, attr->z.max_tx_queues);
    print_info("%s:max_rx_queues : %u\n", lbl, attr->z.max_rx_queues);
    print_info("%s:max_tx_qlen   : %u\n", lbl, attr->z.max_tx_qlen);
    print_info("%s:max_rx_qlen   : %u\n", lbl, attr->z.max_rx_qlen);
    print_info("%s:max_dma_len   : %" PRIu64 "\n", lbl, attr->z.max_dma_len);
    print_info("%s:num_slices    : %u\n", lbl, attr->z.num_slices);
}

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

    rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    /* Leaving the old interface for now. */
    rc = zhpeq_query_attr(&attr);
    if (rc < 0) {
        print_func_err(__func__, __LINE__, "zhpeq_query_attr", "", rc);
        goto done;
    }
    print_attr("query", &attr);
    if (memcmp(&zhpeq_attr, &attr, sizeof(zhpeq_attr))) {
        print_err("%s,%u:attrs differ\n", __func__, __LINE__);
        print_attr("init ", &zhpeq_attr);
        goto done;
    }

 done:
    return ret;
}
