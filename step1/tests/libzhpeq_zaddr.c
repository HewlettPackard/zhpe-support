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
#include <zhpeq_util.h>

static struct zhpeq_attr zhpeq_attr;

struct test {
    const char          *node;
    const char          *service;
    uint32_t            gcid_match;
    uint32_t            queue_match;
    int                 rc_match;
};

static struct test tests[] = {
    { "node1",      NULL, 0x1010, -1u, 0 },
    { "memory31/4", NULL, 0x3025, -1u, 0 },
    { "node42",     "66", 0x3019,  66, 0 },
    { "switch24/1", "10", 0x2008,  10, 0 },
    { "0x0010",     NULL, 0x0010, -1u, 0 },
    { "foobar",     NULL, 0x0000, -1u, -ENOENT },
    { NULL,         "0",  0x0000, -1u, -EINVAL },
    { NULL,         NULL },
};

int main(int argc, char **argv)
{
    int                  rc;
    uint                 i;
    struct sockaddr_zhpe sz;
    uint32_t             gcid;
    uint32_t            queue;
    char                *str;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION, &zhpeq_attr);
    if (rc < 0)
        print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);

    for (i = 0; tests[i].node || tests[i].service; i++) {
        rc = zhpeq_get_zaddr(tests[i].node, tests[i].service, false, &sz);
        gcid = zhpeu_uuid_to_gcid(sz.sz_uuid);
        queue = ntohl(sz.sz_queue);
        if (rc != tests[i].rc_match)
            print_func_err(__func__, __LINE__, "zhpeq_get_zaddr", "", rc);
        else if (tests[i].rc_match < 0)
            printf("test %u returned expected error\n", i);
        else if (gcid != tests[i].gcid_match)
            print_err("test %u gcid match 0x%x != 0x%x\n",
                      i, gcid, tests[i].gcid_match);
        else if (queue != tests[i].queue_match)
            print_err("test %u queue match %u != %u\n",
                      i, queue, tests[i].queue_match);
        else {
            str = _zhpeu_sockaddr_str(&sz);
            if (str) {
                printf("%s = %s\n", tests[i].node, str);
                free(str);
            }
        }
    }
    return 0;
}
