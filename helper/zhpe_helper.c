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

#include <poll.h>
#include <pthread.h>

#include <sys/mman.h>

#include <zhpe.h>
#include <zhpeq_util.h>

#define OPEN_TRIES      (10)
#define POLL_TIMEOUT    (1000)

static char             *dev_name = "/dev/" DRIVER_NAME;
static int               dev_fd = -1;

static struct zhpe_shared_data *shared_data;
static uint debug_flags;

#if defined(NDEBUG)
#define debug_cond(_mask, _cond, _fmt, ...) do {} while (0)
#define debug(_mask, _fmt, ...) do {} while (0)

#define DEFAULT_LOG_LEVEL       (LOG_ERROR)
#else

#define debug_cond(_mask,_cond,  _fmt, ...)             \
do {                                                    \
    if ((debug_flags & (_mask)) && (_cond))             \
        print_dbg(_fmt, ##__VA_ARGS__);                 \
} while (0)
#define debug(_mask, _fmt, ...) debug_cond(_mask, true, _fmt, ##__VA_ARGS__)

#define DEFAULT_LOG_LEVEL       (LOG_DEBUG)
#endif /* defined(NDEBUG) */

static void usage(void) __attribute__ ((__noreturn__));

static void usage(void)
{
    print_err("Usage:%s", appname);

    exit(255);
}

static int write_rsp(const char *callf, uint line,
                     union zhpe_rsp *rsp, size_t len, int status)
{
    ssize_t             res;

    rsp->hdr.version = ZHPE_OP_VERSION;
    rsp->hdr.opcode |= ZHPE_OP_RESPONSE;
    rsp->hdr.status = status;

    res = write(dev_fd, rsp, len);
    return check_func_io(callf, line, "write", dev_name, len, res, 0);
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;
    int                 rc;
    ssize_t             res;
    uint                i;

    /* Open /dev/null on stdin, stdout, and stderr. */
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);
    rc = 0;
    if (!freopen("/dev/null", "r", stdin))
        rc = errno;
    if (!freopen("/dev/null", "w", stdout))
        rc = errno;
    if (!freopen("/dev/null", "w", stderr))
        rc = errno;

    zhpeq_util_init(argv[0], DEFAULT_LOG_LEVEL, true);
    print_info("start");

    if (rc) {
        print_err("%s,%u:Reopening stdio returned error %d:%s",
                  __FUNCTION__, __LINE__, rc, strerror(rc));
        goto done;
    }

    if (argc != 1)
        usage();

    /* Could be a race with udev */
    for (i = 0; ; i++) {
        dev_fd = open(dev_name, O_RDWR);
        if (dev_fd != -1)
            break;
        if (i % 60 == 0) {
            rc = errno;
            print_err("%s,%u:open(%s) returned error %d:%s, delay and retry\n",
                      __FUNCTION__, __LINE__, dev_name, rc, strerror(rc));
        }
        sleep(ZHPE_HELPER_OPEN_SLEEP);
    }

    for (;;) {
        res = read(dev_fd, &op, sizeof(op));
        if (res == -1) {
            print_func_err(__FUNCTION__, __LINE__, "read", "", errno);
            goto done;
        }
        if (!expected_saw("version", ZHPE_OP_VERSION, op.hdr.version))
            goto done;

        switch (op.hdr.opcode)  {

        case ZHPE_OP_HELPER_EXIT:
            debug(DEBUG_IO, "%s,%u:ZHPE_OP_HELPER_EXIT",
                  __FUNCTION__, __LINE__);
            ret = 0;
            goto done;

        case ZHPE_OP_HELPER_INIT:
            shared_data = mmap(NULL, req->helper_init.shared_size,
                               PROT_READ | PROT_WRITE, MAP_SHARED,
                               dev_fd, req->helper_init.shared_offset);
            if (shared_data == MAP_FAILED) {
                shared_data = NULL;
                print_func_err(__FUNCTION__, __LINE__, "mmap", dev_name,
                               errno);
                goto done;
            }
            if (!expected_saw("shared_magic", ZHPE_MAGIC, shared_data->magic))
                goto done;
            if (!expected_saw("shared_version", ZHPE_SHARED_VERSION,
                              shared_data->version))
                goto done;

            debug_flags = shared_data->debug_flags;

            debug(DEBUG_IO, "%s,%u:ZHPE_OP_HELPER_INIT",
                  __FUNCTION__, __LINE__);
            if (write_rsp(__FUNCTION__, __LINE__, rsp,
                          sizeof(rsp->helper_init), 0) < 0)
                goto done;
            break;

        case ZHPE_OP_HELPER_NOP:
            debug(DEBUG_IO, "%s,%u:ZHPE_OP_HELPER_NOP",
                  __FUNCTION__, __LINE__);
            if (write_rsp(__FUNCTION__, __LINE__, rsp,
                          sizeof(rsp->helper_nop), 0) < 0) {
                print_err("seq %lu", rsp->helper_nop.seq);
                goto done;
            }
            break;

        default:
            print_err("%s,%u:Unexpected opcode 0x%02x",
                      __FUNCTION__, __LINE__, op.hdr.opcode);
            goto done;
        }
    }

 done:
    /* Clean up any running threads. Really shouldn't be any. */
    print_info("exit");

    return ret;
}
