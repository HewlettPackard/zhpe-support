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

#include <zhpe.h>
#include <zhpeq_util.h>

#include <poll.h>
#include <signal.h>

#define INDEX_MASK      (0xFFFF)

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    print_usage(
        help,
        "Usage:%s [-p] <count>\n"
        "<count> is the number of no-ops to send\n"
        "<count> may be postfixed with [kmgtKMGT] to specify the"
        " base units.\n"
        "-p : use polling\n",
        appname);

    exit(255);
}

static int _do_poll(const char *callf, uint line, int fd, short events)
{
    int                 ret;
    struct pollfd       pollfd;

    pollfd.fd = fd;
    pollfd.events = events;
    ret = poll(&pollfd, 1, -1);
    if (ret == -1) {
        ret = -errno;
        print_func_err(__FUNCTION__, __LINE__, "poll", "", ret);
    } else if (ret != 1) {
        print_err("%s,%u:poll() returned %d?\n",
                  __FUNCTION__, __LINE__, ret);
        ret = -EIO;
    } else if (!expected_saw("pollfd.revents", 0, pollfd.revents & ~events))
        ret = -EIO;

    return (ret < 0 ? ret : pollfd.revents);
}

#define do_poll(_fd, _events)                           \
    _do_poll(__FUNCTION__, __LINE__, _fd, _events)

static int _do_send(const char *callf, uint line, int fd, uint64_t sent)
{
    union zhpe_req      req;
    uint64_t            size;
    uint64_t            res;

    req.hdr.version = ZHPE_OP_VERSION;
    req.hdr.opcode  = ZHPE_OP_NOP;
    req.hdr.index = (sent & INDEX_MASK);
    req.nop.seq = sent;
    /* Writes must be of the proper size for the opcode. */
    size = sizeof(req.nop);
    res = write(fd, &req, size);
    return check_func_ion(callf, line, "write", sent,
                          size, false, res, 0);
}

#define do_send(_fd, _sent)                             \
    _do_send(__FUNCTION__, __LINE__, _fd, _sent)

static int _do_recv(const char *callf, uint line, int fd, uint64_t recv)
{
    int                 ret;
    union zhpe_rsp      rsp;
    uint64_t            size;
    uint64_t            res;

    /*
     * Weird, chunky, semantics on read: at most one response
     * returned at a time and if buffer is too small, EINVAL will
     * be returned. So, ask for largest possible response,
     * but we expect to get back only the size for a no-op.
     */
    size = sizeof(rsp.nop);
    res = read(fd, &rsp, sizeof(rsp));
    ret = check_func_ion(__FUNCTION__, __LINE__, "read", recv,
                         size, false, res, 0);
    if (ret < 0)
        goto done;
    ret = -EINVAL;
    if (!expected_saw("version", ZHPE_OP_VERSION, rsp.hdr.version))
        goto done;
    if (!expected_saw("index", recv & INDEX_MASK, rsp.hdr.index))
        goto done;
    if (!expected_saw("opcode", ZHPE_OP_NOP | ZHPE_OP_RESPONSE,
                      rsp.hdr.opcode))
        goto done;
    if (rsp.hdr.status < 0) {
        print_err("%s,%u:NOP returned %d:%s\n",
                  __FUNCTION__, __LINE__, -rsp.hdr.status,
                  strerror(-rsp.hdr.status));
        goto done;
    }
    if (!expected_saw("seq", recv, rsp.nop.seq))
        goto done;

    ret = 0;

 done:

    return ret;
}

#define do_recv(_fd, _recv)                             \
    _do_recv(__FUNCTION__, __LINE__, _fd, _recv)


static int polling(int fd, uint64_t count)
{
    int                 ret = 0;
    uint64_t            sent;
    uint64_t            recv;

    /* Do the operations. */
    for (sent = 0, recv = 0; sent < count || recv < count;) {
        for (; sent < count; sent++) {
            if (!(ret & POLLOUT) &&
                (ret = do_poll(fd, POLLIN | POLLOUT)) < 0)
                goto done;
            /* Favor receive over send. */
            if (ret & POLLIN)
                break;
            ret = do_send(fd, sent);
            if (ret < 0)
                goto done;
            ret = 0;
        }
        for (; recv < count; recv++) {
            if (!(ret & POLLIN) &&
                (ret = do_poll(fd, POLLIN | POLLOUT)) < 0)
                goto done;
            if (!(ret & POLLIN))
                break;
            ret = do_recv(fd, recv);
            if (ret < 0)
                goto done;
            ret = 0;
        }
    }

 done:

    return ret;
}

static int pingpong(int fd, uint64_t count)
{
    int                 ret = 0;
    uint64_t            i;

    /* Do the operations. */
    for (i = 0; i < count; i++) {
        ret = do_send(fd, i);
        if (ret < 0)
            goto done;
        ret = do_recv(fd, i);
        if (ret < 0)
            goto done;
    }

 done:

    return ret;
}

int main(int argc, char **argv)
{
    int                 ret = 1;
    int                 fd = -1;
    const char          *devname = "/dev/" DRIVER_NAME;
    bool                use_polling = false;
    int                 opt;
    uint64_t            count;

    zhpeq_util_init(argv[0], LOG_DEBUG, false);
    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "p")) != -1) {

        switch (opt) {

        case 'p':
            if (use_polling)
                usage(false);
            use_polling = true;
            break;

        default:
            usage(false);

        }
    }

    argc -= optind;
    if (argc < 1)
        usage(false);

    if (parse_kb_uint64_t(__FUNCTION__, __LINE__, "count",
                          argv[optind++], &count, 0, 1, SIZE_MAX,
                          PARSE_KB | PARSE_KIB) < 0)
        usage(false);

    /* Open zhpe device */
    fd = open(devname, O_RDWR);
    if (fd == -1) {
        print_func_err(__FUNCTION__, __LINE__, "open", devname, errno);
        goto done;
    }
    if (use_polling) {
        if (polling(fd, count) < 0)
            goto done;
    } else {
        if (pingpong(fd, count) < 0)
            goto done;
    }

    ret = 0;
 done:
    if (fd >= 0)
        close(fd);

    printf("%s:done, ret = %d\n", appname, ret);

    return ret;
}
