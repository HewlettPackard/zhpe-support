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

#undef _ZHPEQ_TEST_COMPAT_
#include <zhpeq.h>

#include <sys/queue.h>

#define DELIM           " \t\n"
#define ACCESS                                                          \
(ZHPEQ_MR_GET | ZHPEQ_MR_PUT | ZHPEQ_MR_SEND | ZHPEQ_MR_RECV |          \
 ZHPEQ_MR_GET_REMOTE | ZHPEQ_MR_PUT_REMOTE)

struct range {
    uint64_t            start;
    uint64_t            end;
};

struct qkdata_list_entry {
    CIRCLEQ_ENTRY(qkdata_list_entry) lentry;
    const struct zhpeq_key_data *qkdata;
};

static CIRCLEQ_HEAD(, qkdata_list_entry) qkdata_list =
    CIRCLEQ_HEAD_INITIALIZER(qkdata_list);

static bool             warnings_fatal;

#define warning(...)                            \
do {                                            \
    zhpeu_print_err(__VA_ARGS__);               \
    if (warnings_fatal)                         \
        abort();                                \
} while (0)

static bool parse_range(char **parseit, void *buf,size_t size,
                        struct range *range)
{
    char                *s;

    if (!(s = strsep(parseit, DELIM)) || !*s) {
        warning("No range found\n");
        return false;
    }
    if (zhpeu_parse_kb_uint64_t("start", s, &range->start, 0, 0, size,
                                PARSE_KIB | PARSE_KB) < 0)
        return false;
    if (!(s = strsep(parseit, DELIM)) || !*s) {
        warning("No <end> found\n");
        return false;
    }
    if (zhpeu_parse_kb_uint64_t("end", s, &range->end,  0, range->start, size,
                                PARSE_KIB | PARSE_KB) < 0)
        return false;

    range->start += (uintptr_t)buf;
    range->end += (uintptr_t)buf;

    return true;
}

static int compare_qkdata(const struct zhpeq_key_data *a,
                          const struct zhpeq_key_data *b)
{
    int                 ret;

    ret = arithcmp(a->z.vaddr, b->z.vaddr);
    if (ret)
        return ret;

    return arithcmp(a->z.len, b->z.len);
}

static int compare_range_qkdata(const struct range *a,
                                const struct zhpeq_key_data *b)
{
    int                 ret;

    ret = arithcmp(a->start, b->z.vaddr);
    if (ret)
        return ret;

    return arithcmp(a->end - a->start, b->z.len);
}

static void qklist_insert(const struct zhpeq_key_data *qkdata)
{
    struct qkdata_list_entry *cur;
    struct qkdata_list_entry *new;

    new = xmalloc(sizeof(*new));
    new->qkdata = qkdata;

    CIRCLEQ_FOREACH(cur, &qkdata_list, lentry) {
        if (compare_qkdata(qkdata, cur->qkdata) > 0)
            continue;
        CIRCLEQ_INSERT_BEFORE(&qkdata_list, cur, new, lentry);
        return;
    }
    CIRCLEQ_INSERT_TAIL(&qkdata_list, new, lentry);
}

static bool qklist_find(struct range *range, bool delete,
                        struct zhpeq_key_data **qkdata)
{
    struct qkdata_list_entry *cur;
    int                 rc;

    CIRCLEQ_FOREACH(cur, &qkdata_list, lentry) {
        rc = compare_range_qkdata(range, cur->qkdata);
        if (rc > 0)
            continue;
        if (rc < 0)
            break;
        *qkdata = (void *)cur->qkdata;
        if (delete) {
            CIRCLEQ_REMOVE(&qkdata_list, cur, lentry);
            free(cur);
        }
        return true;
    }
    warning("0x%lx-0x%lx not found\n", range->start, range->end);

    return false;
}

static void qklist_work(bool (*worker)(void *worker_data,
                                       struct qkdata_list_entry *cur),
                        void *worker_data)
{
    struct qkdata_list_entry *cur;
    struct qkdata_list_entry *nxt;

    for (cur = CIRCLEQ_FIRST(&qkdata_list); cur != (const void *)&qkdata_list;
         cur = nxt) {
        nxt = CIRCLEQ_NEXT(cur, lentry);
        if (worker(worker_data, cur))
            break;
    }
}

#if 0
static bool overlap_range_qkdata(const struct range *a,
                                 const struct zhpeq_key_data *b)
{
    return !(arithcmp(a->end, b->z.vaddr) <= 0 ||
             arithcmp(a->start, b->z.vaddr + b->z.len) >= 0);
}
#endif

struct activate_data {
    struct range        *range;
    bool                activate;
};

static bool activate_worker(void *vadata, struct qkdata_list_entry *cur)
{
    struct activate_data *adata = vadata;
    const struct zhpeq_key_data *qkdata = cur->qkdata;
    int64_t             active;

    if (compare_range_qkdata(adata->range, qkdata))
        return false;

    if (adata->activate)
        active = atm_add(qkdata->active_uptr, 2) + 2;
    else
        active = atm_sub(qkdata->active_uptr, 2) - 2;
    zhpeu_print_info("qkdata 0x%p active %" PRIi64"\n", qkdata, active);

    return true;
}

static bool free_worker(void *dummy, struct qkdata_list_entry *cur)
{
    CIRCLEQ_REMOVE(&qkdata_list, cur, lentry);
    free(cur);
    return false;
}

static void qklist_free(void)
{
    qklist_work(free_worker, NULL);
}

static void gdb_hook(void)
{
    barrier();
}

static void usage(bool help) __attribute__ ((__noreturn__));

static void usage(bool help)
{
    zhpeu_print_usage(
        help,
        "Usage:%s -w <size> [file]\n"
        "Create a region of <size>, aligned to 2MiB and then accepts\n"
        "commands from stdin to test registration logic in low-level\n"
        "library. All numbers may be postfixed with [kmgtKMGT] to specify\n"
        "the base units; lower case is base 10; upper case is base 2.\n"
        "The -w option makes all warnings fatal errors\n"
        "Commands are (<id> is treated as a string):\n"
        "    r <start> <end> : register [start-end) in region\n"
        "    f <start> <end> : free registation\n"
        "    a <start> <end> : activate overlapping registrations\n"
        "    d <start> <end> : deactivate overlapping registrations\n"
        "    u <start> <end> : unmap memory range\n"
        "    b               : breakpoint hook\n",
        zhpeu_appname);

    exit(255);
}

int main(int argc, char **argv)
{
    int                 ret = 255;
    struct zhpeq_dom    *zqdom = NULL;
    char                *map = NULL;
    char                *parsebuf = NULL;
    char                *fname = NULL;
    FILE                *file = stdin;
    bool                echo;
    char                *parseptr;
    char                *cmd;
    struct range        range;
    size_t              map_size;
    char                *buf;
    uint64_t            size;
    struct zhpeq_key_data *qkdata;
    struct activate_data adata;
    int64_t             active;
    int                 rc;
    int                 opt;
    size_t              len;
    char                line[80];

    zhpeu_util_init(argv[0], LOG_DEBUG, false);

    rc = zhpeq_init(ZHPEQ_API_VERSION, NULL);
    if (rc < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_init", "", rc);
        goto done;
    }

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "w")) != -1) {

        switch (opt) {

        case 'w':
            if (warnings_fatal)
                usage(false);
            warnings_fatal = true;
            break;

        default:
            usage(false);

        }
    }

    opt = argc - optind;

    if (opt < 1 || opt > 2)
        usage(false);

    if (zhpeu_parse_kb_uint64_t("size", argv[optind++], &size, 0, 1, SIZE_MAX,
                                PARSE_KIB | PARSE_KB) < 0)
        usage(false);

    ret = 1;

    if (opt > 1) {
        fname = argv[optind]++;
        file = fopen(fname, "r");
        if (!file) {
            ret = -errno;
            zhpeu_print_func_err(__func__, __LINE__, "fopen", fname, rc);
            goto done;
        }
    }
    echo = !isatty(fileno(file));

    rc = zhpeq_domain_alloc(&zqdom);
    if (rc < 0) {
        zhpeu_print_func_err(__func__, __LINE__, "zhpeq_domain_alloc", "", rc);
        goto done;
    }

    ret = zhpeq_feature_enable(ZHPE_FEATURE_MR_OVERLAP_CHECKING);
    if (ret < 0)
        goto done;

    map_size = mask2_up(size, 2 * MiB);
    map = zhpeu_mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (!map)
        goto done;
    buf = TO_PTR(mask2_up((uintptr_t)map, 2 * MiB));

    for (;;) {
        if (!fgets(line, sizeof(line), file)) {
            if (ferror(file)) {
                zhpeu_print_func_err(__func__, __LINE__, "fgets", "", -EIO);
                goto done;
            }
            break;
        }

        free(parsebuf);
        parsebuf = _strdup_or_null(line);
        if (!parsebuf)
            goto done;
        parseptr = parsebuf;
        cmd = strsep(&parseptr, DELIM);
        if (!cmd)
            continue;
        if (echo) {
            len = strlen(line);
            if (line[len - 1] == '\n')
                line[len - 1] = ' ';
            zhpeu_print_info("%s\n", line);
        }
        if (strlen(cmd) != 1) {
            warning("invalid command\n");
            continue;
        }
        if (cmd[0] != 'b' && !parse_range(&parseptr, buf, size, &range)) {
            warning("invalid command\n");
            continue;
        }

        switch (cmd[0]) {

        case 'r':
            rc = zhpeq_mr_reg(zqdom, TO_PTR(range.start),
                              range.end - range.start, ACCESS, &qkdata);
            if (rc < 0) {
                zhpeu_print_func_err(__func__, __LINE__,
                                     "zhpeq_mr_reg", "", rc);
                goto done;
            }
            qklist_insert(qkdata);
            zhpeu_print_info("qkdata 0x%p\n", qkdata);
            break;

        case 'f':
            if (!qklist_find(&range, true, &qkdata))
                break;
            active = atm_load(qkdata->active_uptr);
            zhpeu_print_info("qkdata 0x%p active %" PRIi64"\n",
                             qkdata, active);
            rc = zhpeq_qkdata_free(qkdata);
            if (rc < 0) {
                zhpeu_print_func_err(__func__, __LINE__,
                                     "zhpeq_qkdata_free", "", rc);
                goto done;
            }
            break;

        case 'a':
            adata.range = &range;
            adata.activate = true;
            qklist_work(activate_worker, &adata);
            break;

        case 'd':
            adata.range = &range;
            adata.activate = false;
            qklist_work(activate_worker, &adata);
            break;

        case 'u':
            if (munmap(TO_PTR(range.start), range.end - range.start) == -1) {
                rc = -errno;
                zhpeu_print_func_err(__func__, __LINE__, "munmap", "", rc);
                goto done;
            }
            break;

        case 'b':
            gdb_hook();
            break;

        default:
            warning("invalid command\n");
            break;
        }
    }
    ret = 0;

 done:
    if (file != stdin)
        fclose(file);
    free(parsebuf);
    qklist_free();
    /* We very specificly do not free any qkdatas to test the driver. */
    if (map)
        munmap(map, map_size);
    zhpeq_domain_free(zqdom);

    return ret;
}
