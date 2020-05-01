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

#define _GNU_SOURCE

#include <zhpeq_util.h>

#include <libgen.h>

const char              *zhpeu_appname;

static bool             log_syslog;
static bool             log_syslog_init;
static int              log_level = LOG_ERR;

static uint64_t get_clock_cycles(volatile uint32_t *cpup);
static uint64_t get_tsc_cycles(volatile uint32_t *cpup);
static void do_init_time_cpuinfo(struct zhpeu_init_time *init_time);

static const char *cpuinfo_delim = " \t\n";

struct zhpeu_init_time  *zhpeu_init_time;
static struct zhpeu_init_time  init_time;

static __int128                 atm_dummy;

static void __attribute__((constructor)) lib_init(void)
{
    __int128            old;
    __int128            new;
    long                rcl;
    struct zhpeu_init_time *oldi;

    /*
     * Run only once and force __atomic_load_16 and
     * __atomic_compare_exchange_16 to be linked.
     */
    old = atm_load_rlx(&atm_dummy);
    new = old + 1;
    atm_cmpxchg(&atm_dummy, &old, new);
    if (old) {
        /* Wait for global initialization to complete. */
        while (!atm_load_rlx(&zhpeu_init_time))
            yield();
        return;
    }

    /* Make sure page_size is set before use; if we can't get it, just die. */
    rcl = sysconf(_SC_PAGESIZE);
    if (rcl == -1)
        abort();
    init_time.pagesz = rcl;
    do_init_time_cpuinfo(&init_time);

    oldi = NULL;
    atm_cmpxchg(&zhpeu_init_time, &oldi, &init_time);
}

void zhpeu_util_init(char *argv0, int default_log_level, bool use_syslog)
{
    /* Allow to be called multiple times for testing. */
    zhpeu_appname = basename(argv0);
    log_level  = default_log_level;
    log_syslog = use_syslog;
    if (log_syslog && !log_syslog_init) {
        log_syslog_init = true;
        openlog(zhpeu_appname, LOG_PID | LOG_PERROR, LOG_DAEMON);
    }
}

static void vlog(int priority, FILE *file, const char *prefix,
                 const char *fmt, va_list ap)
{
    if (priority > log_level)
        return;

    if (log_syslog)
        vsyslog(priority, fmt, ap);
    else {
        if (prefix)
            fprintf(file, "%s[%d]: ", prefix, getpid());
        vfprintf(file, fmt, ap);
        if (fmt[strlen(fmt) - 1] != '\n')
            fprintf(file, "\n");
    }
}

void zhpeu_print_dbg(const char *fmt, ...)
{
    va_list             ap;

    va_start(ap, fmt);
    vlog(LOG_DEBUG, stdout, zhpeu_appname, fmt, ap);
    va_end(ap);
}

void zhpeu_print_info(const char *fmt, ...)
{
    va_list             ap;

    va_start(ap, fmt);
    vlog(LOG_INFO, stdout, zhpeu_appname, fmt, ap);
    va_end(ap);
}

void zhpeu_print_err(const char *fmt, ...)
{
    va_list             ap;

    va_start(ap, fmt);
    vlog(LOG_ERR, stderr, zhpeu_appname, fmt, ap);
    va_end(ap);
}

void zhpeu_print_usage(bool use_stdout, const char *fmt, ...)
{
    va_list             ap;

    va_start(ap, fmt);
    vlog(LOG_ERR, (use_stdout ? stdout : stderr), NULL, fmt, ap);
    va_end(ap);
}

void zhpeu_print_func_err(const char *callf, uint line, const char *errf,
                          const char *arg, int err)
{
    if (err < 0)
        err = -err;

    zhpeu_print_err("%s,%u:%s(%s) returned error %d:%s\n",
                    callf, line, errf, arg, err, strerror(err));
}

void zhpeu_print_func_errn(const char *callf, uint line, const char *errf,
                           llong arg, bool arg_hex, int err)
{
    if (arg_hex)
        zhpeu_print_err("%s,%u:%s(0x%Lx) returned error %d:%s\n",
                        callf, line, errf, arg, err, strerror(err));
   else
        zhpeu_print_err("%s,%u:%s(0x%Ld) returned error %d:%s\n",
                        callf, line, errf, arg, err, strerror(err));
}

void zhpeu_print_range_err(const char *callf, uint line, const char *name,
                           int64_t val, int64_t min, int64_t max)
{
    zhpeu_print_err("%s,%u:%s = %Ld: out of range %Ld - %Ld\n",
                    callf, line, name, (llong)val, (llong)min, (llong)max);
}

void zhpeu_print_urange_err(const char *callf, uint line, const char *name,
                             uint64_t val, uint64_t min, uint64_t max)
{
    zhpeu_print_err("%s,%u:%s = %Lu: out of range %Lu - %Lu\n",
                    callf, line, name, (ullong)val, (ullong)min, (ullong)max);
}

char *zhpeu_get_cpuinfo_val(FILE *fp, char *buf, size_t buf_size,
                            uint field, const char *name, ...)
{
    char                *ret = NULL;
    bool                first = true;
    char                *tok;
    char                *save;
    va_list             ap;
    char                *next;

    rewind(fp);

    for (;;) {
        if (!fgets(buf, buf_size, fp))
            goto done;
        save = buf;
        tok = strsep(&save, cpuinfo_delim);
        if (!tok)
            continue;
        if (!first && !strcmp(tok, "processor"))
            break;
        first = false;
        if (!tok || strcmp(tok, name))
            continue;

        va_start(ap, name);
        while ((next = va_arg(ap, char *))) {
            tok = strsep(&save, cpuinfo_delim);
            if (!tok || strcmp(tok, next))
                break;
        }
        va_end(ap);
        if (next)
            continue;
        while ((tok = strsep(&save, cpuinfo_delim))) {
            if (!strcmp(tok, ":"))
                break;
        }
        if (!tok)
            continue;
        tok = save;
        for (; tok && field > 0; field--)
            tok = strsep(&save, cpuinfo_delim);
        if (!tok)
            break;
        ret = tok;
        break;
    }

 done:
    if (!ret)
        errno = ENOENT;

    return ret;
}

#if defined(__x86_32__) || defined( __x86_64__)

static void x86_clflush_range(const void *addr, size_t len,  bool fence)
{
    const char          *p =
        (const char *)((uintptr_t)addr & ~(zhpeu_init_time->l1sz - 1));
    const char          *e = (const char *)addr + len;

    if (fence)
        io_wmb();
    for (; p < e; p += zhpeu_init_time->l1sz)
        _mm_clflush(p);
}

static void x86_clflushopt_range(const void *addr, size_t len, bool fence)
{
    const char          *p =
        (const char *)((uintptr_t)addr & ~(zhpeu_init_time->l1sz - 1));
    const char          *e = (const char *)addr + len;

    if (fence)
        io_wmb();
    for (; p < e; p += zhpeu_init_time->l1sz)
        _mm_clflushopt((void *)p);
}

static void x86_clwb_range(const void *addr, size_t len, bool fence)
{
    const char          *p =
        (const char *)((uintptr_t)addr & ~(zhpeu_init_time->l1sz - 1));
    const char          *e = (const char *)addr + len;

    if (fence)
        io_wmb();
    for (; p < e; p += zhpeu_init_time->l1sz)
        _mm_clwb((void *)p);
}

#endif

static void do_init_time_cpuinfo(struct zhpeu_init_time *init_time)
{
    FILE                *fp = NULL;
    const char          *fname_info = "/proc/cpuinfo";
    const char          *fname_freq =
        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq";
    bool                intel = false;
    const char          *fname;
    char                buf[1024];
    char                *sval;
    char                *tok;
    char                *endp;
    uint64_t            val1;
    uint64_t            val2;
    uint                i;

    /* Assume we use system clock and clflush */
    init_time->clflush_range = x86_clflush_range;
    init_time->clwb_range = x86_clflush_range;
    init_time->l1sz = L1_CACHE_BYTES;
    init_time->get_cycles = get_clock_cycles;
    init_time->freq = NSEC_PER_SEC;

    /*
     * Now, try to find something better. If something goes wrong, try
     * to fail in a forgiving manner.
     */
    fname = fname_info;
    fp = fopen(fname, "r");
    if (!fp) {
        zhpeu_print_func_err(__func__, __LINE__, "fopen", fname, errno);
        goto done;
    }
    sval = _zhpeu_get_cpuinfo_val(fp, buf, sizeof(buf), 1, "vendor_id", NULL);
    if (!sval)
        goto done;
    intel = !strcmp(sval, "GenuineIntel");

    /* Search for flags we care about. */
    sval = _zhpeu_get_cpuinfo_val(fp, buf, sizeof(buf), 0, "flags", NULL);
    if (!sval)
        goto done;
    i = 0;
    while ((tok = strsep(&sval, cpuinfo_delim))) {
        if (!strcmp(tok, "constant_tsc"))
            i |= 0x01;
        if (!strcmp(tok, "nonstop_tsc"))
            i |= 0x02;
        if (!strcmp(tok, "clflushopt"))
            i |= 0x04;
        if (!strcmp(tok, "clwb"))
            i |= 0x08;
        if (i == 0x0F)
            break;
    }

    /* Update flush routines with flag info. */
    if (i & 0x04) {
        init_time->clflush_range = x86_clflushopt_range;
        init_time->clwb_range = x86_clflushopt_range;
    }
    if (i & 0x08)
        init_time->clwb_range = x86_clwb_range;
    /* clflush_size is documented to be cache line size */
    sval = zhpeu_get_cpuinfo_val(fp, buf, sizeof(buf), 0, "clflush_size", NULL);
    if (sval) {
        errno = 0;
        val1 = strtoull(sval, &endp, 0);
        if (!errno && !*endp)
            init_time->l1sz = val1;
    }

    /* CPU support for TSC timekeeping? */
    if ((i & 0x03) != 0x03) {
        /* No. */
        if (zhpeu_is_sim())
            /* Carbon: use rdtsc, assume the frequency is 1GHz. */
            init_time->get_cycles = get_tsc_cycles;
        goto done;
    }

    /*
     * Once we know nonstop_tsc exists, we could measure the frequency,
     * but I don't want to slow down application launch to
     * measure it. Measure it once, perhaps, at package install? Not today.
     *
     * For Intel, the TSC seems to use the listed frequency for the CPU.
     * On real hardware, the /proc/cpuinfo "model name" gives you 3 digit
     * accuracy and /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq,
     * if available, gives you at least 4, it seems.
     */
    tok = NULL;
    if (intel) {
        sval = _zhpeu_get_cpuinfo_val(fp, buf, sizeof(buf), 0,
                                      "model", "name", NULL);
        if (!sval)
            goto done;
        while ((tok = strsep(&sval, cpuinfo_delim))) {
            if (strcmp(tok, "@"))
                continue;
            tok = strsep(&sval, cpuinfo_delim);
            break;
        }
    }
    if (tok) {
        errno = 0;
        val1 = strtoull(tok, &endp, 0);
        if (errno)
            goto done;
        if (*endp != '.')
            goto done;
        tok = ++endp;
        val2 = strtoull(tok, &endp, 0);
        if (errno)
            goto done;
        if (strcmp(endp, "GHz"))
            goto done;
        for (i = endp - tok; i > 0; i--)
            val1 *= 10;
        val1 += val2;
        for (i = 9 - (endp - tok); i > 0; i--)
            val1 *= 10;
        init_time->get_cycles = get_tsc_cycles;
        init_time->freq = val1;
    }
    fclose(fp);

    fname = fname_freq;
    fp = fopen(fname, "r");
    if (fp) {
        if (!fgets(buf, sizeof(buf), fp))
            goto done;
        sval = buf;
        tok = strsep(&sval, cpuinfo_delim);
        if (!tok || *sval != '\0')
            goto done;
        errno = 0;
        val1 = strtoull(tok, &endp, 0) * 1000;
        if (errno || *endp != '\0')
            goto done;
        init_time->get_cycles = get_tsc_cycles;
        init_time->freq = val1;
    } else if (!fp) {
        if (errno != ENOENT) {
            zhpeu_print_func_err(__func__, __LINE__, "fopen", fname, errno);
            goto done;
        }
    }

done:
    if (fp) {
        if (ferror(fp))
            zhpeu_print_err("%s,%u:Error reading %s\n",
                            __func__, __LINE__, fname);
        fclose(fp);
    }
}

static uint64_t get_clock_cycles(volatile uint32_t *cpup)
{
    struct timespec     now;

    /* CPU not supported. */
    if (cpup)
        *cpup = ~(uint32_t)0;

    clock_gettime_monotonic(&now);

    return((uint64_t)now.tv_sec * NSEC_PER_SEC + now.tv_nsec);
}

int zhpeu_parse_kb_uint64_t(const char *name, const char *sp, uint64_t *val,
                            int base, uint64_t min, uint64_t max, int flags)
{
    int                 ret = -EINVAL;
    char                *ep;

    errno = 0;
    *val = strtoull(sp, &ep, base);
    if (errno) {
        ret = errno;
        zhpeu_print_err("%s,%u:Could not parse %s = %s as a number at"
                        " offset %u, char %c, errno %d:%s\n",
                        __func__, __LINE__, name, sp, (uint)(ep - sp), *ep,
                        ret, strerror(ret));
        ret = -ret;
        goto done;
    }

    switch (*ep) {

    case '\0':
        break;

    case 'T':
        *val *= 1024;

    case 'G':
        *val *= 1024;

    case 'M':
        *val *= 1024;

    case 'K':
        *val *= 1024;
        if (!(flags & PARSE_KIB)) {
            zhpeu_print_err("%s,%u:KiB units not permitted for %s = %s at"
                            " offset %u, char %c\n",
                            __func__, __LINE__, name, sp, (uint)(ep - sp), *ep);
            goto done;
        }
        ep++;
        if (!*ep)
            break;

    case 't':
        *val *= 1000;

    case 'g':
        *val *= 1000;

    case 'm':
        *val *= 1000;

    case 'k':
        *val *= 1000;
        if (!(flags & PARSE_KB)) {
            zhpeu_print_err("%s,%u:KB units not permitted for %s = %s at"
                            " offset %u, char %c\n",
                            __func__, __LINE__, name, sp, (uint)(ep - sp), *ep);
            goto done;
        }
        ep++;
        if (!*ep)
            break;

    default:
        zhpeu_print_err("%s,%u:Could not parse units for %s = %s at"
                        " offset %u, char %c\n",
                        __func__, __LINE__, name, sp, (uint)(ep - sp), *ep);
        goto done;
    }

    if (*val < min || *val > max) {
        zhpeu_print_urange_err(__func__, __LINE__, name, *val, min, max);
        ret  = -ERANGE;
        goto done;
    }

    ret = 0;

 done:
    return ret;
}

int zhpeu_check_func_io(const char *callf, uint line, const char *errf,
                        const char *arg, size_t req, ssize_t res, int flags)
{
    int                 ret = 0;

    if (res == -1) {
        ret = -errno;
        if (ret == -EAGAIN && (flags & CHECK_EAGAIN_OK))
            goto done;
        zhpeu_print_func_err(callf, line, errf, arg, ret);
    } else if (req > (size_t)res) {
        if (flags & CHECK_SHORT_IO_OK)
            goto done;
        ret = -EIO;
        zhpeu_print_err("%s,%u:%s(%s) %Ld of %Lu bytes\n",
                        callf, line, errf, arg, (llong)res, (ullong)req);
    }

 done:
    return ret;
}

int zhpeu_check_func_ion(const char *callf, uint line, const char *errf,
                         long arg, bool arg_hex, size_t req, ssize_t res,
                         int flags)
{
    int                 ret = 0;

    if (res == -1) {
        ret = -errno;
        if (ret == -EAGAIN && (flags & CHECK_EAGAIN_OK))
            goto done;
        zhpeu_print_func_errn(callf, line, errf, arg, arg_hex, ret);
    } else if (req > (size_t)res) {
        if (flags & CHECK_SHORT_IO_OK)
            goto done;
        ret = -EIO;
        zhpeu_print_err("%s,%u:%s(%ld) %Ld of %Lu bytes\n",
                        callf, line, errf, arg, (llong)res, (ullong)req);
    }

 done:
    return ret;
}

int zhpeu_sock_getaddrinfo(const char *node, const char *service,
                           int family, int socktype, bool passive,
                           struct addrinfo **res)
{
    int                 ret = 0;
    struct addrinfo     hints;
    int                 rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = (passive ? AI_PASSIVE : 0);
    hints.ai_family = family;
    hints.ai_socktype = socktype;

    rc = getaddrinfo(node, service, &hints, res);
    if (rc) {
        if (rc == EAI_SYSTEM)
            ret = -errno;
    }

    switch (rc) {

    case 0:
    case EAI_SYSTEM:
        break;

    case EAI_ADDRFAMILY:
    case EAI_NODATA:
    case EAI_NONAME:
    case EAI_SERVICE:
        ret = -ENOENT;
        break;

    case EAI_AGAIN:
        ret = -EAGAIN;
        break;

    case EAI_FAIL:
        ret = -EIO;
        break;

    case EAI_MEMORY:
        ret = -ENOMEM;
        break;

        ret = -errno;
        break;

    default:
        ret = -EINVAL;
        break;

    }

    if (ret < 0)
        zhpeu_print_err("%s,%u:getaddrinfo(%s,%s) returned gai %d:%s,\n"
                        "    errno %d:%s\n",
                        __func__, __LINE__, node ?: "", service ?: "",
                        rc, gai_strerror(rc), -ret, strerror(-ret));

    if (ret < 0)
        *res = NULL;

    return ret;
}

int zhpeu_sock_connect(const char *node, const char *service)
{
    int                 ret;
    struct addrinfo     *resp = NULL;

    ret = _zhpeu_sock_getaddrinfo(node, service, AF_UNSPEC, SOCK_STREAM,
                                  false, &resp);
    if (ret < 0)
        goto done;
    ret = socket(resp->ai_family, resp->ai_socktype, resp->ai_protocol);
    if (ret == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "socket", "", ret);
        goto done;
    }
    if (connect(ret, resp->ai_addr, resp->ai_addrlen) == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "connect", "", ret);
        goto done;
    }

done:
    return ret;
}

void zhpeu_random_seed(uint seed)
{
    srandom(seed);
}

/* [start, end] */
uint zhpeu_random_range(uint start, uint end)
{
    const uint64_t      rand_max = (uint64_t)RAND_MAX + 1;
    uint64_t            range;

    /* Handle [0, UINT_MAX] */
    range = end;
    range -= start;
    range += 1;

    return (range * random()) / rand_max + start;
}

uint *zhpeu_random_array(uint *array, uint entries)
{
    uint                *ret = array;
    size_t              i;
    size_t              t;
    ulong               tv;

    /* Generate a shuffled array of indices from 0 to entries - 1. */
    for (i = 0; i < entries; i++)
        ret[i] = i;
    for (i = entries; i > 0;) {
        i--;
        t = zhpeu_random_range(0, i);
        tv = ret[t];
        ret[t] = ret[i];
        ret[i] = tv;
    }

    return ret;
}

int zhpeu_sock_getsockname(int sock_fd, union sockaddr_in46 *sa)
{
    int                 ret = 0;
    socklen_t           addr_len;

    addr_len = sizeof(*sa);
    if (getsockname(sock_fd, (void *)sa, &addr_len) == -1)
        ret = -errno;
    else if (!zhpeu_sockaddr_valid(sa, addr_len, true))
        ret = -EAFNOSUPPORT;
    if (ret < 0)
        zhpeu_print_func_err(__func__, __LINE__, "getsockname", "", ret);

    return ret;
}

int zhpeu_sock_getpeername(int sock_fd, union sockaddr_in46 *sa)
{
    int                 ret = 0;
    socklen_t           addr_len;

    addr_len = sizeof(*sa);
    if (getpeername(sock_fd, (void *)sa, &addr_len) == -1)
        ret = -errno;
    else if (!zhpeu_sockaddr_valid(sa, addr_len, true))
        ret = -EAFNOSUPPORT;
    if (ret < 0)
        zhpeu_print_func_err(__func__, __LINE__, "getpeername", "", ret);

    return ret;
}

int zhpeu_sock_send_blob(int fd, const void *blob, size_t blob_len)
{
    int                 ret = -EINVAL;
    uint32_t            wlen = blob_len;
    size_t              req;
    ssize_t             res;

    if (!blob) {
        blob_len = 0;
        wlen = UINT32_MAX;
    } else if (blob_len >= UINT32_MAX)
        goto done;
    wlen = htonl(wlen);
    req = sizeof(wlen);
    res = write(fd, &wlen, req);
    ret = zhpeu_check_func_io(__func__, __LINE__, "write", "", req, res, 0);
    if (ret < 0)
        goto done;
    req = blob_len;
    if (!req)
        goto done;
    res = write(fd, blob, req);
    ret = zhpeu_check_func_io(__func__, __LINE__, "write", "", req, res, 0);

 done:
    return ret;
}

int zhpeu_sock_recv_fixed_blob(int sock_fd, void *blob, size_t blob_len)
{
    int                 ret;
    uint32_t            wlen;
    size_t              req;
    ssize_t             res;

    req = sizeof(wlen);
    res = read(sock_fd, &wlen, req);
    ret = zhpeu_check_func_io(__func__, __LINE__, "read", "", req, res, 0);
    if (ret < 0)
        goto done;
    req = ntohl(wlen);
    if (!blob_len && req == UINT32_MAX)
        req = 0;
    if (!zhpeu_expected_saw("wire len", blob_len, req)) {
        ret = -EINVAL;
        goto done;
    }
    if (!req)
        goto done;
    res = read(sock_fd, blob, req);
    ret = zhpeu_check_func_io(__func__, __LINE__, "read", "", req, res, 0);

 done:
    return ret;
}

int zhpeu_sock_recv_var_blob(int sock_fd, size_t extra_len,
                              void **blob, size_t *blob_len)
{
    int                 ret;
    uint32_t            wlen;
    size_t              req;
    ssize_t             res;

    *blob = NULL;
    *blob_len = 0;
    req = sizeof(wlen);
    res = read(sock_fd, &wlen, req);
    ret = zhpeu_check_func_io(__func__, __LINE__, "read", "", req, res, 0);
    if (ret < 0)
        goto done;
    req = ntohl(wlen);
    if (req == UINT32_MAX)
        goto done;
    *blob_len = req;
    *blob = malloc(req + extra_len);
    if (!*blob) {
        ret = -errno;
        goto done;
    }
    if (req) {
        res = read(sock_fd, *blob, req);
        ret = zhpeu_check_func_io(__func__, __LINE__, "read", "", req, res, 0);
        if (ret < 0)
            goto done;
    }
    memset((char *)*blob + req, 0, extra_len);

 done:
    if (ret < 0) {
        free(*blob);
        *blob = NULL;
    }

    return ret;
}

int zhpeu_sock_send_string(int fd, const char *s)
{
    return zhpeu_sock_send_blob(fd, s, (s ? strlen(s) : 0));
}

int zhpeu_sock_recv_string(int fd, char **s)
{
    int                 ret;
    void                *blob;
    size_t              blob_len;

    ret = zhpeu_sock_recv_var_blob(fd, 1, &blob, &blob_len);
    *s = blob;

    return ret;
}

static int sockaddr_cmpx(const union sockaddr_in46 *sa1,
                         const union sockaddr_in46 *sa2)
{
    int                 ret;
    union sockaddr_in46 local1;
    union sockaddr_in46 local2;

    /* We should only be called if family1 != family2 */
    switch (sa1->sa_family) {

    case AF_INET:
        memcpy(&local1, sa1, sizeof(struct sockaddr_in));
        break;

    case AF_INET6:
        memcpy(&local1, sa1, sizeof(struct sockaddr_in6));
        zhpeu_sockaddr_6to4(&local1);
        if (local1.sa_family == AF_INET)
            break;

    default:
        ret = arithcmp(sa1->sa_family, sa2->sa_family);
        goto done;

    }

    switch (sa2->sa_family) {

    case AF_INET:
        memcpy(&local2, sa2, sizeof(struct sockaddr_in));
        break;

    case AF_INET6:
        memcpy(&local2, sa2, sizeof(struct sockaddr_in6));
        zhpeu_sockaddr_6to4(&local2);
        if (local2.sa_family == AF_INET)
            break;

    default:
        ret = arithcmp(sa1->sa_family, sa2->sa_family);
        goto done;

    }

    /* We'll only get here if both addresses can be "reduced" to IPv4. */
    ret = arithcmp(local1.addr4.sin_addr.s_addr, local2.addr4.sin_addr.s_addr);
    if (ret)
        goto done;
    ret = arithcmp(ntohs(local1.sin_port), ntohs(local2.sin_port));

 done:
    return ret;
}

uint32_t zhpeu_sockaddr_porth(const void *addr)
{
    const union sockaddr_in46 *sa = addr;

    switch (sa->sa_family) {

    case AF_INET:
    case AF_INET6:
        return ntohs(sa->sin_port);

    case AF_ZHPE:
        return ntohl(sa->zhpe.sz_queue);

    default:
        abort();
    }
}

size_t zhpeu_sockaddr_len(const void *addr)
{
    const union sockaddr_in46 *sa = addr;

    switch (sa->sa_family) {

    case AF_INET:
        return sizeof(struct sockaddr_in);

    case AF_INET6:
        return sizeof(struct sockaddr_in6);

    case AF_ZHPE:
        return sizeof(struct sockaddr_zhpe);

    default:
        return 0;
    }
}

bool zhpeu_sockaddr_valid(const void *addr, size_t addr_len,
                          bool check_len)
{
    size_t              len = zhpeu_sockaddr_len(addr);

    if (!len)
        return false;

    return (!check_len || addr_len >= len);
}

void zhpeu_sockaddr_cpy(union sockaddr_in46 *dst, const void *src)
{
    memcpy(dst, src, zhpeu_sockaddr_len(src));
}

void *zhpeu_sockaddr_dup(const void *addr)
{
    void                *ret = NULL;
    size_t              addr_len = zhpeu_sockaddr_len(addr);

    if (addr_len) {
        ret = malloc(addr_len);
        if (ret)
            memcpy(ret, addr, addr_len);
    }

    return ret;
}

uint32_t zhpeu_uuid_to_gcid(const uuid_t uuid)
{
    return (uuid[0] << 20) | (uuid[1] << 12) | (uuid[2] << 4) | (uuid[3]  >> 4);
}

void zhpeu_install_gcid_in_uuid(uuid_t uuid, uint32_t gcid)
{
    uuid[0] = gcid >> 20;
    uuid[1] = gcid >> 12;
    uuid[2] = gcid >> 4;
    uuid[3] &= 0xF;
    uuid[3] |= gcid << 4;
}

bool zhpeu_uuid_gcid_only(const uuid_t uuid)
{
    uint                i;
    uuid_t              uuid_x;

    if (uuid[3] & 0xF)
        return false;
    for (i = 4; i < ARRAY_SIZE(uuid_x); i++) {
        if (uuid[i])
            return false;
    }

    return true;
}

int zhpeu_sockaddr_portcmp(const void *addr1, const void *addr2)
{
    int                 ret;
    const union sockaddr_in46 *sa1 = addr1;
    const union sockaddr_in46 *sa2 = addr2;

    assert(sa1->sa_family == sa2->sa_family);

    switch (sa1->sa_family) {

    case AF_INET:
    case AF_INET6:
        ret = arithcmp(ntohs(sa1->sin_port), ntohs(sa2->sin_port));
        break;

    case AF_ZHPE:
        ret = arithcmp(ntohl(sa1->zhpe.sz_queue), ntohl(sa2->zhpe.sz_queue));
        break;

    default:
        abort();
    }

    return ret;
}

int zhpeu_sockaddr_cmp(const void *addr1, const void *addr2, uint flags)
{
    int                 ret;
    const union sockaddr_in46 *sa1 = addr1;
    const union sockaddr_in46 *sa2 = addr2;
    uint32_t            gcid1;
    uint32_t            gcid2;

    if (sa1->sa_family != sa2->sa_family) {
        ret = sockaddr_cmpx(sa1, sa2);
        goto done;
    }

    switch (sa1->sa_family) {

    case AF_INET:
        if (!(flags & ZHPEU_SACMP_PORT_ONLY))
            ret = arithcmp(sa1->addr4.sin_addr.s_addr,
                           sa2->addr4.sin_addr.s_addr);
        else
            ret = 0;
        if (ret)
            goto done;
        if (!(flags & ZHPEU_SACMP_ADDR_ONLY))
            ret = arithcmp(ntohs(sa1->sin_port), ntohs(sa2->sin_port));
        break;

    case AF_INET6:
        /* Use memcmp for -1, 0, 1 behavior. */
        if (!(flags & ZHPEU_SACMP_PORT_ONLY))
            ret = memcmp(&sa1->addr6.sin6_addr, &sa2->addr6.sin6_addr,
                         sizeof(sa1->addr6.sin6_addr));
        else
            ret = 0;
        if (ret)
            goto done;
        if (!(flags & ZHPEU_SACMP_ADDR_ONLY))
            ret = arithcmp(ntohs(sa1->sin_port), ntohs(sa2->sin_port));
        break;

    case AF_ZHPE:
        if (!(flags & ZHPEU_SACMP_PORT_ONLY)) {
            gcid1 = zhpeu_uuid_to_gcid(sa1->zhpe.sz_uuid);
            gcid2 = zhpeu_uuid_to_gcid(sa2->zhpe.sz_uuid);
            ret = arithcmp(gcid1, gcid2);
        }
        else
            ret = 0;
        if (ret)
            goto done;
        if (!(flags & ZHPEU_SACMP_ADDR_ONLY))
            ret = arithcmp(ntohl(sa1->zhpe.sz_queue),
                           ntohl(sa2->zhpe.sz_queue));
        break;

    default:
        abort();
    }

 done:
    return ret;
}

bool zhpeu_sockaddr_inet(const void *addr)
{
    const union sockaddr_in46 *sa = addr;

    switch (sa->sa_family) {

    case AF_INET:
    case AF_INET6:
        return true;

    default:
        return false;
    }
}

static inline bool sockaddr_wildcard6(const struct sockaddr_in6 *sa)
{
    return !memcmp(&sa->sin6_addr, &in6addr_any, sizeof(sa->sin6_addr));
}

bool zhpeu_sockaddr_wildcard(const void *addr)
{
    bool                ret = false;
    const union sockaddr_in46 *sa = addr;

    switch (sa->sa_family) {

    case AF_INET:
        ret = (sa->addr4.sin_addr.s_addr == htonl(INADDR_ANY));
        break;

    case AF_INET6:
        ret = sockaddr_wildcard6(&sa->addr6);
        break;

    default:
        break;
    }

    return ret;
}

static inline bool sockaddr_loopback6(const struct sockaddr_in6 *sa)
{
    return !memcmp(&sa->sin6_addr, &in6addr_loopback, sizeof(sa->sin6_addr));
}

bool zhpeu_sockaddr_loopback(const void *addr, bool loopany)
{
    bool                ret = false;
    const union sockaddr_in46 *sa = addr;
    uint32_t            netmask;

    switch (sa->sa_family) {

    case AF_INET:
        netmask = (loopany ? IN_CLASSA_NET : ~(uint32_t)0);
        ret = ((ntohl(sa->addr4.sin_addr.s_addr) & netmask) ==
               (INADDR_LOOPBACK & netmask));
        break;

    case AF_INET6:
        ret = sockaddr_loopback6(&sa->addr6);
        break;

    default:
        break;
    }

    return ret;
}

void zhpeu_sockaddr_6to4(void *addr)
{
    union sockaddr_in46 *sa = addr;
    uint                i;
    uchar               *cp;

    if (sa->sa_family != AF_INET6)
        goto done;
    if (sockaddr_wildcard6(&sa->addr6))
        sa->addr4.sin_addr.s_addr = htonl(INADDR_ANY);
    else if (sockaddr_loopback6(&sa->addr6))
        sa->addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    else {
        /* IPV4 mapped: ten bytes of zero followed by 2 bytes of 0xFF? */
        for (i = 0, cp = sa->addr6.sin6_addr.s6_addr; i < 10; i++, cp++) {
            if (*cp)
                goto done;
        }
        for (i = 0; i < 2; i++, cp++) {
            if (*cp != 0xFF)
                goto done;
        }
        memmove(&sa->addr4.sin_addr, cp, sizeof(sa->addr4.sin_addr));
    }
    sa->sa_family = AF_INET;

 done:
    return;
}

const char *zhpeu_sockaddr_ntop(const void *addr, char *buf, size_t len)
{
    const char          *ret = NULL;
    const union sockaddr_in46 *sa = addr;

    if (!buf) {
        errno = EFAULT;
        goto done;
    }
    errno = 0;

    switch (sa->sa_family) {

    case AF_INET:
        ret = inet_ntop(AF_INET, &sa->addr4.sin_addr, buf, len);
        break;

    case AF_INET6:
        ret = inet_ntop(AF_INET6, &sa->addr6.sin6_addr, buf, len);
        break;

    case AF_ZHPE:
        if (len < ZHPE_ADDRSTRLEN) {
            errno = ENOSPC;
            break;
        }
        uuid_unparse_upper(sa->zhpe.sz_uuid, buf);
        ret = buf;
        break;

    default:
        errno = EAFNOSUPPORT;
        break;
    }

 done:
    if (!ret && len > 0)
        buf[0] = '\0';

    return ret;
}

char *zhpeu_sockaddr_str(const void *addr)
{
    char                *ret = NULL;
    const union sockaddr_in46 *sa = addr;
    const char          ipv6_dual_pre[] = "::ffff:";
    const size_t        ipv6_dual_pre_len = sizeof(ipv6_dual_pre) - 1;
    size_t              len;
    const char          *family;
    uint32_t            port;
    char                ntop[INET6_ADDRSTRLEN];

    if (!zhpeu_sockaddr_ntop(addr, ntop, sizeof(ntop)))
        goto done;

    switch (sa->sa_family) {

    case AF_INET:
        family = "ipv4";
        port = ntohs(sa->sin_port);
        break;

    case AF_INET6:
        family = "ipv6";
        port = ntohs(sa->sin_port);
        /* ipv6 dual output causes attempts to connect as ipv6 */
        len = strlen(ntop);
        if (len > ipv6_dual_pre_len &&
            !strncmp(ntop, ipv6_dual_pre, ipv6_dual_pre_len) &&
            !strchr(ntop + ipv6_dual_pre_len, ':'))
            memmove(ntop, ntop + ipv6_dual_pre_len,
                    len - ipv6_dual_pre_len + 1);
        break;

    case AF_ZHPE:
        family = "zhpe";
        port = htonl(sa->zhpe.sz_queue);
        break;

    default:
        abort();
    }

    xasprintf(&ret, "%s:%s:%u", family, ntop, port);

done:
    return ret;
}

int zhpeu_munmap(void *addr, size_t length)
{
    int                 ret = 0;

    if (!addr)
        return 0;

    if (munmap(addr, length) == -1) {
        ret = -errno;
        zhpeu_print_func_err(__func__, __LINE__, "munmap", "", ret);
    }

    return ret;
}

void *zhpeu_mmap(void *addr, size_t length, int prot, int flags,
                 int fd, off_t offset)
{
    void                *ret;

    ret = mmap(addr, length, prot, flags, fd, offset);
    if (ret == MAP_FAILED)
        ret = NULL;

    return ret;
}

char *zhpeu_tm_to_str(char *str, size_t max_len, struct tm *tm, uint nsec)
{
    char                fmt_buf[32];
    char                time_buf[ZHPEU_TM_STR_LEN];

    if (!max_len)
        return str;

    /* XXXX-XX-XXTXX:XX:XX.XXXXXXXXX+XXXX, 35 bytes w/null */
    snprintf(fmt_buf, sizeof(fmt_buf), "%s.%09u%s", "%FT%H:%M:%S", nsec, "%z");
    strftime(time_buf, sizeof(time_buf), fmt_buf, tm);
    time_buf[sizeof(time_buf) - 1] = '\0';
    strncpy(str, time_buf, max_len);
    str[max_len - 1] = '\0';

    return str;
}

static bool thr_wait_signal_atomic_fast(struct zhpeu_thr_wait *thr_wait)
{
    int32_t             old = ZHPEU_THR_WAIT_IDLE;
    int32_t             new = ZHPEU_THR_WAIT_SIGNAL;

    /* One sleeper, many wakers. */
    if (atm_cmpxchg(&thr_wait->state, &old, new) || old == new)
        /* Done! */
        return false;

    /* Need slow path. */
    assert(old == ZHPEU_THR_WAIT_SLEEP);

    return true;
}

static void thr_wait_signal_atomic_slow(struct zhpeu_thr_wait *thr_wait,
                                        bool lock, bool unlock);

void zhpeu_thr_wait_signal_init(
    struct zhpeu_thr_wait *thr_wait,
    bool (*signal_fast)(struct zhpeu_thr_wait *thr_wait),
    void (*signal_slow)(struct zhpeu_thr_wait *thr_wait,
                        bool lock, bool unlock))
{
    memset(thr_wait, 0, sizeof(*thr_wait));
    mutex_init(&thr_wait->mutex, NULL);
    cond_init(&thr_wait->cond, NULL);
    thr_wait->signal_fast = signal_fast;
    thr_wait->signal_slow = signal_slow;
    atm_store_rlx(&thr_wait->state, ZHPEU_THR_WAIT_IDLE);
}

void zhpeu_thr_wait_init(struct zhpeu_thr_wait *thr_wait)
{
    zhpeu_thr_wait_signal_init(thr_wait, thr_wait_signal_atomic_fast,
                               thr_wait_signal_atomic_slow);
}

void zhpeu_thr_wait_destroy(struct zhpeu_thr_wait *thr_wait)
{
    mutex_destroy(&thr_wait->mutex);
    cond_destroy(&thr_wait->cond);
}

static void thr_wait_signal_atomic_slow(struct zhpeu_thr_wait *thr_wait,
                                        bool lock, bool unlock)
{
    int32_t             old = ZHPEU_THR_WAIT_SLEEP;
    int32_t             new = ZHPEU_THR_WAIT_IDLE;

    /* One sleeper, many wakers. */
    assert(old == ZHPEU_THR_WAIT_SLEEP);

    if (lock)
            mutex_lock(&thr_wait->mutex);
    new = ZHPEU_THR_WAIT_IDLE;
    atm_cmpxchg(&thr_wait->state, &old, new);
    if (unlock)
            mutex_unlock(&thr_wait->mutex);
    cond_broadcast(&thr_wait->cond);
}

int zhpeu_thr_wait_sleep_slow(struct zhpeu_thr_wait *thr_wait,
                              int64_t timeout_us, bool lock, bool unlock)
{
    int                 ret = 0;
    int32_t             old = ZHPEU_THR_WAIT_SLEEP;
    int32_t             new = ZHPEU_THR_WAIT_IDLE;
    struct timespec     timeout;

    /* One sleeper, many wakers. */
    if (lock)
        mutex_lock(&thr_wait->mutex);
    if (timeout_us < 0) {
        while (atm_load_rlx(&thr_wait->state) == old)
            cond_wait(&thr_wait->cond, &thr_wait->mutex);
    } else {
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_nsec += timeout_us * US_PER_SEC;
        if (timeout.tv_nsec >= NS_PER_SEC) {
            timeout.tv_sec += timeout.tv_nsec / NS_PER_SEC;
            timeout.tv_nsec = timeout.tv_nsec % NS_PER_SEC;
        }
        while (atm_load_rlx(&thr_wait->state) == old) {
            ret = cond_timedwait(&thr_wait->cond, &thr_wait->mutex, &timeout);
            if (ret < 0) {
                atm_cmpxchg(&thr_wait->state, &old, new);
                break;
            }
        }
    }
    if (unlock)
        mutex_unlock(&thr_wait->mutex);

    return ret;
}

void zhpeu_work_head_signal_init(
    struct zhpeu_work_head *head,
    bool (*signal_fast)(struct zhpeu_thr_wait *thr_wait),
    void (*signal_slow)(struct zhpeu_thr_wait *thr_wait,
                        bool lock, bool unlock))
{
    zhpeu_thr_wait_signal_init(&head->thr_wait, signal_fast, signal_slow);
    STAILQ_INIT(&head->work_list);
}

void zhpeu_work_head_init(struct zhpeu_work_head *head)
{
    zhpeu_thr_wait_init(&head->thr_wait);
    STAILQ_INIT(&head->work_list);
}

void zhpeu_work_head_destroy(struct zhpeu_work_head *head)
{
    zhpeu_thr_wait_destroy(&head->thr_wait);
}

bool zhpeu_work_process(struct zhpeu_work_head *head, bool lock, bool unlock)
{
    bool                ret = false;
    struct zhpeu_work   *work;

    if (lock)
        mutex_lock(&head->thr_wait.mutex);
    while ((work = STAILQ_FIRST(&head->work_list))) {
        ret = work->worker(head, work);
        if (ret)
            break;
        STAILQ_REMOVE_HEAD(&head->work_list, lentry);
        work->worker = NULL;
        cond_broadcast(&work->cond);
    }
    if (unlock)
        mutex_unlock(&head->thr_wait.mutex);

    return ret;
}

/* Error wrappers. */

void zhpeu_fatal(const char *callf, uint line, const char *errf, int err)
{
    zhpeu_print_func_err(callf, line, errf, "", err);
    abort();
}

void zhpeu_err(const char *callf, uint line, const char *errf, int err)
{
    zhpeu_print_func_err(callf, line, errf, "", err);
}

void zhpeu_dbg(const char *callf, uint line, const char *errf, int err)
{
    zhpeu_print_dbg("%s,%u:%s(%s) returned error %d:%s\n",
                    callf, line, errf, "", err, strerror(err));
}

/* Keep _GNU_SOURCE out of the headers. */

int zhpeu_asprintf(char **strp, const char *fmt, ...)
{
    int                 ret;
    va_list             ap;

    va_start(ap, fmt);
    ret = vasprintf(strp, fmt, ap);
    va_end(ap);
    if (ret == -1) {
        errno = ENOMEM;
        *strp = NULL;
    }

    return ret;
}

void zhpeu_yield(void)
{
    zhpeu_posixcall(zhpeu_fatal, pthread_yield,);
}

void zhpeu_timing_reset(struct zhpeu_timing *t)
{
    t->tot = 0;
    t->min = ~(uint64_t)0;
    t->max = 0;
    t->cnt = 0;
    t->skw = 0;
}

void zhpeu_timing_update(struct zhpeu_timing *t, uint64_t cycles)
{
    if ((int64_t)cycles < 0)
        t->skw++;
    t->tot += cycles;
    t->min = min(t->min, cycles);
    t->max = max(t->max, cycles);
    t->cnt++;
}

void zhpeu_timing_print(struct zhpeu_timing *t, const char *lbl,
                        uint64_t divisor)
{
    if (!t->cnt)
        return;

    zhpeu_print_info("%s:%s:ave/min/max/cnt/skw %.3lf/%.3lf/%.3lf/%" PRIu64
                     "/%" PRIu64 "\n",
                     zhpeu_appname, lbl,
                     cycles_to_usec(t->tot, t->cnt * divisor),
                     cycles_to_usec(t->min, divisor),
                     cycles_to_usec(t->max, divisor),
                     t->cnt, t->skw);
}

void zhpeu_debug_log(void *vlog, const char *str, uint line,
                     uint64_t v0, uint64_t v1, uint64_t v2, uint64_t v3,
                     uint64_t v4, uint64_t cycles)
{
    struct zhpeu_debug_log *log = vlog;
    uint                idx = atm_inc(&log->idx);
    struct zhpeu_debug_rec *rec = &log->ent[idx & log->mask];

    rec->idx = idx;
    rec->line = line;
    rec->str = str;
    rec->cycles = cycles;
    rec->v[0] = v0;
    rec->v[1] = v1;
    rec->v[2] = v2;
    rec->v[3] = v3;
    rec->v[4] = v4;
}

void zhpeu_assert_fail(const char *expr, const char *func, uint line)
{
    zhpeu_print_err("assertion %s failed at %s,%u\n", expr, func, line);
    abort();
}
