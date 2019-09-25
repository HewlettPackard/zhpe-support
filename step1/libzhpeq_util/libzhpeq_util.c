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

#define _GNU_SOURCE

#include <zhpeq_util.h>

#include <libgen.h>

const char              *appname;

static bool             log_syslog;
static bool             log_syslog_init;
static int              log_level = LOG_ERR;

static uint64_t get_clock_cycles(volatile uint32_t *cpup);
static uint64_t get_tsc_cycles(volatile uint32_t *cpup);
static void do_init_time_cpuinfo(struct zhpeu_init_time *init_time);

static const char *cpuinfo_delim = " \t\n";

struct zhpeu_init_time  *zhpeu_init_time;
struct zhpeu_init_time  init_time;

static struct zhpeu_atm_list_ptr atm_dummy;

static void __attribute__((constructor)) lib_init(void)
{
    long                rcl;
    struct zhpeu_atm_list_ptr oldh;
    struct zhpeu_atm_list_ptr newh;
    struct zhpeu_init_time *oldi;

    /*
     * Run only once and force __atomic_load_16 and
     * __atomic_compare_exchange_16 to be linked.
     */
    oldh = atm_load_rlx(&atm_dummy);
    newh.ptr = NULL;
    newh.seq = oldh.seq + 1;
    atm_cmpxchg(&atm_dummy, &oldh, newh);
    if (oldh.seq) {
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

void zhpeq_util_init(char *argv0, int default_log_level, bool use_syslog)
{
    /* Allow to be called multiple times for testing. */
    appname = basename(argv0);
    log_level  = default_log_level;
    log_syslog = use_syslog;
    if (log_syslog && !log_syslog_init) {
        log_syslog_init = true;
        openlog(appname, LOG_PID | LOG_PERROR, LOG_DAEMON);
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

void print_dbg(const char *fmt, ...)
{
    va_list             ap;

    va_start(ap, fmt);
    vlog(LOG_DEBUG, stdout, appname, fmt, ap);
    va_end(ap);
}

void print_info(const char *fmt, ...)
{
    va_list             ap;

    va_start(ap, fmt);
    vlog(LOG_INFO, stdout, appname, fmt, ap);
    va_end(ap);
}

void print_err(const char *fmt, ...)
{
    va_list             ap;

    va_start(ap, fmt);
    vlog(LOG_ERR, stderr, appname, fmt, ap);
    va_end(ap);
}

void print_usage(bool use_stdout, const char *fmt, ...)
{
    va_list             ap;

    va_start(ap, fmt);
    vlog(LOG_ERR, (use_stdout ? stdout : stderr), NULL, fmt, ap);
    va_end(ap);
}

void print_errs(const char *callf, uint line, char *errf_str,
                int err, const char *errs)
{
    if (errf_str == (void *)(intptr_t)-1)
        print_err("%s,%u:fatal error, out of memory?\n", callf, line);
    else {
        print_err("%s,%u:%s%sreturned error %d:%s\n", callf, line,
                  (errf_str ?: ""), (errf_str ? " " : ""), err, errs);
        free(errf_str);
    }
}

char *errf_str(const char *fmt, ...)
{
    char                *ret = NULL;
    va_list             ap;

    va_start(ap, fmt);
    if (vasprintf(&ret, fmt, ap) == -1)
        ret = (void *)(intptr_t)-1;
    va_end(ap);

    return ret;
}

void print_func_err(const char *callf, uint line, const char *errf,
                    const char *arg, int err)
{
    char                *estr = NULL;

    if (errf)
        estr = errf_str("%s(%s)", errf, arg);
    if (err < 0)
        err = -err;

    print_errs(callf, line, estr, err, strerror(err));
}

void print_func_errn(const char *callf, uint line, const char *errf,
                     llong arg, bool arg_hex, int err)
{
    char                *estr = NULL;

    if (errf)
        estr = errf_str((arg_hex ? "%s(0x%Lx)" : "%s(%Ld)"), errf, arg);
    if (err < 0)
        err = -err;

    print_errs(callf, line, estr, err, strerror(err));
}

void print_range_err(const char *callf, uint line, const char *name,
                     int64_t val, int64_t min, int64_t max)
{
    print_err("%s,%u:%s = %Ld: out of range %Ld - %Ld\n",
              callf, line, name, (llong)val, (llong)min, (llong)max);
}

void print_urange_err(const char *callf, uint line, const char *name,
                      uint64_t val, uint64_t min, uint64_t max)
{
    print_err("%s,%u:%s = %Lu: out of range %Lu - %Lu\n",
              callf, line, name, (ullong)val, (ullong)min, (ullong)max);
}

char *get_cpuinfo_val(FILE *fp, char *buf, size_t buf_size,
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
        print_func_err(__func__, __LINE__, "fopen", fname, errno);
        goto done;
    }
    /* We only handle Intel, for now */
    sval = get_cpuinfo_val(fp, buf, sizeof(buf), 1, "vendor_id", NULL);
    if (!sval)
        goto done;
    intel = !strcmp(sval, "GenuineIntel");

    /* Search for flags we care about. */
    sval = get_cpuinfo_val(fp, buf, sizeof(buf), 0, "flags", NULL);
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
    sval = get_cpuinfo_val(fp, buf, sizeof(buf), 0, "clflush_size", NULL);
    if (sval) {
        errno = 0;
        val1 = strtoull(sval, &endp, 0);
        if (!errno && !*endp)
            init_time->l1sz = val1;
    }

    /* CPU support for TSC timekeeping? */
    if (!(i & 0x03))
        /* No. */
        goto done;

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
        sval = get_cpuinfo_val(fp, buf, sizeof(buf), 0, "model", "name", NULL);
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
            print_func_err(__func__, __LINE__, "fopen", fname, errno);
            goto done;
        }
    }

done:
    if (fp) {
        if (ferror(fp))
            print_err("%s,%u:Error reading %s\n",
                      __func__, __LINE__, fname);
        fclose(fp);
    }
}

static uint64_t get_tsc_cycles(volatile uint32_t *cpup)
{
    uint32_t            lo;
    uint32_t            hi;
    uint32_t            cpu;

    asm volatile("rdtscp" : "=a" (lo), "=d" (hi), "=c" (cpu) : :);

    if (cpup)
        *cpup = cpu;

    return ((uint64_t)hi << 32 | lo);
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

int parse_kb_uint64_t(const char *callf, uint line,
                      const char *name, const char *sp, uint64_t *val,
                      int base, uint64_t min, uint64_t max, int flags)
{
    int                 ret = -EINVAL;
    char                *ep;

    errno = 0;
    *val = strtoull(sp, &ep, base);
    if (errno) {
        ret = errno;
        print_err("%s,%u:Could not parse %s = %s as a number at"
                  " offset %u, char %c, errno %d:%s\n",
                  callf, line, name, sp, (uint)(ep - sp), *ep,
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
            print_err("%s,%u:KiB units not permitted for %s = %s at"
                      " offset %u, char %c\n",
                      callf, line, name, sp, (uint)(ep - sp), *ep);
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
            print_err("%s,%u:KB units not permitted for %s = %s at"
                      " offset %u, char %c\n",
                      callf, line, name, sp, (uint)(ep - sp), *ep);
            goto done;
        }
        ep++;
        if (!*ep)
            break;

    default:
        print_err("%s,%u:Could not parse units for %s = %s at"
                  " offset %u, char %c\n",
                  callf, line, name, sp, (uint)(ep - sp), *ep);
        goto done;
    }

    if (*val < min || *val > max) {
        print_urange_err(callf, line, name, *val, min, max);
        ret  = -ERANGE;
        goto done;
    }

    ret = 0;

 done:

    return ret;
}

int check_func_io(const char *callf, uint line, const char *errf,
                  const char *arg, size_t req, ssize_t res, int flags)
{
    int                 ret = 0;

    if (res == -1) {
        ret = -errno;
        if (ret == -EAGAIN && (flags & CHECK_EAGAIN_OK))
            goto done;
        print_func_err(callf, line, errf, arg, ret);
    } else if (req > (size_t)res) {
        if (flags & CHECK_SHORT_IO_OK)
            goto done;
        ret = -EIO;
        print_err("%s,%u:%s(%s) %Ld of %Lu bytes\n",
                  callf, line, errf, arg, (llong)res, (ullong)req);
    }

 done:
    return ret;
}

int check_func_ion(const char *callf, uint line, const char *errf,
                   long arg, bool arg_hex, size_t req, ssize_t res, int flags)
{
    int                 ret = 0;

    if (res == -1) {
        ret = -errno;
        if (ret == -EAGAIN && (flags & CHECK_EAGAIN_OK))
            goto done;
        print_func_errn(callf, line, errf, arg, arg_hex, ret);
    } else if (req > (size_t)res) {
        if (flags & CHECK_SHORT_IO_OK)
            goto done;
        ret = -EIO;
        print_err("%s,%u:%s(%ld) %Ld of %Lu bytes\n",
                  callf, line, errf, arg, (llong)res, (ullong)req);
    }

 done:
    return ret;
}

int do_getaddrinfo(const char *node, const char *service,
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
        print_err("%s,%u:getaddrinfo(%s,%s) returned gai %d:%s,\n"
                  "    errno %d:%s\n",
                  __func__, __LINE__, node ?: "", service ?: "",
                  rc, gai_strerror(rc), -ret, (ret < 0 ? strerror(-ret) : ""));

    if (ret < 0)
        *res = NULL;

    return ret;
}

int connect_sock(const char *node, const char *service)
{
    int                 ret;
    struct addrinfo     *resp = NULL;

    ret = do_getaddrinfo(node, service, AF_UNSPEC, SOCK_STREAM, false, &resp);
    if (ret < 0)
        goto done;
    ret = socket(resp->ai_family, resp->ai_socktype, resp->ai_protocol);
    if (ret == -1) {
        ret = -errno;
        print_func_err(__func__, __LINE__, "socket", "", ret);
        goto done;
    }
    if (connect(ret, resp->ai_addr, resp->ai_addrlen) == -1) {
        ret = -errno;
        print_func_err(__func__, __LINE__, "connect", "", ret);
        goto done;
    }

done:


    return ret;
}

void random_seed(uint seed)
{
    srandom(seed);
}

/* [start, end] */
uint random_range(uint start, uint end)
{
    const uint64_t      rand_max = (uint64_t)RAND_MAX + 1;
    uint64_t            range;

    /* Handle [0, UINT_MAX] */
    range = end;
    range -= start;
    range += 1;

    return (range * random()) / rand_max + start;
}

uint *random_array(uint *array, uint entries)
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
        t = random_range(0, i);
        tv = ret[t];
        ret[t] = ret[i];
        ret[i] = tv;
    }

    return ret;
}

bool _expected_saw(const char *callf, uint line,
                   const char *label, uintptr_t expected, uintptr_t saw)
{
    if (expected == saw)
        return true;

    print_err("%s,%u:%s:expected 0x%Lx, saw 0x%Lx\n",
              callf, line, label, (ullong)expected, (ullong)saw);

    return false;
}

char *_sockaddr_port_str(const char *callf, uint line, const void *addr)
{
    char                *ret = NULL;
    const union sockaddr_in46 *sa = addr;

    if (!sockaddr_len(sa)) {
        errno = EAFNOSUPPORT;
        goto done;
    }
    if (asprintf(&ret, "%d", ntohs(sa->sin_port))) {
        ret = NULL;
        print_func_err(callf, line, "asprintf", "", ENOMEM);
        errno = ENOMEM;
    }

 done:
    return ret;
}

char *_sockaddr_str(const char *callf, uint line, const void *addr)
{
    char                *ret = NULL;
    const char          ipv6_dual_pre[] = "::ffff:";
    const size_t        ipv6_dual_pre_len = sizeof(ipv6_dual_pre) - 1;
    size_t              ret_len;

    ret = zhpeu_malloc(INET6_ADDRSTRLEN, callf, line);
    if (!ret)
        goto done;
    if (!sockaddr_ntop(addr, ret, INET6_ADDRSTRLEN)) {
        free(ret);
        ret = NULL;
        goto done;
    }
    /* ipv6 dual output causes attempts to connect as ipv6 */
    ret_len = strlen(ret);
    if (ret_len > ipv6_dual_pre_len &&
        !strncmp(ret, ipv6_dual_pre, ipv6_dual_pre_len) &&
        !strchr(ret + ipv6_dual_pre_len, ':'))
        memmove(ret, ret + ipv6_dual_pre_len, ret_len - ipv6_dual_pre_len + 1);

done:
    return ret;
}

int _do_getsockname(const char *callf, uint line,
                    int sock_fd, union sockaddr_in46 *sa)
{
    int                 ret = 0;
    socklen_t           addr_len;

    addr_len = sizeof(*sa);
    if (getsockname(sock_fd, (void *)sa, &addr_len) == -1)
        ret = -errno;
    else if (!sockaddr_valid(sa, addr_len, true))
        ret = -EAFNOSUPPORT;
    if (ret < 0)
        print_func_err(callf, line, "getsockname", "", ret);

    return ret;
}

int _do_getpeername(const char *callf, uint line,
                    int sock_fd, union sockaddr_in46 *sa)
{
    int                 ret = 0;
    socklen_t           addr_len;

    addr_len = sizeof(*sa);
    if (getpeername(sock_fd, (void *)sa, &addr_len) == -1)
        ret = -errno;
    else if (!sockaddr_valid(sa, addr_len, true))
        ret = -EAFNOSUPPORT;
    if (ret < 0)
        print_func_err(callf, line, "getpeername", "", ret);

    return ret;
}

int _sock_send_blob(const char *callf, uint line, int fd,
                    const void *blob, size_t blob_len)
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
    ret = check_func_io(callf, line, "write", "", req, res, 0);
    if (ret < 0)
        goto done;
    req = blob_len;
    if (!req)
        goto done;
    res = write(fd, blob, req);
    ret = check_func_io(callf, line, "write", "", req, res, 0);
 done:

    return ret;
}

int _sock_recv_fixed_blob(const char *callf, uint line,
                          int sock_fd, void *blob, size_t blob_len)
{
    int                 ret;
    uint32_t            wlen;
    size_t              req;
    ssize_t             res;

    req = sizeof(wlen);
    res = read(sock_fd, &wlen, req);
    ret = check_func_io(callf, line, "read", "", req, res, 0);
    if (ret < 0)
        goto done;
    req = ntohl(wlen);
    if (!blob_len && req == UINT32_MAX)
        req = 0;
    if (!_expected_saw(callf, line, "wire len", blob_len, req)) {
        ret = -EINVAL;
        goto done;
    }
    if (!req)
        goto done;
    res = read(sock_fd, blob, req);
    ret = check_func_io(callf, line, "read", "", req, res, 0);
 done:

    return ret;
}

int _sock_recv_var_blob(const char *callf, uint line,
                        int sock_fd, size_t extra_len,
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
    ret = check_func_io(callf, line, "read", "", req, res, 0);
    if (ret < 0)
        goto done;
    req = ntohl(wlen);
    if (req == UINT32_MAX)
        goto done;
    *blob_len = req;
    *blob = zhpeu_malloc(req + extra_len, callf, line);
    if (!*blob) {
        ret = -errno;
        goto done;
    }
    if (req) {
        res = read(sock_fd, *blob, req);
        ret = check_func_io(callf, line, "read", "", req, res, 0);
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

const char *sockaddr_ntop(const void *addr, char *buf, size_t len)
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
    if (!ret && len > 0)
        buf[0] = '\0';
 done:

    return ret;
}

int sockaddr_cmpx(const union sockaddr_in46 *sa1,
                  const union sockaddr_in46 *sa2, bool noport)
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
        sockaddr_6to4(&local1);
        if (local1.sa_family == AF_INET)
            break;

    default:
        ret = memcmp(&sa1->sa_family, &sa2->sa_family, sizeof(sa1->sa_family));
        goto done;

    }

    /* We should only be called if family2 != family2 */
    switch (sa2->sa_family) {

    case AF_INET:
        memcpy(&local2, sa2, sizeof(struct sockaddr_in));
        break;

    case AF_INET6:
        memcpy(&local2, sa2, sizeof(struct sockaddr_in6));
        sockaddr_6to4(&local2);
        if (local2.sa_family == AF_INET)
            break;

    default:
        ret = memcmp(&sa1->sa_family, &sa2->sa_family, sizeof(sa1->sa_family));
        goto done;

    }

    /* We'll only get here if both addresses can be "reduced" to IPv4. */
    ret = memcmp(&local1.addr4.sin_addr, &local2.addr4.sin_addr,
                 sizeof(local1.addr4.sin_addr));
    if (ret || noport)
        goto done;
    ret = memcmp(&local1.sin_port, &local2.sin_port, sizeof(local1.sin_port));

 done:

    return ret;
}

int zhpeu_asprintf(char **strp, const char *fmt, ...)
{
    int                 ret;
    va_list             ap;

    va_start(ap, fmt);
    ret = vasprintf(strp, fmt, ap);
    va_end(ap);
    if (ret == -1)
        *strp = NULL;

    return ret;
}

#undef posix_memalign

int zhpeu_posix_memalign(void **memptr, size_t alignment, size_t size,
                         const char *callf, uint line)
{
    int                 ret = posix_memalign(memptr, alignment, size);

    if (unlikely(ret)) {
        *memptr = NULL;
        print_func_errn(callf, line, "posix_memalign", size, false, ret);
    }

    return ret;
}

#undef malloc

void *zhpeu_malloc(size_t size, const char *callf, uint line)
{
    void                *ret = malloc(size);
    int                 save_err;

    if (unlikely(!ret)) {
        save_err = errno;
        print_func_errn(callf, line, "malloc", size, false, errno);
        errno = save_err;
    }

    return ret;
}

#undef realloc

void *zhpeu_realloc(void *ptr, size_t size, const char *callf, uint line)
{
    void                *ret = realloc(ptr, size);
    int                 save_err;

    if (unlikely(!ret)) {
        save_err = errno;
        print_func_errn(callf, line, "realloc", size, false, errno);
        errno = save_err;
    }

    return ret;
}

#undef calloc

void *zhpeu_calloc(size_t nmemb, size_t size, const char *callf, uint line)
{
    void                *ret = calloc(nmemb, size);
    int                 save_err;

    if (unlikely(!ret)) {
        save_err = errno;
        print_func_errn(callf, line, "calloc", size, false, errno);
        errno = save_err;
    }

    return ret;
}

/* For things that want a function pointer to free. */
void zhpeu_free_ptr(void *ptr)
{
    free(ptr);
}

#undef free

void zhpeu_free(void *ptr, const char *callf, uint line)
{
    /* XXX:Implement alloc/free tracking? */
    free(ptr);
}

void *zhpeu_malloc_aligned(size_t alignment, size_t size,
                           const char *callf, uint line)
{
    void                *ret;

    (void)zhpeu_posix_memalign(&ret, alignment, size, callf, line);

    return ret;
}

void *zhpeu_calloc_aligned(size_t alignment, size_t nmemb, size_t size,
                           const char *callf, uint line)
{
    void                *ret;

    size *= nmemb;
    (void)zhpeu_posix_memalign(&ret, alignment, size, callf, line);
    if (likely(ret))
        memset(ret, 0, size);

    return ret;
}
