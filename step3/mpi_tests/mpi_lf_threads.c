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

/* Written to be independent of the utility libraries. */

#include <mpi.h>

#include <zhpeq_lf.h>

struct args {
    const char          *provider;
    const char          *domain;
    uint64_t            stripe_size;
    uint64_t            stripes;
    uint64_t            loops;
    bool                rma_events;
    bool                sep;
    bool                exclude_self;
    bool                verbose;
};

struct cli_thr {
    pthread_t           thread_id;
    size_t              rank;
    struct args         *args;
    struct zhpel_data   *lf_data;
    void                *retval;
};

static uint             cli_done;

static void usage(bool error) __attribute__ ((__noreturn__));

static void usage(bool use_stdout)
{
    print_usage(use_stdout,
                "Usage:%s [-esv][-d domain] <provider> <stripe_size>"
                " <stripes> <loops>\n"
                "All numbers may be postfixed with [kmgtKMGT] to specify the"
                " base units.\n"
                "Lower case is base 10; upper case is base 2.\n"
                " -d : domain for libfabric provider\n"
                " -e : use RMA_EVENTs\n"
                " -s : use scalable ep for client\n"
                " -x : exclude self (don't send to self)\n"
                " -v : verbose mode\n",
                appname);

    zhpel_mpi_exit(255);
}

static inline fi_addr_t r_addr(size_t r, struct zhpel_eps *lf_eps)
{
    return (r >= lf_eps->n_eps ? r - lf_eps->n_eps : r);
}

static void *cli_func(void *vcli_thr)
{
    struct cli_thr      *cli_thr = vcli_thr;
    struct args         *args = cli_thr->args;
    struct zhpel_data   *lf_data = cli_thr->lf_data;
    struct zhpel_eps    *lf_eps = &lf_data->cli;
    struct fid_ep       *ep = lf_eps->eps[cli_thr->rank];
    struct fid_cntr     *rcnt = lf_eps->rcnts[cli_thr->rank];
    struct fid_cntr     *wcnt = lf_eps->wcnts[cli_thr->rank];
    size_t              per_node_size;
    char                *lstripe;
    size_t              roff;
    size_t              l;
    size_t              s;
    size_t              r;
    size_t              rops;
    size_t              wops;
    size_t              n_srv;

    n_srv = lf_eps->n_eps;
    if (args->exclude_self)
        n_srv--;
    per_node_size = args->stripe_size / n_srv;
    for (l = 0, rops = 0, wops = 0 ; l < args->loops; l++) {
        lstripe = (char *)lf_eps->mem + cli_thr->rank * lf_eps->per_thr_size;
        roff = ((lf_data->rank * lf_eps->n_eps +
                 cli_thr->rank) *
                lf_eps->per_thr_size / n_srv);
        for (s = 0 ; s < args->stripes ; s++, roff += per_node_size) {
            for (r = 0 ; r < lf_eps->n_eps ; r++) {
                if (args->exclude_self && r == lf_data->rank)
                    continue;
                FI_EAGAINOK(fi_write,
                            (ep, lstripe, per_node_size,
                             fi_mr_desc(lf_data->mr), r_addr(r, lf_eps), roff,
                             ZHPEL_RKEY, NULL), wcnt);
                wops++;
                lstripe += per_node_size;
            }
            FI_ERRCHK(fi_cntr_wait, (wcnt, wops, -1));
        }
        if (args->verbose)
            print_info("%s,%u:rank %ld thr %ld loop %ld, writes complete\n",
                       __func__, __LINE__, lf_data->rank, cli_thr->rank, l + 1);

        lstripe = (char *)lf_eps->mem + cli_thr->rank * lf_eps->per_thr_size;
        roff = ((lf_data->rank * lf_eps->n_eps + cli_thr->rank) *
                lf_eps->per_thr_size / n_srv);
        for (s = 0 ; s < args->stripes ; s++, roff += per_node_size) {
            for (r = 0 ; r < lf_eps->n_eps ; r++) {
                if (args->exclude_self && r == lf_data->rank)
                    continue;
                FI_EAGAINOK(fi_read,
                            (ep, lstripe, per_node_size,
                             fi_mr_desc(lf_data->mr), r_addr(r, lf_eps), roff,
                             ZHPEL_RKEY, NULL), rcnt);
                rops++;
                lstripe += per_node_size;
            }
            FI_ERRCHK(fi_cntr_wait, (rcnt, rops, -1));
        }
        if (args->verbose)
            print_info("%s,%u:rank %ld thr %ld loop %ld, reads complete\n",
                       __func__, __LINE__, lf_data->rank, cli_thr->rank, l + 1);
    }
    atm_inc(&cli_done);

    return NULL;
}


int main(int argc, char **argv)
{
    int                 ret = 255;
    struct args         args = { NULL };
    struct zhpel_data   lf_data = { 0 };
    struct cli_thr      *cli_thr = NULL;
    int                 ival;
    int                 provided;
    int                 opt;
    size_t              rank;
    size_t              n_ranks;
    size_t              n_srv;
    size_t              cli_per_thr_size;
    size_t              svr_per_thr_size;
    size_t              ops_per_loop;
    size_t              ops;
    size_t              r;
    size_t              l;

    zhpeq_util_init(argv[0], LOG_INFO, false);

    MPI_ERRCHK(MPI_Init_thread, (&argc, &argv, MPI_THREAD_FUNNELED, &provided));
    if (provided < MPI_THREAD_FUNNELED) {
        fprintf (stderr, "%s:%s,%u:MPI_Init_thread returned provided %d\n",
                 appname, __func__, __LINE__, provided);
        zhpel_mpi_exit(ret);
    }
    MPI_ERRCHK(MPI_Comm_size, (MPI_COMM_WORLD, &ival));
    n_ranks = ival;
    n_srv = ival;
    MPI_ERRCHK(MPI_Comm_rank, (MPI_COMM_WORLD, &ival));
    rank = ival;

    if (argc == 1)
        usage(true);

    while ((opt = getopt(argc, argv, "d:esxv")) != -1) {

        switch (opt) {

        case 'd':
            if (args.domain)
                usage(false);
            args.domain = optarg;
            break;

        case 'e':
            if (args.rma_events)
                usage(false);
            args.rma_events = true;
            break;

        case 's':
            if (args.sep)
                usage(false);
            args.sep = true;
            break;

        case 'x':
            if (args.exclude_self)
                usage(false);
            if (n_srv == 1) {
                print_err("%s:-x requires more than one rank\n", __func__);
                zhpel_mpi_exit(ret);
            }
            n_srv--;
            args.exclude_self = true;
            break;

        case 'v':
            if (args.verbose)
                usage(false);
            args.verbose = true;
            break;

        default:
            usage(false);

        }
    }

    argc -= optind;
    if (argc != 4)
        usage(false);

    args.provider = argv[optind++];
    if (parse_kb_uint64_t(__func__, __LINE__, "stripe_size",
                          argv[optind++], &args.stripe_size, 0, 1, SIZE_MAX,
                          PARSE_KB | PARSE_KIB) < 0 ||
        parse_kb_uint64_t(__func__, __LINE__, "stripes",
                          argv[optind++], &args.stripes, 0, 1, SIZE_MAX,
                          PARSE_KB | PARSE_KIB) < 0 ||
        parse_kb_uint64_t(__func__, __LINE__, "loops",
                          argv[optind++], &args.loops, 0, 1, SIZE_MAX,
                          PARSE_KB | PARSE_KIB) < 0)
                          usage(false);

    if (args.stripe_size % n_srv) {
        print_err("%s,%u:stripe_size %lu not divisible by servers %lu\n",
                  __func__, __LINE__, args.stripe_size, n_srv);
        zhpel_mpi_exit(ret);
    }
    cli_per_thr_size = args.stripe_size * args.stripes;
    svr_per_thr_size = cli_per_thr_size * n_ranks;

    ret = 1;

    zhpel_init(&lf_data, args.provider, args.domain, args.sep, args.rma_events,
               rank, n_ranks, cli_per_thr_size, svr_per_thr_size);

    MPI_Barrier(MPI_COMM_WORLD);

    /* Launch clients. */
    cli_thr = NULLCHK(calloc, (n_ranks, sizeof(*cli_thr)));
    for (r = 0; r < n_ranks; r++) {
        cli_thr[r].rank = r;
        cli_thr[r].args = &args;
        cli_thr[r].lf_data = &lf_data;
        POSIX_ERRCHK(pthread_create,
                     (&cli_thr[r].thread_id, NULL, cli_func, &cli_thr[r]));
    }

    /* Server in main thread; wait for all events. */
    if (args.rma_events) {
        ops_per_loop = args.stripes * n_srv * n_srv;
        for (l = 0, ops = 0; l < args.loops; l++) {
            ops += ops_per_loop;
            FI_ERRCHK(fi_cntr_wait, (lf_data.svr.wcnts[0], ops, -1));
            if (args.verbose)
                print_info("%s,%u:rank %ld loop %ld, writes complete\n",
                           __func__, __LINE__, rank, l + 1);
            FI_ERRCHK(fi_cntr_wait, (lf_data.svr.rcnts[0], ops, -1));
            if (args.verbose)
                print_info("%s,%u:rank %ld loop %ld, reads complete\n",
                           __func__, __LINE__, rank, l + 1);
        }
    }

    /* Poll sever counter to guarantee progress. */
    while (atm_load_rlx(&cli_done) != n_ranks)
        (void)fi_cntr_read(lf_data.svr.rcnts[0]);

    /* Wait for clients to exit. */
    for (r = 0; r < n_ranks; r++)
        POSIX_ERRCHK(pthread_join,
                     (cli_thr[r].thread_id, &cli_thr[r].retval));

    MPI_Barrier(MPI_COMM_WORLD);

    zhpel_destroy(&lf_data);

    MPI_Barrier(MPI_COMM_WORLD);

    ret = 0;

    zhpel_mpi_exit(ret);
}
