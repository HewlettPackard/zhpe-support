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

#include <assert.h>

#include <mpi.h>

#include <zhpeq_lf.h>

#define FI_VER          FI_VERSION(1, 5)

void zhpel_mpi_exit(int status)
{
    if (status)
        MPI_Abort(MPI_COMM_WORLD, status);
        /* Possibly returns  if error handler changed. */
    MPI_Finalize();
    exit(status);
}

static void ep_init(struct zhpel_data *lf_data, struct zhpel_eps *lf_eps, int i)
{
    struct fi_cntr_attr cntr_attr = {
	.events = FI_CNTR_EVENTS_COMP,
    };
    uint64_t            flags;

    if (!lf_eps->eps) {
        lf_eps->eps = NULLCHK(calloc, (lf_eps->n_eps, sizeof(*lf_eps->eps)));
        lf_eps->rcnts = NULLCHK(calloc,
                                (lf_eps->n_eps, sizeof(*lf_eps->rcnts)));
        lf_eps->wcnts = NULLCHK(calloc,
                                (lf_eps->n_eps, sizeof(*lf_eps->wcnts)));
        lf_eps->mem = (char *)lf_data->mem + lf_data->mem_off;
        lf_data->mem_off += lf_eps->per_thr_size * lf_eps->n_eps;
    }
    if (lf_data->sep) {
        if (lf_eps->tx)
            FI_ERRCHK(fi_tx_context,
                      (lf_data->sep, i, lf_data->fi->tx_attr,
                       &lf_eps->eps[i], NULL));
        else
            FI_ERRCHK(fi_rx_context,
                      (lf_data->sep, i, lf_data->fi->rx_attr,
                       &lf_eps->eps[i], NULL));
    } else {
        FI_ERRCHK(fi_endpoint,
                  (lf_data->domain, lf_data->fi, &lf_eps->eps[i], NULL));
        FI_ERRCHK(fi_ep_bind, (lf_eps->eps[i], &lf_data->av->fid, 0));
    }
    FI_ERRCHK(fi_cntr_open,
              (lf_data->domain, &cntr_attr, &lf_eps->rcnts[i], NULL));
    flags = FI_READ | (lf_data->use_rma_events ? FI_REMOTE_READ : 0);
    FI_ERRCHK(fi_ep_bind, (lf_eps->eps[i], &lf_eps->rcnts[i]->fid, flags));
    FI_ERRCHK(fi_cntr_open,
              (lf_data->domain, &cntr_attr, &lf_eps->wcnts[i], NULL));
    flags = FI_WRITE | (lf_data->use_rma_events ? FI_REMOTE_WRITE : 0);
    FI_ERRCHK(fi_ep_bind, (lf_eps->eps[i], &lf_eps->wcnts[i]->fid, flags));
    /* Enable the endpoint, if not using sep */
    if (!lf_data->sep)
        FI_ERRCHK(fi_enable, (lf_eps->eps[i]));
}

static void ep_destroy(struct zhpel_eps *lf_eps)
{
    size_t              i;

    if (lf_eps->wcnts) {
        for (i = 0; i < lf_eps->n_eps; i++) {
            FI_CLOSE(lf_eps->eps[i]);
            FI_CLOSE(lf_eps->wcnts[i]);
            FI_CLOSE(lf_eps->rcnts[i]);
        }
    }
    free(lf_eps->wcnts);
    free(lf_eps->rcnts);
    free(lf_eps->eps);
}

void zhpel_init(struct zhpel_data *lf_data, const char *provider,
                const char *domain, bool use_sep, bool use_rma_events,
                size_t rank, size_t n_ranks, size_t cli_per_thr_size,
                size_t svr_per_thr_size)
{
    struct fi_info      *hints = NULL;
    struct fi_av_attr   av_attr = {
        .type           = FI_AV_TABLE,
    };
    union sockaddr_in46 *svr_addrs = NULL;
    union sockaddr_in46 our_addr = { 0 };
    size_t              our_addrlen = sizeof(our_addr);
    size_t              mem_size;
    size_t              r;
    int                 rc;
    struct fid_ep       *ep;
    struct fid_cntr     *rcnt;
    struct fid_cntr     *scnt;

    /* Initialize lf_data. */
    memset(lf_data, 0, sizeof(*lf_data));
    lf_data->rank = rank;
    lf_data->cli.n_eps = n_ranks;
    lf_data->cli.per_thr_size = cli_per_thr_size;
    lf_data->cli.tx = true;
    lf_data->svr.n_eps = 1;
    lf_data->svr.per_thr_size = svr_per_thr_size;
    lf_data->use_rma_events = use_rma_events;
    /* Provider discovery */
    hints = NULLCHK(fi_allocinfo, ());
    hints->caps = FI_RMA | (use_rma_events ? FI_RMA_EVENT : 0);
    hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_ALLOCATED;
    /* Assume provider can always just lie and give us thread-safe behavior. */
    hints->domain_attr->threading = FI_THREAD_COMPLETION;
    /* hints->domain_attr->data_progress = FI_PROGRESS_AUTO; */
    hints->ep_attr->type = FI_EP_RDM;
    if (use_sep) {
        hints->domain_attr->tx_ctx_cnt  = lf_data->cli.n_eps;
        hints->domain_attr->rx_ctx_cnt  = lf_data->svr.n_eps;
    }
    hints->fabric_attr->prov_name = NULLCHK(strdup, (provider));
    if (domain)
        hints->domain_attr->name = NULLCHK(strdup, (domain));

    FI_ERRCHK(fi_getinfo, (FI_VER, NULL, "0", FI_SOURCE, hints, &lf_data->fi));
    if (lf_data->fi->next) {
	/* TODO: Add 'domain' option */
	print_err("%s,%u:More than one domain for %s, using %s\n",
                  __func__, __LINE__,
                  lf_data->fi->fabric_attr->prov_name,
                  lf_data->fi->domain_attr->name);
        fi_freeinfo(lf_data->fi->next);
        lf_data->fi->next = NULL;
    }

    /* Create a single instance of fabric, domain, and av. */
    FI_ERRCHK(fi_fabric, (lf_data->fi->fabric_attr, &lf_data->fabric, NULL));
    lf_data->fi->fabric_attr->fabric = lf_data->fabric;
    FI_ERRCHK(fi_domain,
              (lf_data->fabric, lf_data->fi, &lf_data->domain, NULL));
    lf_data->fi->domain_attr->domain = lf_data->domain;
    FI_ERRCHK(fi_av_open, (lf_data->domain, &av_attr, &lf_data->av, NULL));

    /* Allocate all the memory. */
    mem_size = (lf_data->cli.per_thr_size * lf_data->cli.n_eps +
                lf_data->svr.per_thr_size * lf_data->svr.n_eps);
    POSIX_ERRCHK(posix_memalign, (&lf_data->mem, page_size, mem_size));
    memset(lf_data->mem, 0, mem_size);
    FI_ERRCHK(fi_mr_reg,
              (lf_data->domain, lf_data->mem, mem_size,
               (FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE |
                FI_SEND | FI_RECV), 0, ZHPEL_RKEY, 0, &lf_data->mr, NULL));

    /* Create scalable ep and bind av, if requested. */
    if (use_sep) {
        FI_ERRCHK(fi_scalable_ep,
                  (lf_data->domain, lf_data->fi, &lf_data->sep, NULL));
        FI_ERRCHK(fi_scalable_ep_bind, (lf_data->sep, &lf_data->av->fid, 0));
    }

    /* Create server endpoint and counters. */
    ep_init(lf_data, &lf_data->svr, 0);

    for (r = 0; r < n_ranks; r++)
        ep_init(lf_data, &lf_data->cli, r);

    assert(lf_data->mem_off == mem_size);

    ep = lf_data->svr.eps[0];
    /* Enable sep */
    if (lf_data->sep) {
        ep = lf_data->sep;
        FI_ERRCHK(fi_enable, (ep));
    }

    /* Use MPI to exchange server addresses; clients don't need this. */
    svr_addrs = NULLCHK(calloc, (n_ranks, sizeof(*svr_addrs)));
    FI_ERRCHK(fi_getname, (&ep->fid, &our_addr, &our_addrlen));
    MPI_ERRCHK(MPI_Allgather, (&our_addr, sizeof(our_addr), MPI_BYTE,
                               svr_addrs, sizeof(our_addr), MPI_BYTE,
                               MPI_COMM_WORLD));
    /* Insert server addresses into AV_TABLE; fi_addr will be rank.
     * We will also do a zero-byte read to make sure all the setup
     * is finished while we are single threaded. This is a workaround
     * for ugliness in the IB backend.
     */
    scnt = lf_data->svr.rcnts[0];
    for (r = 0; r < n_ranks; r++) {
        /* Do addresses one at a time because packing assumed. */
        rc = FI_ERRCHK(fi_av_insert,
                       (lf_data->av, svr_addrs + r, 1, NULL, 0, NULL));
        if (rc != 1) {
            print_err("%s,%u:fi_av_insert returned %d\n",
                      __func__, __LINE__, rc);
            zhpel_mpi_exit(1);
        }
        ep = lf_data->cli.eps[r];
        rcnt = lf_data->cli.rcnts[r];
        /* Read one byte to fully instantiate the connection and
         * import the rkey data.
         */
        FI_EAGAINOK(fi_read,
                    (ep, lf_data->mem, 1, fi_mr_desc(lf_data->mr), r,
                     0, ZHPEL_RKEY, NULL), rcnt);
        /* Read client and server counters to drive progress. */
        while (fi_cntr_read(rcnt) < 1) {
            if (fi_cntr_readerr(rcnt) > 0) {
                print_err("%s,%u:fi_cntr_readerr indicates error\n",
                             __func__, __LINE__);
               zhpel_mpi_exit(1);
            }
            (void)fi_cntr_read(scnt);
        }
        FI_ERRCHK(fi_cntr_set, (rcnt, 0));
    }
    if (use_rma_events) {
        while (fi_cntr_read(scnt) < n_ranks) {
            if (fi_cntr_readerr(scnt) > 0) {
                print_err("%s,%u:fi_cntr_readerr indicates error\n",
                             __func__, __LINE__);
               zhpel_mpi_exit(1);
            }
            for (r = 0; r < n_ranks; r++)
                (void)fi_cntr_read(lf_data->cli.rcnts[r]);
        }
        FI_ERRCHK(fi_cntr_set, (scnt, 0));
    }

    fi_freeinfo(hints);
    free(svr_addrs);
}

void zhpel_destroy(struct zhpel_data *lf_data)
{
    if (!lf_data)
        return;

    ep_destroy(&lf_data->cli);
    ep_destroy(&lf_data->svr);
    FI_CLOSE(lf_data->mr);
    FI_CLOSE(lf_data->sep);
    FI_CLOSE(lf_data->av);
    FI_CLOSE(lf_data->domain);
    FI_CLOSE(lf_data->fabric);
    FREE_IF(lf_data->fi, fi_freeinfo);
    free(lf_data->mem);
}
