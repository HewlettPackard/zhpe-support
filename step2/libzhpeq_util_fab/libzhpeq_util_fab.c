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
#include <search.h>

#include <zhpeq_util_fab.h>

void fab_dom_init(struct fab_dom *dom)
{
    memset(dom, 0, sizeof(*dom));
    dom->av_mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    atm_inc(&dom->use_count);
}

static void onfree_dom(struct fab_dom *dom, void *data)
{
    free(dom);
}

struct fab_dom *_fab_dom_alloc(void (*onfree)(struct fab_dom *dom, void *data),
                               void *data, const char *callf, uint line)
{
    struct fab_dom      *ret;

    ret = zhpeu_malloc_aligned(L1_CACHE_BYTES, sizeof(*ret), callf, line);
    if (ret) {
        fab_dom_init(ret);
        if (onfree) {
            ret->onfree = onfree;
            ret->onfree_data = data;
        } else
            ret->onfree = onfree_dom;
    }

    return ret;
}

void fab_conn_init(struct fab_dom *dom, struct fab_conn *conn)
{
    memset(conn, 0, sizeof(*conn));
    conn->dom = dom;
    atm_inc(&dom->use_count);
    atm_inc(&conn->use_count);
}

static void onfree_conn(struct fab_conn *conn, void *data)
{
    free(conn);
}

struct fab_conn *_fab_conn_alloc(struct fab_dom *dom,
                                 void (*onfree)(struct fab_conn *conn,
                                                void *data),
                                 void *data, const char *callf, uint line)
{
    struct fab_conn     *ret;

    ret = zhpeu_malloc_aligned(L1_CACHE_BYTES, sizeof(*ret), callf, line);
    if (ret) {
        fab_conn_init(dom, ret);
        if (onfree) {
            ret->onfree = onfree;
            ret->onfree_data = data;
        } else
            ret->onfree = onfree_conn;
    }

    return ret;
}

static void dummy_free(void *key)
{
}

void fab_finfo_free(struct fab_info *finfo)
{
    FREE_IF(finfo->info, fi_freeinfo);
    FREE_IF(finfo->hints, fi_freeinfo);
    free(finfo->service);
    free(finfo->node);
}

int fab_dom_free(struct fab_dom *dom)
{
    int                 ret = 0;
    int32_t             use_count;
    int                 rc;

    if (!dom)
        return 0;

    use_count = atm_dec(&dom->use_count);
    assert(use_count > 0);
    if (use_count > 1)
        return 1;

    fab_finfo_free(&dom->finfo);
    rc = FI_CLOSE(dom->av);
    ret = (ret >= 0 ? rc : ret);
    rc = FI_CLOSE(dom->domain);
    ret = (ret >= 0 ? rc : ret);
    rc = FI_CLOSE(dom->fabric);
    ret = (ret >= 0 ? rc : ret);

    tdestroy(dom->av_fi_tree, dummy_free);
    tdestroy(dom->av_sa_tree, free);

    if (dom->onfree)
        dom->onfree(dom, dom->onfree_data);

    return (ret > 0 ? 0 : ret);
}

int fab_conn_free(struct fab_conn *conn)
{
    int                 ret = 0;
    int32_t             use_count;
    int                 rc;

    if (!conn)
        return 0;

    use_count = atm_dec(&conn->use_count);
    assert(use_count > 0);
    if (use_count > 1)
        return 1;

    rc = fab_mrmem_free(&conn->mrmem);
    ret = (ret >= 0 ? rc : ret);
    rc = FI_CLOSE(conn->ep);
    ret = (ret >= 0 ? rc : ret);
    rc = FI_CLOSE(conn->pep);
    ret = (ret >= 0 ? rc : ret);
    rc = FI_CLOSE(conn->rx_cq);
    ret = (ret >= 0 ? rc : ret);
    rc = FI_CLOSE(conn->tx_cq);
    ret = (ret >= 0 ? rc : ret);
    rc = FI_CLOSE(conn->eq);
    ret = (ret >= 0 ? rc : ret);
    fab_finfo_free(&conn->finfo);
    rc = fab_dom_free(conn->dom);
    ret = (ret >= 0 ? rc : ret);

    if (conn->onfree)
        conn->onfree(conn, conn->onfree_data);

    return (ret > 0 ? 0 : ret);
}

static int finfo_init(const char *callf, uint line,
                      const char *service, const char *node, bool passive,
                      const char *provider, const char *domain,
                      enum fi_ep_type ep_type, struct fi_info *hints,
                      struct fab_info *finfo)
{
    int                 ret = -FI_ENOMEM;

    memset(finfo, 0, sizeof(*finfo));
    finfo->node = _strdup_or_null(callf, line, node);
    if (!finfo->node && node)
        goto done;
    if (passive) {
        if (!service)
            service = "0";
        finfo->flags |= FI_SOURCE;
    }
    finfo->service = _strdup_or_null(callf, line, service);
    if (!finfo->service && service)
        goto done;
    /* fi_dupinfo() will allocate a new fi_info and all assocaiated
     * leaves if hints == NULL; if hints != NULL, it will duplicate
     * the existing fi_info, but does not allocate missing leaves.
     * We're going to assume that any hints passed to this was
     * fully populated, since _fab_dom_setup() will call this with
     * hints == NULL and _fab_dom_getinfo() is the only other caller
     * when the fabric and the domain will be filled in.
     */
    finfo->hints = fi_dupinfo(hints);
    if (!finfo->hints) {
            print_func_fi_err(callf, line, "fi_dupinfo", "", ret);
            goto done;
    }
    /* Provider, domain, and ep_type ignored if hints specified. */
    if (!hints) {
        finfo->hints->fabric_attr->prov_name =
            _strdup_or_null(callf, line, provider);
        if (!finfo->hints->fabric_attr->prov_name && provider)
            goto done;
        finfo->hints->domain_attr->name =
            _strdup_or_null(callf, line, domain);
        if (!finfo->hints->domain_attr->name && domain)
            goto done;
        finfo->hints->ep_attr->type = ep_type;
    }

    ret = 0;

 done:
    return ret;
}

static int finfo_getinfo(const char *callf, uint line, struct fab_info *finfo)
{
    int                 ret;
    struct fi_info      *info;

    ret = fi_getinfo(FAB_FIVERSION, finfo->node, finfo->service, finfo->flags,
                     finfo->hints, &finfo->info);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_getinfo", "", ret);
        goto done;
    }

    /* Utility providers seem to be a tad agressive about matching;
     * find an exact match. May not be necessary in top-of-tree, but
     * it shouldn't hurt anything.
     */
    if (!finfo->hints ||
        !finfo->hints->fabric_attr ||
        !finfo->hints->fabric_attr->prov_name)
        goto done;
    for (info = finfo->info; info; info = info->next) {
        if (!info->fabric_attr || !info->fabric_attr->prov_name ||
            strcmp(info->fabric_attr->prov_name,
                   finfo->hints->fabric_attr->prov_name))
            continue;
        info = fi_dupinfo(info);
        if (!info) {
            ret = -FI_ENOMEM;
            print_func_fi_err(callf, line, "fi_dupinfo", "", ret);
            goto done;
        }
        fi_freeinfo(finfo->info);
        finfo->info = info;
        goto done;
    }
    ret = -FI_ENODATA;

 done:
    fi_freeinfo(finfo->hints);
    finfo->hints = NULL;

    return ret;
}

int _fab_dom_setup(const char *callf, uint line,
                   const char *service, const char *node, bool passive,
                   const char *provider, const char *domain,
                   enum fi_ep_type ep_type, struct fab_dom *dom)
{
    int                 ret;
    struct fi_av_attr   av_attr = { .type = FI_AV_TABLE };

    ret = finfo_init(callf, line, service, node, passive,
                     provider, domain, ep_type, NULL, &dom->finfo);
    if (ret < 0)
        goto done;

    dom->finfo.hints->caps = (FI_RMA | FI_READ | FI_WRITE |
                              FI_REMOTE_READ | FI_REMOTE_WRITE);
    dom->finfo.hints->mode = (FI_LOCAL_MR | FI_RX_CQ_DATA |
                              FI_CONTEXT | FI_CONTEXT2);
    /* dom->finfo->hints->domain_attr->data_progress = FI_PROGRESS_MANUAL; */
    dom->finfo.hints->domain_attr->mr_mode = FI_MR_BASIC;
    dom->finfo.hints->addr_format = FI_SOCKADDR;

    ret = finfo_getinfo(callf, line, &dom->finfo);
    if (ret < 0)
        goto done;

    ret = fi_fabric(dom->finfo.info->fabric_attr, &dom->fabric, NULL);
    if (ret < 0) {
        dom->fabric = NULL;
	print_func_fi_err(callf, line, "fi_fabric", "", ret);
	goto done;
    }
    dom->finfo.info->fabric_attr->fabric = dom->fabric;
    ret = fi_domain(dom->fabric, dom->finfo.info, &dom->domain, NULL);
    if (ret < 0) {
        dom->domain = NULL;
	print_func_fi_err(callf, line, "fi_domain", "", ret);
	goto done;
    }
    dom->finfo.info->domain_attr->domain = dom->domain;
    if (dom->finfo.info->ep_attr->type == FI_EP_RDM) {
        ret = fi_av_open(dom->domain, &av_attr, &dom->av, NULL);
        if (ret < 0) {
            dom->av = NULL;
            print_func_fi_err(callf, line, "fi_av_open", "", ret);
            goto done;
        }
    }

 done:
    return ret;
}
int _fab_dom_getinfo(const char *callf, uint line,
                     const char *service, const char *node, bool passive,
                     struct fab_dom *dom, struct fab_info *finfo)
{
    int                 ret;

    ret = finfo_init(callf, line, service, node, passive, NULL, NULL, 0,
                     dom->finfo.info, finfo);
    if (ret < 0)
        goto done;
    ret = finfo_getinfo(callf, line, finfo);

 done:
    return ret;
}

int _fab_listener_setup(const char *callf, uint line, int backlog,
                        struct fab_conn *listener)
{
    int                 ret;
    struct fi_info      *info = fab_conn_info(listener);
    struct fi_eq_attr   eq_attr = { .wait_obj = FI_WAIT_UNSPEC };

    ret = fi_eq_open(listener->dom->fabric, &eq_attr, &listener->eq, NULL);
    if (ret < 0) {
        listener->eq = NULL;
	print_func_fi_err(callf, line, "fi_eq_open", "", ret);
	goto done;
    }
    ret = fi_passive_ep(listener->dom->fabric, info, &listener->pep, NULL);
    if (ret < 0) {
        listener->pep = NULL;
	print_func_fi_err(callf, line, "fi_passive_ep", "", ret);
        goto done;
    }
    ret = fi_pep_bind(listener->pep, &listener->eq->fid, 0);
    if (ret < 0) {
	print_func_fi_err(callf, line, "fi_pep_bind", "", ret);
	goto done;
    }
    if (backlog) {
        ret = fi_control(&listener->pep->fid, FI_BACKLOG, &backlog);
        if (ret < 0 && ret != -FI_ENOSYS) {
            print_errs(callf, line,
                       errf_str("fi_control(FI_BACKLOG = %d)", backlog),
                       ret, fi_strerror(-ret));
            goto done;
        }
    }
    ret = fi_listen(listener->pep);
    if (ret < 0) {
	print_func_fi_err(__func__, __LINE__, "fi_listen", "", ret);
	goto done;
    }

 done:
    return ret;
}

int _fab_listener_wait_and_accept(const char *callf, uint line,
                                  struct fab_conn *listener, int timeout,
                                  size_t tx_size, size_t rx_size,
                                  struct fab_conn *conn)
{
    int                 ret = 0;
    struct fi_eq_cm_entry entry;

    ret = _fab_eq_cm_event(callf, line, listener, timeout, FI_CONNREQ, &entry);
    if (ret < 0)
        goto done;
    conn->finfo.info = entry.info;
    ret = _fab_ep_setup(callf, line, conn, listener->eq, tx_size, rx_size);
    if (ret < 0)
        goto done;
    ret = fi_accept(conn->ep, NULL, 0);
    if (ret < 0) {
	print_func_fi_err(callf, line, "fi_accept", "", ret);
	goto done;
    }
    /* Wait to be fully connected. */
    ret = _fab_eq_cm_event(callf, line, listener, timeout, FI_CONNECTED,
                           &entry);
    if (ret < 0)
        goto done;
    if (!_expected_saw(callf, line, "CONN fid", (uintptr_t)&conn->ep->fid,
                       (uintptr_t)entry.fid))  {
        ret = -FI_EINVAL;
        goto done;
    }

 done:
    return ret;
}

int _fab_connect(const char *callf, uint line, int timeout,
                 size_t tx_size, size_t rx_size, struct fab_conn *conn)
{
    int                 ret;
    struct fi_info      *info = fab_conn_info(conn);
    struct fi_eq_attr   eq_attr = { .wait_obj = FI_WAIT_UNSPEC };
    struct fi_eq_cm_entry entry;

    ret = fi_eq_open(conn->dom->fabric, &eq_attr, &conn->eq, NULL);
    if (ret < 0) {
	print_func_fi_err(callf, line, "fi_eq_open", "", ret);
	goto done;
    }
    ret = _fab_ep_setup(callf, line, conn, conn->eq, tx_size, rx_size);
    if (ret < 0)
        goto done;
    ret = fi_connect(conn->ep, info->dest_addr, NULL, 0);
    if (ret) {
	print_func_fi_err(__func__, __LINE__, "fi_connect", "", ret);
	goto done;
    }
    /* Wait to be fully connected. */
    ret = _fab_eq_cm_event(callf, line, conn, timeout, FI_CONNECTED, &entry);
    if (ret < 0)
        goto done;
    if (!_expected_saw(callf, line, "CONN fid", (uintptr_t)&conn->ep->fid,
                       (uintptr_t)entry.fid))  {
        ret = -FI_EINVAL;
        goto done;
    }

 done:
    return ret;
}

int _fab_ep_setup(const char *callf, uint line,
                  struct fab_conn *conn, struct fid_eq *eq,
                  size_t tx_size, size_t rx_size)
{
    int                 ret;
    struct fi_info      *info = fab_conn_info(conn);
    struct fi_cq_attr   tx_cq_attr =  {
        .format = FI_CQ_FORMAT_CONTEXT,
        .wait_obj = FI_WAIT_NONE,
    };
    struct fi_cq_attr   rx_cq_attr =  {
        .format = FI_CQ_FORMAT_CONTEXT,
        .wait_obj = FI_WAIT_NONE,
    };

    tx_size = (tx_size ?: info->tx_attr->size);
    info->tx_attr->size = tx_size;
    tx_cq_attr.size = tx_size;
    rx_size = (rx_size ?: info->rx_attr->size);
    info->rx_attr->size = rx_size;
    rx_cq_attr.size = rx_size;

    ret = fi_endpoint(conn->dom->domain, info, &conn->ep, NULL);
    if (ret < 0) {
	print_func_fi_err(callf, line, "fi_endpoint", "", ret);
	goto done;
    }
    if (eq) {
        ret = fi_ep_bind(conn->ep, &eq->fid, 0);
        if (ret < 0) {
            print_func_fi_err(callf, line, "fi_ep_bind", "eq", ret);
            goto done;
        }
    }
    ret = fi_cq_open(conn->dom->domain, &tx_cq_attr, &conn->tx_cq, NULL);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_cq_open", "tx", ret);
        goto done;
    }
    ret = fi_ep_bind(conn->ep, &conn->tx_cq->fid, FI_TRANSMIT);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_ep_bind", "tx_cq", ret);
        goto done;
    }
    ret = fi_cq_open(conn->dom->domain, &rx_cq_attr, &conn->rx_cq, NULL);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_cq_open", "rx", ret);
        goto done;
    }
    ret = fi_ep_bind(conn->ep, &conn->rx_cq->fid, FI_RECV);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_ep_bind", "rx_cq", ret);
        goto done;
    }
    if (info->ep_attr->type == FI_EP_RDM) {
        ret = fi_ep_bind(conn->ep, &conn->dom->av->fid, 0);
        if (ret < 0) {
            print_func_fi_err(callf, line, "fi_ep_bind", "av", ret);
            goto done;
        }
    }
    ret = fi_enable(conn->ep);
    if (ret < 0) {
	print_func_fi_err(callf, line, "fi_enable", "", ret);
	goto done;
    }

 done:
    return ret;
}

int _fab_eq_cm_event(const char *callf, uint line,
                     struct fab_conn *conn, int timeout, uint32_t expected,
                     struct fi_eq_cm_entry *entry)
{
    ssize_t             ret;
    struct fi_eq_err_entry fi_eq_err;
    uint32_t            event;

    /* Wait for the next event. */
    ret = fi_eq_sread(conn->eq, &event, entry, sizeof(*entry), timeout, 0);
    if (ret >= 0 && ret < sizeof(entry))
        ret = -FI_EOTHER;
    if (ret < 0) {
        if (ret == -FI_EAVAIL) {
            ret = fi_eq_readerr(conn->eq, &fi_eq_err, 0);
            if (ret >= 0  && ret != sizeof(fi_eq_err))
                ret = -FI_EOTHER;
            if (ret < 0) {
                print_func_fi_err(callf, line,
                                  "fi_eq_readerr", "", ret);
                goto done;
            }
            ret = -fi_eq_err.err;
            print_func_fi_err(callf, line, __func__, "", ret);
            goto done;
        }
	print_func_fi_err(callf, line, "fi_eq_sread", "", ret);
	goto done;
    }
    if (!_expected_saw(callf, line, "CONN event", expected, event)) {
	ret = -FI_EOTHER;
	goto done;
    }

 done:
    return ret;
}

int _fab_mrmem_alloc(const char *callf, uint line,
                     struct fab_conn *conn, struct fab_mrmem *mrmem,
                     size_t len, uint64_t access)
{
    int                 ret = 0;

    ret = -posix_memalign(&mrmem->mem, page_size, len);
    if (ret) {
        mrmem->mem = NULL;
        print_func_errn(callf, line, "posix_memalign",
                        len, true, ret);
        goto done;
    }
    memset(mrmem->mem, 0, len);
    mrmem->len = len;

    if (!access)
        access = (FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE);
    ret = fi_mr_reg(conn->dom->domain, mrmem->mem, len, access, 0, 0, 0,
                    &mrmem->mr, NULL);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_mr_reg", "", ret);
        goto done;
    }

 done:
    return ret;
}

int fab_mrmem_free(struct fab_mrmem *mrmem)
{
    int                 ret = 0;

    if (!mrmem)
        goto done;

    ret = FI_CLOSE(mrmem->mr);
    free(mrmem->mem);

 done:
    return ret;
}

ssize_t _fab_completions(const char *callf, uint line,
                         struct fid_cq *cq, size_t count,
                         void (*cq_update)(void *arg, void *cqe, bool err),
                         void *arg)
{
    ssize_t             ret = 0;
    ssize_t             rc;
    ssize_t             len;
    ssize_t             i;
    struct fi_cq_tagged_entry fi_cqe[1];
    struct fi_cq_err_entry fi_cqerr;

    /* The verbs rdm code forces all entries to be tagged, but the msg
     * code dosn't support tagged. All I want is the context; so we
     * read a single entry; pass in a fi_cq_tagged; and pull the context
     * off the front. The entries are designed to be compatible, but
     * the API means that is not terribly useful.
     */

    /* If count specified, read up to count entries; if not, all available. */
    for (ret = 0; !count || ret < count;) {
        len = ARRAY_SIZE(fi_cqe);
        if (count) {
            rc = count - ret;
            if (len > rc)
                rc = len;
        }
        rc = _fab_cq_read(callf, line, cq, fi_cqe, len,
                          (cq_update ? &fi_cqerr : NULL));
        if (!rc)
            break;
        if (rc >= 0) {
            ret += rc;
            if (cq_update) {
                for (i = 0; i < rc; i++)
                    cq_update(arg, fi_cqe + i, false);
            }
            continue;
        }
        if (rc == -FI_EAGAIN)
            break;
        if (rc != -FI_EAVAIL || !cq_update) {
            ret = rc;
            break;
        }
        cq_update(arg, &fi_cqerr, true);
        ret++;
    }

    return ret;
}

void fab_print_info(struct fab_conn *conn)
{
    int                 rc;
    struct fab_dom      dom;
    struct fab_info     finfo = { NULL };
    struct fi_info      *info;

    fab_dom_init(&dom);
    if (conn)
        info = fab_conn_info(conn);
    else {
        rc = finfo_getinfo(__func__, __LINE__, &finfo);
        if (rc < 0)
            goto done;
        info = finfo.info;
    }

    if (!conn && info)
        print_info("Available providers/domains:\n");
    for (; info; info = info->next) {
        print_info("provider %s domain %s tx_size %Lu ep_type %s\n",
                   info->fabric_attr->prov_name, info->domain_attr->name,
                   (ullong)info->tx_attr->size,
                   fi_tostr(&info->ep_attr->type, FI_TYPE_EP_TYPE));
        /* Only print the active info for a live conn. */
        if (conn)
            break;
    }

 done:
    if (!conn)
        fab_finfo_free(&finfo);
}

int _fab_av_ep(const char *callf, uint line, struct fab_conn *conn,
               size_t tx_size, size_t rx_size)
{
    return _fab_ep_setup(callf, line, conn, NULL, tx_size, rx_size);
}

int _fab_cq_sread(const char *callf, uint line,
                  struct fid_cq *cq, struct fi_cq_tagged_entry *fi_cqe,
                  size_t count, void *cond, int timeout,
                  struct fi_cq_err_entry *fi_cqerr)
{
    ssize_t             ret = 0;
    int                 rc;
    struct fi_cq_err_entry err_entry;

    for (;;) {
        ret = fi_cq_sread(cq, fi_cqe, count, cond, timeout);
        if (ret >= 0)
            break;
        if (ret == -FI_EAGAIN) {
            ret = 0;
            break;
        }
        if (ret != -FI_EAVAIL) {
            print_func_err(callf, line, "fi_cq_sread", "", ret);
            break;
        }
        if (!fi_cqerr)
            fi_cqerr = &err_entry;
        rc = fi_cq_readerr(cq, fi_cqerr, 0);
        if (!rc)
            /* Possible no error? If so, retry. */
            continue;
        if (rc > 0) {
            if (fi_cqerr == &err_entry)
                ret = -fi_cqerr->err;
            break;
        }
        if (rc == -FI_EAGAIN)
            /* Possible no error? If so, retry. */
            continue;
        print_func_fi_err(callf, line, "fi_cq_readerr", "", rc);
        ret = rc;
        break;
    }

    return ret;
}

int _fab_cq_read(const char *callf, uint line,
                 struct fid_cq *cq, struct fi_cq_tagged_entry *fi_cqe,
                 size_t count, struct fi_cq_err_entry *fi_cqerr)
{
    ssize_t             ret = 0;
    int                 rc;
    struct fi_cq_err_entry err_entry;

    for (;;) {
        ret = fi_cq_read(cq, fi_cqe, count);
        if (ret >= 0)
            break;
        if (ret == -FI_EAGAIN) {
            ret = 0;
            break;
        }
        if (ret != -FI_EAVAIL) {
            print_func_err(callf, line, "fi_cq_read", "", ret);
            break;
        }
        if (!fi_cqerr)
            fi_cqerr = &err_entry;
        rc = fi_cq_readerr(cq, fi_cqerr, 0);
        if (!rc)
            /* Possibly no error? If so, retry. */
            continue;
        if (rc > 0) {
            if (fi_cqerr == &err_entry)
                ret = -fi_cqerr->err;
            break;
        }
        if (rc == -FI_EAGAIN)
            /* Possible no error? If so, retry. */
            continue;
        print_func_fi_err(callf, line, "fi_cq_readerr", "", rc);
        ret = rc;
        break;
    }

    return ret;
}

int _fab_av_xchg_addr(const char *callf, uint line, struct fab_conn *conn,
                      int sock_fd, union sockaddr_in46 *ep_addr)
{
    int                 ret;
    size_t              addr_len = sizeof(*ep_addr);
    in_port_t           save_port;

    ret = fi_getname(&conn->ep->fid, ep_addr, &addr_len);
    if (ret >= 0 && !sockaddr_valid(ep_addr, addr_len, true))
        ret = -EAFNOSUPPORT;
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_getname", "", ret);
        goto done;
    }
    sockaddr_6to4(ep_addr);
    if (sockaddr_loopback(ep_addr, true)) {
        save_port = ep_addr->sin_port;
        ret = do_getsockname(sock_fd, ep_addr);
        if (ret < 0)
            goto done;
        sockaddr_6to4(ep_addr);
        ep_addr->sin_port = save_port;
    }
    if (ret < 0 || sock_fd == -1)
        goto done;
    ret = _sock_send_blob(callf, line, sock_fd, ep_addr, sizeof(*ep_addr));
    if (ret < 0)
        goto done;
    ret = _sock_recv_fixed_blob(callf, line, sock_fd, ep_addr,
                                sizeof(*ep_addr));
    if (ret < 0)
        goto done;
 done:

    return ret;
}

struct xchg_retry_args {
    struct timespec     ts_beg;
    uint64_t            timeout_ns;
};

static int xchg_retry(void *vargs)
{
    struct xchg_retry_args *args = vargs;
    struct timespec     ts_cur;

    if (!args->timeout_ns)
        return -FI_ETIMEDOUT;
    clock_gettime_monotonic(&ts_cur);
    if (ts_delta(&args->ts_beg, &ts_cur) >= args->timeout_ns)
        return -FI_ETIMEDOUT;

    /* Retry. */
    return 0;
}

int _fab_av_xchg(const char *callf, uint line, struct fab_conn *conn,
                 int sock_fd, int timeout, fi_addr_t *fi_addr)
{
    int                 ret;
    bool                fi_addr_valid = false;
    int                 (*retry)(void *args) = xchg_retry;
    union sockaddr_in46 ep_addr;
    struct xchg_retry_args retry_args;

    /* FIXME: Add timeout support to xchg_addr? */
    if (timeout == 0)
        retry_args.timeout_ns = 0;
    else if (timeout < 0)
        retry = NULL;
    else {
        retry_args.timeout_ns = (uint64_t)timeout * 1000000;
        clock_gettime_monotonic(&retry_args.ts_beg);
    }
    ret = _fab_av_xchg_addr(callf, line, conn, sock_fd, &ep_addr);
    if (ret < 0)
        goto done;
    ret = _fab_av_insert(callf, line, conn->dom, &ep_addr, fi_addr);
    if (ret < 0)
        goto done;
    fi_addr_valid = true;
    ret = _fab_av_wait_send(callf, line, conn, *fi_addr, retry, &retry_args);
    if (ret < 0)
        goto done;
    ret = _fab_av_wait_recv(callf, line, conn, *fi_addr, retry, &retry_args);

 done:
    if (ret < 0) {
        if (fi_addr_valid)
            _fab_av_remove(callf, line, conn->dom, *fi_addr);
        print_func_err(callf, line, "_fab_av_xchg", "", ret);
    }

    return ret;
}

struct av_tree_entry {
    union sockaddr_in46 sa;
    fi_addr_t           fi_addr;
    int32_t             use_count;
};

static int compare_sa(const void *key1, const void *key2)
{
    return sockaddr_cmp(key1, key2);
}

static int compare_fi(const void *key1, const void *key2)
{
    fi_addr_t           fi_addr1 = *(const fi_addr_t *)key1;
    fi_addr_t           fi_addr2 = *(const fi_addr_t *)key2;

    return arithcmp(fi_addr1, fi_addr2);
}

int _fab_av_insert(const char *callf, uint line, struct fab_dom *dom,
                   union sockaddr_in46 *saddr, fi_addr_t *fi_addr_out)
{
    int                 ret = -FI_EINVAL;
    struct av_tree_entry *ave = NULL;
    fi_addr_t           fi_addr;
    void                **tval;

    if (!fi_addr_out)
        goto done;
    *fi_addr_out = FI_ADDR_UNSPEC;
    if (!dom || !saddr || !sockaddr_len(saddr))
        goto done;

    mutex_lock(&dom->av_mutex);
    tval = tsearch(saddr, &dom->av_sa_tree, compare_sa);
    if (!tval) {
        ret = -FI_ENOMEM;
        print_func_fi_err(callf, line, "tsearch", "", ret);
        goto done;
    }
    if (*tval != saddr) {
        ret = 1;
        ave = *tval;
        *fi_addr_out = ave->fi_addr;
        ave->use_count++;
        goto done;
    }
    ave = zhpeu_malloc(sizeof(*ave), callf, line);
    if (!ave) {
        ret = -FI_ENOMEM;
        goto done;
    }
    sockaddr_cpy(&ave->sa, saddr);
    ave->fi_addr = FI_ADDR_UNSPEC;
    ave->use_count = 1;
    *tval = ave;

    ret = fi_av_insert(dom->av, saddr, 1,  &fi_addr, 0, NULL);
    if (ret < 0) {
	print_func_fi_err(callf, line, "fi_av_insert", "", ret);
        goto done;
    } else if (!_expected_saw(callf, line, "fi_av_insert", 1, ret)) {
        ret = -FI_EINVAL;
        goto done;
    }
    *fi_addr_out = ave->fi_addr = fi_addr;

    /* Going to use a tree, since it will be more general and
     * we don't really just don't want o(n) in the worst case.
     */
    tval = tsearch(&ave->fi_addr, &dom->av_fi_tree, compare_fi);
    if (!tval) {
        ret = -FI_ENOMEM;
        print_func_fi_err(callf, line, "tsearch", "", ret);
        goto done;
    }
    assert(*tval == &ave->fi_addr);
    ret = 0;

 done:
    if (ret < 0) {
        if (ave) {
            (void)tdelete(saddr, &dom->av_sa_tree, compare_sa);
            if (ave->fi_addr != FI_ADDR_UNSPEC)
                fi_av_remove(dom->av, &fi_addr, 1, 0);
            free(ave);
        }
    }
    mutex_unlock(&dom->av_mutex);

    return ret;
}

int _fab_av_remove(const char *callf, uint line, struct fab_dom *dom,
                   fi_addr_t fi_addr)
{
    int                 ret;
    struct av_tree_entry *ave;
    void                **tval;

    mutex_lock(&dom->av_mutex);
    tval = tfind(&fi_addr, &dom->av_fi_tree, compare_fi);
    if (!tval) {
        ret = -FI_ENOENT;
        goto done;
    }
    ave = container_of((fi_addr_t *)*tval, struct av_tree_entry, fi_addr);
    if (--(ave->use_count)) {
        ret = 0;
        goto done;
    }
    (void)tdelete(&fi_addr, &dom->av_fi_tree, compare_fi);
    (void)tdelete(ave, &dom->av_sa_tree, compare_sa);
    free(ave);

    ret = fi_av_remove(dom->av, &fi_addr, 1, 0);
    if (ret < 0)
	print_func_fi_err(callf, line, "fi_av_remove", "", ret);

 done:
    mutex_unlock(&dom->av_mutex);

    return ret;
}

int _fab_av_wait_send(const char *callf, uint line, struct fab_conn *conn,
                      fi_addr_t fi_addr,
                      int (*retry)(void *retry_arg), void *retry_arg)
{
    int                 ret;

    /* Do zero length fi_inject until it stops returning FI_EAGAIN. */
    for (;;) {
        ret = fi_tinject(conn->ep, NULL, 0, fi_addr, 0);
        if (ret != -FI_EAGAIN)
            goto done;
        if (retry && (ret = retry(retry_arg)))
            goto done;
        else
            yield();
    }
    if (ret < 0) {
	print_func_fi_err(callf, line, "fi_tinject", "", ret);
        goto done;
    }
    ret = 0;

 done:

    return ret;
}

int _fab_av_wait_recv(const char *callf, uint line, struct fab_conn *conn,
                      fi_addr_t fi_addr,
                      int (*retry)(void *retry_arg), void *retry_arg)
{
    int                 ret;
    struct fi_context2  fi_ctxt;
    struct fi_msg_tagged fi_tmsg = {
        .addr           = fi_addr,
        .context        = &fi_ctxt,
    };
    struct fi_cq_tagged_entry fi_cqe;

    /* Must be single-threaded to prevent races. */
    for (;;) {
        /* Peek for message from other side. */
        ret = fi_trecvmsg(conn->ep, &fi_tmsg, FI_PEEK | FI_DISCARD);
        if (ret < 0) {
            print_func_fi_err(callf, line, "fi_trecvmsg", "FI_PEEK", ret);
            goto done;
        }
        /* Get peek completion; should be there. */
        for (;;) {
            ret = _fab_cq_read(callf, line, conn->rx_cq, &fi_cqe, 1, NULL);
            if (ret == 1) {
                if (fi_cqe.op_context != (void *)&fi_ctxt) {
                    print_err("%s,%u:invalid context seen\n", callf, line);
                    continue;
                }
                ret = 0;
                goto done;
            }
            if (ret == -FI_ENOMSG)
                break;
            if (ret < 0) {
                print_err("%s,%u:FI_PEEK returned an unexpected error %d:%s\n",
                          callf, line, ret, fi_strerror(-ret));
                goto done;
            }
            if (retry && (ret = retry(retry_arg)))
                goto done;
            else
                yield();
        }
        if (retry && (ret = retry(retry_arg)))
            goto done;
        else
            yield();
        /*
         * The utility code assumes that an error/completion available
         * that there is no reason to call the progress function because
         * progress is occuring. Calling with count == 0 forces progress.
         */
        (void)_fab_cq_read(callf, line, conn->rx_cq, NULL, 0, NULL);
    }

 done:

    return ret;
}
