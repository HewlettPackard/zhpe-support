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

#include <zhpeq_util_fab.h>

static pthread_mutex_t  fab_mutex = PTHREAD_MUTEX_INITIALIZER;

enum fab_list_type {
    FAB_LIST_FABRIC,
    FAB_LIST_DOMAIN,
};

struct fab_list {
    struct fab_list     *next;
    void                *ptr;
    char                *name;
    const void          *parent;
    const void          *context;
    uint32_t            use_count;
    enum fab_list_type  type;
};

struct fab_list         *fab_list;

/* Try to have a single fabric/domain instance for each; imperfect. */

static struct fab_list *fab_list_find(const void *parent, const char *name,
                                      const void *context,
                                      enum fab_list_type type)
{
    struct fab_list     *cur;

    for (cur = fab_list; cur; cur = cur->next) {
        if (cur->type == type && cur->parent == parent &&
            cur->context == context && !strcmp(cur->name, name)) {
            cur->use_count++;
            break;
        }
    }

    return  cur;
}

static struct fab_list *fab_list_new(const char *callf, uint line,
                                     const void *parent, const char *name,
                                     const void *context,
                                     enum fab_list_type type)
{
    struct fab_list     *cur;
    size_t              len;

    len = strlen(name);
    cur = _do_calloc(callf, line, 1, sizeof(*cur) + len + 1);
    if (!cur)
        goto done;
    cur->name = (void *)(cur + 1);
    strncpy(cur->name, name, len);
    cur->parent = parent;
    cur->context = context;
    cur->use_count = 1;
    cur->type = type;

 done:
    return cur;
}

static int fab_list_fabric(const char *callf, uint line,
                           struct fi_fabric_attr *attr,
                           struct fid_fabric **fabric, void *context)
{
    int                 ret = 0;
    struct fab_list     *cur;

    mutex_lock(&fab_mutex);
    cur = fab_list_find(NULL, attr->name, context, FAB_LIST_FABRIC);
    mutex_unlock(&fab_mutex);
    if (cur) {
        *fabric = cur->ptr;
        goto done;
    }

    /* Cannot hold the mutex because of recursion in libzhpeq. */
    ret = fi_fabric(attr, fabric, context);
    if (ret < 0) {
        *fabric = NULL;
        print_func_fi_err(callf, line, "fi_fabric", "", ret);
        goto done;
    }

    mutex_lock(&fab_mutex);
    cur = fab_list_find(NULL, attr->name, context, FAB_LIST_FABRIC);
    if (cur) {
        mutex_unlock(&fab_mutex);
        fi_close(&(*fabric)->fid);
        *fabric = cur->ptr;
        goto done;
    }

    cur = fab_list_new(callf, line, NULL, attr->name, context,
                       FAB_LIST_FABRIC);
    if (cur) {
        cur->ptr = *fabric;
        cur->next = fab_list;
        fab_list = cur;
        mutex_unlock(&fab_mutex);
    } else {
        mutex_unlock(&fab_mutex);
        fi_close(&(*fabric)->fid);
        *fabric = NULL;
        ret = -ENOMEM;
    }

 done:

    return ret;
}

static int fab_list_domain(const char *callf, uint line,
                           struct fid_fabric *fabric, struct fi_info *info,
                           struct fid_domain **domain, void *context)
{
    int                 ret = 0;
    struct fab_list     *cur;

    /* Free any extra infos. */
    if (info->next) {
        fi_freeinfo(info->next);
        info->next = NULL;
    }

    mutex_lock(&fab_mutex);
    cur = fab_list_find(fabric, info->domain_attr->name, context,
                        FAB_LIST_DOMAIN);
    mutex_unlock(&fab_mutex);
    if (cur) {
        *domain = cur->ptr;
        goto done;
    }

    /* Cannot hold the mutex because of recursion in libzhpeq. */
    ret = fi_domain(fabric, info, domain, context);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_domain", "", ret);
        goto done;
    }

    mutex_lock(&fab_mutex);
    cur = fab_list_find(fabric, info->domain_attr->name, context,
                        FAB_LIST_DOMAIN);
    if (cur) {
        mutex_unlock(&fab_mutex);
        fi_close(&(*domain)->fid);
        *domain = cur->ptr;
        goto done;
    }

    cur = fab_list_new(callf, line, fabric, info->domain_attr->name, context,
                       FAB_LIST_DOMAIN);
    if (cur) {
        cur->ptr = *domain;
        cur->next = fab_list;
        fab_list = cur;
        mutex_unlock(&fab_mutex);
    } else {
        mutex_unlock(&fab_mutex);
        fi_close(&(*domain)->fid);
        *domain = NULL;
        ret = -ENOMEM;
    }

 done:

    return ret;
}

static int fab_list_close(void *ptr)
{
    int                 ret = 0;
    struct fab_list     *cur = NULL;
    struct fab_list     **prev;

    if (!ptr)
        goto done;

    mutex_lock(&fab_mutex);
    for (prev = &fab_list; (cur = *prev); prev = &cur->next) {
        if (cur->ptr == ptr) {
            if (--(cur->use_count)) {
                mutex_unlock(&fab_mutex);
                goto done;
            }
            *prev = cur->next;
            free(cur);
            break;
        }
    }
    mutex_unlock(&fab_mutex);
    /* Assuming fid is at the start, but we could fix that. */
    ret = fi_close(ptr);

 done:

    return ret;
}

static void *fab_list_get(void *ptr)
{
    struct fab_list     *cur;

    if (!ptr)
        goto done;

    mutex_lock(&fab_mutex);
    for (cur = fab_list; cur; cur = cur->next) {
        if (cur->ptr == ptr) {
            cur->use_count++;
            break;
        }
    }
    mutex_unlock(&fab_mutex);

 done:
    return ptr;
}

void fab_conn_init(struct fab_dom *dom, struct fab_conn *conn)
{
    memset(conn, 0, sizeof(*conn));
    if (dom) {
        conn->fabric = fab_list_get(dom->fab_conn.fabric);
        conn->domain = fab_list_get(dom->fab_conn.domain);
        conn->info = fi_dupinfo(dom->fab_conn.info);
        if (!conn->info) {
            print_func_err(__FUNCTION__, __LINE__, "fi_dupinfo", "", -ENOMEM);
            abort();
        }
    }
}

struct fab_conn *_fab_conn_alloc(const char *callf, uint line,
                                 struct fab_dom *dom)
{
    struct fab_conn     *ret = _do_malloc(callf, line, sizeof(*ret));

    if (ret) {
        fab_conn_init(dom, ret);
        ret->allocated = true;
    }

    return ret;
}

int fab_conn_free(struct fab_conn *conn)
{
    if (!conn)
        return 0;

    fab_mrmem_free(&conn->mrmem);
    FI_CLOSE(conn->ep);
    FI_CLOSE(conn->pep);
    FI_CLOSE(conn->rx_cq);
    FI_CLOSE(conn->tx_cq);
    FI_CLOSE(conn->av);
    FI_CLOSE(conn->eq);
    FREE(conn->domain, fab_list_close);
    FREE(conn->fabric, fab_list_close);
    FREE(conn->info, fi_freeinfo);
    FREE(conn->hints, fi_freeinfo);
    FREE(conn->service, free);
    FREE(conn->node, free);

    if (conn->allocated)
        free(conn);

    return 0;
}

int _fab_getinfo(const char *callf, uint line,
                 const char *service, const char *node,
                 const char *provider, const char *domain,
                 enum fi_ep_type ep_type, bool passive, struct fab_conn *conn)
{
    int                 ret = -EEXIST;
    uint64_t            flags = 0;

    ret = -ENOMEM;
    conn->node = _strdup_or_null(callf, line, node);
    if (node && !conn->node)
        goto done;

    conn->hints = fi_allocinfo();
    if (!conn->hints) {
        print_func_err(callf, line, "fi_allocinfo", "", ret);
        goto done;
    }

    conn->hints->fabric_attr->prov_name =
        _strdup_or_null(callf, line, provider);
    if (provider && !conn->hints->fabric_attr->prov_name)
        goto done;

    conn->hints->caps = (FI_RMA | FI_READ | FI_WRITE |
                       FI_REMOTE_READ | FI_REMOTE_WRITE);
    conn->hints->mode = (FI_LOCAL_MR | FI_RX_CQ_DATA |
                         FI_CONTEXT | FI_CONTEXT2);
    conn->hints->ep_attr->type = ep_type;
    /* XXX: conn->hints->domain_attr->data_progress = FI_PROGRESS_MANUAL; */
    conn->hints->domain_attr->mr_mode = FI_MR_BASIC;
    if (domain) {
        conn->hints->domain_attr->name = _strdup_or_null(callf, line, domain);
        if (domain && !conn->hints->domain_attr->name)
            goto done;
    }
    conn->hints->addr_format = FI_SOCKADDR;
    if (passive) {
        if (!service)
            service = "0";
        flags = FI_SOURCE;
    }
    conn->service = strdup_or_null(service);
    if (service && !conn->service)
        goto done;

    ret = fi_getinfo(FAB_FIVERSION, conn->node, conn->service, flags,
                     conn->hints, &conn->info);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_getinfo", "", ret);
        goto done;
    }
    fi_freeinfo(conn->hints);
    conn->hints = NULL;

 done:
    return ret;
}

int _fab_listener_setup(const char *callf, uint line, int backlog,
                        struct fab_conn *listener)
{
    int                 ret;
    struct fi_eq_attr   eq_attr = { .wait_obj = FI_WAIT_UNSPEC };

    ret = fab_list_fabric(callf, line, listener->info->fabric_attr,
                          &listener->fabric, NULL);
    if (ret < 0)
        goto done;
    ret = fi_eq_open(listener->fabric, &eq_attr, &listener->eq, NULL);
    if (ret < 0) {
	print_func_fi_err(callf, line, "fi_eq_open", "", ret);
	goto done;
    }
    ret = fi_passive_ep(listener->fabric, listener->info,
                        &listener->pep, NULL);
    if (ret < 0) {
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
	print_func_fi_err(__FUNCTION__, __LINE__, "fi_listen", "", ret);
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
    conn->info = entry.info;
    /* Provider name may not be filled in, but we might want it, later. */
    if (!conn->info->fabric_attr->prov_name)
        conn->info->fabric_attr->prov_name =
            _strdup_or_null(callf, line,
                            listener->info->fabric_attr->prov_name);
    ret = fab_list_domain(callf, line, listener->fabric, conn->info,
                          &conn->domain, NULL);
    if (ret < 0)
	goto done;
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
        ret = -EINVAL;
        goto done;
    }

 done:
    return ret;
}

int _fab_connect(const char *callf, uint line, int timeout,
                 size_t tx_size, size_t rx_size, struct fab_conn *conn)
{
    int                 ret;
    struct fi_eq_attr   eq_attr = { .wait_obj = FI_WAIT_UNSPEC };
    struct fi_eq_cm_entry entry;

    ret = fab_list_fabric(callf, line, conn->info->fabric_attr,
                          &conn->fabric, NULL);
    if (ret < 0)
        goto done;
    ret = fi_eq_open(conn->fabric, &eq_attr, &conn->eq, NULL);
    if (ret < 0) {
	print_func_fi_err(callf, line, "fi_eq_open", "", ret);
	goto done;
    }
    ret = fab_list_domain(callf, line, conn->fabric, conn->info,
                          &conn->domain, NULL);
    if (ret < 0)
	goto done;
    ret = _fab_ep_setup(callf, line, conn, conn->eq, tx_size, rx_size);
    if (ret < 0)
        goto done;
    ret = fi_connect(conn->ep, conn->info->dest_addr, NULL, 0);
    if (ret) {
	print_func_fi_err(__FUNCTION__, __LINE__, "fi_connect", "", ret);
	goto done;
    }
    /* Wait to be fully connected. */
    ret = _fab_eq_cm_event(callf, line, conn, timeout, FI_CONNECTED, &entry);
    if (ret < 0)
        goto done;
    if (!_expected_saw(callf, line, "CONN fid", (uintptr_t)&conn->ep->fid,
                       (uintptr_t)entry.fid))  {
        ret = -EINVAL;
        goto done;
    }

 done:
    return ret;
}

int _fab_ep_setup(const char *callf, uint line,
                  struct fab_conn *conn, struct fid_eq *eq,
                  size_t tx_size, size_t rx_size)
{
    int                 ret = -EEXIST;
    struct fi_cq_attr   tx_cq_attr =  {
        .format = FI_CQ_FORMAT_CONTEXT,
        .wait_obj = FI_WAIT_NONE,
    };
    struct fi_cq_attr   rx_cq_attr =  {
        .format = FI_CQ_FORMAT_CONTEXT,
        .wait_obj = FI_WAIT_NONE,
    };
    struct fi_av_attr   av_attr = { .type = FI_AV_TABLE };

    tx_size = (tx_size ?:conn->info->tx_attr->size);
    conn->info->tx_attr->size = tx_size;
    tx_cq_attr.size = tx_size;
    rx_size = (rx_size ?: conn->info->rx_attr->size);
    conn->info->rx_attr->size = rx_size;
    rx_cq_attr.size = rx_size;

    ret = fi_endpoint(conn->domain, conn->info, &conn->ep, NULL);
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
    ret = fi_cq_open(conn->domain, &tx_cq_attr, &conn->tx_cq, NULL);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_cq_open", "tx", ret);
        goto done;
    }
    ret = fi_ep_bind(conn->ep, &conn->tx_cq->fid, FI_TRANSMIT);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_ep_bind", "tx_cq", ret);
        goto done;
    }
    ret = fi_cq_open(conn->domain, &rx_cq_attr, &conn->rx_cq, NULL);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_cq_open", "rx", ret);
        goto done;
    }
    ret = fi_ep_bind(conn->ep, &conn->rx_cq->fid, FI_RECV);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_ep_bind", "rx_cq", ret);
        goto done;
    }
    if (conn->info->ep_attr->type == FI_EP_RDM) {
        ret = fi_av_open(conn->domain, &av_attr, &conn->av, NULL);
        if (ret < 0) {
            print_func_fi_err(callf, line, "fi_av_open", "", ret);
            goto done;
        }
        ret = fi_ep_bind(conn->ep, &conn->av->fid, 0);
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
            print_func_fi_err(callf, line, __FUNCTION__, "", ret);
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

    if (!access)
        access = (FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE);
    ret = fi_mr_reg(conn->domain, mrmem->mem, len, access, 0, 0, 0,
                    &mrmem->mr, NULL);
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_mr_reg", "", ret);
        goto done;
    }

 done:
    return ret;
}

void fab_mrmem_free(struct fab_mrmem *mrmem)
{
    if (!mrmem)
        return;

    FI_CLOSE(mrmem->mr);
    free(mrmem->mem);
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
    struct fi_cq_tagged_entry  fi_cqe[1];
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
        rc = fab_cq_read(cq, fi_cqe, len, (cq_update ? &fi_cqerr : NULL));
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
    struct fab_conn     fab_conn;
    struct fi_info      *info;

    if (conn)
        info = conn->info;
    else {
        fab_conn_init(NULL, &fab_conn);
        (void)fab_getinfo(NULL, NULL, NULL, NULL, FI_EP_UNSPEC, false,
                          &fab_conn);
        info = fab_conn.info;
    }

    if (!conn && info)
        printf("Available providers/domains:\n");
    for (; info; info = info->next) {
        printf("provider %s domain %s tx_size %Lu ep_type %s\n",
               info->fabric_attr->prov_name, info->domain_attr->name,
               (ullong)info->tx_attr->size,
               fi_tostr(&info->ep_attr->type, FI_TYPE_EP_TYPE));
        /* Only print the active info for a live conn. */
        if (conn)
            break;
    }

    if (!conn)
        fab_conn_free(&fab_conn);
}

int _fab_av_domain(const char *callf, uint line, const char *provider,
                   const char *domain, struct fab_dom *dom)
{
    int                 ret;
    struct fab_conn     *conn = &dom->fab_conn;

    ret = _fab_getinfo(callf, line, NULL, NULL, provider, domain, FI_EP_RDM,
                       false, conn);
    if (ret < 0)
        goto done;
    ret = fab_list_fabric(callf, line, conn->info->fabric_attr,
                          &conn->fabric, NULL);
    if (ret < 0) {
	print_func_fi_err(callf, line, "fi_fabric", "", ret);
	goto done;
    }
    ret = fab_list_domain(callf, line, conn->fabric, conn->info,
                          &conn->domain, NULL);
    if (ret < 0)
	goto done;

 done:
    return ret;
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

    ret = fi_getname(&conn->ep->fid, ep_addr, &addr_len);
    if (ret >= 0 && !sockaddr_valid(ep_addr, addr_len, true))
        ret = -EAFNOSUPPORT;
    if (ret < 0) {
        print_func_fi_err(callf, line, "fi_getname", "", ret);
        goto done;
    }
    if (ret < 0 || sock_fd == -1)
        goto done;
    ret = _sock_send_blob(callf, line, sock_fd, ep_addr, addr_len);
    if (ret < 0)
        goto done;
    ret = _sock_recv_fixed_blob(callf, line, sock_fd, ep_addr, addr_len);
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
        return -ETIMEDOUT;
    gettime(&ts_cur);
    if (ts_delta(&args->ts_beg, &ts_cur) >= args->timeout_ns)
        return -ETIMEDOUT;

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
        gettime(&retry_args.ts_beg);
    }
    ret = _fab_av_xchg_addr(callf, line, conn, sock_fd, &ep_addr);
    if (ret < 0)
        goto done;
    ret = _fab_av_insert(callf, line, conn, &ep_addr, fi_addr);
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
            _fab_av_remove(callf, line, conn, *fi_addr);
        print_func_err(callf, line, "_fab_av_xchg", "", ret);
    }

    return ret;
}

int _fab_av_insert(const char *callf, uint line, struct fab_conn *conn,
                   union sockaddr_in46 *saddr, fi_addr_t *fi_addr)
{
    int                 ret;

    ret = fi_av_insert(conn->av, saddr, 1,  fi_addr, 0, NULL);
    if (ret < 0) {
	print_func_fi_err(callf, line, "fi_av_insert", "", ret);
        goto done;
    } else if (!_expected_saw(callf, line, "fi_av_insert", 1, ret)) {
        ret = -FI_EINVAL;
        goto done;
    }

 done:
    if (ret < 0)
        *fi_addr = FI_ADDR_UNSPEC;

    return ret;
}

int _fab_av_remove(const char *callf, uint line, struct fab_conn *conn,
                   fi_addr_t idx)
{
    int                 ret;

    ret = fi_av_remove(conn->av, &idx, 1, 0);
    if (ret < 0)
	print_func_fi_err(callf, line, "fi_av_remove", "", ret);

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
            sched_yield();
    }
    if (ret < 0) {
	print_func_fi_err(callf, line, "fi_tinject", "", ret);
        goto done;
    }

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
                sched_yield();
        }
        if (retry && (ret = retry(retry_arg)))
            goto done;
        else
            sched_yield();
    }

 done:

    return ret;
}
