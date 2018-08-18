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

#include <internal.h>

#define NODE_CHUNKS     (128)

static int              dev_fd = -1;

static struct zhpe_shared_data *shared_data;

struct zdom_data {
    pthread_mutex_t     node_mutex;
    int32_t             node_idx;
    struct {
        uuid_t          uuid;
    }                   *nodes;
};

/* For the moment, we will do all driver I/O synchronously.*/

static int driver_cmd(union zhpe_op *op, size_t req_len, size_t rsp_len)
{
    int                 ret = 0;
    int                 opcode = op->hdr.opcode;
    ssize_t             res;

    op->hdr.version = ZHPE_OP_VERSION;
    op->hdr.index = 0;

    res = write(dev_fd, op, req_len);
    ret = check_func_io(__FUNCTION__, __LINE__, "write", DEV_NAME,
                        req_len, res, 0);
    if (ret < 0)
        goto done;

    res = read(dev_fd, op, rsp_len);
    ret = check_func_io(__FUNCTION__, __LINE__, "read", DEV_NAME,
                        rsp_len, res, 0);
    if (ret < 0)
        goto done;
    ret = -EIO;
    if (res < sizeof(op->hdr)) {
        print_err("%s,%u:Unexpected short read %lu\n",
                  __FUNCTION__, __LINE__, res);
        goto done;
    }
    ret = -EINVAL;
    if (!expected_saw("version", ZHPE_OP_VERSION, op->hdr.version))
        goto done;
    if (!expected_saw("opcode", opcode | ZHPE_OP_RESPONSE, op->hdr.opcode))
        goto done;
    if (!expected_saw("index", 0, op->hdr.index))
        goto done;
    ret = op->hdr.status;
    if (ret < 0)
        print_err("%s,%u:zhpe command 0x%02x returned error %d:%s\n",
                  __FUNCTION__, __LINE__, op->hdr.opcode,
                  -ret, strerror(-ret));

 done:
    return ret;
}

static int zhpe_lib_init(struct zhpeq_attr *attr)
{
    int                 ret = -EINVAL;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;
    ulong               check_val;
    ulong               check_off;

    dev_fd = open(DEV_NAME, O_RDWR);
    if (dev_fd == -1) {
        ret = -errno;
        print_func_err(__FUNCTION__, __LINE__, "open", DEV_NAME, ret);
        goto done;
    }

    req->hdr.opcode = ZHPE_OP_INIT;
    ret = driver_cmd(&op, sizeof(req->init), sizeof(rsp->init));
    if (ret < 0)
        goto done;

    shared_data = do_mmap(NULL, rsp->init.shared_size, PROT_READ, MAP_SHARED,
                          dev_fd, rsp->init.shared_offset, &ret);
    if (!shared_data)
        goto done;
    ret = -EINVAL;
    if (!expected_saw("shared_magic", ZHPE_MAGIC, shared_data->magic))
        goto done;
    if (!expected_saw("shared_version", ZHPE_SHARED_VERSION,
                      shared_data->version))
        goto done;
    memcpy(zhpeq_uuid, rsp->init.uuid, sizeof(zhpeq_uuid));

    check_off = rsp->init.shared_size - sizeof(ulong);
    if (check_off >= sizeof(*shared_data)) {
        check_off += rsp->init.shared_offset;
        check_val = *(ulong *)((void *)shared_data + check_off);
        if (!expected_saw("shared_check_last", check_off, check_val))
            goto done;
    }
    attr->backend = ZHPEQ_BACKEND_ZHPE;
    attr->z = shared_data->default_attr;

    ret = 0;
 done:

    return ret;
}

static void uuid_free(uuid_t uuid)
{
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    if (uuid_is_null(uuid))
        return;
    req->hdr.opcode = ZHPE_OP_UUID_FREE;
    memcpy(req->uuid_free.uuid, uuid, sizeof(req->uuid_free.uuid));
    (void)driver_cmd(&op, sizeof(req->uuid_free), sizeof(rsp->uuid_free));
    uuid_clear(uuid);
}

static int zhpe_domain_free(struct zhpeq_dom *zdom)
{
    struct zdom_data    *bdom = zdom->backend_data;
    uint32_t            i;

    if (!bdom)
        return 0;

    zdom->backend_data = NULL;
    mutex_destroy(&bdom->node_mutex);
    for (i = 0; i < bdom->node_idx; i++)
        uuid_free(bdom->nodes[i].uuid);
    do_free(bdom->nodes);
    do_free(bdom);

    return 0;
}

static int zhpe_domain(struct zhpeq_dom *zdom)
{
    int                 ret = -ENOMEM;
    struct zdom_data    *bdom;

    bdom = zdom->backend_data = do_calloc(1, sizeof(*bdom));
    if (!bdom)
        goto done;
    mutex_init(&bdom->node_mutex, NULL);
    ret = 0;

 done:

    return ret;
}

static int zhpe_qalloc(struct zhpeq *zq, int wqlen, int cqlen,
                       int traffic_class, int priority, int slice_mask)
{
    int                 ret;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    req->hdr.opcode = ZHPE_OP_XQALLOC;
    req->xqalloc.cmdq_ent = wqlen;
    req->xqalloc.cmplq_ent = wqlen;
    req->xqalloc.traffic_class = traffic_class;
    req->xqalloc.priority = priority;
    req->xqalloc.slice_mask = slice_mask;
    ret = driver_cmd(&op, sizeof(req->xqalloc), sizeof(rsp->xqalloc));
    if (ret < 0)
        goto done;
    zq->fd = dev_fd;
    zq->xqinfo = rsp->xqalloc.info;

 done:

    return ret;
}

static int zhpe_open(struct zhpeq *zq, int sock_fd)
{
    int                 ret;
    struct zdom_data    *bdom = zq->zdom->backend_data;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;
    uuid_t              uuid;

    /* FIXME: open/close should use zdom, not zq, and exchange should happen
     * in another routine. Exchange should be a sockaddr_in46 containing
     * the uuid and rdm queue, but for now exchange uuid.
     */
    mutex_lock(&bdom->node_mutex);

    ret = sock_send_blob(sock_fd, zhpeq_uuid, sizeof(zhpeq_uuid));
    if (ret < 0)
        goto done;
    ret = sock_recv_fixed_blob(sock_fd, uuid, sizeof(uuid));
    if (ret < 0)
        goto done;

    req->hdr.opcode = ZHPE_OP_UUID_IMPORT;
    memcpy(req->uuid_import.uuid, uuid, sizeof(req->uuid_import.uuid));
    ret = driver_cmd(&op, sizeof(req->uuid_import), sizeof(rsp->uuid_import));
    if (ret < 0)
        goto done;

    if ((bdom->node_idx % NODE_CHUNKS) == 0) {
        bdom->nodes = do_realloc(
            bdom->nodes, (bdom->node_idx + NODE_CHUNKS) * sizeof(*bdom->nodes));
        if (!bdom->nodes)
            ret = -ENOMEM;
    }
    if (ret >= 0) {
        if (bdom->node_idx < INT32_MAX) {
            ret = bdom->node_idx++;
            memcpy(bdom->nodes[ret].uuid, uuid, sizeof(bdom->nodes[ret].uuid));
        } else
            ret = -ENOSPC;
    }
    if (ret <  0)
        uuid_free(uuid);

 done:
    mutex_unlock(&bdom->node_mutex);

    return ret;
}

static int zhpe_close(struct zhpeq *zq, int open_idx)
{
    struct zdom_data    *bdom = zq->zdom->backend_data;

    mutex_lock(&bdom->node_mutex);
    uuid_free(bdom->nodes[open_idx].uuid);
    mutex_unlock(&bdom->node_mutex);

    return 0;
}

static int zhpe_qfree(struct zhpeq *zq)
{
    int                 ret;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    req->hdr.opcode = ZHPE_OP_XQFREE;
    req->xqfree.info = zq->xqinfo;
    ret = driver_cmd(&op, sizeof(req->xqfree), sizeof(rsp->xqfree));

    return ret;
}

static int zhpe_mr_reg(struct zhpeq_dom *zdom,
                       const void *buf, size_t len,
                       uint32_t access, struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -ENOMEM;
    struct zhpeq_mr_desc_v1 *desc = NULL;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    desc = do_malloc(sizeof(*desc));
    if (!desc)
        goto done;
    req->hdr.opcode = ZHPE_OP_MR_REG;
    req->mr_reg.vaddr = (uintptr_t)buf;
    req->mr_reg.len = len;
    desc->access_plus = access | ZHPE_MR_INDIVIDUAL;
    req->mr_reg.access = desc->access_plus;
    ret = driver_cmd(&op, sizeof(req->mr_reg), sizeof(rsp->mr_reg));
    if (ret < 0)
        goto done;

    desc->hdr.magic = ZHPE_MAGIC;
    desc->hdr.version = ZHPEQ_MR_V1;
    desc->qkdata.z.vaddr = (uintptr_t)buf;
    desc->qkdata.laddr = (uintptr_t)buf;
    desc->qkdata.z.len = len;
    desc->qkdata.z.zaddr = rsp->mr_reg.rsp_zaddr;
    desc->qkdata.z.access = access;
    desc->qkdata.z.key = 0;
    *qkdata_out = &desc->qkdata;

    ret = 0;

 done:
    if (ret < 0)
        do_free(desc);

    return ret;
}

static int zhpe_mr_free(struct zhpeq_dom *zdom, struct zhpeq_key_data *qkdata)
{
    int                 ret = -EINVAL;
    struct zhpeq_mr_desc_v1 *desc = container_of(qkdata,
                                                 struct zhpeq_mr_desc_v1,
                                                 qkdata);
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;


    if (desc->hdr.magic != ZHPE_MAGIC || desc->hdr.version != ZHPEQ_MR_V1)
        goto done;

    req->hdr.opcode = ZHPE_OP_MR_FREE;
    req->mr_free.vaddr = desc->qkdata.z.vaddr;
    req->mr_free.len = desc->qkdata.z.len;
    req->mr_free.access = desc->access_plus;
    req->mr_free.rsp_zaddr = desc->qkdata.z.zaddr;
    ret = driver_cmd(&op, sizeof(req->mr_free), sizeof(rsp->mr_free));
    do_free(desc);

 done:
    return ret;
}

static int zhpe_zmmu_import(struct zhpeq_dom *zdom, int open_idx,
                            const void *blob, size_t blob_len, bool cpu_visible,
                            struct zhpeq_key_data **qkdata_out)
{
    int                 ret = -EINVAL;
    struct zdom_data    *bdom = zdom->backend_data;
    const struct key_data_packed *pdata = blob;
    struct zhpeq_mr_desc_v1 *desc = NULL;
    uuid_t              *uuidp;
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    if (blob_len != sizeof(*pdata) || cpu_visible ||
        open_idx < 0 || open_idx >= bdom->node_idx)
        goto done;
    uuidp = &bdom->nodes[open_idx].uuid;
    if (uuid_is_null(*uuidp))
        goto done;

    ret = -ENOMEM;
    desc = do_malloc(sizeof(*desc));
    if (!desc)
        goto done;

    desc->hdr.magic = ZHPE_MAGIC;
    desc->hdr.version = ZHPEQ_MR_V1 | ZHPEQ_MR_REMOTE;
    unpack_kdata(pdata, &desc->qkdata);
    req->hdr.opcode = ZHPE_OP_RMR_IMPORT;
    memcpy(req->rmr_import.uuid, *uuidp, sizeof(req->rmr_import.uuid));
    req->rmr_import.rsp_zaddr = desc->qkdata.z.zaddr;
    desc->qkdata.rsp_zaddr = desc->qkdata.z.zaddr;
    req->rmr_import.len = desc->qkdata.z.len;
    desc->access_plus = desc->qkdata.z.access | ZHPE_MR_INDIVIDUAL;
    req->rmr_import.access = desc->access_plus;
    ret = driver_cmd(&op, sizeof(req->rmr_import), sizeof(rsp->rmr_import));
    if (ret < 0)
        goto done;
    desc->qkdata.z.zaddr = rsp->rmr_import.req_addr;
    desc->uuid_idx = open_idx;
    *qkdata_out = &desc->qkdata;

    ret = 0;

 done:
    if (ret < 0)
        do_free(desc);

    return ret;
}

static int zhpe_zmmu_free(struct zhpeq_dom *zdom, struct zhpeq_key_data *qkdata)
{
    int                 ret = -EINVAL;
    struct zdom_data    *bdom = zdom->backend_data;
    struct zhpeq_mr_desc_v1 *desc = container_of(qkdata,
                                                 struct zhpeq_mr_desc_v1,
                                                 qkdata);
    union zhpe_op       op;
    union zhpe_req      *req = &op.req;
    union zhpe_rsp      *rsp = &op.rsp;

    if (desc->hdr.magic != ZHPE_MAGIC ||
        desc->hdr.version != (ZHPEQ_MR_V1 | ZHPEQ_MR_REMOTE))
        goto done;

    req->hdr.opcode = ZHPE_OP_RMR_FREE;
    memcpy(req->rmr_free.uuid, bdom->nodes[desc->uuid_idx].uuid,
           sizeof(req->rmr_free.uuid));
    req->rmr_free.req_addr = qkdata->z.zaddr;
    req->rmr_free.len = qkdata->z.len;
    req->rmr_free.access = desc->access_plus;
    req->rmr_free.rsp_zaddr = qkdata->rsp_zaddr;
    ret = driver_cmd(&op, sizeof(req->rmr_free), sizeof(rsp->rmr_free));
    do_free(desc);

 done:
    return ret;
}

static int zhpe_zmmu_export(struct zhpeq_dom *zdom,
                            const struct zhpeq_key_data *qkdata,
                            void **blob_out, size_t *blob_len)
{
    int                 ret = -EINVAL;
    struct zhpeq_mr_desc_v1 *desc = container_of(qkdata,
                                                 struct zhpeq_mr_desc_v1,
                                                 qkdata);
    struct key_data_packed *blob = NULL;

    if (desc->hdr.magic != ZHPE_MAGIC || desc->hdr.version != ZHPEQ_MR_V1)
        goto done;

    ret = -ENOMEM;
    *blob_len = sizeof(*blob);
    blob = do_malloc(*blob_len);
    if (!blob)
        goto done;

    pack_kdata(qkdata, blob, qkdata->z.zaddr);
    *blob_out = blob;

    ret = 0;

 done:
    return ret;
}

static void zhpe_print_info(struct zhpeq *zq)
{
    print_info("GenZ ASIC backend\n");
}

static int zhpe_getaddr(struct zhpeq *zq, union sockaddr_in46 *sa)
{
    sa->sa_family = AF_ZHPE;
    memcpy(sa->zhpe.sz_uuid, &zhpeq_uuid, sizeof(sa->zhpe.sz_uuid));
    sa->zhpe.sz_queue = ZHPE_QUEUEINVAL;

    return 0;
}

char *zhpe_qkdata_id_str(struct zhpeq_dom *zdom,
                         const struct zhpeq_key_data *qkdata)
{
    char                *ret = NULL;
    struct zdom_data    *bdom = zdom->backend_data;
    struct zhpeq_mr_desc_v1 *desc = container_of(qkdata,
                                                 struct zhpeq_mr_desc_v1,
                                                 qkdata);
    char                uuid_str[37];

    if (!(desc->hdr.version & ZHPEQ_MR_REMOTE))
        goto done;

    uuid_unparse_upper(bdom->nodes[desc->uuid_idx].uuid, uuid_str);
    if (asprintf(&ret, "%d %s", desc->uuid_idx, uuid_str) == -1)
        ret = NULL;
 done:

    return ret;
}

struct backend_ops ops = {
    .lib_init           = zhpe_lib_init,
    .domain             = zhpe_domain,
    .domain_free        = zhpe_domain_free,
    .qalloc             = zhpe_qalloc,
    .qfree              = zhpe_qfree,
    .open               = zhpe_open,
    .close              = zhpe_close,
    .mr_reg             = zhpe_mr_reg,
    .mr_free            = zhpe_mr_free,
    .zmmu_import        = zhpe_zmmu_import,
    .zmmu_free          = zhpe_zmmu_free,
    .zmmu_export        = zhpe_zmmu_export,
    .print_info         = zhpe_print_info,
    .getaddr            = zhpe_getaddr,
    .qkdata_id_str      = zhpe_qkdata_id_str,
};

void zhpeq_backend_zhpe_init(int fd)
{
    if (fd == -1)
        return;

    zhpeq_register_backend(ZHPE_BACKEND_ZHPE, &ops);
}
