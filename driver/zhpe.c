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

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/uaccess.h>

#if LINUX_VERSION_CODE >=  KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#endif
#include <zhpe.h>

static const char driver_name[] = DRIVER_NAME;

static atomic64_t       mem_total = ATOMIC64_INIT(0);

#define DEBUG_TRACKER_SANE (0)

static struct zmap *shared_zmap;
static struct zhpe_shared_data *shared_data;

static DEFINE_SPINLOCK(zmap_lock);
/* XXX: potentially 3000 entries, rbtree? */
static LIST_HEAD(zmap_list);
#define ZMAP_BAD_OWNER  (ERR_PTR(-EACCES))

struct io_entry {
    void                (*free)(const char *callf, uint line, void *ptr);
    atomic_t            count;
    bool                nonblock;
    struct zhpe_common_hdr hdr;
    struct file_data    *fdata;
    struct list_head    list;
    size_t              data_len;
    union {
        uint8_t         data[0];
        union zhpe_op   op;
    };
};

enum {
    STATE_CLOSED        = 1,
    STATE_READY         = 2,
};

struct zpages {
    size_t              size;
    void                *pages[0];
};

struct zmap {
    struct list_head    list;
    struct file_data    *owner;
    ulong               offset;
    struct zpages       *zpages;
};

struct file_data {
    void                (*free)(const char *callf, uint line, void *ptr);
    atomic_t            count;
    uint8_t             state;
    spinlock_t          io_lock;
    wait_queue_head_t   io_wqh;
    struct list_head    rd_list;
};

#define TRACKER_MAX     (256)

struct helper_data {
    struct file_data    fdata;
    struct task_struct  *task;
    wait_queue_head_t   tracker_wqh;
    uint                tracker_max;
    uint                tracker_freecnt;
    void                *tracker_free;
    struct io_entry     *tracker[0];
};

static int __init zhpe_init(void);
static void zhpe_exit(void);

module_init(zhpe_init);
module_exit(zhpe_exit);

MODULE_LICENSE("GPL");

static pid_t            helper_pid;
static struct helper_data *helper_data;
static DECLARE_WAIT_QUEUE_HEAD(helper_wqh);

static DECLARE_WAIT_QUEUE_HEAD(poll_wqh);

#define HELPER_EXIT_TIMEOUT (5 * HZ)

static char *helper_path = "/sbin/zhpe_helper";
module_param(helper_path, charp, 0444);
MODULE_PARM_DESC(helper_path, "path-to-helper");

/* "libfabric" is the default for now. */
static char *backend = "libfabric";
module_param(backend, charp, 0444);
MODULE_PARM_DESC(backend, "backend transport: zhpe, libfabric (default)");

static uint tracker_max = TRACKER_MAX;
module_param(tracker_max, uint, 0444);
MODULE_PARM_DESC(tracker_max, "Maximum outstanding requests to helper");

static uint debug_flags;

#if defined(NDEBUG)
#define debug_cond(_mask, _cond, _fmt, ...) do {} while (0)
#define debug(_mask, _fmt, ...) do {} while (0)
#define debug_mem_add(_size)
#define debug_mem_sub(_size)
#else
module_param_named(debug, debug_flags, uint, 0644);
MODULE_PARM_DESC(debug, "debug output bitmask");

#define  debug_cond(_mask,_cond,  _fmt, ...)            \
do {                                                    \
    if ((debug_flags & (_mask)) && (_cond))             \
        printk(KERN_DEBUG _fmt, ##__VA_ARGS__);         \
} while (0)
#define debug(_mask, _fmt, ...) debug_cond(_mask, true, _fmt, ##__VA_ARGS__)

#endif /* defined(NDEBUG) */

static bool _expected_saw(const char *callf, uint line,
                          const char *label, uintptr_t expected, uintptr_t saw)
{
    if (expected == saw)
        return true;

    printk(KERN_ERR "%s,%u:%s:%s:expected 0x%lx saw 0x%lx\n",
           callf, line, __FUNCTION__, label, expected, saw);

    return false;
}

#define expected_saw(...) \
    _expected_saw(__FUNCTION__, __LINE__, __VA_ARGS__)

static void _do_kfree(const char *callf, uint line, void *ptr)
{
    size_t              size;

    if (!ptr)
        return;

    ptr -= sizeof(void *);
    size = *(uintptr_t *)ptr;
    atomic64_sub(size, &mem_total);
    debug(DEBUG_MEM, "%s:%s,%u:%s:ptr 0x%p size %lu\n",
          driver_name, callf, line, __FUNCTION__, ptr, size);
    kfree(ptr);
}

#define do_kfree(...) \
    _do_kfree(__FUNCTION__, __LINE__, __VA_ARGS__)

static void *_do_kmalloc(const char *callf, uint line,
                         size_t size, gfp_t flags, bool zero)
{
    void                *ret;

    /* kmalloc alignment is sizeof(void *) */
    ret = kmalloc(size + sizeof(void *), flags);
    if (!ret) {
        if (flags != GFP_ATOMIC)
            printk(KERN_ERR "%s:%s,%d:%s:failed to allocate %lu bytes\n",
                   driver_name, callf, line, __FUNCTION__, size);
        return NULL;
    }
    if (zero)
        memset(ret, 0, size);
    debug(DEBUG_MEM, "%s:%s,%u:%s:ret 0x%p size %lu\n",
          driver_name, callf, line, __FUNCTION__, ret, size);
    atomic64_add(size, &mem_total);
    *(uintptr_t *)ret = size;
    ret += sizeof(void *);

    return ret;
}

#define do_kmalloc(...) \
    _do_kmalloc(__FUNCTION__, __LINE__, __VA_ARGS__)

static void _do_free_pages(const char *callf, uint line, void *ptr, int order)
{
    size_t              size;
    struct page         *page;

    if (!ptr)
        return;

    size = 1UL << (order + PAGE_SHIFT);
    atomic64_sub(size, &mem_total);
    page = virt_to_page(ptr);
    (void)page;
    debug(DEBUG_MEM, "%s:%s,%u:%s:ptr/page/pfn 0x%p/0x%p/0x%lx size %lu\n",
          driver_name, callf, line, __FUNCTION__,
          ptr, page, page_to_pfn(page), size);
    free_pages((ulong)ptr, order);
}

#define do_free_pages(...) \
    _do_free_pages(__FUNCTION__, __LINE__, __VA_ARGS__)

static void *_do__get_free_pages(const char *callf, uint line,
                                int order, gfp_t flags, bool zero)
{
    void                *ret;
    size_t              size = 1UL << (order + PAGE_SHIFT);
    struct page         *page;

    ret = (void *)__get_free_pages(flags, order);
    if (!ret) {
        if (flags != GFP_ATOMIC)
            printk(KERN_ERR "%s:%s,%u:%s:failed to allocate %lu bytes\n",
                   driver_name, callf, line, __FUNCTION__, size);
        return NULL;
    }
    if (zero)
        memset(ret, 0, size);
    atomic64_add(size, &mem_total);
    page = virt_to_page(ret);
    (void)page;
    debug(DEBUG_MEM, "%s:%s,%u:%s:ret/page/pfn 0x%p/0x%p/0x%lx size %lu\n",
          driver_name, callf, line, __FUNCTION__,
          ret, page, page_to_pfn(page), size);

    return ret;
}

#define do__get_free_pages(...) \
    _do__get_free_pages(__FUNCTION__, __LINE__, __VA_ARGS__)

static inline void _put_io_entry(const char *callf, uint line,
                                 struct io_entry *entry)
{
    int                 count;

    if (entry) {
        count = atomic_dec_return(&entry->count);
        debug(DEBUG_COUNT, "%s:%s,%u:%s:entry 0x%p count %d\n",
              driver_name, callf, line, __FUNCTION__, entry, count);
        if (!count && entry->free)
            entry->free(callf, line, entry);
    }
}

#define put_io_entry(...) \
    _put_io_entry(__FUNCTION__, __LINE__, __VA_ARGS__)

static inline struct io_entry *_get_io_entry(const char *callf, uint line,
                                             struct io_entry *entry)
{
    int                 count;

    if (!entry)
        return NULL;

    count = atomic_inc_return(&entry->count);
    /* Override unused variable warning. */
    (void)count;
    debug(DEBUG_COUNT, "%s:%s,%u:%s:entry 0x%p count %d\n",
          driver_name, callf, line, __FUNCTION__, entry, count);

    return entry;
}

#define get_io_entry(...) \
    _get_io_entry(__FUNCTION__, __LINE__, __VA_ARGS__)

static void _free_io_lists(const char *callf, uint line,
                           struct file_data *fdata)
{
    struct io_entry     *next;
    struct io_entry     *entry;
    int i = 0;

    debug(DEBUG_RELEASE, "%s:%s,%u:%s:fdata 0x%p\n",
          driver_name, callf, line, __FUNCTION__, fdata);

    list_for_each_entry_safe(entry, next, &fdata->rd_list, list) {
        debug(DEBUG_RELEASE, "%s:%s,%u:i %d entry 0x%p idx 0x%04x\n",
              driver_name, __FUNCTION__, __LINE__, i, entry,
              entry->op.hdr.index);
        list_del_init(&entry->list);
        put_io_entry(entry);
        i++;
    }
}

#define free_io_lists(...) \
    _free_io_lists(__FUNCTION__, __LINE__, __VA_ARGS__)

static void file_data_free(const char *callf, uint line, void *ptr)
{
    _do_kfree(callf, line, ptr);
}

static inline void _put_file_data(const char *callf, uint line,
                                  struct file_data *fdata)
{
    int                 count;

    if (fdata) {
        count = atomic_dec_return(&fdata->count);
        debug(DEBUG_COUNT, "%s:%s,%u:%s:fdata 0x%p count %d\n",
              driver_name, callf, line, __FUNCTION__, fdata, count);
        if (!count && fdata->free)
            fdata->free(callf, line, fdata);
    }
}

#define put_file_data(...) \
    _put_file_data(__FUNCTION__, __LINE__, __VA_ARGS__)

static inline struct file_data *_get_file_data(const char *callf, uint line,
                                               struct file_data *fdata)
{
    int                 count;

    if (!fdata)
        return NULL;

    count = atomic_inc_return(&fdata->count);
    /* Override unused variable warning. */
    (void)count;
    debug(DEBUG_COUNT, "%s:%s,%u:%s:fdata 0x%p count %d\n",
          driver_name, callf, line, __FUNCTION__, fdata, count);

    return fdata;
}

#define get_file_data(...) \
    _get_file_data(__FUNCTION__, __LINE__, __VA_ARGS__)

static void _zpages_free(const char *callf, uint line, struct zpages *zpages)
{
    size_t              npages;
    size_t              i;
    struct page         *page;

    if (!zpages)
        return;

    debug(DEBUG_MEM, "%s:%s,%u:%s:zpages 0x%p\n",
          driver_name, callf, line, __FUNCTION__, zpages);

    npages = zpages->size >> PAGE_SHIFT;
    for (i = 0; i < npages; i++) {
        page = virt_to_page(zpages->pages[i]);
        if (page_count(page) != 1 || page_mapcount(page) != 0)
            printk(KERN_WARNING
                   "%s:%s,%u:i %lu ptr/page/pfn 0x%p/0x%p/0x%lx c %d/%d\n",
                   driver_name, __FUNCTION__, __LINE__, i, zpages->pages[i],
                   page, page_to_pfn(page), page_count(page),
                   page_mapcount(page));
        do_free_pages(zpages->pages[i], 0);
    }
    do_kfree(zpages);
}

#define zpages_free(...) \
    _zpages_free(__FUNCTION__, __LINE__, __VA_ARGS__)

static struct zpages *_zpages_alloc(const char *callf, uint line,
                                    size_t size, bool contig)
{
    struct zpages       *ret = NULL;
    int                 order = 0;
    size_t              npages;
    size_t              i;

    debug(DEBUG_MEM, "%s:%s,%u:%s:size %lu contig %d\n",
          driver_name, callf, line, __FUNCTION__, size, contig);

    if  (contig) {
        order = get_order(size);
        npages = 1UL << order;
        size = npages << PAGE_SHIFT;
    } else {
        size = PAGE_ALIGN(size);
        npages = size >> PAGE_SHIFT;
    }

    ret = do_kmalloc(sizeof(*ret) + npages * sizeof(ret->pages[0]),
                     GFP_KERNEL, true);
    if (!ret || !npages)
        goto done;

    ret->size = size;
    if (contig) {
        ret->pages[0] = _do__get_free_pages(callf, line,
                                            order, GFP_KERNEL | __GFP_ZERO,
                                            true);
        i = 1;
        if (ret->pages[0]) {
            split_page(virt_to_page(ret->pages[0]), order);
            for (; i < npages; i++)
                ret->pages[i] = ret->pages[i - 1] + PAGE_SIZE;
        }
    } else {
        for (i = 0; i < npages; i++) {
            ret->pages[i] = _do__get_free_pages(callf, line,
                                                0, GFP_KERNEL | __GFP_ZERO,
                                                true);
            if (!ret->pages[i])
                break;
        }
    }
    if (!ret->pages[i-1]) {
        for (i = 0; i < npages; i++)
            do_free_pages(ret->pages[i], 0);
        do_kfree(ret);
        ret = NULL;
    }

 done:
    debug(DEBUG_MEM, "%s:%s,%u:%s:ret 0x%p\n",
          driver_name, callf, line, __FUNCTION__, ret);

    return ret;
}

#define zpages_alloc(...) \
    _zpages_alloc(__FUNCTION__, __LINE__, __VA_ARGS__)

static void _zmap_free(const char *callf, uint line, struct zmap *zmap)
{
    if (!zmap)
        return;

    debug(DEBUG_MEM, "%s:%s,%u:%s:zmap 0x%p offset 0x%lx size 0x%lx\n",
          driver_name, callf, line, __FUNCTION__,
          zmap, zmap->offset, zmap->zpages->size);

    if (zmap->zpages)
        zpages_free(zmap->zpages);
    do_kfree(zmap);
}

#define zmap_free(...) \
    _zmap_free(__FUNCTION__, __LINE__, __VA_ARGS__)

static struct zmap *_zmap_alloc(const char *callf, uint line,
                               struct zpages *zpages)
{
    struct zmap         *ret;
    struct zmap         *cur;
    ulong               coff;
    size_t              size;

    debug(DEBUG_MEM, "%s:%s,%u:%s:zpages 0x%p\n",
          driver_name, callf, line, __FUNCTION__, zpages);

    ret = _do_kmalloc(callf, line, sizeof(*ret), GFP_KERNEL, true);
    if (!ret) {
        ret = ERR_PTR(-EINVAL);
        goto done;
    }

    INIT_LIST_HEAD(&ret->list);
    ret->zpages = zpages;
    /* Set bad owner to keep entry from being used until ready. */
    ret->owner = ZMAP_BAD_OWNER;
    /*
     * Look for a hole in betwen entries; allow space for unmapped pages
     * between entries.
     */
    size = zpages->size + PAGE_SIZE * 2;
    coff = 0;
    spin_lock(&zmap_lock);
    list_for_each_entry(cur, &zmap_list, list) {
        if (cur->offset - coff >= size)
            break;
        coff = cur->offset + cur->zpages->size;
    }
    /*
     * cur will either point to a real entry before which we want to insert
     * ret or &cur->list == head and we want to add ourselves at the tail.
     *
     * Can we wrap around in real life? Probably not.
     */
    if (coff < coff + size) {
        ret->offset = coff;
        if (coff)
            ret->offset += PAGE_SIZE;
        list_add_tail(&ret->list, &cur->list);
    }
    spin_unlock(&zmap_lock);
    if (list_empty(&ret->list)) {
        _zmap_free(callf, line, ret);
        printk(KERN_ERR "%s:%s,%u:Out of file space.\n",
               driver_name, __FUNCTION__, __LINE__);
        ret = ERR_PTR(-ENOSPC);
        goto done;
    }

 done:
    return ret;
}

#define zmap_alloc(...) \
    _zmap_alloc(__FUNCTION__, __LINE__, __VA_ARGS__)

static bool _free_zmap_list(const char *callf, uint line,
                            struct file_data *fdata)
{
    bool                ret = true;
    struct zmap         *zmap;
    struct zmap         *next;

    debug(DEBUG_RELEASE, "%s:%s,%u:%s:fdata 0x%p\n",
          driver_name, callf, line, __FUNCTION__, fdata);

    spin_lock(&zmap_lock);
    list_for_each_entry_safe(zmap, next, &zmap_list, list) {
        if (!fdata || zmap->owner == fdata) {
            list_del_init(&zmap->list);
            zmap_free(zmap);
        }
    }
    spin_unlock(&zmap_lock);

    return ret;
}

#define free_zmap_list(...) \
    _free_zmap_list(__FUNCTION__, __LINE__, __VA_ARGS__)

static inline void queue_io_entry_locked(struct file_data *fdata,
                                         struct list_head *head,
                                         struct io_entry *entry)
{
    bool                wake = list_empty(head);

    list_add_tail(&entry->list, head);
    spin_unlock(&fdata->io_lock);
    wake_up(&fdata->io_wqh);
    if (wake)
        wake_up_all(&poll_wqh);
}

static inline int queue_io_entry(struct file_data *fdata,
                                 struct list_head *head,
                                 struct io_entry *entry)
{
    int                 ret = 0;

    spin_lock(&fdata->io_lock);
    if (fdata->state & STATE_CLOSED) {
        ret = -EIO;
        spin_unlock(&fdata->io_lock);
    } else
        queue_io_entry_locked(fdata, head, entry);

    return ret;
}

static void io_free(const char *callf, uint line, void *ptr)
{
    struct io_entry     *entry = ptr;

    _put_file_data(callf, line, entry->fdata);
    _do_kfree(callf, line, entry);
}

static inline struct io_entry *_io_alloc(
    const char *callf, uint line, size_t size, bool nonblock,
    struct file_data *fdata,
    void (*free)(const char *callf, uint line, void *ptr))
{
    struct io_entry     *ret = NULL;

    if (size < sizeof(ret->op))
        size = sizeof(ret->op);
    size += sizeof(*ret);
    ret = do_kmalloc(size, (nonblock ? GFP_ATOMIC : GFP_KERNEL), false);
    if (!ret)
        goto done;

    ret->free = free;
    atomic_set(&ret->count, 1);
    ret->nonblock = nonblock;
    ret->fdata = get_file_data(fdata);
    INIT_LIST_HEAD(&ret->list);

 done:

    return ret;
}

#define io_alloc(...) \
    _io_alloc(__FUNCTION__, __LINE__, __VA_ARGS__)

#if DEBUG_TRACKER_SANE

static bool tracker_sane_locked(const char *callf, uint line,
                                struct helper_data *hdata)
{
    bool                ret = true;
    uintptr_t           cur;
    uint64_t            check[TRACKER_MAX / 64];
    uint                i;

    memset(check, 0, sizeof(check));
    for (i = 0, cur = (uintptr_t)hdata->tracker_free;
         i < hdata->tracker_freecnt;
         i++, cur = (uintptr_t)hdata->tracker[cur]) {
        if (!cur)
            break;
        if (cur >= hdata->tracker_max)
            break;
        check[cur >> 6] |= (((uint64_t)1) << (cur & 63));
    }
    if (i != hdata->tracker_freecnt || (i && cur)) {
        spin_unlock(&hdata->fdata.io_lock);
        printk(KERN_ERR "%s:%s,%u:i %u free %u  cur %lu\n",
               driver_name, callf, line, i, hdata->tracker_freecnt, cur);
        spin_lock(&hdata->fdata.io_lock);
        ret = false;
        goto done;
    }
    for (i = 1; i < TRACKER_MAX; i++) {
        if (!(check[i >> 6] & (((uint64_t)1) << (i & 63))) &&
            (uintptr_t)hdata->tracker[i] < hdata->tracker_max)
            break;
    }
    if (i != TRACKER_MAX) {
        spin_unlock(&hdata->fdata.io_lock);
        printk(KERN_ERR "%s:%s,%u:i %u ptr 0x%lx\n",
               driver_name, callf, line, i, (uintptr_t)hdata->tracker[i]);
        spin_lock(&hdata->fdata.io_lock);
        ret = false;
        goto done;
    }
 done:

    return ret;
}

static bool tracker_sane(const char *callf, uint line,
                         struct helper_data *hdata)
{
    bool                ret;

    spin_lock(&hdata->fdata.io_lock);
    ret = tracker_sane_locked(callf, line, hdata);
    spin_unlock(&hdata->fdata.io_lock);

    return ret;
}

#else

static inline bool tracker_sane_locked(const char *callf, uint line,
                                  struct helper_data *hdata)
{
    return true;
}

static inline bool tracker_sane(const char *callf, uint line,
                                struct helper_data *hdata)
{
    return true;
}

#endif

static struct io_entry *_tracker_fetch(const char *callf, uint line,
                                       struct helper_data *hdata, uint index)
{
    struct io_entry     *ret = NULL;
    bool                wake = false;

    if (index < 1 || index >= hdata->tracker_max)
        goto done;

    spin_lock(&hdata->fdata.io_lock);
    if (!tracker_sane_locked(__FUNCTION__, __LINE__, hdata))
        goto unlock;
    ret = hdata->tracker[index];
    /* Kernel addresses >> hdata->tracker_max */
    if ((uintptr_t)ret >= hdata->tracker_max && list_empty(&ret->list)) {
        wake = !(uintptr_t)hdata->tracker_free;
        hdata->tracker[index] = hdata->tracker_free;
        hdata->tracker_free = (void *)(uintptr_t)index;
        hdata->tracker_freecnt++;
        if (!tracker_sane_locked(__FUNCTION__, __LINE__, hdata))
            goto unlock;
    }
 unlock:
    spin_unlock(&hdata->fdata.io_lock);
    wake_up(&hdata->tracker_wqh);
    if (wake)
        wake_up_all(&poll_wqh);

 done:
    if (!ret)
        printk(KERN_ERR "%s:%s,%u:No entry found for index 0x%04x\n",
               driver_name, callf, line, index);

    return ret;
}

#define tracker_fetch(...) \
    _tracker_fetch(__FUNCTION__, __LINE__, __VA_ARGS__)

static int try_tracker_save(struct helper_data *hdata, struct io_entry *entry)
{
    int                 ret = 0;

    spin_lock(&hdata->fdata.io_lock);
    if (!tracker_sane_locked(__FUNCTION__, __LINE__, hdata))
        ret = -EIO;
    else if (hdata->fdata.state & STATE_CLOSED)
        ret = -EIO;
    else if ((ret = (uintptr_t)hdata->tracker_free)) {
        hdata->tracker_free = hdata->tracker[ret];
        hdata->tracker[ret] = entry;
        hdata->tracker_freecnt--;
        entry->op.hdr.index = ret;
        if (tracker_sane_locked(__FUNCTION__, __LINE__, hdata)) {
            get_io_entry(entry);
            queue_io_entry_locked(&hdata->fdata, &hdata->fdata.rd_list, entry);
            goto done;
        } else
            ret = -EIO;
    } else if (entry->nonblock)
        ret = -EAGAIN;
    spin_unlock(&hdata->fdata.io_lock);

 done:

    return ret;
}

static int tracker_save(struct helper_data *hdata, struct io_entry *entry)
{
    int                 ret;
    int                 rc;

    ret = try_tracker_save(hdata, entry);
    if (ret)
        goto done;
    rc = wait_event_interruptible(hdata->tracker_wqh,
                                  (ret = try_tracker_save(hdata, entry)));
    if (!ret)
        ret = rc;

 done:

    return ret;
}

static int queue_io_rsp(struct io_entry *entry, size_t data_len, int status)
{
    int                 ret = 0;
    struct file_data    *fdata = entry->fdata;
    struct zhpe_common_hdr *op_hdr = &entry->op.hdr;

    op_hdr->version = ZHPE_OP_VERSION;
    op_hdr->opcode = entry->hdr.opcode | ZHPE_OP_RESPONSE;
    op_hdr->index = entry->hdr.index;
    op_hdr->status = status;
    if (!data_len)
        data_len = sizeof(*op_hdr);
    entry->data_len = data_len;

    if (fdata)
        ret = queue_io_entry(fdata, &fdata->rd_list, entry);

    return ret;
}

static int queue_io_helper(struct io_entry *entry, size_t data_len)
{
    struct helper_data  *hdata = helper_data;
    struct zhpe_common_hdr *op_hdr = &entry->op.hdr;

    op_hdr->version = ZHPE_OP_VERSION;
    entry->data_len = data_len;

    return tracker_save(hdata, entry);
}

static int zhpe_user_req_INIT(struct io_entry *entry)
{
    union zhpe_rsp      *rsp = &entry->op.rsp;

    rsp->init.shared_offset = shared_zmap->offset;
    rsp->init.shared_size = shared_zmap->zpages->size;
    return queue_io_rsp(entry, sizeof(rsp->init), 0);
}

static int zhpe_user_req_MR_REG(struct io_entry *entry)
{
    return -ENOSYS;
}

static int zhpe_user_req_MR_DEREG(struct io_entry *entry)
{
    return -ENOSYS;
}

static int zhpe_user_req_NOP(struct io_entry *entry)
{
    union zhpe_req      *req = &entry->op.req;

    req->hdr.opcode = ZHPE_OP_HELPER_NOP;
    return queue_io_helper(entry, sizeof(req->helper_nop));
}

static int zhpe_user_req_QALLOC(struct io_entry *entry)
{
    int                 ret = -EINVAL;
    union zhpe_req      *req = &entry->op.req;
    union zhpe_rsp      *rsp = &entry->op.rsp;
    struct zpages       *zpages[3] = { NULL, NULL, NULL };
    struct zmap         *zmaps[3] = { NULL, NULL, NULL };
    size_t              sizes[3];
    uint32_t            qlen;
    size_t              qsize;
    size_t              i;

    qlen = req->qalloc.qlen;
    if (qlen < 1 || qlen > shared_data->default_attr.max_hw_qlen)
        goto done;
    /* To support qlen entries, we need a real size of qlen + 1 rounded
     * up to the next power of 2.
     */
    rsp->qalloc.info.qlen = 1U << fls(qlen);
    /* Compute sizes; assume a page for registers. */
    rsp->qalloc.info.rsize = PAGE_SIZE;
    sizes[0] = PAGE_SIZE;
    qsize = req->qalloc.qlen * ZHPE_HW_ENTRY_LEN;
    qsize = PAGE_ALIGN(qsize);
    rsp->qalloc.info.qsize = qsize;
    sizes[1] = qsize;
    sizes[2] = qsize;
    /* Allocate zpages and zmaps. */
    ret = -ENOMEM;
    for (i = 0; i < ARRAY_SIZE(sizes); i++) {
        zpages[i] = zpages_alloc(sizes[i], false);
        if (!zpages[i])
            goto done;
        zmaps[i] = zmap_alloc(zpages[i]);
        if (IS_ERR(zmaps[i])) {
            ret = PTR_ERR(zmaps[i]);
            zmaps[i] = NULL;
            goto done;
        }
    }
    rsp->qalloc.info.reg_off = zmaps[0]->offset;
    rsp->qalloc.info.wq_off = zmaps[1]->offset;
    rsp->qalloc.info.cq_off = zmaps[2]->offset;
    /* Set owner field to valid value; can't fail after this. */
    for (i = 0; i < ARRAY_SIZE(sizes); i++)
        zmaps[i]->owner = entry->fdata;
    /* Make sure owner is seen before we advertise the queue anywhere. */
    smp_wmb();
    ret = 0;

 done:
    if (ret < 0) {
        for (i = 0; i < ARRAY_SIZE(sizes); i++) {
            if (zmaps[i])
                zmap_free(zmaps[i]);
            else if (zpages[i])
                zpages_free(zpages[i]);
        }
    }

    return queue_io_rsp(entry, sizeof(rsp->qalloc), ret);
}

static int zhpe_user_req_QFREE(struct io_entry *entry)
{
    int                 ret = 0;
    struct file_data    *fdata = entry->fdata;
    union zhpe_req      *req = &entry->op.req;
    union zhpe_rsp      *rsp = &entry->op.rsp;
    int                 count = 3;
    struct zmap         *zmap;
    struct zmap         *next;

    spin_lock(&zmap_lock);
    list_for_each_entry_safe(zmap, next, &zmap_list, list) {
        if (zmap->offset == req->qfree.info.reg_off ||
            zmap->offset == req->qfree.info.wq_off ||
            zmap->offset == req->qfree.info.cq_off) {
            if (zmap->owner != fdata) {
                if (ret >= 0)
                    ret = -EACCES;
            } else {
                list_del_init(&zmap->list);
                zmap_free(zmap);
            }
            if (--count == 0)
                break;
        }
    }
    spin_unlock(&zmap_lock);
    if (ret >= 0 && count)
        ret = -ENOENT;

    return queue_io_rsp(entry, sizeof(rsp->qfree), ret);
}

static int zhpe_user_req_ZMMU_REG(struct io_entry *entry)
{
    return -ENOSYS;
}

static int zhpe_user_req_ZMMU_DEREG(struct io_entry *entry)
{
    return -ENOSYS;
}

static void helper_data_free(const char *callf, uint line, void *ptr)
{
    struct helper_data  *hdata = (void *)ptr;

    if (hdata->task)
        put_task_struct(hdata->task);
    _do_kfree(callf, line, hdata);
}

static int zhpe_release(struct inode *inode, struct file *file)
{
    struct file_data    *fdata = file->private_data;

    spin_lock(&fdata->io_lock);
    fdata->state |= STATE_CLOSED;
    spin_unlock(&fdata->io_lock);
    free_zmap_list(fdata);
    free_io_lists(fdata);
    put_file_data(fdata);

    debug(DEBUG_IO, "%s:%s,%u:ret = %d pid = %d\n",
          driver_name, __FUNCTION__, __LINE__, 0, task_pid_vnr(current));

    return 0;
}

static ssize_t zhpe_read(struct file *file, char __user *buf, size_t len,
                         loff_t *ppos)
{
    ssize_t             ret = 0;
    struct file_data    *fdata = file->private_data;
    struct io_entry     *entry;

    if (!len)
        goto done;

    if (!tracker_sane(__FUNCTION__, __LINE__, helper_data)) {
        ret = -EIO;
        goto done;
    }

    /*
     * Weird semantics: read must be big enough to read entire packet
     * at once; if not, return -EINVAL;
     */
    for (;;) {
        entry = NULL;
        spin_lock(&fdata->io_lock);
        if (!list_empty(&fdata->rd_list)) {
            entry = list_first_entry(&fdata->rd_list, struct io_entry, list);
            if (len >= entry->data_len) {
                list_del_init(&entry->list);
                len = entry->data_len;
            } else
                ret = -EINVAL;
        }
        spin_unlock(&fdata->io_lock);
        if (ret < 0)
            goto done;
        if (entry)
            break;
        if (file->f_flags & O_NONBLOCK) {
            ret = -EAGAIN;
            goto done;
        }
        ret = wait_event_interruptible(fdata->io_wqh,
                                       !list_empty(&fdata->rd_list));
        if (ret < 0)
            goto done;
    }
    ret = copy_to_user(buf, entry->data, len);
    put_io_entry(entry);

 done:
    if (!tracker_sane(__FUNCTION__, __LINE__, helper_data) && ret >= 0)
        ret = -EIO;

    debug_cond(DEBUG_IO, (ret /* != -EAGAIN*/),
               "%s:%s,%u:ret = %ld len = %ld pid = %d\n",
               driver_name, __FUNCTION__, __LINE__, ret, len,
               task_pid_vnr(current));

    return (ret < 0 ? ret : len);
}

static ssize_t zhpe_write(struct file *file, const char __user *buf,
                          size_t len, loff_t *ppos)
{
    ssize_t             ret = 0;
    struct file_data    *fdata = file->private_data;
    bool                nonblock = !!(file->f_flags & O_NONBLOCK);
    struct io_entry     *entry = NULL;
    struct zhpe_common_hdr *op_hdr;
    size_t              op_len;

    if (!len)
        goto done;

    if (!tracker_sane(__FUNCTION__, __LINE__, helper_data)) {
        ret = -EIO;
        goto done;
    }

    /*
     * Weird semantics: requires write be a packet containing a single
     * request.
     */
    if (len < sizeof(*op_hdr)) {
        ret = -EINVAL;
        printk(KERN_ERR "%s:%s,%u:Unexpected short write %lu\n",
               driver_name, __FUNCTION__, __LINE__, len);
        goto done;
    }

    entry = io_alloc(0, nonblock, fdata, io_free);
    if (!entry) {
        ret = (nonblock ? -EAGAIN : -ENOMEM);
        goto done;
    }
    op_hdr = &entry->op.hdr;

    op_len = sizeof(union zhpe_req);
    if (op_len > len)
        op_len = len;
    ret = copy_from_user(op_hdr, buf, op_len);
    if (ret < 0)
        goto done;
    entry->hdr = *op_hdr;

    ret = -EINVAL;
    if (!expected_saw("version", ZHPE_OP_VERSION, op_hdr->version))
        goto done;

#define USER_REQ_HANDLER(_op)                           \
    case ZHPE_OP_ ## _op:                               \
        debug(DEBUG_IO, "%s:%s:ZHPE_OP_" # _op,         \
              driver_name, __FUNCTION__);               \
        op_len = sizeof(struct zhpe_req_ ## _op);       \
        if (len != op_len)                              \
            goto done;                                  \
        ret = zhpe_user_req_ ## _op(entry);             \
        break;

    switch (op_hdr->opcode) {

    USER_REQ_HANDLER(INIT);
    USER_REQ_HANDLER(MR_REG);
    USER_REQ_HANDLER(MR_DEREG);
    USER_REQ_HANDLER(NOP);
    USER_REQ_HANDLER(QALLOC);
    USER_REQ_HANDLER(QFREE);
    USER_REQ_HANDLER(ZMMU_REG);
    USER_REQ_HANDLER(ZMMU_DEREG);

    default:
        printk(KERN_ERR "%s:%s,%u:Unexpected opcode 0x%02x\n",
               driver_name, __FUNCTION__, __LINE__, op_hdr->opcode);
        ret = -EIO;
        break;
    }

#undef USER_REQ_HANDLER

    /*
     * If handler accepts op, it is no longer our responsibility to free
     * the entry.
     */
    if (ret >= 0)
        entry = NULL;

 done:
    put_io_entry(entry);

    if (!tracker_sane(__FUNCTION__, __LINE__, helper_data) && ret >= 0)
        ret = -EIO;

    debug_cond(DEBUG_IO, (ret != -EAGAIN),
               "%s:%s,%u:ret = %ld len = %ld pid = %d\n",
               driver_name, __FUNCTION__, __LINE__, ret, len,
               task_pid_vnr(current));

    return (ret < 0 ? ret : len);
}

static uint zhpe_poll(struct file *file, struct poll_table_struct *wait)
{
    uint                ret = 0;
    struct file_data    *fdata = file->private_data;

    poll_wait(file, &poll_wqh, wait);
    ret |= (list_empty(&fdata->rd_list) ? 0 : POLLIN | POLLRDNORM);
    ret |= ((uintptr_t)helper_data->tracker_free ? POLLOUT | POLLWRNORM : 0);

    return ret;
}

/*
 * zhpe_vma_close() keeps vmas from being merged, so zhpe_mmap() will
 * be called on every mmap() and zhpe_vma_close/open() are used to track
 * when things are unmapped.
 *
 * mmap_sem will be held for write when this is called.
 */

static void zhpe_vma_close(struct vm_area_struct *vma)
{
}

static void zhpe_vma_open(struct vm_area_struct *vma)
{
}

static struct vm_operations_struct zhpe_vm_ops = {
    .open               = zhpe_vma_open,
    .close              = zhpe_vma_close,
};

static int zhpe_mmap(struct file *file, struct vm_area_struct *vma)
{
    int                 ret = -ENOENT;
    struct file_data    *fdata = file->private_data;
    pid_t               pid = task_tgid_vnr(current);
    struct zmap         *zmap;
    struct zpages       *zpages;
    ulong               vaddr;
    ulong               i;

    vma->vm_flags |= VM_MIXEDMAP;
    vma->vm_ops = &zhpe_vm_ops;
    vma->vm_private_data = NULL;

    spin_lock(&zmap_lock);
    list_for_each_entry(zmap, &zmap_list, list) {
        if (vma->vm_pgoff << PAGE_SHIFT == zmap->offset &&
            vma->vm_end - vma->vm_start == zmap->zpages->size) {
            if (!zmap->owner || zmap->owner == fdata ||
                (helper_pid == pid && zmap->owner != ZMAP_BAD_OWNER))
                ret = 0;
            break;
        }
    }
    spin_unlock(&zmap_lock);
    if (ret < 0)
        goto done;
    /* Only allow read-write mappings of shared data from helper. */
    ret = -EPERM;
    if (!(vma->vm_flags & VM_SHARED))
        goto done;
    if (vma->vm_flags & VM_EXEC)
        goto done;
    vma->vm_flags &= ~VM_MAYEXEC;
    if (zmap == shared_zmap && pid != helper_pid) {
        if (vma->vm_flags & VM_WRITE)
            goto done;
        vma->vm_flags &= ~VM_MAYWRITE;
    }

    zpages = zmap->zpages;
    vma->vm_private_data = zmap;

    for (vaddr = vma->vm_start, i = 0; vaddr < vma->vm_end;
         vaddr += PAGE_SIZE, i++) {
        ret = vm_insert_page(vma, vaddr, virt_to_page(zpages->pages[i]));
        if (ret < 0) {
            printk(KERN_ERR "%s:%s,%u:vm_insert_page() returned %d\n",
                   driver_name, __FUNCTION__, __LINE__, ret);
            break;
        }
    }
    ret = 0;

 done:
    if (ret < 0) {
        if (vma->vm_private_data) {
            /*
             * I don't think close gets called if we return error, so
             * call it ourselves and clear vm_private_data in case I am
             * wrong.
             */
            zhpe_vma_close(vma);
            vma->vm_private_data = NULL;
        }
        printk(KERN_ERR "%s:%s,%u:ret = %d:start 0x%lx end 0x%lx off 0x%lx\n",
               driver_name, __FUNCTION__, __LINE__, ret,
               vma->vm_start, vma->vm_end, vma->vm_pgoff);
    }

    return ret;
}

static int zhpe_open(struct inode *inode, struct file *file);

static const struct file_operations zhpe_fops = {
    .owner              =       THIS_MODULE,
    .open               =       zhpe_open,
    .release            =       zhpe_release,
    .read               =       zhpe_read,
    .write              =       zhpe_write,
    .poll               =       zhpe_poll,
    .mmap               =       zhpe_mmap,
    .llseek             =       no_llseek,
};

static int zhpe_helper_release(struct inode *inode, struct file *file)
{
    struct helper_data  *hdata = file->private_data;
    struct file_data    *fdata = &hdata->fdata;
    struct io_entry     *entry;
    uint                i;

    spin_lock(&fdata->io_lock);
    fdata->state |= STATE_CLOSED;
    spin_unlock(&fdata->io_lock);
    free_zmap_list(fdata);
    free_io_lists(fdata);
    for (i = 0; i < hdata->tracker_max; i++) {
        entry = hdata->tracker[i];
        if ((uintptr_t)entry < hdata->tracker_max)
            continue;
        debug(DEBUG_RELEASE, "%s:%s,%u:0x%04x entry 0x%p list %d\n",
              driver_name, __FUNCTION__, __LINE__, i, entry,
              !list_empty(&entry->list));
        if (entry->fdata && queue_io_rsp(entry, 0, -EIO) >= 0)
            entry = NULL;
        put_io_entry(entry);
    }
    put_file_data(fdata);
    wake_up_all(&helper_wqh);

    return 0;
}

static void zhpe_helper_rsp_HELPER_NOP(struct helper_data *hdata,
                                      struct io_entry *entry)
{
    if (queue_io_rsp(entry, sizeof(struct zhpe_rsp_HELPER_NOP), 0) < 0)
        put_io_entry(entry);
}

static int zhpe_helper_rsp_HELPER_INIT(struct helper_data *hdata,
                                       struct io_entry *entry)
{
    struct file_data    *fdata = &hdata->fdata;

    /* No status check:if helper fails to init, it will just exit. */
    spin_lock(&fdata->io_lock);
    fdata->state |= STATE_READY;
    spin_unlock(&fdata->io_lock);
    wake_up_all(&helper_wqh);

    put_io_entry(entry);

    return 0;
}

static ssize_t zhpe_helper_write(struct file *file, const char __user *buf,
                                 size_t len, loff_t *ppos)
{
    ssize_t             ret = 0;
    struct helper_data  *hdata = file->private_data;
    bool                nonblock = !!(file->f_flags & O_NONBLOCK);
    struct io_entry     *entry = NULL;
    struct zhpe_common_hdr hdr;
    size_t              op_len;

    if (!len)
        goto done;

    if (!tracker_sane(__FUNCTION__, __LINE__, helper_data)) {
        ret = -EIO;
        goto done;
    }

    /*
     * Weird semantics: requires write be a packet containing a single
     * request/response.
     */
    if (len < sizeof(hdr)) {
        ret = -EINVAL;
        printk(KERN_WARNING "%s:%s,%u:Unexpected short write %lu\n",
               driver_name, __FUNCTION__, __LINE__, len);
        goto done;
    }

    op_len = sizeof(hdr);
    if (op_len > len)
        op_len = len;
    ret = copy_from_user(&hdr, buf, op_len);
    if (ret < 0)
        goto done;

    ret = -EINVAL;
    if (!expected_saw("version", ZHPE_OP_VERSION, hdr.version))
        goto done;
    if (hdr.opcode & ZHPE_OP_RESPONSE) {
        entry = tracker_fetch(hdata, hdr.index);
        if (!entry)
            goto done;
        /* XXX: Override nonblock setting for fetched entry. */
        entry->nonblock = nonblock;
    } else {
        entry = io_alloc(0, nonblock, &hdata->fdata, io_free);
        if (!entry) {
            ret = (nonblock ? -EAGAIN : -ENOMEM);
            goto done;
        }
        entry->hdr = hdr;
    }

    op_len = sizeof(entry->op);
    if (op_len > len)
        op_len = len;
    ret = copy_from_user(&entry->op, buf, op_len);

#define HELPER_REQ_HANDLER(_op)                         \
    case ZHPE_OP_ ## _op:                               \
        debug(DEBUG_IO, "%s:%s:ZHPE_OP_" # _op,         \
              driver_name, __FUNCTION__);               \
        if (op_len != sizeof(struct zhpe_req_ ## _op))  \
            goto done;                                  \
        ret = zhpe_helper_req_ ## _op(entry);           \
        break;

#define HELPER_RSP_HANDLER(_op)                         \
    case ZHPE_OP_ ## _op | ZHPE_OP_RESPONSE:            \
        debug(DEBUG_IO, "%s:%s:ZHPE_OP_" # _op " RSP",  \
              driver_name, __FUNCTION__);               \
        if (op_len != sizeof(struct zhpe_rsp_ ## _op))  \
            goto done;                                  \
        zhpe_helper_rsp_ ## _op(hdata, entry);          \
        break;

    ret = 0;

    switch (hdr.opcode) {

    HELPER_RSP_HANDLER(HELPER_NOP);
    HELPER_RSP_HANDLER(HELPER_INIT);

    default:
        printk(KERN_WARNING "%s:%s,%u:Unexpected opcode 0x%02x\n",
               driver_name, __FUNCTION__, __LINE__, hdr.opcode);
        ret = -EIO;
        break;
    }

#undef HELPER_REQ_HANDLER
#undef HELPER_RSP_HANDLER

    /*
     * If handler accepts op, it is no longer our responsibility to free
     * the entry. If the op is refused and is a response, then send the
     * error back to the originator.
     */
    if (ret >= 0)
        entry = NULL;

 done:
    put_io_entry(entry);

    if (!tracker_sane(__FUNCTION__, __LINE__, helper_data) && ret >= 0)
        ret = -EIO;

    debug(DEBUG_IO, "%s:%s,%u:ret = %ld len = %ld pid = %d\n",
          driver_name, __FUNCTION__, __LINE__, ret, len,
          task_pid_vnr(current));

    return (ret < 0 ? ret : len);
}

/* If any ops are added this, they must be cleared in zhpe_exit(). */

static const struct file_operations zhpe_helper_fops = {
    .open               =       zhpe_open,
    .release            =       zhpe_helper_release,
    .read               =       zhpe_read,
    .write              =       zhpe_helper_write,
    .poll               =       zhpe_poll,
    .mmap               =       zhpe_mmap,
    .llseek             =       no_llseek,
};

static bool is_helper_ready(void)
{
    struct helper_data  *hdata = READ_ONCE(helper_data);

    return (!!(hdata && READ_ONCE(hdata->fdata.state) & STATE_READY));
}

static int zhpe_open(struct inode *inode, struct file *file)
{
    int                 ret = -ENOMEM;
    struct file_data    *fdata = NULL;
    bool                is_helper = (helper_pid == task_pid_vnr(current));
    size_t              size;
    struct helper_data  *hdata;
    uint                i;
    struct io_entry     *entry;
    union zhpe_req      *req;
    const struct file_operations *fops_orig;

    if (is_helper)
        size = sizeof(*hdata) + sizeof(hdata->tracker[0]) *tracker_max;
    else
        size = sizeof(*fdata);
    fdata = do_kmalloc(size, GFP_KERNEL, true);
    if (!fdata)
        goto done;

    fdata->free = file_data_free;
    atomic_set(&fdata->count, 1);
    spin_lock_init(&fdata->io_lock);
    init_waitqueue_head(&fdata->io_wqh);
    INIT_LIST_HEAD(&fdata->rd_list);

    /* Are we being called from the main thread of the helper? */
    if (is_helper) {
        ret = -EBUSY;
        if (helper_data)
            goto done;
        hdata = (void *)fdata;
        hdata->fdata.free = helper_data_free;
        /* Initialize tracker data; skip first slot: index == 0 reserved. */
        init_waitqueue_head(&hdata->tracker_wqh);
        hdata->tracker_max = tracker_max;
        for (i = 1; i < hdata->tracker_max - 1; i++)
            hdata->tracker[i] = (void *)(uintptr_t)(i + 1);
        hdata->tracker[i] = 0;
        hdata->tracker_free = (void *)(uintptr_t)1;
        hdata->tracker_freecnt = hdata->tracker_max - 1;
        if (!tracker_sane(__FUNCTION__, __LINE__, hdata))
            goto done;
        /* Extra count to make sure structure isn't freed until zhpe_exit. */
        get_file_data(&hdata->fdata);
        /* Hold helper task struct for zhpe_exit cleanup. */
        hdata->task = current;
        get_task_struct(hdata->task);
        /*
         * Replace fops, but don't fops_get new fops because no owner
         * and don't put old ones until after helper_data is visible.
         */
        fops_orig = file->f_op;
        file->f_op = &zhpe_helper_fops;
        wmb();
        WRITE_ONCE(helper_data, hdata);
        wmb();
        /*
         * Put original fops which decrements module use count. Module will
         * look free only after helper_data will be visible to zhpe_exit.
         */
        fops_put(fops_orig);
        /* Tell helper what it needs to init itself. */
        entry = io_alloc(0, false, NULL, io_free);
        if (entry) {
            req = &entry->op.req;
            req->hdr.opcode = ZHPE_OP_HELPER_INIT;
            req->helper_init.shared_offset = shared_zmap->offset;
            req->helper_init.shared_size = shared_zmap->zpages->size;
            ret = queue_io_helper(entry, sizeof(req->helper_init));
            if (ret < 0)
                put_io_entry(entry);
        }
    } else {
        /* Wait for helper to be ready. */
        ret = wait_event_interruptible(helper_wqh, is_helper_ready());
        goto done;
    }

    ret = 0;

 done:
    if (ret < 0 && fdata) {
        put_file_data(fdata);
        fdata = NULL;
    }
    file->private_data = fdata;

    debug(DEBUG_IO, "%s:%s,%u:ret = %d pid = %d\n",
          driver_name, __FUNCTION__, __LINE__, ret, task_pid_vnr(current));

    return ret;
}

static int helper_init(struct subprocess_info *info, struct cred *new)
{
    pid_t               *pidp = info->data;

    *pidp = task_pid_vnr(current);

    return 0;
}

static struct miscdevice miscdev = {
    .name               = driver_name,
    .fops               = &zhpe_fops,
    .minor              = MISC_DYNAMIC_MINOR,
    .mode               = 0666,
};

static int __init zhpe_init(void)
{
    int                 ret = -ENODEV;
    char                *argv[] = { helper_path, NULL };
    char                *envp[] = { NULL };
    struct zhpeq_attr default_attr = {
        .max_tx_queues      = 1024,
        .max_rx_queues      = 1024,
        .max_hw_qlen        = 65535,
        .max_sw_qlen        = 65535,
        .max_dma_len        = (1U << 31),
    };
    struct zpages       *zpages = NULL;
    struct subprocess_info *helper_info;
    ulong               check_off;
    ulong               check_val;

    printk(KERN_INFO "%s:%s helper_path %s backend %s tracker_max %u\n",
           driver_name, __FUNCTION__, helper_path, backend, tracker_max);

    if (tracker_max < 1 || tracker_max > 65536) {
        printk(KERN_WARNING "%s:%s:tracker_max %u must be 1 to 65536\n",
               driver_name, __FUNCTION__, tracker_max);
        goto done;
    }

    if (!strcmp(backend, "zhpe"))
        default_attr.backend = ZHPEQ_BACKEND_ZHPE;
    else if (!strcmp(backend, "libfabric"))
        default_attr.backend = ZHPEQ_BACKEND_LIBFABRIC;
    else {
        printk(KERN_WARNING "%s:%s:unrecognized backend = %s\n",
               driver_name, __FUNCTION__, backend);
        goto done;
    }
    if (default_attr.backend != ZHPEQ_BACKEND_LIBFABRIC) {
        printk(KERN_WARNING
               "%s:%s:only LIBFABRIC backend supported at this time.\n",
               driver_name, __FUNCTION__);
        goto done;
    }

    ret = -ENOMEM;
    zpages = zpages_alloc(sizeof(*shared_data), false);
    if (!zpages)
        goto done;
    shared_zmap = zmap_alloc(zpages);
    if (IS_ERR(shared_zmap)) {
        ret = PTR_ERR(shared_zmap);
        shared_zmap = NULL;
        goto done;
    }
    /* Make sure owner is seen before we advertise it. */
    shared_zmap->owner = NULL;
    smp_wmb();
    shared_data = zpages->pages[0];
    shared_data->magic = ZHPE_MAGIC;
    shared_data->version = ZHPE_SHARED_VERSION;
    shared_data->debug_flags = debug_flags;
    shared_data->default_attr = default_attr;
    check_off = zpages->size - sizeof(ulong);
    if (check_off >= sizeof(*shared_data)) {
        check_val = shared_zmap->offset + check_off;
        *(ulong *)((void *)shared_data + check_off) = check_val;
    }
    zpages = NULL;

    /* Create device. */
    ret = misc_register(&miscdev);
    if (ret < 0) {
        printk(KERN_WARNING "%s:%s:misc_register() returned %d\n",
               driver_name, __FUNCTION__, ret);
        goto done;
    }

    /* Launch helper. */
    helper_info = call_usermodehelper_setup(helper_path, argv, envp,
                                            GFP_KERNEL, helper_init, NULL,
                                            &helper_pid);
    if (!helper_info) {
        printk(KERN_WARNING
               "%s:%s:call_usermodehelper_setup(%s) returned NULL\n",
               driver_name, __FUNCTION__, helper_path);
        ret = -ENOMEM;
        goto done;
    }
    ret = call_usermodehelper_exec(helper_info, UMH_WAIT_EXEC);
    if (ret < 0) {
        printk(KERN_WARNING "%s:%s:call_usermodehelper_exec(%s) returned %d\n",
               driver_name, __FUNCTION__, helper_path, ret);
        goto done;
    }

 done:
    if (ret >= 0)
        ret = 0;
    else {
        zpages_free(zpages);
        zhpe_exit();
    }
    printk(KERN_INFO "%s:%s:%s %s, helper_pid = %d, ret = %d\n",
           driver_name, __FUNCTION__, __DATE__, __TIME__, helper_pid, ret);

    return ret;
}

static bool is_helper_closed(struct helper_data *hdata)
{
    return (!!(READ_ONCE(hdata->fdata.state) & STATE_CLOSED));
}

static void zhpe_exit(void)
{
    struct helper_data  *hdata = helper_data;
    struct io_entry     *entry;
    union zhpe_req      *req;

    /*
     * The only thing that can be accessing the driver, now, is the helper.
     * If the helper never opened the control file, skip to the end.
     */
    if (!hdata)
        goto done;

    /*
     * If the control file is open, ask the helper to exit; if it doesn't
     * exit, kill it; if it still doesn't close the file, then it is
     * badly hung: replace the fops and leak memory.
     */
    if (!is_helper_closed(hdata)) {
        /* Ask helper to exit and wait for it. */
        entry = io_alloc(0, false, NULL, io_free);
        if (entry) {
            req = &entry->op.req;
            req->hdr.opcode = ZHPE_OP_HELPER_EXIT;
            if (queue_io_helper(entry, sizeof(req->helper_exit)) < 0)
                put_io_entry(entry);
            (void)wait_event_timeout(helper_wqh, is_helper_closed(hdata),
                                     HELPER_EXIT_TIMEOUT);
        }
    }
    if (!is_helper_closed(hdata)) {
        /* Didn't close file; kill helper. */
        printk(KERN_WARNING "%s:%s:shutdown failed, killing %s %d\n",
               driver_name, __FUNCTION__, helper_path, helper_pid);
        send_sig(SIGKILL, helper_data->task, 0);
        (void)wait_event_timeout(helper_wqh, is_helper_closed(hdata),
                                 HELPER_EXIT_TIMEOUT);
    }
    if (!is_helper_closed(hdata)) {
        printk(KERN_WARNING "%s:%s:waiting for helper exit\n",
               driver_name, __FUNCTION__);
        wait_event(helper_wqh, is_helper_closed(hdata));
    }
    put_file_data(&hdata->fdata);

done:
    if (miscdev.minor != MISC_DYNAMIC_MINOR)
        misc_deregister(&miscdev);
    if (!free_zmap_list(NULL)) {
        printk(KERN_WARNING "%s:%s:waiting for zmap free\n",
               driver_name, __FUNCTION__);
        wait_event(helper_wqh, free_zmap_list(NULL));
    }

    printk(KERN_INFO "%s:%s mem_total %lu\n",
                 driver_name, __FUNCTION__, atomic64_read(&mem_total));
}
