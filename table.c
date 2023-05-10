/*
 * Deduplication metadata table.
 *
 * Copyright (c) 2020-2023 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/atomic.h>
#include <linux/string.h>

#include "nova.h"
#include "faststr.h"
#include "arithmetic.h"
#include "joinable.h"
#include "rhashtable-ext.h"
#include "uaccess-ext.h"

// #define static _Static_assert(1, "2333");

static inline void
assign_pmm_entry_to_blocknr(struct light_dedup_meta *meta,
	unsigned long blocknr, struct nova_pmm_entry *pentry,
	struct nova_write_para_normal *wp)
{
	struct nova_sb_info *sbi = light_dedup_meta_to_sbi(meta);
	__le64 *offset = meta->entry_allocator.map_blocknr_to_pentry + blocknr;
	*offset = nova_get_addr_off(sbi, pentry);
	if (!in_the_same_cacheline(offset, wp->dirty_map_blocknr_to_pentry) &&
		wp->dirty_map_blocknr_to_pentry != NULL)
	{
		nova_flush_cacheline(wp->dirty_map_blocknr_to_pentry, false);
	}
	wp->dirty_map_blocknr_to_pentry = offset;
}

static inline void
clear_pmm_entry_at_blocknr(struct light_dedup_meta *meta,
	unsigned long blocknr) 
{
	struct nova_sb_info *sbi = light_dedup_meta_to_sbi(meta);
	__le64 *offset = meta->entry_allocator.map_blocknr_to_pentry + blocknr;
	BUG_ON(*offset == 0);
	nova_unlock_write_flush(sbi, offset, 0, false);
}
static inline struct nova_pmm_entry *
blocknr_pmm_entry(struct light_dedup_meta *meta, unsigned long blocknr)
{
	return nova_get_block(meta->sblock,
		le64_to_cpu(
			meta->entry_allocator.map_blocknr_to_pentry[blocknr]));
}

struct nova_rht_entry {
	struct rhash_head node;
	struct nova_fp fp;
	struct nova_pmm_entry *pentry;
};

static u32 nova_rht_entry_key_hashfn(const void *data, u32 len, u32 seed)
{
	struct nova_fp *fp = (struct nova_fp *)data;
	return fp->index;
}

static u32 nova_rht_entry_hashfn(const void *data, u32 len, u32 seed)
{
	struct nova_rht_entry *entry = (struct nova_rht_entry *)data;
	return entry->fp.index;
}

static int nova_rht_key_entry_cmp(
	struct rhashtable_compare_arg *arg,
	const void *obj)
{
	const struct nova_fp *fp = (const struct nova_fp *)arg->key;
	struct nova_rht_entry *entry = (struct nova_rht_entry *)obj;
	// printk("%s: %llx, %llx", __func__, fp->value, entry->fp.value);
	return fp->value != entry->fp.value;
}

const struct rhashtable_params nova_rht_params = {
	.key_len = sizeof(struct nova_fp),
	.head_offset = offsetof(struct nova_rht_entry, node),
	.automatic_shrinking = true,
	.hashfn = nova_rht_entry_key_hashfn,
	.obj_hashfn = nova_rht_entry_hashfn,
	.obj_cmpfn = nova_rht_key_entry_cmp,
};

static inline struct nova_rht_entry* rht_entry_alloc(
	struct light_dedup_meta *meta)
{
	return kmem_cache_alloc(meta->rht_entry_cache, GFP_ATOMIC);
}

static void nova_rht_entry_free(void *entry, void *arg)
{
	struct kmem_cache *c = (struct kmem_cache *)arg;
	kmem_cache_free(c, entry);
}

struct pentry_free_task {
	struct rcu_head head;
	struct entry_allocator *allocator;
	struct nova_pmm_entry *pentry;
};

struct rht_entry_free_task {
	struct rcu_head head;
	struct entry_allocator *allocator;
	struct nova_rht_entry *entry;
};

static void __rcu_pentry_free(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry)
{
	struct light_dedup_meta *meta =
		entry_allocator_to_light_dedup_meta(allocator);
	struct super_block *sb = meta->sblock;
	unsigned long blocknr = nova_pmm_entry_blocknr(pentry);
	BUG_ON(blocknr == 0);
	clear_pmm_entry_at_blocknr(meta, blocknr);
	nova_free_data_block(sb, blocknr);
	nova_free_entry(allocator, pentry);
}

static void __rcu_rht_entry_free(struct entry_allocator *allocator,
	struct nova_rht_entry *entry)
{
	struct light_dedup_meta *meta =
		entry_allocator_to_light_dedup_meta(allocator);
	struct kmem_cache *rht_entry_cache = meta->rht_entry_cache;
	struct nova_pmm_entry *pentry = entry->pentry;
	__rcu_pentry_free(allocator, pentry);
	nova_rht_entry_free(entry, rht_entry_cache);
}

static void rcu_rht_entry_free(struct rcu_head *head)
{
	struct rht_entry_free_task *task =
		container_of(head, struct rht_entry_free_task, head);
	__rcu_rht_entry_free(task->allocator, task->entry);
	kfree(task);
}

static inline void new_dirty_fpentry(struct nova_pmm_entry *last_pentries[2],
	struct nova_pmm_entry *pentry)
{
	if (!in_the_same_cacheline(last_pentries[0], last_pentries[1]))
		nova_flush_entry_if_not_null(last_pentries[1], false);
	last_pentries[1] = last_pentries[0];
	last_pentries[0] = pentry;
}

static void free_rht_entry(
	struct light_dedup_meta *meta,
	struct nova_rht_entry *entry)
{
	struct rht_entry_free_task *task;
	// Remove the entry first to make it invisible to other threads.
	int ret = rhashtable_remove_fast(&meta->rht, &entry->node, nova_rht_params);
	BUG_ON(ret < 0);
	// printk("Block %lu removed from rhashtable\n",
	// 	nova_pmm_entry_blocknr(entry->pentry));
	nova_pmm_entry_mark_to_be_freed(entry->pentry);
	task = kmalloc(sizeof(struct rht_entry_free_task), GFP_ATOMIC);
	if (task) {
		task->allocator = &meta->entry_allocator;
		task->entry = entry;
		call_rcu(&task->head, rcu_rht_entry_free);
	} else {
		// printk(KERN_ERR "%s: Fail to allocate task\n", __func__);
		synchronize_rcu();
		__rcu_rht_entry_free(&meta->entry_allocator, entry);
	}
}

static void print(const char *addr) {
	int i;
	for (i = 0; i < 4096; ++i) {
		printk(KERN_CONT "%02x ", addr[i] & 0xff);
	}
	printk("\n");
}
static int alloc_and_fill_block(
	struct super_block *sb,
	struct nova_write_para_normal *wp)
{
	void *xmem;
	// unsigned long irq_flags = 0;
	INIT_TIMING(memcpy_time);

	wp->blocknr = nova_new_data_block(sb);
	if (wp->blocknr == 0)
		return -ENOSPC;
	// printk("%s: Block %ld allocated", __func__, wp->blocknr);
	xmem = nova_blocknr_to_addr(sb, wp->blocknr);
	// nova_memunlock_block(sb, xmem, &irq_flags);
	NOVA_START_TIMING(memcpy_data_block_t, memcpy_time);
	memcpy_flushcache((char *)xmem, (const char *)wp->addr, 4096);
	NOVA_END_TIMING(memcpy_data_block_t, memcpy_time);
	// nova_memlock_block(sb, xmem, &irq_flags);
	return 0;
}
#if 0
static int rewrite_block(
	struct super_block *sb,
	struct nova_write_para_normal *__wp)
{
	struct nova_write_para_rewrite *wp = (struct nova_write_para_rewrite *)__wp;
	void *xmem;
	unsigned long irq_flags = 0;
	INIT_TIMING(memcpy_time);

	xmem = nova_blocknr_to_addr(sb, wp->normal.blocknr);
	NOVA_START_TIMING(memcpy_data_block_t, memcpy_time);
	nova_memunlock_range(sb, xmem + wp->offset, wp->len, &irq_flags);
	memcpy_flushcache((char *)xmem + wp->offset, (const char *)wp->normal.addr + wp->offset, wp->len);
	nova_memlock_range(sb, xmem + wp->offset, wp->len, &irq_flags);
	NOVA_END_TIMING(memcpy_data_block_t, memcpy_time);
	return 0;
}
#endif
static void assign_entry(
	struct nova_rht_entry *entry,
	struct nova_pmm_entry *pentry,
	struct nova_fp fp)
{
	entry->fp = fp;
	entry->pentry = pentry;
}
static int handle_new_block(
	struct light_dedup_meta *meta,
	struct nova_write_para_normal *wp,
	int get_new_block(struct super_block *, struct nova_write_para_normal *))
{
	struct super_block *sb = meta->sblock;
	struct nova_rht_entry *entry;
	struct nova_fp fp = wp->base.fp;
	int cpu;
	struct entry_allocator_cpu *allocator_cpu;
	struct nova_pmm_entry *pentry;
	int64_t refcount;
	int ret;
	// unsigned long irq_flags = 0;
	INIT_TIMING(index_insert_new_entry_time);

	entry = rht_entry_alloc(meta);
	if (entry == NULL) {
		ret = -ENOMEM;
		goto fail0;
	}
	cpu = get_cpu();
	allocator_cpu = &per_cpu(entry_allocator_per_cpu, cpu);
	pentry = nova_alloc_entry(&meta->entry_allocator, allocator_cpu);
	if (IS_ERR(pentry)) {
		put_cpu();
		ret = PTR_ERR(pentry);
		goto fail1;
	}
	ret = get_new_block(sb, wp);
	if (ret < 0) {
		nova_alloc_entry_abort(allocator_cpu);
		put_cpu();
		goto fail1;
	}
	assign_pmm_entry_to_blocknr(meta, wp->blocknr, pentry, wp);
	nova_write_entry(&meta->entry_allocator, allocator_cpu, pentry, fp,
		wp->blocknr);
	put_cpu(); // Calls barrier() inside
	// Now the pentry won't be allocated by others
	assign_entry(entry, pentry, fp);
	NOVA_START_TIMING(index_insert_new_entry_t,
		index_insert_new_entry_time);
	ret = rhashtable_lookup_insert_key(&meta->rht, &fp, &entry->node,
		nova_rht_params);
	NOVA_END_TIMING(index_insert_new_entry_t, index_insert_new_entry_time);
	if (ret < 0) {
		// printk("Block %lu with fp %llx fail to insert into rhashtable "
		// 	"with error code %d\n", wp->blocknr, fp.value, ret);
		goto fail2;
	}
	// printk("Block %lu inserted into rhashtable\n", wp->blocknr);
	// nova_memunlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
	// 	&irq_flags);
	refcount = atomic64_cmpxchg(&pentry->refcount, 0, 1);
	// nova_memlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
	// 	&irq_flags);
	BUG_ON(refcount != 0);
	new_dirty_fpentry(wp->last_new_entries, pentry);
	// printk("Block %lu with fp %llx inserted into rhashtable %p, "
	// 	"fpentry offset = %p\n", wp->blocknr, fp.value, rht, pentry);
	return 0;
fail2:
	// The pentry can not be referenced by others, because its refcount is
	// zero, so is not considered readable.
	__rcu_pentry_free(&meta->entry_allocator, pentry);
fail1:
	nova_rht_entry_free(entry, meta->rht_entry_cache);
fail0:
	return ret;
}
// True: Not equal. False: Equal
static bool cmp_content(struct super_block *sb, unsigned long blocknr, const void *addr) {
	INIT_TIMING(memcmp_time);
	const char *content;
	bool res;
	NOVA_START_TIMING(memcmp_t, memcmp_time);
	content = nova_blocknr_to_addr(sb, blocknr);
	res = cmp64((const uint64_t *)content, addr);
	NOVA_END_TIMING(memcmp_t, memcmp_time);
	if (res) {
		print(content);
		printk("\n");
		print(addr);
	}
	return res;
}

static int incr_ref(struct light_dedup_meta *meta,
	struct nova_write_para_normal *wp,
	int (*get_new_block)(struct super_block *,
		struct nova_write_para_normal *))
{
	struct super_block *sb = meta->sblock;
	struct rhashtable *rht = &meta->rht;
	struct nova_rht_entry *entry;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	// unsigned long irq_flags = 0;
	int ret;
	INIT_TIMING(index_lookup_time);

retry:
	rcu_read_lock();
	NOVA_START_TIMING(index_lookup_t, index_lookup_time);
	entry = rhashtable_lookup(rht, &wp->base.fp, nova_rht_params);
	NOVA_END_TIMING(index_lookup_t, index_lookup_time);
	// We have to hold the read lock because if it is a hash collision,
	// then the entry, pentry, and blocknr could be freed by another thread.
	if (entry == NULL) {
		rcu_read_unlock();
		// printk("Block with fp %llx not found in rhashtable %p\n",
		// 	wp->base.fp.value, rht);
		ret = handle_new_block(meta, wp, get_new_block);
		if (ret == -EEXIST)
			goto retry;
		wp->base.refcount = 1;
		return ret;
	}
	pentry = entry->pentry;
	BUG_ON(nova_pmm_entry_is_free(pentry));
	blocknr = nova_pmm_entry_blocknr(pentry);
	if (cmp_content(sb, blocknr, wp->addr)) {
		rcu_read_unlock();
		nova_dbg("fp:%llx rentry.fp:%llx",wp->base.fp.value, entry->pentry->fp.value);
		printk("Collision, just write it.");
		wp->base.refcount = 0;
		return get_new_block(sb, wp);
		// const void *content = nova_get_block(sb, nova_sb_blocknr_to_addr(sb, le64_to_cpu(leaf->blocknr), NOVA_BLOCK_TYPE_4K));
		// printk("First 8 bytes of existed_entry: %llx, chunk_id = %llx, fingerprint = %llx %llx %llx %llx\nFirst 8 bytes of incoming block: %llx, fingerprint = %llx %llx %llx %llx\n",
		// 	*(uint64_t *)content, leaf->blocknr, leaf->fp_strong.u64s[0], leaf->fp_strong.u64s[1], leaf->fp_strong.u64s[2], leaf->fp_strong.u64s[3],
		// 	*(uint64_t *)addr, entry->fp_strong.u64s[0], entry->fp_strong.u64s[1], entry->fp_strong.u64s[2], entry->fp_strong.u64s[3]);
	}
	wp->blocknr = blocknr;// retrieval block info
	// nova_memunlock_range(sb, &pentry->refcount,
	// 	sizeof(pentry->refcount), &irq_flags);
	wp->base.refcount = atomic64_fetch_add_unless(&pentry->refcount, 1, 0);
	// nova_memlock_range(sb, &pentry->refcount,
	// 	sizeof(pentry->refcount), &irq_flags);
	rcu_read_unlock();
	if (wp->base.refcount == 0)
		return -EAGAIN;
	wp->base.refcount += 1;
	if (!in_the_same_cacheline(wp->last_ref_entry, pentry))
		nova_flush_entry_if_not_null(wp->last_ref_entry, false);
	wp->last_ref_entry = pentry;
	// printk("Block %lu has refcount %lld now\n",
	// 	wp->blocknr, wp->base.refcount);
	return 0;
}
static int incr_ref_normal(struct light_dedup_meta *meta,
	struct nova_write_para_normal *wp)
{
	return incr_ref(meta, wp, alloc_and_fill_block);
}
static int light_dedup_incr_ref_atomic(struct light_dedup_meta *meta,
	const void *addr, struct nova_write_para_normal *wp)
{
	int ret;
	INIT_TIMING(incr_ref_time);

	NOVA_START_TIMING(incr_ref_t, incr_ref_time);
	BUG_ON(nova_fp_calc(&meta->fp_ctx, addr, &wp->base.fp));
	wp->addr = addr;
	ret = incr_ref_normal(meta, wp);
	NOVA_END_TIMING(incr_ref_t, incr_ref_time);
	return ret;
}
int light_dedup_incr_ref(struct light_dedup_meta *meta, const void* addr,
	struct nova_write_para_normal *wp)
{
	int ret;
	while (1) {
		ret = light_dedup_incr_ref_atomic(meta, addr, wp);
		if (likely(ret != -EAGAIN))
			break;
		schedule();
	};
	return ret;
}

static void free_pentry(struct light_dedup_meta *meta,
	struct nova_pmm_entry *pentry)
{
	struct rhashtable *rht = &meta->rht;
	struct nova_rht_entry *entry;
	INIT_TIMING(index_lookup_time);

	rcu_read_lock();
	NOVA_START_TIMING(index_lookup_t, index_lookup_time);
	entry = rhashtable_lookup(rht, &pentry->fp, nova_rht_params);
	NOVA_END_TIMING(index_lookup_t, index_lookup_time);
	BUG_ON(entry == NULL);
	BUG_ON(entry->pentry != pentry);
	rcu_read_unlock();
	free_rht_entry(meta, entry);
}
static int64_t decr_ref(struct light_dedup_meta *meta,
	struct nova_pmm_entry *pentry)
{
	unsigned long blocknr;
	int64_t refcount;

	blocknr = nova_pmm_entry_blocknr(pentry);
	BUG_ON(blocknr == 0);
	// nova_memunlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
	// 	&irq_flags);
	refcount = atomic64_add_return(-1, &pentry->refcount);
	// nova_memlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
	// 	&irq_flags);
	BUG_ON(refcount < 0);
	if (refcount == 0) {
		// Now only we can free the entry,
		// because there are no any other deleter.
		free_pentry(meta, pentry);
	}
	return refcount;
}
void light_dedup_decr_ref(struct light_dedup_meta *meta, unsigned long blocknr,
	struct nova_pmm_entry **last_pentry)
{
	struct super_block *sb = meta->sblock;
	INIT_TIMING(decr_ref_time);
	struct nova_pmm_entry *pentry;
	int64_t refcount;
	BUG_ON(blocknr == 0);
	// for (i = 0; i < 64; ++i)
	// 	prefetcht0(addr + i * 64);
	// BUG_ON(nova_fp_calc(&table->fp_ctx, addr, &wp.base.fp));
	pentry = blocknr_pmm_entry(meta, blocknr);
	if (pentry == NULL) {
		printk("Block without deduplication: %lu\n", blocknr);
		nova_free_data_block(sb, blocknr);
		return;
	}
	BUG_ON(nova_pmm_entry_blocknr(pentry) != blocknr);
	NOVA_START_TIMING(decr_ref_t, decr_ref_time);
	refcount = decr_ref(meta, pentry);
	NOVA_END_TIMING(decr_ref_t, decr_ref_time);
	if (refcount != 0) {
		if (!in_the_same_cacheline(pentry, *last_pentry) &&
				*last_pentry) {
			if (*last_pentry != NULL) {
				nova_flush_cacheline(*last_pentry, false);
			}
		}
		*last_pentry = pentry;
	}
}

// refcount-- only if refcount == 1
static int decr_ref_1(
	struct light_dedup_meta *meta,
	struct nova_write_para_normal *wp)
{
	struct rhashtable *rht = &meta->rht;
	struct nova_rht_entry *entry;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	int64_t refcount;
	INIT_TIMING(index_lookup_time);

	rcu_read_lock();
	NOVA_START_TIMING(index_lookup_t, index_lookup_time);
	entry = rhashtable_lookup(rht, &wp->base.fp, nova_rht_params);
	NOVA_END_TIMING(index_lookup_t, index_lookup_time);
	// We have to hold the read lock because if it is a hash collision,
	// then the entry could be freed by another thread.
	if (!entry) {
		rcu_read_unlock();
		// Collision happened. Just free it.
		printk("Block %ld can not be found in the hash table.", wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	pentry = entry->pentry;
	BUG_ON(nova_pmm_entry_is_free(pentry));
	blocknr = nova_pmm_entry_blocknr(pentry);
	if (blocknr != wp->blocknr) {
		rcu_read_unlock();
		// Collision happened. Just free it.
		printk("%s: Blocknr mismatch: blocknr = %ld, expected %ld\n",
			__func__, blocknr, wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	// The entry won't be freed by others
	// because we are referencing it.
	rcu_read_unlock();
	refcount = atomic64_cmpxchg(&pentry->refcount, 1, 0);
	BUG_ON(refcount == 0);
	if (refcount == 1) {
		free_rht_entry(meta, entry);
		wp->base.refcount = 0;
		return 0;
	}
	// refcount >= 2. So we do not decrease refcount.
	wp->base.refcount = refcount;
	// printk(KERN_WARNING " found at %d, ref %llu\n", leaf_index, refcount);
	return 0;
}
long light_dedup_decr_ref_1(struct light_dedup_meta *meta, const void *addr,
	unsigned long blocknr)
{
	struct nova_write_para_normal wp;
	int    retval;
	INIT_TIMING(decr_ref_time);

	BUG_ON(blocknr == 0);
	BUG_ON(nova_fp_calc(&meta->fp_ctx, addr, &wp.base.fp));

	wp.addr = addr;
	wp.blocknr = blocknr;
	NOVA_START_TIMING(decr_ref_t, decr_ref_time);
	retval = decr_ref_1(meta, &wp);
	NOVA_END_TIMING(decr_ref_t, decr_ref_time);
	return retval < 0 ? retval : wp.base.refcount;
}

int light_dedup_insert_rht_entry(struct light_dedup_meta *meta,
	struct nova_fp fp, struct nova_pmm_entry *pentry)
{
	struct nova_rht_entry *entry = rht_entry_alloc(meta);
	int ret;
	INIT_TIMING(insert_entry_time);

	if (entry == NULL)
		return -ENOMEM;
	NOVA_START_TIMING(insert_rht_entry_t, insert_entry_time);
	assign_entry(entry, pentry, fp);
	while (1) {
		ret = rhashtable_insert_fast(&meta->rht, &entry->node,
			nova_rht_params);
		if (ret != -EBUSY)
			break;
		schedule();
	};
	if (ret < 0) {
		printk("%s: rhashtable_insert_fast returns %d\n",
			__func__, ret);
		nova_rht_entry_free(entry, meta->rht_entry_cache);
	}
	NOVA_END_TIMING(insert_rht_entry_t, insert_entry_time);
	return ret;
}

static inline void attach_blocknr(struct nova_write_para_continuous *wp,
	unsigned long blocknr)
{
	if (wp->blocknr == 0) {
		wp->blocknr = blocknr;
		wp->num = 1;
	} else if (wp->blocknr + wp->num == blocknr) {
		wp->num += 1;
	} else {
		wp->blocknr_next = blocknr;
	}
}

static int copy_from_user_incr_ref(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp)
{
	int ret;
	INIT_TIMING(copy_from_user_time);

	NOVA_START_TIMING(copy_from_user_t, copy_from_user_time);
	ret = copy_from_user(wp->kbuf, wp->ubuf, PAGE_SIZE);
	NOVA_END_TIMING(copy_from_user_t, copy_from_user_time);
	if (ret)
		return -EFAULT;
	ret = light_dedup_incr_ref_atomic(&sbi->light_dedup_meta, wp->kbuf,
		&wp->normal);
	if (ret < 0)
		return ret;
	attach_blocknr(wp, wp->normal.blocknr);
	return 0;
}

int light_dedup_incr_ref_continuous(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp)
{
	int ret = 0;
	// unsigned long irq_flags = 0;
	INIT_TIMING(time);

	NOVA_START_TIMING(incr_ref_continuous_t, time);
	// Unlock here because it seems that wprotect will affect prefetching
	// nova_memunlock(sbi, &irq_flags);
	while (wp->blocknr_next == 0 && wp->len >= PAGE_SIZE) {
		while (1) {
			ret = copy_from_user_incr_ref(sbi, wp);
			if (likely(ret != -EAGAIN))
				break;
			// nova_memlock(sbi, &irq_flags);
			schedule();
			// nova_memunlock(sbi, &irq_flags);
		}
		if (ret < 0)
			break;
		wp->ubuf += PAGE_SIZE;
		wp->len -= PAGE_SIZE;
	}
	// nova_memlock(sbi, &irq_flags);
	NOVA_END_TIMING(incr_ref_continuous_t, time);
	return ret;
}

struct rht_save_local_arg {
	size_t cur, end;
	struct nova_entry_refcount_record *rec;
	atomic64_t *saved;
	struct nova_sb_info *sbi;
	unsigned long irq_flags;
};
struct rht_save_factory_arg {
	struct nova_sb_info *sbi;
	atomic64_t saved;
};
static void *rht_save_local_arg_factory(void *factory_arg) {
	struct rht_save_factory_arg *arg =
		(struct rht_save_factory_arg *)factory_arg;
	struct nova_sb_info *sbi = arg->sbi;
	struct rht_save_local_arg *local_arg = kmalloc(
		sizeof(struct rht_save_local_arg), GFP_ATOMIC);
	if (local_arg == NULL)
		return ERR_PTR(-ENOMEM);
	local_arg->cur = 0;
	local_arg->end = 0;
	local_arg->rec = nova_sbi_blocknr_to_addr(
		sbi, sbi->entry_refcount_record_start);
	local_arg->saved = &arg->saved;
	local_arg->sbi = sbi;
	local_arg->irq_flags = 0;
	return local_arg;
}
static void rht_save_local_arg_recycler(void *local_arg)
{
	struct rht_save_local_arg *arg =
		(struct rht_save_local_arg *)local_arg;
	memset_nt(arg->rec + arg->cur,
		(arg->end - arg->cur) *
			sizeof(struct nova_entry_refcount_record),
		0);
	kfree(arg);
}
static void rht_save_worker_init(void *local_arg)
{
	struct rht_save_local_arg *arg =
		(struct rht_save_local_arg *)local_arg;
	nova_memunlock(arg->sbi, &arg->irq_flags);
}
static void rht_save_worker_finish(void *local_arg)
{
	struct rht_save_local_arg *arg =
		(struct rht_save_local_arg *)local_arg;
	nova_memlock(arg->sbi, &arg->irq_flags);
	PERSISTENT_BARRIER();
}
static void rht_save_func(void *ptr, void *local_arg)
{
	struct nova_rht_entry *entry = (struct nova_rht_entry *)ptr;
	struct rht_save_local_arg *arg =
		(struct rht_save_local_arg *)local_arg;
	// printk("%s: entry = %p, rec = %p, cur = %lu\n", __func__, entry, arg->rec, arg->cur);
	// TODO: Make it a list
	if (arg->cur == arg->end) {
		arg->end = atomic64_add_return(ENTRY_PER_REGION, arg->saved);
		arg->cur = arg->end - ENTRY_PER_REGION;
		// printk("New region to save, start = %lu, end = %lu\n", arg->cur, arg->end);
	}
	nova_ntstore_val(&arg->rec[arg->cur].entry_offset,
		cpu_to_le64(nova_get_addr_off(arg->sbi, entry->pentry)));
	++arg->cur;
}
static void rht_save(struct nova_sb_info *sbi,
	struct nova_recover_meta *recover_meta, struct rhashtable *rht)
{
	struct rht_save_factory_arg factory_arg;
	uint64_t saved;
	INIT_TIMING(save_refcount_time);

	NOVA_START_TIMING(rht_save_t, save_refcount_time);
	atomic64_set(&factory_arg.saved, 0);
	factory_arg.sbi = sbi;
	if (rhashtable_traverse_multithread(
		rht, sbi->cpus, rht_save_func, rht_save_worker_init,
		rht_save_worker_finish, rht_save_local_arg_factory,
		rht_save_local_arg_recycler, &factory_arg) < 0)
	{
		nova_warn("%s: Fail to save the fingerprint table with multithread. Fall back to single thread.", __func__);
		BUG(); // TODO
	}
	saved = atomic64_read(&factory_arg.saved);
	nova_unlock_write_flush(sbi, &recover_meta->refcount_record_num,
		cpu_to_le64(saved), true);
	printk("About %llu entries in hash table saved in NVM.", saved);
	NOVA_END_TIMING(rht_save_t, save_refcount_time);
}

struct rht_recover_para {
	struct light_dedup_meta *meta;
	entrynr_t entry_start, entry_end;
};
static int __rht_recover_func(struct light_dedup_meta *meta,
	entrynr_t entry_start, entrynr_t entry_end)
{
	struct super_block *sb = meta->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_entry_refcount_record *rec = nova_sbi_blocknr_to_addr(
		sbi, sbi->entry_refcount_record_start);
	struct nova_pmm_entry *pentry;
	entrynr_t i;
	int ret = 0;
	// printk("entry_start = %lu, entry_end = %lu\n", (unsigned long)entry_start, (unsigned long)entry_end);
	for (i = entry_start; i < entry_end; ++i) {
		if (rec[i].entry_offset == 0)
			continue;
		pentry = (struct nova_pmm_entry *)nova_sbi_get_block(sbi,
			le64_to_cpu(rec[i].entry_offset));
		BUG_ON(nova_pmm_entry_is_free(pentry));
		ret = light_dedup_insert_rht_entry(meta, pentry->fp,
			pentry);
		if (ret < 0)
			break;
	}
	return ret;
}
static int rht_recover_func(void *__para)
{
	struct rht_recover_para *para = (struct rht_recover_para *)__para;
	return __rht_recover_func(para->meta, para->entry_start,
		para->entry_end);
}
static int rht_recover(struct light_dedup_meta *meta, struct nova_sb_info *sbi,
	struct nova_recover_meta *recover_meta)
{
	entrynr_t n = le64_to_cpu(recover_meta->refcount_record_num);
	unsigned long entry_per_thread_max =
		max_ul(1UL << 10, (n + sbi->cpus - 1) / sbi->cpus);
	unsigned long thread_num =
		(n + entry_per_thread_max - 1) / entry_per_thread_max;
	unsigned long i;
	unsigned long base;
	struct rht_recover_para *para;
	struct joinable_kthread *ts;
	int ret = 0;

	nova_info("About %lu hash table entries found.\n", (unsigned long)n);
	if (n == 0)
		return 0;
	nova_info("Recover fingerprint table using %lu thread(s)\n", thread_num);
	if (thread_num == 1)
		return __rht_recover_func(meta, 0, n);
	para = kmalloc(thread_num * sizeof(para[0]), GFP_KERNEL);
	if (para == NULL) {
		ret = -ENOMEM;
		goto out0;
	}
	ts = kmalloc(thread_num * sizeof(ts[0]), GFP_KERNEL);
	if (ts == NULL) {
		ret = -ENOMEM;
		goto out1;
	}
	base = 0;
	for (i = 0; i < thread_num; ++i) {
		para[i].meta = meta;
		para[i].entry_start = base;
		base += entry_per_thread_max;
		para[i].entry_end = base < n ? base : n;
		ts[i].threadfn = rht_recover_func;
		ts[i].data = para + i;
	}
	ret = joinable_kthreads_run_join_check_lt_zero(ts, thread_num,
		__func__);
	kfree(ts);
out1:
	kfree(para);
out0:
	return ret;
}

static struct llist_node *allocate_kbuf(gfp_t flags)
{
	struct kbuf_obj *obj = kmalloc(sizeof(struct kbuf_obj), flags);
	if (obj == NULL)
		return NULL;
	obj->kbuf = kmalloc(PAGE_SIZE, flags);
	if (obj->kbuf == NULL) {
		kfree(obj);
		return NULL;
	}
	return &obj->node;
}

static void free_kbuf(struct llist_node *node)
{
	struct kbuf_obj *obj = container_of(node, struct kbuf_obj, node);
	kfree(obj->kbuf);
	kfree(obj);
}

// nelem_hint: If 0 then use default
// entry_allocator is left for the caller to initialize
int light_dedup_meta_alloc(struct light_dedup_meta *meta,
	struct super_block *sb, size_t nelem_hint)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *psb = (struct nova_super_block *)sbi->virt_addr;
	int ret;
	INIT_TIMING(table_init_time);

	NOVA_START_TIMING(meta_alloc_t, table_init_time);
	printk("psb = %p\n", psb);
	meta->sblock = sb;
	generic_cache_init(&meta->kbuf_cache, allocate_kbuf, free_kbuf);
	ret = nova_fp_strong_ctx_init(&meta->fp_ctx);
	if (ret < 0)
		goto err_out0;

	ret = rhashtable_init_large(&meta->rht, nelem_hint, &nova_rht_params);
	if (ret < 0)
		goto err_out1;

	meta->rht_entry_cache = kmem_cache_create("rht_entry_cache",
		sizeof(struct nova_rht_entry), 0, TABLE_KMEM_CACHE_FLAGS, NULL);
	if (meta->rht_entry_cache == NULL) {
		ret = -ENOMEM;
		goto err_out2;
	}
	atomic64_set(&meta->thread_num, 0);
	NOVA_END_TIMING(meta_alloc_t, table_init_time);
	return 0;
err_out2:
	rhashtable_free_and_destroy(&meta->rht, nova_rht_entry_free,
		meta->rht_entry_cache);
err_out1:
	nova_fp_strong_ctx_free(&meta->fp_ctx);
err_out0:
	NOVA_END_TIMING(meta_alloc_t, table_init_time);
	return ret;
}
// Free everything except entry_allocator
void light_dedup_meta_free(struct light_dedup_meta *meta)
{
	struct super_block *sb = meta->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	INIT_TIMING(table_free_time);

	generic_cache_destroy(&meta->kbuf_cache);
	nova_fp_strong_ctx_free(&meta->fp_ctx);

	NOVA_START_TIMING(rht_free_t, table_free_time);
	rhashtable_free_and_destroy_multithread(&meta->rht,
		nova_rht_entry_free, meta->rht_entry_cache, sbi->cpus);
	kmem_cache_destroy(meta->rht_entry_cache);
	NOVA_END_TIMING(rht_free_t, table_free_time);
}
int light_dedup_meta_init(struct light_dedup_meta *meta, struct super_block* sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	ret = light_dedup_meta_alloc(meta, sb, 0);
	if (ret < 0)
		return ret;
	ret = nova_init_entry_allocator(sbi, &meta->entry_allocator);
	if (ret < 0) {
		light_dedup_meta_free(meta);
		return ret;
	}
	return 0;
}
int light_dedup_meta_restore(struct light_dedup_meta *meta,
	struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	int ret;
	INIT_TIMING(normal_recover_fp_table_time);

	ret = light_dedup_meta_alloc(meta, sb,
		le64_to_cpu(recover_meta->refcount_record_num));
	if (ret < 0)
		goto err_out0;
	ret = nova_entry_allocator_recover(sbi, &meta->entry_allocator);
	if (ret < 0)
		goto err_out1;

	NOVA_START_TIMING(normal_recover_rht_t, normal_recover_fp_table_time);
	ret = rht_recover(meta, sbi, recover_meta);
	NOVA_END_TIMING(normal_recover_rht_t, normal_recover_fp_table_time);

	if (ret < 0)
		goto err_out2;
	return 0;
err_out2:
	nova_free_entry_allocator(&meta->entry_allocator);
err_out1:
	light_dedup_meta_free(meta);
err_out0:
	return ret;
}
void light_dedup_meta_save(struct light_dedup_meta *meta)
{
	struct super_block *sb = meta->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	rht_save(sbi, recover_meta, &meta->rht);
	nova_save_entry_allocator(sb, &meta->entry_allocator);
	nova_unlock_write_flush(sbi, &recover_meta->saved,
		NOVA_RECOVER_META_FLAG_COMPLETE, true);
	light_dedup_meta_free(meta);
}

int nova_table_stats(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct light_dedup_meta *meta = &sbi->light_dedup_meta;
	return __nova_entry_allocator_stats(sbi, &meta->entry_allocator);
}
