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
nova_assign_pmm_entry_to_blocknr(struct entry_allocator *allocator,
	unsigned long blocknr, struct nova_pmm_entry *pentry,
	struct nova_write_para_normal *wp)
{
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table,
			entry_allocator);
	struct nova_sb_info *sbi =
		container_of(meta_table, struct nova_sb_info, meta_table);
	__le64 *offset = allocator->map_blocknr_to_pentry + blocknr;
	*offset = nova_get_addr_off(sbi, pentry);
	if (!in_the_same_cacheline(offset, wp->dirty_map_blocknr_to_pentry) &&
		wp->dirty_map_blocknr_to_pentry != NULL)
	{
		nova_flush_cacheline(wp->dirty_map_blocknr_to_pentry, false);
	}
	wp->dirty_map_blocknr_to_pentry = offset;
}

static inline void
nova_clear_pmm_entry_at_blocknr(struct entry_allocator *allocator,
	unsigned long blocknr) 
{
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table,
			entry_allocator);
	struct nova_sb_info *sbi =
		container_of(meta_table, struct nova_sb_info, meta_table);
	__le64 *offset = allocator->map_blocknr_to_pentry + blocknr;
	BUG_ON(*offset == 0);
	nova_unlock_write_flush(sbi, offset, 0, false);
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

static inline struct nova_rht_entry* nova_rht_entry_alloc(
	struct nova_mm_table *table)
{
	return kmem_cache_alloc(table->rht_entry_cache, GFP_ATOMIC);
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
	struct nova_meta_table *meta_table = container_of(allocator,
		struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	unsigned long blocknr = nova_pmm_entry_blocknr(pentry);
	BUG_ON(blocknr == 0);
	nova_clear_pmm_entry_at_blocknr(allocator, blocknr);
	nova_free_data_block(sb, blocknr);
	nova_free_entry(allocator, pentry);
}

static void __rcu_rht_entry_free(struct entry_allocator *allocator,
	struct nova_rht_entry *entry)
{
	struct nova_meta_table *meta_table = container_of(allocator,
		struct nova_meta_table, entry_allocator);
	struct nova_mm_table *table = &meta_table->metas;
	struct kmem_cache *rht_entry_cache = table->rht_entry_cache;
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
	struct nova_mm_table *table,
	struct rhashtable *rht,
	struct nova_rht_entry *entry)
{
	struct rht_entry_free_task *task;
	// Remove the entry first to make it invisible to other threads.
	int ret = rhashtable_remove_fast(rht, &entry->node, nova_rht_params);
	BUG_ON(ret < 0);
	// printk("Block %lu removed from rhashtable\n",
	// 	nova_pmm_entry_blocknr(entry->pentry));
	nova_pmm_entry_mark_to_be_freed(entry->pentry);
	task = kmalloc(sizeof(struct rht_entry_free_task), GFP_ATOMIC);
	if (task) {
		task->allocator = table->entry_allocator;
		task->entry = entry;
		call_rcu(&task->head, rcu_rht_entry_free);
	} else {
		// printk(KERN_ERR "%s: Fail to allocate task\n", __func__);
		synchronize_rcu();
		__rcu_rht_entry_free(table->entry_allocator, entry);
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
static int nova_table_leaf_insert(
	struct nova_mm_table *table,
	struct rhashtable *rht,
	struct nova_write_para_normal *wp,
	int get_new_block(struct super_block *, struct nova_write_para_normal *))
{
	struct super_block *sb = table->sblock;
	struct nova_rht_entry *entry;
	struct nova_fp fp = wp->base.fp;
	int cpu;
	struct entry_allocator_cpu *allocator_cpu;
	struct nova_pmm_entry *pentry;
	int64_t refcount;
	int ret;
	// unsigned long irq_flags = 0;
	INIT_TIMING(index_insert_new_entry_time);

	entry = nova_rht_entry_alloc(table);
	if (entry == NULL) {
		ret = -ENOMEM;
		goto fail0;
	}
	cpu = get_cpu();
	allocator_cpu = &per_cpu(entry_allocator_per_cpu, cpu);
	pentry = nova_alloc_entry(table->entry_allocator, allocator_cpu);
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
	nova_assign_pmm_entry_to_blocknr(table->entry_allocator, wp->blocknr,
		pentry, wp);
	nova_write_entry(table->entry_allocator, allocator_cpu, pentry, fp,
		wp->blocknr);
	put_cpu(); // Calls barrier() inside
	// Now the pentry won't be allocated by others
	assign_entry(entry, pentry, fp);
	NOVA_START_TIMING(index_insert_new_entry_t,
		index_insert_new_entry_time);
	ret = rhashtable_lookup_insert_key(rht, &fp, &entry->node,
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
	wp->last_accessed = pentry;
	// printk("Block %lu with fp %llx inserted into rhashtable %p, "
	// 	"fpentry offset = %p\n", wp->blocknr, fp.value, rht, pentry);
	return 0;
fail2:
	// The pentry can not be referenced by others, because its refcount is
	// zero, so is not considered readable.
	__rcu_pentry_free(table->entry_allocator, pentry);
fail1:
	nova_rht_entry_free(entry, table->rht_entry_cache);
fail0:
	return ret;
}
// True: Not equal. False: Equal
static bool cmp_content(struct super_block *sb, unsigned long blocknr, const void *addr) {
	INIT_TIMING(memcmp_time);
	const char *content;
	size_t i;
	bool res;
	NOVA_START_TIMING(memcmp_t, memcmp_time);
	content = nova_blocknr_to_addr(sb, blocknr);
	for (i = 0; i < 16; ++i)
		prefetcht0(content + i * 256);
	for (i = 0; i < 16; ++i) {
		prefetcht0(content + i * 256 + 64);
		prefetcht0(content + i * 256 + 64 * 2);
		prefetcht0(content + i * 256 + 64 * 3);
	}
	res = cmp64((const uint64_t *)content, addr);
	NOVA_END_TIMING(memcmp_t, memcmp_time);
	if (res) {
		print(content);
		printk("\n");
		print(addr);
	}
	return res;
}

static int upsert_block(struct nova_mm_table *table,
	struct nova_write_para_normal *wp,
	int (*get_new_block)(struct super_block *,
		struct nova_write_para_normal *))
{
	struct super_block *sb = table->sblock;
	struct rhashtable *rht = &table->rht;
	struct nova_rht_entry *entry;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	// unsigned long irq_flags = 0;
	int ret;
	INIT_TIMING(mem_bucket_find_time);

retry:
	rcu_read_lock();
	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	entry = rhashtable_lookup(rht, &wp->base.fp, nova_rht_params);
	NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	// We have to hold the read lock because if it is a hash collision,
	// then the entry, pentry, and blocknr could be freed by another thread.
	if (entry == NULL) {
		rcu_read_unlock();
		// printk("Block with fp %llx not found in rhashtable %p\n",
		// 	wp->base.fp.value, rht);
		ret = nova_table_leaf_insert(table, rht, wp, get_new_block);
		if (ret == -EEXIST)
			goto retry;
		wp->base.refcount = 1;
		return ret;
	}
	pentry = entry->pentry;
	blocknr = nova_pmm_entry_blocknr(pentry);
	BUG_ON(blocknr == 0);
	if (cmp_content(sb, blocknr, wp->addr)) {
		rcu_read_unlock();
		wp->last_accessed = NULL;
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
	new_dirty_fpentry(wp->last_ref_entries, pentry);
	wp->last_accessed = pentry;
	// printk("Block %lu (fpentry %p) has refcount %lld now\n",
	// 	wp->blocknr, pentry, wp->base.refcount);
	return 0;
}

void nova_table_deref_block(struct nova_mm_table *table,
	struct nova_pmm_entry *pentry, struct nova_pmm_entry **last_pentry)
{
	struct super_block *sb = table->sblock;
	struct rhashtable *rht = &table->rht;
	struct nova_rht_entry *entry;
	unsigned long blocknr;
	int64_t refcount;
	unsigned long irq_flags = 0;
	INIT_TIMING(mem_bucket_find_time);

	blocknr = nova_pmm_entry_blocknr(pentry);
	BUG_ON(blocknr == 0);
	nova_memunlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
		&irq_flags);
	refcount = atomic64_add_return(-1, &pentry->refcount);
	nova_memlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
		&irq_flags);
	BUG_ON(refcount < 0);
	if (refcount == 0) {
		// Now only we can free the entry,
		// because there are no any other deleter.
		rcu_read_lock();
		NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
		entry = rhashtable_lookup(rht, &pentry->fp, nova_rht_params);
		NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
		BUG_ON(entry == NULL);
		BUG_ON(entry->pentry != pentry);
		rcu_read_unlock();
		free_rht_entry(table, rht, entry);
	} else {
		if (!in_the_same_cacheline(pentry, *last_pentry) &&
				*last_pentry) {
			if (*last_pentry != NULL) {
				nova_flush_cacheline(*last_pentry, false);
			}
		}
		*last_pentry = pentry;
	}
}

// Upsert : update or insert
int nova_table_upsert_normal(struct nova_mm_table *table, struct nova_write_para_normal *wp)
{
	return upsert_block(table, wp, alloc_and_fill_block);
}
// Inplace 
#if 0
int nova_table_upsert_rewrite(struct nova_mm_table *table, struct nova_write_para_rewrite *wp)
{
	return upsert_block(table, (struct nova_write_para_normal *)wp,
		rewrite_block);
}
#endif

// refcount-- only if refcount == 1
int nova_table_upsert_decr1(
	struct nova_mm_table *table,
	struct nova_write_para_normal *wp)
{
	struct rhashtable *rht = &table->rht;
	struct nova_rht_entry *entry;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	int64_t refcount;
	INIT_TIMING(mem_bucket_find_time);

	rcu_read_lock();
	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	entry = rhashtable_lookup(rht, &wp->base.fp, nova_rht_params);
	NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
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
	blocknr = nova_pmm_entry_blocknr(pentry);
	BUG_ON(blocknr == 0);
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
		free_rht_entry(table, rht, entry);
		wp->base.refcount = 0;
		return 0;
	}
	// refcount >= 2. So we do not decrease refcount.
	wp->base.refcount = refcount;
	// printk(KERN_WARNING " found at %d, ref %llu\n", leaf_index, refcount);
	return 0;
}

int nova_table_insert_entry(struct nova_mm_table *table, struct nova_fp fp,
	struct nova_pmm_entry *pentry)
{
	struct nova_rht_entry *entry = nova_rht_entry_alloc(table);
	int ret;
	INIT_TIMING(insert_entry_time);

	if (entry == NULL)
		return -ENOMEM;
	NOVA_START_TIMING(insert_entry_t, insert_entry_time);
	assign_entry(entry, pentry, fp);
	while (1) {
		ret = rhashtable_insert_fast(&table->rht, &entry->node,
			nova_rht_params);
		if (ret != -EBUSY)
			break;
		schedule();
	};
	if (ret < 0) {
		printk("%s: rhashtable_insert_fast returns %d\n",
			__func__, ret);
		nova_rht_entry_free(entry, table->rht_entry_cache);
	}
	NOVA_END_TIMING(insert_entry_t, insert_entry_time);
	return ret;
}

static int nova_fp_table_incr_atomic(struct nova_mm_table *table,
	const void *addr, struct nova_write_para_normal *wp)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	INIT_TIMING(incr_ref_time);

	NOVA_START_TIMING(incr_ref_t, incr_ref_time);
	BUG_ON(nova_fp_calc(&sbi->meta_table.fp_ctx, addr, &wp->base.fp));
	wp->addr = addr;
	ret = nova_table_upsert_normal(table, wp);
	NOVA_END_TIMING(incr_ref_t, incr_ref_time);
	return ret;
}

int nova_fp_table_incr(struct nova_mm_table *table, const void* addr,
	struct nova_write_para_normal *wp)
{
	int ret;
	while (1) {
		ret = nova_fp_table_incr_atomic(table, addr, wp);
		if (likely(ret != -EAGAIN))
			break;
		schedule();
	};
	return ret;
}

// Return the original persistent hint.
static u64 __update_hint(atomic64_t *next_hint, u64 old_hint, u64 new_hint)
{
	return le64_to_cpu(atomic64_cmpxchg_relaxed(
		next_hint,
		cpu_to_le64(old_hint),
		cpu_to_le64(new_hint)));
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

static int copy_from_user_incr(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp)
{
	int ret;
	INIT_TIMING(copy_from_user_time);

	NOVA_START_TIMING(copy_from_user_t, copy_from_user_time);
	ret = copy_from_user(wp->kbuf, wp->ubuf, PAGE_SIZE);
	NOVA_END_TIMING(copy_from_user_t, copy_from_user_time);
	if (ret)
		return -EFAULT;
	ret = nova_fp_table_incr_atomic(&sbi->meta_table.metas, wp->kbuf,
		&wp->normal);
	if (ret < 0)
		return ret;
	attach_blocknr(wp, wp->normal.blocknr);
	return 0;
}

static int handle_no_hint(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, atomic64_t *next_hint,
	u64 old_hint)
{
	u64 offset;
	uint64_t hint;
	int ret;
	// unsigned long irq_flags = 0;
	INIT_TIMING(update_hint_time);

	ret = copy_from_user_incr(sbi, wp);
	if (ret < 0)
		return ret;
	NOVA_STATS_ADD(no_hint, 1);
	if (unlikely(wp->normal.last_accessed == NULL))
		return 0;
	offset = nova_get_addr_off(sbi, wp->normal.last_accessed);
	NOVA_START_TIMING(update_hint_t, update_hint_time);
	// nova_sbi_memunlock_range(sbi, next_hint, sizeof(*next_hint),
	// 	&irq_flags);
	hint = __update_hint(next_hint, old_hint, offset);
	// nova_sbi_memlock_range(sbi, next_hint, sizeof(*next_hint),
	// 	&irq_flags);
	// nova_flush_cacheline(next_hint, false);
	NOVA_END_TIMING(update_hint_t, update_hint_time);
	return 0;
}

// The caller should hold rcu_read_lock
static void handle_hint_of_hint(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, atomic64_t *next_hint)
{
	uint64_t hint = le64_to_cpu(atomic64_read(next_hint));
	u64 offset = hint;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;

	// Be conservative because prefetching consumes bandwidth.
	if (offset == 0)
		return;
	// Do not prefetch across syscall.
	if (wp->len < PAGE_SIZE * 2)
		return;
	pentry = nova_sbi_get_block(sbi, offset);
	if (!nova_pmm_entry_is_readable(pentry))
		return;
	blocknr = nova_pmm_entry_blocknr(pentry);
	BUG_ON(blocknr == 0);
	wp->block_prefetching = nova_sbi_blocknr_to_addr(sbi, blocknr);
	NOVA_STATS_ADD(prefetch_next, 1);
	wp->prefetched_blocknr[1] = wp->prefetched_blocknr[0];
	wp->prefetched_blocknr[0] = blocknr;
}

static inline void prefetch_next_stage_1(struct nova_write_para_continuous *wp)
{
	size_t i;
	INIT_TIMING(time);

	if (wp->block_prefetching == NULL)
		return;
	NOVA_START_TIMING(prefetch_next_stage_1_t, time);
	for (i = 0; i < 8; ++i) {
		prefetcht2(wp->block_prefetching + i * 256);
	}
	NOVA_END_TIMING(prefetch_next_stage_1_t, time);
}

static inline void prefetch_next_stage_2(struct nova_write_para_continuous *wp)
{
	size_t i;
	INIT_TIMING(time);

	if (wp->block_prefetching == NULL)
		return;
	NOVA_START_TIMING(prefetch_next_stage_2_t, time);
	for (i = 8; i < 16; ++i) {
		prefetcht2(wp->block_prefetching + i * 256);
	}
	NOVA_END_TIMING(prefetch_next_stage_2_t, time);
	wp->block_prefetching = NULL;
}

// The caller should hold rcu_read_lock
// Return whether the block is deduplicated successfully.
static int check_hint(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, struct nova_pmm_entry *pentry)
{
	struct nova_meta_table *table = &sbi->meta_table;
	unsigned long blocknr;
	const char *addr;
	size_t i;
	int64_t ret;
	// unsigned long irq_flags = 0;
	INIT_TIMING(prefetch_cmp_time);
	INIT_TIMING(cmp_user_time);
	INIT_TIMING(hit_incr_ref_time);

	if (!nova_pmm_entry_is_readable(pentry))
		return 0;
	blocknr = nova_pmm_entry_blocknr(pentry);
	BUG_ON(blocknr == 0);
	// It is guaranteed that the block will not be freed,
	// because we are holding the RCU read lock.
	addr = nova_sbi_blocknr_to_addr(sbi, blocknr);

	if (atomic64_read(&table->thread_num) < 6) {
		handle_hint_of_hint(sbi, wp, &pentry->next_hint);
		NOVA_START_TIMING(prefetch_cmp_t, prefetch_cmp_time);
		// Prefetch with stride 256B first in case that this block have
		// not been prefetched yet.
		for (i = 0; i < PAGE_SIZE; i += 256)
			prefetcht0(addr + i);
		for (i = 0; i < PAGE_SIZE; i += 256) {
			prefetcht0(addr + i + 64);
			prefetcht0(addr + i + 64 * 2);
			prefetcht0(addr + i + 64 * 3);
		}
		NOVA_END_TIMING(prefetch_cmp_t, prefetch_cmp_time);
	} else {
		// Do not prefetch with stride 256B if there are many threads
		// reading/writing NVM
		NOVA_START_TIMING(prefetch_cmp_t, prefetch_cmp_time);
		for (i = 0; i < PAGE_SIZE; i += 64)
			prefetcht0(addr + i);
		NOVA_END_TIMING(prefetch_cmp_t, prefetch_cmp_time);
	}

	prefetch_next_stage_1(wp);

	NOVA_START_TIMING(cmp_user_t, cmp_user_time);
	ret = cmp_user_generic_const_8B_aligned(wp->ubuf, addr, PAGE_SIZE);
	NOVA_END_TIMING(cmp_user_t, cmp_user_time);

	prefetch_next_stage_2(wp);

	if (ret < 0)
		return -EFAULT;
	if (ret != 0) {
		// printk("Prediction miss: %lld\n", ret);
		// BUG_ON(copy_from_user(wp->kbuf, wp->ubuf, PAGE_SIZE));
		// print(wp->kbuf);
		// printk("\n");
		// print(addr);
		return 0;
	}

	NOVA_START_TIMING(hit_incr_ref_t, hit_incr_ref_time);
	// nova_memunlock_range(sbi->sb, &pentry->refcount,
	// 	sizeof(pentry->refcount), &irq_flags);
	ret = atomic64_add_unless(&pentry->refcount, 1, 0);
	// nova_memlock_range(sbi->sb, &pentry->refcount,
	// 	sizeof(pentry->refcount), &irq_flags);
	NOVA_END_TIMING(hit_incr_ref_t, hit_incr_ref_time);

	if (ret == false)
		return 0;
	// The blocknr will not be released now, because we are referencing it.
	if (blocknr == wp->prefetched_blocknr[1] ||
			blocknr == wp->prefetched_blocknr[0]) {
		// The hit counts of prefetching is slightly underestimated
		// because there is also probability that the current hint
		// misses but the prefetched block hits.
		NOVA_STATS_ADD(prefetch_hit, 1);
	}
	attach_blocknr(wp, blocknr);
	new_dirty_fpentry(wp->normal.last_ref_entries, pentry);
	wp->normal.last_accessed = pentry;
	// printk("Prediction hit! blocknr = %ld, pentry = %p\n", blocknr, pentry);
	return 1;
}

static int handle_hint(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, atomic64_t *next_hint)
{
	uint64_t hint = le64_to_cpu(atomic64_read(next_hint));
	u64 offset = hint;
	struct nova_pmm_entry *pentry;
	int ret;

	if (offset == 0) {
		// Actually no hint
		return handle_no_hint(sbi, wp, next_hint, hint);
	}
	pentry = nova_sbi_get_block(sbi, offset);

	// To make sure that pentry will not be released while we
	// are reading its content.
	rcu_read_lock();
	ret = check_hint(sbi, wp, pentry);
	rcu_read_unlock();

	if (ret < 0)
		return ret;
	if (ret == 1) {
		NOVA_STATS_ADD(predict_hit, 1);
		return 0;
	}
	NOVA_STATS_ADD(predict_miss, 1);
	BUG_ON(ret != 0);
	ret = copy_from_user_incr(sbi, wp);
	if (ret < 0)
		return ret;
	if (unlikely(wp->normal.last_accessed == NULL))
		return 0;
	return 0;
}

static inline struct nova_pmm_entry *
get_last_accessed(struct nova_write_para_continuous *wp, bool check)
{
	struct nova_pmm_entry *last_pentry = wp->normal.last_accessed;
	if (check && last_pentry &&
			last_pentry != wp->normal.last_new_entries[0] &&
			last_pentry != wp->normal.last_ref_entries[0]) {
		printk("last_pentry: %p, last_new_entries: [%p,%p], "
			"last_ref_entries: [%p,%p], NULL_PENTRY: %p\n",
			last_pentry,
			wp->normal.last_new_entries[0],
			wp->normal.last_new_entries[1],
			wp->normal.last_ref_entries[0],
			wp->normal.last_ref_entries[1],
			NULL_PENTRY);
		BUG();
	}
	return last_pentry;
}

static int handle_last_accessed_pentry(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, struct nova_pmm_entry *pentry)
{
	if (pentry) {
		return handle_hint(sbi, wp, &pentry->next_hint);
	} else {
		return copy_from_user_incr(sbi, wp);
	}
}

int nova_fp_table_incr_continuous(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp)
{
	struct nova_pmm_entry *last_pentry;
	bool first = true;
	int ret = 0;
	// unsigned long irq_flags = 0;
	INIT_TIMING(time);

	NOVA_START_TIMING(incr_continuous_t, time);
	// Unlock here because it seems that wprotect will affect prefetching
	// nova_memunlock(sbi, &irq_flags);
	while (wp->blocknr_next == 0 && wp->len >= PAGE_SIZE) {
		last_pentry = get_last_accessed(wp, !first);
		while (1) {
			ret = handle_last_accessed_pentry(sbi, wp, last_pentry);
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
		first = false;
	}
	// nova_memlock(sbi, &irq_flags);
	NOVA_END_TIMING(incr_continuous_t, time);
	return ret;
}

struct table_save_local_arg {
	size_t cur, end;
	struct nova_entry_refcount_record *rec;
	atomic64_t *saved;
	struct nova_sb_info *sbi;
	unsigned long irq_flags;
};
struct table_save_factory_arg {
	struct nova_mm_table *table;
	atomic64_t saved;
};
static void *table_save_local_arg_factory(void *factory_arg) {
	struct table_save_factory_arg *arg =
		(struct table_save_factory_arg *)factory_arg;
	struct nova_mm_table *table = arg->table;
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct table_save_local_arg *local_arg = kmalloc(
		sizeof(struct table_save_local_arg), GFP_ATOMIC);
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
static void table_save_local_arg_recycler(void *local_arg)
{
	struct table_save_local_arg *arg =
		(struct table_save_local_arg *)local_arg;
	memset_nt(arg->rec + arg->cur,
		(arg->end - arg->cur) *
			sizeof(struct nova_entry_refcount_record),
		0);
	kfree(arg);
}
static void table_save_worker_init(void *local_arg)
{
	struct table_save_local_arg *arg =
		(struct table_save_local_arg *)local_arg;
	nova_memunlock(arg->sbi, &arg->irq_flags);
}
static void table_save_worker_finish(void *local_arg)
{
	struct table_save_local_arg *arg =
		(struct table_save_local_arg *)local_arg;
	nova_memlock(arg->sbi, &arg->irq_flags);
	PERSISTENT_BARRIER();
}
static void table_save_func(void *ptr, void *local_arg)
{
	struct nova_rht_entry *entry = (struct nova_rht_entry *)ptr;
	struct table_save_local_arg *arg =
		(struct table_save_local_arg *)local_arg;
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
static void table_save(struct nova_mm_table *table)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	struct table_save_factory_arg factory_arg;
	uint64_t saved;

	atomic64_set(&factory_arg.saved, 0);
	factory_arg.table = table;
	if (rhashtable_traverse_multithread(
		&table->rht, sbi->cpus, table_save_func, table_save_worker_init,
		table_save_worker_finish, table_save_local_arg_factory,
		table_save_local_arg_recycler, &factory_arg) < 0)
	{
		nova_warn("%s: Fail to save the fingerprint table with multithread. Fall back to single thread.", __func__);
		BUG(); // TODO
	}
	saved = atomic64_read(&factory_arg.saved);
	nova_unlock_write_flush(sbi, &recover_meta->refcount_record_num,
		cpu_to_le64(saved), true);
	printk("About %llu entries in hash table saved in NVM.", saved);
}

void nova_table_free(struct nova_mm_table *table)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	rhashtable_free_and_destroy_multithread(&table->rht,
		nova_rht_entry_free, table->rht_entry_cache, sbi->cpus);
	kmem_cache_destroy(table->rht_entry_cache);
}
void nova_table_save(struct nova_mm_table* table)
{
	INIT_TIMING(save_refcount_time);
	INIT_TIMING(table_free_time);

	NOVA_START_TIMING(save_refcount_t, save_refcount_time);
	table_save(table);
	NOVA_END_TIMING(save_refcount_t, save_refcount_time);

	NOVA_START_TIMING(table_free_t, table_free_time);
	nova_table_free(table);
	NOVA_END_TIMING(table_free_t, table_free_time);
}

// nelem_hint: If 0 then use default
int nova_table_init(struct super_block *sb, struct nova_mm_table *table,
	size_t nelem_hint)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *psb = (struct nova_super_block *)sbi->virt_addr;
	int ret;
	INIT_TIMING(table_init_time);

	NOVA_START_TIMING(table_init_t, table_init_time);
	printk("psb = %p\n", psb);

	table->sblock = sb;
	table->entry_allocator = &sbi->meta_table.entry_allocator;

	ret = rhashtable_init_large(&table->rht, nelem_hint,
		&nova_rht_params);
	if (ret < 0)
		goto err_out0;

	table->rht_entry_cache = kmem_cache_create("rht_entry_cache",
		sizeof(struct nova_rht_entry), 0, TABLE_KMEM_CACHE_FLAGS, NULL);
	if (table->rht_entry_cache == NULL) {
		ret = -ENOMEM;
		goto err_out1;
	}
	NOVA_END_TIMING(table_init_t, table_init_time);
	return 0;
err_out1:
	rhashtable_free_and_destroy(&table->rht, nova_rht_entry_free,
		table->rht_entry_cache);
err_out0:
	NOVA_END_TIMING(table_init_t, table_init_time);
	return ret;
}

struct table_recover_para {
	struct nova_mm_table *table;
	entrynr_t entry_start, entry_end;
};
static int __table_recover_func(struct nova_mm_table *table,
	entrynr_t entry_start, entrynr_t entry_end)
{
	struct super_block *sb = table->sblock;
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
		ret = nova_table_insert_entry(table, pentry->fp,
			pentry);
		if (ret < 0)
			break;
	}
	return ret;
}
static int table_recover_func(void *__para)
{
	struct table_recover_para *para = (struct table_recover_para *)__para;
	return __table_recover_func(para->table, para->entry_start,
		para->entry_end);
}
int nova_table_recover(struct nova_mm_table *table)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	entrynr_t n = le64_to_cpu(recover_meta->refcount_record_num);
	unsigned long entry_per_thread_max =
		max_ul(1UL << 10, (n + sbi->cpus - 1) / sbi->cpus);
	unsigned long thread_num =
		(n + entry_per_thread_max - 1) / entry_per_thread_max;
	unsigned long i;
	unsigned long base;
	struct table_recover_para *para;
	struct joinable_kthread *ts;
	int ret = 0;

	nova_info("About %lu hash table entries found.\n", (unsigned long)n);
	if (n == 0)
		return 0;
	nova_info("Recover fingerprint table using %lu thread(s)\n", thread_num);
	if (thread_num == 1)
		return __table_recover_func(table, 0, n);
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
		para[i].table = table;
		para[i].entry_start = base;
		base += entry_per_thread_max;
		para[i].entry_end = base < n ? base : n;
		ts[i].threadfn = table_recover_func;
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

int nova_table_stats(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_meta_table *meta_table = &sbi->meta_table;
	struct nova_mm_table *table = &meta_table->metas;
	return __nova_entry_allocator_stats(sbi, table->entry_allocator);
}
