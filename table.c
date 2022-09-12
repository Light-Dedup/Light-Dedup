#include <linux/atomic.h>
#include <linux/string.h>

#include "nova.h"
#include "faststr.h"
#include "arithmetic.h"
#include "multithread.h"
#include "rhashtable-ext.h"

// #define static _Static_assert(1, "2333");

struct nova_rht_entry {
	struct rhash_head node;
	struct nova_fp_partial fp_partial;
	struct nova_pmm_entry *pentry;
};

static u32 nova_rht_entry_key_hashfn(const void *data, u32 len, u32 seed)
{
	struct nova_fp *fp = (struct nova_fp *)data;
	return fp->partial.index;
}

static u32 nova_rht_entry_hashfn(const void *data, u32 len, u32 seed)
{
	struct nova_rht_entry *entry = (struct nova_rht_entry *)data;
	return entry->fp_partial.index;
}

static int nova_rht_key_entry_cmp(
	struct rhashtable_compare_arg *arg,
	const void *obj)
{
	const struct nova_fp *fp = (const struct nova_fp *)arg->key;
	struct nova_rht_entry *entry = (struct nova_rht_entry *)obj;
	// printk("%s: %llx, %llx", __func__, fp->value, entry->fp.value);
	return fp->partial.value != entry->fp_partial.value ||
		fp->u64s[1] != entry->pentry->fp.u64s[1] ||
		fp->u64s[2] != entry->pentry->fp.u64s[2] ||
		fp->u64s[3] != entry->pentry->fp.u64s[3];
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

struct rht_entry_free_task {
	struct rcu_head head;
	struct entry_allocator *allocator;
	struct nova_rht_entry *entry;
};

static void rht_entry_free(struct rcu_head *head)
{
	struct rht_entry_free_task *task =
		container_of(head, struct rht_entry_free_task, head);
	struct nova_meta_table *meta_table = container_of(task->allocator,
		struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	struct nova_mm_table *table = &meta_table->metas;
	struct kmem_cache *rht_entry_cache = table->rht_entry_cache;
	struct nova_rht_entry *entry = task->entry;
	struct nova_pmm_entry *pentry = entry->pentry;
	unsigned long blocknr = nova_pmm_entry_blocknr(pentry);
	BUG_ON(blocknr == 0);
	nova_free_data_block(sb, blocknr);
	nova_free_entry(task->allocator, pentry);
	nova_rht_entry_free(entry, rht_entry_cache);
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

static void nova_table_leaf_delete(
	struct nova_mm_table *table,
	struct rhashtable *rht,
	struct nova_rht_entry *entry)
{
	struct rht_entry_free_task *task;
	// Remove the entry first to make it invisible to other threads.
	int ret = rhashtable_remove_fast(rht, &entry->node, nova_rht_params);
	BUG_ON(ret < 0);
	nova_pmm_entry_mark_to_be_freed(entry->pentry);
	task = kmalloc(sizeof(struct rht_entry_free_task), GFP_ATOMIC);
	if (task) {
		task->allocator = table->entry_allocator;
		task->entry = entry;
		call_rcu(&task->head, rht_entry_free);
	} else {
		// printk(KERN_ERR "%s: Fail to allocate task\n", __func__);
		synchronize_rcu();
		nova_free_entry(table->entry_allocator, entry->pentry);
		nova_rht_entry_free(entry, table->rht_entry_cache);
	}
}
static int alloc_and_fill_block(
	struct super_block *sb,
	struct nova_write_para_normal *wp)
{
	void *xmem;
	unsigned long irq_flags = 0;
	INIT_TIMING(memcpy_time);

	wp->blocknr = nova_new_data_block(sb);
	if (wp->blocknr == 0)
		return -ENOSPC;
	// printk("%s: Block %ld allocated", __func__, wp->blocknr);
	xmem = nova_blocknr_to_addr(sb, wp->blocknr);
	nova_memunlock_block(sb, xmem, &irq_flags);
	NOVA_START_TIMING(memcpy_data_block_t, memcpy_time);
	memcpy_flushcache((char *)xmem, (const char *)wp->addr, 4096);
	NOVA_END_TIMING(memcpy_data_block_t, memcpy_time);
	nova_memlock_block(sb, xmem, &irq_flags);
	// wp->refcount = wp->base.delta;
	// printk("xmem = %pK", xmem);
	return 0;
}
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
	// wp->refcount = wp->base.delta;
	NOVA_END_TIMING(memcpy_data_block_t, memcpy_time);
	return 0;
}
static void assign_entry(
	struct nova_rht_entry *entry,
	struct nova_pmm_entry *pentry,
	const struct nova_fp *fp)
{
	entry->fp_partial = fp->partial;
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
	const struct nova_fp *fp = &wp->base.fp;
	int cpu;
	struct entry_allocator_cpu *allocator_cpu;
	struct nova_pmm_entry *pentry;
	int ret;
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
	nova_write_entry(table->entry_allocator, allocator_cpu, pentry, fp,
		wp->blocknr);
	put_cpu();
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
	new_dirty_fpentry(wp->last_new_entries, pentry);
	wp->last_accessed = pentry;
	// printk("Block %lu with fp %llx inserted into rhashtable %p, "
	// 	"fpentry offset = %p\n", wp->blocknr, fp.value, rht, pentry);
	return 0;
fail2:
	nova_free_data_block(sb, nova_pmm_entry_blocknr(pentry));
	nova_free_entry(table->entry_allocator, pentry);
fail1:
	nova_rht_entry_free(entry, table->rht_entry_cache);
fail0:
	return ret;
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
	unsigned long irq_flags = 0;
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
	wp->blocknr = blocknr;// retrieval block info
	nova_memunlock_range(sb, &pentry->refcount,
		sizeof(pentry->refcount), &irq_flags);
	wp->base.refcount = atomic64_fetch_add_unless(&pentry->refcount, 1, 0);
	nova_memlock_range(sb, &pentry->refcount,
		sizeof(pentry->refcount), &irq_flags);
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

int nova_table_deref_block(struct nova_mm_table *table,
	struct nova_write_para_normal *wp)
{
	struct super_block *sb = table->sblock;
	struct rhashtable *rht = &table->rht;
	struct nova_rht_entry *entry;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	unsigned long irq_flags = 0;
	INIT_TIMING(mem_bucket_find_time);

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
		// Collision happened. Just free it.
		printk("Block %ld can not be found in the hash table.", wp->blocknr);
		wp->base.refcount = 0;
		wp->last_accessed = NULL;
		return 0;
	}
	pentry = entry->pentry;
	blocknr = nova_pmm_entry_blocknr(pentry);
	BUG_ON(blocknr == 0);
	if (blocknr != wp->blocknr) {
		// Collision happened. Just free it.
		rcu_read_unlock();
		printk("%s: Blocknr mismatch: blocknr = %ld, expected %ld\n", __func__, blocknr, wp->blocknr);
		wp->base.refcount = 0;
		wp->last_accessed = NULL;
		return 0;
	}
	rcu_read_unlock();
	nova_memunlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
		&irq_flags);
	wp->base.refcount = atomic64_add_return(-1, &entry->pentry->refcount);
	nova_memlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
		&irq_flags);
	BUG_ON(wp->base.refcount < 0);
	if (wp->base.refcount == 0) {
		// Now only we can free the entry,
		// because there are no any other deleter.
		wp->last_accessed = NULL;
		nova_table_leaf_delete(table, rht, entry);
		return 0;
	}
	nova_flush_entry(table->entry_allocator, pentry);
	wp->last_accessed = pentry;
	return 0;
}

// Upsert : update or insert
int nova_table_upsert_normal(struct nova_mm_table *table, struct nova_write_para_normal *wp)
{
	return upsert_block(table, wp, alloc_and_fill_block);
}
// Inplace 
int nova_table_upsert_rewrite(struct nova_mm_table *table, struct nova_write_para_rewrite *wp)
{
	return upsert_block(table, (struct nova_write_para_normal *)wp,
		rewrite_block);
}

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
		nova_table_leaf_delete(table, rht, entry);
		wp->base.refcount = 0;
		return 0;
	}
	// refcount >= 2. So we do not decrease refcount.
	wp->base.refcount = refcount;
	// printk(KERN_WARNING " found at %d, ref %llu\n", leaf_index, refcount);
	return 0;
}

int nova_table_insert_entry(struct nova_mm_table *table, struct nova_fp *fp,
	struct nova_pmm_entry *pentry)
{
	struct nova_rht_entry *entry = nova_rht_entry_alloc(table);
	int ret;

	if (entry == NULL)
		return -ENOMEM;
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

static inline void incr_stream_trust_degree(
	struct nova_write_para_continuous *wp)
{
	if (wp->stream_trust_degree < TRUST_DEGREE_MAX)
		wp->stream_trust_degree += 1;
}

static inline void decr_stream_trust_degree(
	struct nova_write_para_continuous *wp)
{
	if (wp->stream_trust_degree < TRUST_DEGREE_MIN + 2)
		wp->stream_trust_degree = TRUST_DEGREE_MIN;
	else
		wp->stream_trust_degree -= 2;
}

static inline bool hint_trustable(uint8_t trust_degree)
{
	return trust_degree >= HINT_TRUST_DEGREE_THRESHOLD;
}

// Return the original persistent hint.
static u64 __update_hint(atomic64_t *next_hint, u64 old_hint, u64 new_hint)
{
	return le64_to_cpu(atomic64_cmpxchg_relaxed(
		next_hint,
		cpu_to_le64(old_hint),
		cpu_to_le64(new_hint)));
}

static inline bool trust_degree_out_of_bound(uint8_t trust_degree)
{
	return trust_degree & (1 << TRUST_DEGREE_BITS);
}

// Return 0: Successful
// Return x (!= 0): The offset has been changed, and the new hint is x.
static u64 __incr_trust_degree(atomic64_t *next_hint, u64 offset_ori,
	uint8_t trust_degree)
{
	__le64 old_hint = cpu_to_le64(offset_ori | trust_degree);
	__le64 tmp;
	uint64_t hint;

	while (1) {
		if (trust_degree == TRUST_DEGREE_MAX)
			return 0;
		trust_degree += 1;
		hint = offset_ori | trust_degree;
		tmp = atomic64_cmpxchg_relaxed(next_hint, old_hint,
			cpu_to_le64(hint));
		if (tmp == old_hint)
			return 0;
		hint = le64_to_cpu(tmp);
		if ((hint & HINT_OFFSET_MASK) != offset_ori) {
			// The hinted fpentry has been changed.
			return hint;
		}
		trust_degree = hint & TRUST_DEGREE_MASK;
		old_hint = tmp;
	}
}

// Update offset to offset_new if the resulting trust degree is not trustable.
// Return 0: Successful
// Return x (!= 0): The offset has been changed, and the new hint is x.
static u64 __decr_trust_degree(atomic64_t *next_hint, u64 offset_ori,
	u64 offset_new, uint8_t trust_degree)
{
	__le64 old_hint = cpu_to_le64(offset_ori | trust_degree);
	__le64 tmp;
	uint64_t hint;

	while (1) {
		if (trust_degree < TRUST_DEGREE_MIN + 2) {
			trust_degree = TRUST_DEGREE_MIN;
		} else {
			trust_degree -= 2;
		}
		if (!hint_trustable(trust_degree)) {
			hint = offset_new | trust_degree;
		} else {
			hint = offset_ori | trust_degree;
		}
		tmp = atomic64_cmpxchg_relaxed(next_hint, old_hint,
			cpu_to_le64(hint));
		if (tmp == old_hint)
			return 0;
		hint = le64_to_cpu(tmp);
		if ((hint & HINT_OFFSET_MASK) != offset_ori) {
			// The hinted fpentry has been changed.
			return hint;
		}
		trust_degree = hint & TRUST_DEGREE_MASK;
		old_hint = tmp;
	}
}

static u64 incr_trust_degree(struct nova_sb_info *sbi, atomic64_t *next_hint,
	u64 offset_ori, uint8_t trust_degree)
{
	u64 ret;
	// unsigned long irq_flags = 0;
	INIT_TIMING(update_hint_time);

	NOVA_START_TIMING(update_hint_t, update_hint_time);
	// nova_sbi_memunlock_range(sbi, next_hint, sizeof(*next_hint),
	// 	&irq_flags);
	ret = __incr_trust_degree(next_hint, offset_ori, trust_degree);
	// nova_sbi_memlock_range(sbi, next_hint, sizeof(*next_hint), &irq_flags);
	// nova_flush_cacheline(next_hint, false);
	NOVA_END_TIMING(update_hint_t, update_hint_time);
	return ret;
}

static inline u64 decr_trust_degree(struct nova_sb_info *sbi,
	atomic64_t *next_hint, u64 offset_ori, u64 offset_new,
	uint8_t trust_degree)
{
	u64 ret;
	// unsigned long irq_flags = 0;
	INIT_TIMING(update_hint_time);
	NOVA_START_TIMING(update_hint_t, update_hint_time);
	// nova_sbi_memunlock_range(sbi, next_hint, sizeof(*next_hint),
	// 	&irq_flags);
	ret = __decr_trust_degree(next_hint, offset_ori, offset_new,
		trust_degree);
	// nova_sbi_memlock_range(sbi, next_hint, sizeof(*next_hint), &irq_flags);
	// nova_flush_cacheline(next_hint, false);
	NOVA_END_TIMING(update_hint_t, update_hint_time);
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

static int copy_from_user_incr(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp)
{
	int ret;

	ret = nova_fp_table_incr_atomic(&sbi->meta_table.metas,
		wp->kbuf + wp->kstart, &wp->normal);
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
	uint8_t trust_degree;
	uint64_t hint;
	int ret;
	// unsigned long irq_flags = 0;
	INIT_TIMING(update_hint_time);

	ret = copy_from_user_incr(sbi, wp);
	if (ret < 0)
		return ret;
	NOVA_STATS_ADD(no_hint, 1);
	offset = nova_get_addr_off(sbi, wp->normal.last_accessed);
	NOVA_START_TIMING(update_hint_t, update_hint_time);
	// nova_sbi_memunlock_range(sbi, next_hint, sizeof(*next_hint),
	// 	&irq_flags);
	hint = __update_hint(next_hint, old_hint,
		offset | HINT_TRUST_DEGREE_THRESHOLD);
	if ((hint & HINT_OFFSET_MASK) == offset) {
		trust_degree = hint & TRUST_DEGREE_MASK;
		__incr_trust_degree(next_hint, offset, trust_degree);
	}
	// nova_sbi_memlock_range(sbi, next_hint, sizeof(*next_hint),
	// 	&irq_flags);
	// nova_flush_cacheline(next_hint, false);
	NOVA_END_TIMING(update_hint_t, update_hint_time);
	return 0;
}

static int handle_not_trust(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, atomic64_t *next_hint,
	u64 offset, uint8_t trust_degree)
{
	u64 offset_new;
	int ret;
	ret = copy_from_user_incr(sbi, wp);
	if (ret < 0)
		return ret;
	offset_new = nova_get_addr_off(sbi, wp->normal.last_accessed);
	if (offset_new == offset) {
		NOVA_STATS_ADD(hint_not_trusted_hit, 1);
		incr_trust_degree(sbi, next_hint, offset, trust_degree);
		incr_stream_trust_degree(wp);
	} else {
		NOVA_STATS_ADD(hint_not_trusted_miss, 1);
		decr_trust_degree(sbi, next_hint, offset, offset_new,
			trust_degree);
		decr_stream_trust_degree(wp);
	}
	return 0;
}

// The caller should hold rcu_read_lock
static void handle_hint_of_hint(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, atomic64_t *next_hint)
{
	uint64_t hint = le64_to_cpu(atomic64_read(next_hint));
	u64 offset = hint & HINT_OFFSET_MASK;
	uint8_t trust_degree = hint & TRUST_DEGREE_MASK;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;

	// Be conservative because prefetching consumes bandwidth.
	if (wp->stream_trust_degree != TRUST_DEGREE_MAX || offset == 0 ||
			!hint_trustable(trust_degree))
		return;
	// Do not prefetch across syscall.
	if (wp->len < PAGE_SIZE * 2)
		return;
	pentry = nova_sbi_get_block(sbi, offset);
	if (nova_pmm_entry_is_to_be_freed(pentry))
		return;
	blocknr = nova_pmm_entry_blocknr(pentry);
	if (blocknr) {
		wp->block_prefetching = nova_sbi_blocknr_to_addr(sbi, blocknr);
		wp->prefetched_blocknr[1] = wp->prefetched_blocknr[0];
		wp->prefetched_blocknr[0] = blocknr;
	}
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

	blocknr = nova_pmm_entry_blocknr(pentry);
	if (blocknr == 0) {
		// The hinted fpentry has already been released
		return 0;
	}
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
	ret = cmp64((const uint64_t *)(wp->kbuf + wp->kstart),
		(const uint64_t *)addr);
	NOVA_END_TIMING(cmp_user_t, cmp_user_time);

	prefetch_next_stage_2(wp);

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
	u64 offset = hint & HINT_OFFSET_MASK;
	uint8_t trust_degree = hint & TRUST_DEGREE_MASK;
	struct nova_pmm_entry *pentry;
	int ret;

	if (offset == 0) {
		// Actually no hint
		return handle_no_hint(sbi, wp, next_hint, hint);
	}
	if (!hint_trustable(trust_degree)) {
		return handle_not_trust(sbi, wp, next_hint,
			offset, trust_degree);
	}
	pentry = nova_sbi_get_block(sbi, offset);
	if (nova_pmm_entry_is_to_be_freed(pentry))
		return handle_no_hint(sbi, wp, next_hint, hint);

	// To make sure that pentry will not be released while we
	// are reading its content.
	rcu_read_lock();
	ret = check_hint(sbi, wp, pentry);
	rcu_read_unlock();

	if (ret < 0)
		return ret;
	if (ret == 1) {
		NOVA_STATS_ADD(predict_hit, 1);
		incr_trust_degree(sbi, next_hint, offset, trust_degree);
		incr_stream_trust_degree(wp);
		return 0;
	}
	NOVA_STATS_ADD(predict_miss, 1);
	BUG_ON(ret != 0);
	ret = copy_from_user_incr(sbi, wp);
	if (ret < 0)
		return ret;
	decr_trust_degree(sbi, next_hint, offset,
		nova_get_addr_off(sbi, wp->normal.last_accessed),
		trust_degree);
	decr_stream_trust_degree(wp);
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

int nova_fp_table_incr_continuous_kbuf(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp)
{
	struct nova_pmm_entry *last_pentry;
	bool first = true;
	int ret = 0;
	unsigned long irq_flags = 0;
	INIT_TIMING(time);

	NOVA_START_TIMING(incr_continuous_t, time);
	// Unlock here because it seems that wprotect will affect prefetching
	nova_memunlock(sbi, &irq_flags);
	while (wp->blocknr_next == 0 && wp->klen > 0) {
		last_pentry = get_last_accessed(wp, !first);
		while (1) {
			ret = handle_last_accessed_pentry(sbi, wp, last_pentry);
			if (likely(ret != -EAGAIN))
				break;
			nova_memlock(sbi, &irq_flags);
			schedule();
			nova_memunlock(sbi, &irq_flags);
		}
		if (ret < 0)
			break;
		wp->kstart = (wp->kstart + PAGE_SIZE) % KBUF_LEN_MAX;
		wp->klen -= PAGE_SIZE;
		first = false;
	}
	nova_memlock(sbi, &irq_flags);
	NOVA_END_TIMING(incr_continuous_t, time);
	return ret;
}

int nova_fp_table_incr_continuous(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp)
{
	size_t to_copy;
	size_t start;
	size_t n;
	int ret;
	INIT_TIMING(copy_from_user_time);

	while (wp->blocknr_next == 0 && wp->len >= PAGE_SIZE) {
		NOVA_START_TIMING(copy_from_user_t, copy_from_user_time);
		// to_copy = min_usize(to_copy, KBUF_LEN - wp->klen);
		to_copy = wp->len & ~(PAGE_SIZE - 1);
		start = wp->kstart + wp->klen;
		if (start >= KBUF_LEN_MAX) {
			start -= KBUF_LEN_MAX;
			n = min_usize(wp->kstart - start, to_copy);
			if (copy_from_user(wp->kbuf + start, wp->ubuf, n))
				return -EFAULT;
			wp->klen += n;
			wp->len -= n;
			wp->ubuf += n;
		} else {
			n = min_usize(KBUF_LEN_MAX - start, to_copy);
			if (copy_from_user(wp->kbuf + start, wp->ubuf, n))
				return -EFAULT;
			wp->klen += n;
			wp->len -= n;
			wp->ubuf += n;
			if (n < to_copy) {
				to_copy -= n;
				n = min_usize(wp->kstart, to_copy);
				if (copy_from_user(wp->kbuf, wp->ubuf, n))
					return -EFAULT;
				wp->klen += n;
				wp->len -= n;
				wp->ubuf += n;
			}
		}
		NOVA_END_TIMING(copy_from_user_t, copy_from_user_time);
		ret = nova_fp_table_incr_continuous_kbuf(sbi, wp);
		if (ret < 0)
			return ret;
	}
	return 0;
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
	rhashtable_free_and_destroy(&table->rht, nova_rht_entry_free,
		table->rht_entry_cache);
	kmem_cache_destroy(table->rht_entry_cache);
}
void nova_table_save(struct nova_mm_table* table)
{
	INIT_TIMING(save_refcount_time);

	NOVA_START_TIMING(save_refcount_t, save_refcount_time);
	table_save(table);
	nova_table_free(table);
	NOVA_END_TIMING(save_refcount_t, save_refcount_time);
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
	struct completion entered;
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
		ret = nova_table_insert_entry(table, &pentry->fp,
			pentry);
		if (ret < 0)
			break;
	}
	return ret;
}
static int table_recover_func(void *__para)
{
	struct table_recover_para *para = (struct table_recover_para *)__para;
	int ret;
	// printk("%s\n", __func__);
	complete(&para->entered);
	ret = __table_recover_func(para->table, para->entry_start, para->entry_end);
	// printk("%s waiting for kthread_stop\n", __func__);
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	return ret;
}
int nova_table_recover(struct nova_mm_table *table)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	entrynr_t n = le64_to_cpu(recover_meta->refcount_record_num);
	unsigned long entry_per_thread_bit = max_ul(20, ceil_log_2(n / sbi->cpus));
	unsigned long entry_per_thread = 1UL << entry_per_thread_bit;
	unsigned long i, thread_num = ((n - 1) >> entry_per_thread_bit) + 1;
	unsigned long base;
	struct table_recover_para *para = NULL;
	struct task_struct **tasks = NULL;
	int ret = 0, ret2;

	nova_info("About %lu hash table entries found.\n", (unsigned long)n);
	if (n == 0)
		return 0;
	nova_info("Recover fingerprint table using %lu thread(s)\n", thread_num);
	if (thread_num == 1)
		return __table_recover_func(table, 0, n);
	para = kmalloc(thread_num * sizeof(para[0]), GFP_KERNEL);
	if (para == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	tasks = kmalloc(thread_num * sizeof(struct task_struct *), GFP_KERNEL);
	if (tasks == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	base = 0;
	for (i = 0; i < thread_num; ++i) {
		init_completion(&para[i].entered);
		para[i].table = table;
		para[i].entry_start = base;
		base += entry_per_thread;
		para[i].entry_end = base < n ? base : n;
		tasks[i] = kthread_create(table_recover_func, para + i,
			"%s_%lu", __func__, i);
		if (IS_ERR(tasks[i])) {
			ret = PTR_ERR(tasks[i]);
			nova_err(sb, "%lu: kthread_create %lu return %d\n",
				__func__, i, ret);
			break;
		}
	}
	ret2 = run_and_stop_kthreads(tasks, para, thread_num, i);
	if (ret2 < 0)
		ret = ret2;
out:
	if (para)
		kfree(para);
	if (tasks)
		kfree(tasks);
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
