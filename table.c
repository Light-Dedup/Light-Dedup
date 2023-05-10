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
	meta->entry_allocator.map_blocknr_to_pentry[blocknr] = pentry;
}

static inline void
clear_pmm_entry_at_blocknr(struct light_dedup_meta *meta,
	unsigned long blocknr) 
{
	struct nova_pmm_entry **pentry =
		meta->entry_allocator.map_blocknr_to_pentry + blocknr;
	BUG_ON(*pentry == 0);
	*pentry = NULL;
}
static inline struct nova_pmm_entry *
blocknr_pmm_entry(struct light_dedup_meta *meta, unsigned long blocknr)
{
	return meta->entry_allocator.map_blocknr_to_pentry[blocknr];
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
	refcount = atomic64_cmpxchg(&pentry->refcount, 0, 1);
	BUG_ON(refcount != 0);
	new_dirty_fpentry(wp->last_new_entries, pentry);
	wp->last_accessed = pentry;
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
	wp->base.refcount = atomic64_fetch_add_unless(&pentry->refcount, 1, 0);
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
	INIT_TIMING(update_hint_time);

	NOVA_START_TIMING(update_hint_t, update_hint_time);
	ret = __incr_trust_degree(next_hint, offset_ori, trust_degree);
	// nova_flush_cacheline(next_hint, false);
	NOVA_END_TIMING(update_hint_t, update_hint_time);
	return ret;
}

static inline u64 decr_trust_degree(struct nova_sb_info *sbi,
	atomic64_t *next_hint, u64 offset_ori, u64 offset_new,
	uint8_t trust_degree)
{
	u64 ret;
	INIT_TIMING(update_hint_time);
	NOVA_START_TIMING(update_hint_t, update_hint_time);
	ret = __decr_trust_degree(next_hint, offset_ori, offset_new,
		trust_degree);
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

static int handle_no_hint(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, atomic64_t *next_hint,
	u64 old_hint)
{
	u64 offset;
	uint8_t trust_degree;
	uint64_t hint;
	int ret;
	INIT_TIMING(update_hint_time);

	ret = copy_from_user_incr_ref(sbi, wp);
	if (ret < 0)
		return ret;
	NOVA_STATS_ADD(no_hint, 1);
	if (unlikely(wp->normal.last_accessed == NULL))
		return 0;
	offset = (u64)wp->normal.last_accessed;
	NOVA_START_TIMING(update_hint_t, update_hint_time);
	hint = __update_hint(next_hint, old_hint,
		offset | HINT_TRUST_DEGREE_THRESHOLD);
	if ((hint & HINT_OFFSET_MASK) == offset) {
		trust_degree = hint & TRUST_DEGREE_MASK;
		__incr_trust_degree(next_hint, offset, trust_degree);
	}
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
	ret = copy_from_user_incr_ref(sbi, wp);
	if (ret < 0)
		return ret;
	if (unlikely(wp->normal.last_accessed == NULL))
		return 0;
	offset_new = (u64)wp->normal.last_accessed;
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
	pentry = (struct nova_pmm_entry *)offset;
	if (nova_pmm_entry_is_readable(pentry))
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

// Return whether the block is deduplicated successfully.
static int check_hint(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, struct nova_pmm_entry *pentry)
{
	struct light_dedup_meta *meta = &sbi->light_dedup_meta;
	unsigned long blocknr;
	const char *addr;
	size_t i;
	int64_t ret;
	INIT_TIMING(prefetch_cmp_time);
	INIT_TIMING(cmp_user_time);
	INIT_TIMING(hit_incr_ref_time);

	// To make sure that pentry will not be released while we
	// are reading its content.
	rcu_read_lock();

	if (!nova_pmm_entry_is_readable(pentry)) {
		rcu_read_unlock();
		return 0;
	}
	blocknr = nova_pmm_entry_blocknr(pentry);
	BUG_ON(blocknr == 0);
	// It is guaranteed that the block will not be freed,
	// because we are holding the RCU read lock.
	addr = nova_sbi_blocknr_to_addr(sbi, blocknr);

	if (atomic64_read(&meta->thread_num) < transition_threshold) {
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

	// Increase refcount speculatively
	NOVA_START_TIMING(hit_incr_ref_t, hit_incr_ref_time);
	// nova_memunlock_range(sbi->sb, &pentry->refcount,
	// 	sizeof(pentry->refcount), &irq_flags);
	ret = atomic64_add_unless(&pentry->refcount, 1, 0);
	// nova_memlock_range(sbi->sb, &pentry->refcount,
	// 	sizeof(pentry->refcount), &irq_flags);
	NOVA_END_TIMING(hit_incr_ref_t, hit_incr_ref_time);
	if (ret == false) {
		rcu_read_unlock();
		return 0;
	}

	// The blocknr will not be released now, because we are referencing it.
	rcu_read_unlock();

	prefetch_next_stage_1(wp);

	NOVA_START_TIMING(cmp_user_t, cmp_user_time);
	ret = cmp_user_generic_const_8B_aligned(wp->ubuf, addr, PAGE_SIZE);
	NOVA_END_TIMING(cmp_user_t, cmp_user_time);

	prefetch_next_stage_2(wp);

	if (ret < 0) {
		decr_ref(meta, pentry);
		return -EFAULT;
	}
	if (ret != 0) {
		// printk("Prediction miss: %lld\n", ret);
		// BUG_ON(copy_from_user(wp->kbuf, wp->ubuf, PAGE_SIZE));
		// print(wp->kbuf);
		// printk("\n");
		// print(addr);
		decr_ref(meta, pentry);
		return 0;
	}
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
	pentry = (struct nova_pmm_entry *)offset;

	ret = check_hint(sbi, wp, pentry);

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
	ret = copy_from_user_incr_ref(sbi, wp);
	if (ret < 0)
		return ret;
	if (unlikely(wp->normal.last_accessed == NULL))
		return 0;
	decr_trust_degree(sbi, next_hint, offset,
		(u64)wp->normal.last_accessed,
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
		return copy_from_user_incr_ref(sbi, wp);
	}
}

int light_dedup_incr_ref_continuous(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp)
{
	struct nova_pmm_entry *last_pentry;
	bool first = true;
	int ret = 0;
	// unsigned long irq_flags = 0;
	INIT_TIMING(time);

	NOVA_START_TIMING(incr_ref_continuous_t, time);
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
	NOVA_END_TIMING(incr_ref_continuous_t, time);
	return ret;
}

#if 0
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
#endif

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
#if 0
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
#endif
	BUG();
}
void light_dedup_meta_save(struct light_dedup_meta *meta)
{
	struct super_block *sb = meta->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	// rht_save(sbi, recover_meta, &meta->rht);
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
