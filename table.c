#include <linux/atomic.h>
#include <linux/string.h>

#include "nova.h"
#include "faststr.h"
#include "arithmetic.h"
#include "multithread.h"
#include "uaccess-ext.h"

// #define static _Static_assert(1, "2333");

#define NOVA_TABLE_NOT_FOUND ((uint64_t)-1)

struct nova_write_para_entry {
	struct nova_write_para_base base;
	struct nova_pmm_entry *pentry;
};

static uint64_t nova_table_leaf_find(
	const struct nova_mm_table *table,
	const struct nova_pmm_entry *pentries,
	const struct nova_fp *fp)
{
	entrynr_t index = fp->value % table->entry_allocator->num_entry;
	entrynr_t base = index & ~(ENTRY_PER_REGION - 1);
	entrynr_t offset = index & (ENTRY_PER_REGION - 1);
	entrynr_t i = offset;
	do {
		index = base + i;
		if (pentries[index].blocknr != 0)
			if (nova_fp_equal(fp, &pentries[index].fp))
				return index;
		++i;
		i &= ENTRY_PER_REGION - 1;
	} while (i != offset);
	return NOVA_TABLE_NOT_FOUND;
}

static inline void new_dirty_fpentry(struct nova_pmm_entry *last_pentries[2],
	struct nova_pmm_entry *pentry)
{
	nova_flush_entry_if_not_null(last_pentries[1], false);
	last_pentries[1] = last_pentries[0];
	last_pentries[0] = pentry;
}

static void nova_table_leaf_delete(
	struct nova_mm_table *table,
	entrynr_t entry_index)
{
	entrynr_t entrynr = entry_index;
	nova_free_entry(table->entry_allocator, entrynr);
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

static int nova_table_leaf_insert(
	struct nova_mm_table *table,
	struct nova_write_para_normal *wp,
	int get_new_block(struct super_block *, struct nova_write_para_normal *))
{
	struct super_block *sb = table->sblock;
	struct entry_allocator *allocator = table->entry_allocator;
	struct nova_pmm_entry *pentries = table->pentries;
	struct nova_pmm_entry *pentry;
	struct nova_fp fp = wp->base.fp;
	entrynr_t entrynr;
	int retval;

	retval = get_new_block(sb,wp);
	if(retval < 0)
		return retval;
	spin_lock(&allocator->lock);
	entrynr = nova_alloc_entry(allocator, fp);
	if (entrynr != REGION_FULL)
		nova_write_entry(allocator, entrynr, fp, wp->blocknr);
	else
		++allocator->entry_collision;
	spin_unlock(&allocator->lock);

	pentry = pentries + entrynr;
	new_dirty_fpentry(wp->last_new_entries, pentry);
	wp->last_accessed = pentry;
	return 0;
}
#if 0
static void print_bucket_entry(
	struct nova_mm_table *table,
	const struct nova_bucket *bucket,
	size_t index)
{
	struct nova_pmm_entry *pentry =
		table->pentries + bucket->entry_p[index].entrynr;
	struct nova_mm_entry_info entry_info = entry_info_pmm_to_mm(pentry->info);
	BUG_ON(entry_info.flag != NOVA_LEAF_ENTRY_MAGIC);
	printk("index = %lu, tag = %d, indicator = %d, blocknr = %lu, fp = %llx\n",
		index, bucket->tags[index], bucket->indicators[index],
		(unsigned long)entry_info.blocknr,
		pentry->fp.value);
}
#endif

// True: Not equal. False: Equal
static bool cmp_content(struct super_block *sb, unsigned long blocknr, const void *addr) {
	INIT_TIMING(memcmp_time);
	const void *content;
	bool res;
	NOVA_START_TIMING(memcmp_t, memcmp_time);
	content = nova_blocknr_to_addr(sb, blocknr);
	res = cmp64(content, addr);
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
	struct nova_pmm_entry *pentries = table->pentries;
	uint64_t leaf_index;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	unsigned long irq_flags = 0;
	int ret;
	INIT_TIMING(mem_bucket_find_time);

retry:
	rcu_read_lock();
	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	leaf_index = nova_table_leaf_find(table, pentries, &wp->base.fp);
	NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	if (leaf_index == NOVA_TABLE_NOT_FOUND) {
		rcu_read_unlock();
		// printk("Block with fp %llx not found in rhashtable %p\n",
		// 	wp->base.fp.value, rht);
		ret = nova_table_leaf_insert(table, wp, get_new_block);
		if (ret == -EEXIST)
			goto retry;
		wp->base.refcount = 1;
		return ret;
	}
	pentry = pentries + leaf_index;
	blocknr = le64_to_cpu(pentry->blocknr);
	BUG_ON(blocknr == 0);
	if (cmp_content(sb, blocknr, wp->addr)) {
		rcu_read_unlock();
		wp->last_accessed = NULL;
		nova_dbg("fp:%llx rentry.fp:%llx",wp->base.fp.value, pentry->fp.value);
		printk("Collision, just write it.");
		wp->base.refcount = 0;
		return get_new_block(sb, wp);
		// const void *content = nova_get_block(sb, nova_sb_blocknr_to_addr(sb, le64_to_cpu(leaf->blocknr), NOVA_BLOCK_TYPE_4K));
		// printk("First 8 bytes of existed_entry: %llx, chunk_id = %llx, fingerprint = %llx %llx %llx %llx\nFirst 8 bytes of incoming block: %llx, fingerprint = %llx %llx %llx %llx\n",
		// 	*(uint64_t *)content, leaf->blocknr, leaf->fp_strong.u64s[0], leaf->fp_strong.u64s[1], leaf->fp_strong.u64s[2], leaf->fp_strong.u64s[3],
		// 	*(uint64_t *)addr, entry->fp_strong.u64s[0], entry->fp_strong.u64s[1], entry->fp_strong.u64s[2], entry->fp_strong.u64s[3]);
	}
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
	struct nova_pmm_entry *pentries = table->pentries;
	uint64_t leaf_index;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	unsigned long irq_flags = 0;
	INIT_TIMING(mem_bucket_find_time);

	rcu_read_lock();
	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	leaf_index = nova_table_leaf_find(table, pentries, &wp->base.fp);
	NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	if (leaf_index == NOVA_TABLE_NOT_FOUND) {
		rcu_read_unlock();
		// printk("Block with fp %llx not found in rhashtable %p\n",
		// 	wp->base.fp.value, rht);
		// Collision happened. Just free it.
		printk("Block %ld can not be found in the hash table.", wp->blocknr);
		wp->base.refcount = 0;
		wp->last_accessed = NULL;
		return 0;
	}
	pentry = pentries + leaf_index;
	blocknr = le64_to_cpu(pentry->blocknr);
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
	wp->base.refcount = atomic64_add_return(-1, &pentry->refcount);
	nova_memlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
		&irq_flags);
	BUG_ON(wp->base.refcount < 0);
	if (wp->base.refcount == 0) {
		// Now only we can free the entry,
		// because there are no any other deleter.
		wp->last_accessed = NULL;
		nova_table_leaf_delete(table, leaf_index);
		return 0;
	}
	nova_flush_cacheline(pentry, true);
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
	struct nova_pmm_entry *pentries = table->pentries;
	uint64_t leaf_index;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	int64_t refcount;
	INIT_TIMING(mem_bucket_find_time);

	rcu_read_lock();
	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	leaf_index = nova_table_leaf_find(table, pentries, &wp->base.fp);
	NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	if (leaf_index == NOVA_TABLE_NOT_FOUND) {
		// Collision happened. Just free it.
		printk("Block %ld can not be found in the hash table.", wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	pentry = pentries + leaf_index;
	blocknr = le64_to_cpu(pentry->blocknr);
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
		// printk("Before nova_table_leaf_delete");
		nova_table_leaf_delete(table, leaf_index);
		// printk("nova_table_leaf_delete return");
		wp->base.refcount = 0;
		return 0;
	}
	// refcount >= 2. So we do not decrease refcount.
	wp->base.refcount = refcount;
	// printk(KERN_WARNING " found at %d, ref %llu\n", leaf_index, refcount);
	return 0;
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

static inline void prefetcht0(const void *x)
{
	asm volatile("prefetcht0 %0" : : "m" (*(const char *)x));
}

static inline void prefetcht2(const void *x)
{
	asm volatile("prefetcht2 %0" : : "m" (*(const char *)x));
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

// The original offset is 0
// Return 0: Successful
// Return x (!= 0): The offset has been changed, and the new hint is x.
static uint64_t __update_offset(atomic64_t *next_hint, u64 offset,
	uint8_t trust_degree)
{
	__le64 old_hint = cpu_to_le64(trust_degree);
	__le64 tmp;
	uint64_t hint;

	while (1) {
		hint = offset | trust_degree;
		tmp = atomic64_cmpxchg_relaxed(next_hint, old_hint,
			cpu_to_le64(hint));
		if (tmp == old_hint)
			return 0;
		hint = le64_to_cpu(tmp);
		if ((hint & HINT_OFFSET_MASK) != 0) {
			// The hinted fpentry has been changed.
			return hint;
		}
		trust_degree = hint & TRUST_DEGREE_MASK;
		old_hint = tmp;
	}
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
	uint8_t trust_degree)
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
	offset = nova_get_addr_off(sbi, wp->normal.last_accessed);
	NOVA_START_TIMING(update_hint_t, update_hint_time);
	// nova_sbi_memunlock_range(sbi, next_hint, sizeof(*next_hint),
	// 	&irq_flags);
	hint = __update_offset(next_hint, offset, trust_degree);
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
	blocknr = le64_to_cpu(pentry->blocknr);
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

// Return whether the block is deduplicated successfully.
static int check_hint(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp, struct nova_pmm_entry *pentry)
{
	unsigned long blocknr;
	const char *addr;
	size_t i;
	int64_t ret;
	// unsigned long irq_flags = 0;
	INIT_TIMING(prefetch_cmp_time);
	INIT_TIMING(cmp_user_time);
	INIT_TIMING(hit_incr_ref_time);

	// To make sure that pentry will not be released while we
	// are reading its content.
	rcu_read_lock();
	blocknr = le64_to_cpu(pentry->blocknr);
	if (blocknr == 0) {
		rcu_read_unlock();
		// The hinted fpentry has already been released
		return 0;
	}
	handle_hint_of_hint(sbi, wp, &pentry->next_hint);
	// It is guaranteed that the block will not be freed,
	// because we are holding the RCU read lock.
	addr = nova_sbi_blocknr_to_addr(sbi, blocknr);

	NOVA_START_TIMING(prefetch_cmp_t, prefetch_cmp_time);
	for (i = 0; i < PAGE_SIZE; i += 64)
		prefetcht0(addr + i);
	NOVA_END_TIMING(prefetch_cmp_t, prefetch_cmp_time);

	prefetch_next_stage_1(wp);

	NOVA_START_TIMING(cmp_user_t, cmp_user_time);
	ret = cmp_user_generic_const_8B_aligned(wp->ubuf, addr, PAGE_SIZE);
	NOVA_END_TIMING(cmp_user_t, cmp_user_time);

	prefetch_next_stage_2(wp);

	if (ret < 0) {
		rcu_read_unlock();
		return -EFAULT;
	}
	if (ret != 0) {
		rcu_read_unlock();
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

	rcu_read_unlock();
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
		return handle_no_hint(sbi, wp, next_hint,
			trust_degree);
	}
	if (!hint_trustable(trust_degree)) {
		return handle_not_trust(sbi, wp, next_hint,
			offset, trust_degree);
	}
	pentry = nova_sbi_get_block(sbi, offset);
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

int nova_fp_table_incr_continuous(struct nova_sb_info *sbi,
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
	while (wp->blocknr_next == 0 && wp->len >= PAGE_SIZE) {
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
		wp->ubuf += PAGE_SIZE;
		wp->len -= PAGE_SIZE;
		first = false;
	}
	nova_memlock(sbi, &irq_flags);
	NOVA_END_TIMING(incr_continuous_t, time);
	return ret;
}

void nova_table_free(struct nova_mm_table *table)
{
	return;
}
void nova_table_save(struct nova_mm_table* table)
{
	return;
}

// nelem_hint: If 0 then use default
int nova_table_init(struct super_block *sb, struct nova_mm_table *table,
	size_t nelem_hint)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *psb = (struct nova_super_block *)sbi->virt_addr;
	INIT_TIMING(table_init_time);

	NOVA_START_TIMING(table_init_t, table_init_time);
	printk("psb = %p\n", psb);

	table->sblock = sb;
	table->pentries = nova_blocknr_to_addr(sb, sbi->entry_table_start);
	table->entry_allocator = &sbi->meta_table.entry_allocator;

	NOVA_END_TIMING(table_init_t, table_init_time);
	
	return 0;
}

struct table_recover_para {
	struct completion entered;
	struct nova_mm_table *table;
	entrynr_t entry_start, entry_end;
};
int nova_table_recover(struct nova_mm_table *table)
{
	return 0;
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
