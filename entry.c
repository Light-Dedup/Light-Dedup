#include "nova.h"
#include "multithread.h"
#include "arithmetic.h"

// #define static _Static_assert(1, "2333");

#define ENTRY_PER_CACHELINE (CACHELINE_SIZE / sizeof(struct nova_pmm_entry))
// If the number of free entries in a region is greater or equal to FREE_THRESHOLD, then the region is regarded as free.
#define FREE_THRESHOLD (REAL_ENTRY_PER_REGION / 2)

DEFINE_PER_CPU(struct entry_allocator_cpu, entry_allocator_per_cpu);

static int entry_allocator_alloc(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	int cpu;
	struct entry_allocator_cpu *allocator_cpu;
	int ret;
	xa_init(&allocator->valid_entry);
	ret = nova_queue_init(&allocator->free_regions, GFP_KERNEL);
	if (ret)
		return ret;
	for_each_possible_cpu(cpu) {
		allocator_cpu = &per_cpu(entry_allocator_per_cpu, cpu);
		// The first allocation will trigger a new_region request.
		allocator_cpu->top_entry = NULL_PENTRY;
		allocator_cpu->last_entry = NULL_PENTRY;
		allocator_cpu->allocated = 0;
	}
	spin_lock_init(&allocator->lock);
	return 0;
}

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	regionnr_t i;
	unsigned long blocknr;
	int ret;
	allocator->region_num = VALID_ENTRY_COUNTER_PER_BLOCK;
	allocator->last_region_tail = (__le64 *)nova_sbi_blocknr_to_addr(sbi,
		sbi->region_start + VALID_ENTRY_COUNTER_PER_BLOCK) - 1;
	allocator->max_region_num = VALID_ENTRY_COUNTER_PER_BLOCK;
	allocator->last_counter_block_tail =
		(__le64 *)nova_sbi_blocknr_to_addr(sbi,
			sbi->first_counter_block_start + 1)
		- 1;
	ret = entry_allocator_alloc(sbi, allocator);
	if (ret < 0)
		return ret;
	blocknr = sbi->region_start;
	for (i = 0; i < allocator->region_num; ++i, ++blocknr) {
		ret = xa_err(xa_store_bh(&allocator->valid_entry, blocknr,
			xa_mk_value(0), GFP_KERNEL));
		BUG_ON(ret < 0); // TODO: Handle it
		BUG_ON(nova_queue_push_ul(
			&allocator->free_regions, blocknr, GFP_KERNEL
		) < 0); // TODO: Handle it
	}
	return 0;
}

// Returns the total number of valid entries
static size_t rebuild_free_regions(struct nova_sb_info *sbi,
	struct entry_allocator *allocator)
{
	unsigned long blocknr;
	void *entry;
	int16_t count;
	size_t tot = 0;
	xa_for_each(&allocator->valid_entry, blocknr, entry) {
		count = xa_to_value(entry);
		tot += count;
		if (count <= FREE_THRESHOLD) {
			BUG_ON(nova_queue_push_ul(
				&allocator->free_regions,
				blocknr,
				GFP_KERNEL
			) < 0);
		}
	}
	return tot;
}
static inline int
__scan_valid_entry_counts(struct xarray *blocknr_count, __le64 *blocknrs,
	__le16 *counts, size_t len)
{
	__le16 *end = counts + len;
	int ret;
	while (counts != end) {
		ret = xa_err(xa_store(
			blocknr_count,
			*blocknrs++,
			xa_mk_value(le16_to_cpu(*counts++)),
			GFP_KERNEL
		));
		if (ret < 0)
			return ret;
	}
	return 0;
}
static inline int
scan_valid_entry_counts(struct nova_sb_info *sbi, struct xarray *blocknr_count,
	size_t len)
{
	__le64 *blocknrs = nova_sbi_blocknr_to_addr(
		sbi, sbi->region_blocknr_start);
	__le16 *counts = nova_sbi_blocknr_to_addr(
		sbi, sbi->first_counter_block_start);
	u64 offset;
	int ret;
	while (len >= VALID_ENTRY_COUNTER_PER_BLOCK) {
		ret = __scan_valid_entry_counts(blocknr_count, blocknrs, counts,
			VALID_ENTRY_COUNTER_PER_BLOCK);
		if (ret < 0)
			return ret;
		blocknrs += VALID_ENTRY_COUNTER_PER_BLOCK;
		offset = le64_to_cpu(
			*(__le64 *)((u64)counts + PAGE_SIZE - sizeof(__le64))
		);
		counts = (__le16 *)nova_sbi_get_block(sbi, offset);
		len -= VALID_ENTRY_COUNTER_PER_BLOCK;
	}
	return __scan_valid_entry_counts(blocknr_count, blocknrs, counts, len);
}
int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	int ret;
	INIT_TIMING(normal_recover_entry_allocator_time);

	NOVA_START_TIMING(normal_recover_entry_allocator_t,
		normal_recover_entry_allocator_time);
	allocator->region_num = le64_to_cpu(recover_meta->region_num);
	printk("%s: region_num = %u\n", __func__, allocator->region_num);
	ret = entry_allocator_alloc(sbi, allocator);
	if (ret < 0)
		return ret;
	allocator->last_region_tail = nova_sbi_get_block(sbi,
		le64_to_cpu(recover_meta->last_region_tail));
	allocator->max_region_num =
		le64_to_cpu(recover_meta->max_region_num);
	allocator->last_counter_block_tail = nova_sbi_get_block(sbi,
		le64_to_cpu(
			recover_meta->last_counter_block_tail_offset
		)
	);
	ret = scan_valid_entry_counts(sbi, &allocator->valid_entry,
		allocator->region_num);
	BUG_ON(ret < 0); // TODO
	rebuild_free_regions(sbi, allocator);
	NOVA_END_TIMING(normal_recover_entry_allocator_t, normal_recover_entry_allocator_time);
	return 0;
}

void nova_free_entry_allocator(struct entry_allocator *allocator)
{
	xa_destroy(&allocator->valid_entry);
	nova_queue_destroy(&allocator->free_regions);
}

struct scan_para {
	struct completion entered;
	struct nova_sb_info *sbi;
	struct xatable *xat;
	regionnr_t start;
	regionnr_t end;
};
static int scan_region(struct entry_allocator *allocator, struct xatable *xat,
	void *region_start)
{
	struct nova_pmm_entry *pentry = (struct nova_pmm_entry *)region_start;
	struct nova_pmm_entry *pentry_end = pentry + REAL_ENTRY_PER_REGION;
	int16_t count = 0;
	int ret;

	for (; pentry < pentry_end; ++pentry) {
		if (pentry->blocknr == 0)
			continue;
		// Impossible to conflict
		++count;
		ret = xa_err(xatable_store(
			xat, le64_to_cpu(pentry->blocknr), pentry, GFP_KERNEL));
		if (ret < 0)
			return ret;
		// atomic64_set(&pentry->refcount, 0);
		// TODO: A more elegant way
		*(u64 *)(&pentry->refcount) = 0;
	}
	nova_flush_buffer(region_start, REGION_SIZE, true);
	return count;
}
static int __scan_worker(struct scan_para *para)
{
	struct nova_sb_info *sbi = para->sbi;
	struct xatable *xat = para->xat;
	struct nova_meta_table *meta_table = &sbi->meta_table;
	struct entry_allocator *allocator = &meta_table->entry_allocator;
	regionnr_t i = para->start;
	regionnr_t region_end = para->end;
	__le64 *blocknrs = nova_sbi_blocknr_to_addr(
		sbi, sbi->region_blocknr_start);
	unsigned long blocknr;
	int ret;

	for (; i < region_end; ++i) {
		blocknr = blocknrs[i];
		ret = scan_region(allocator, xat,
			nova_sbi_blocknr_to_addr(sbi, blocknr));
		if (ret < 0)
			return ret;
		ret = xa_err(xa_store(
			&allocator->valid_entry,
			blocknr,
			xa_mk_value(ret),
			GFP_KERNEL
		));
		if (ret < 0)
			return ret;
	}
	return 0;
}
static int scan_worker(void *__para) {
	struct scan_para *para = (struct scan_para *)__para;
	int ret;
	complete(&para->entered);
	ret = __scan_worker(para);
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	return ret;
}
static int scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	regionnr_t region_per_thread;
	unsigned long thread_num;
	struct scan_para *para = NULL;
	struct task_struct **tasks = NULL;
	unsigned long i;
	regionnr_t cur_start = 0;
	int ret = 0, ret2;

	if (allocator->region_num == 0)
		return 0;
	region_per_thread = ceil_div_u32(allocator->region_num, sbi->cpus);
	thread_num = ceil_div_ul(allocator->region_num, region_per_thread);
	nova_info("Scan fingerprint entry table using %lu thread(s)\n", thread_num);
	para = kmalloc(thread_num * sizeof(struct scan_para), GFP_KERNEL);
	if (para == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	tasks = kmalloc(thread_num * sizeof(struct task_struct *), GFP_KERNEL);
	if (tasks == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; i < thread_num; ++i) {
		init_completion(&para[i].entered);
		para[i].sbi = sbi;
		para[i].xat = xat;
		para[i].start = cur_start;
		para[i].end = min_u32(cur_start + region_per_thread,
			allocator->region_num);
		tasks[i] = kthread_create(scan_worker, para + i,
			"scan_worker_%lu", i);
		if (IS_ERR(tasks[i])) {
			ret = PTR_ERR(tasks[i]);
			tasks[i] = NULL;
			nova_err(sb, "kthread_create %lu return %d\n", i, ret);
			break;
		}
		cur_start += region_per_thread;
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
static void scan_region_tails(struct nova_sb_info *sbi,
	struct entry_allocator *allocator, unsigned long *bm)
{
	u64 offset = nova_get_blocknr_off(sbi->region_start);
	__le64 *next;
	allocator->region_num = 0;
	do {
		set_bit(offset / PAGE_SIZE, bm);
		++allocator->region_num;
		next = (__le64 *)nova_sbi_get_block(sbi,
			offset + PAGE_SIZE - sizeof(__le64));
		offset = le64_to_cpu(*next);
	} while (offset);
	allocator->last_region_tail = next;
}
static void scan_valid_entry_count_block_tails(struct nova_sb_info *sbi,
	struct entry_allocator *allocator, unsigned long *bm)
{
	unsigned long offset = nova_get_blocknr_off(
		sbi->first_counter_block_start);
	__le64 *next;
	allocator->max_region_num = 0;
	do {
		set_bit(offset / PAGE_SIZE, bm);
		allocator->max_region_num +=
			VALID_ENTRY_COUNTER_PER_BLOCK;
		next = (__le64 *)nova_sbi_get_block(sbi,
			offset + PAGE_SIZE - sizeof(__le64));
		offset = *next;
	} while (offset);
	allocator->last_counter_block_tail = next;
}
int nova_scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat,
	unsigned long *bm, size_t *tot)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	scan_region_tails(sbi, allocator, bm);
	scan_valid_entry_count_block_tails(sbi, allocator, bm);
	ret = entry_allocator_alloc(sbi, allocator);
	if (ret < 0)
		return ret;
	ret = scan_entry_table(sb, allocator, xat);
	if (ret < 0)
		goto err_out;
	*tot = rebuild_free_regions(sbi, allocator);
	return 0;
err_out:
	nova_free_entry_allocator(allocator);
	nova_err(sb, "%s return with error code %d\n", __func__, ret);
	return ret;
}

static inline void flush_last_entry(struct entry_allocator_cpu *allocator_cpu)
{
	// TODO: Does flush need memunlock?
	if (allocator_cpu->last_entry != NULL_PENTRY)
		nova_flush_cacheline(allocator_cpu->last_entry, true);
}
void nova_flush_entry(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry)
{
	// TODO: Is flushing a not dirty cache line expensive?
	nova_flush_cacheline(pentry, true);
}

static int
alloc_region(struct entry_allocator *allocator)
{
	struct nova_meta_table *meta_table = container_of(
		allocator, struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	__le64 *region_blocknrs = nova_sbi_blocknr_to_addr(
		sbi, sbi->region_blocknr_start);
	unsigned long region_blocknr = nova_new_log_block(sb, true, ANY_CPU);
	unsigned long count_blocknr = 0;
	__le64 *new_tail;
	int ret;
	if (region_blocknr == 0) {
		ret = -ENOSPC;
		goto err_out0;
	}
	if (allocator->region_num == allocator->max_region_num) {
		count_blocknr = nova_new_log_block(sb, false, ANY_CPU);
		if (count_blocknr == 0) {
			ret = -ENOSPC;
			goto err_out1;
		}
	}
	ret = xa_err(xa_store_bh(&allocator->valid_entry, region_blocknr,
		xa_mk_value(0), GFP_ATOMIC));
	if (ret < 0)
		goto err_out2;
	ret = nova_queue_push_ul(&allocator->free_regions, region_blocknr, GFP_ATOMIC);
	if (ret < 0)
		goto err_out3;
	region_blocknrs[allocator->region_num] = cpu_to_le64(region_blocknr);
	if (allocator->region_num == allocator->max_region_num) {
		new_tail = (__le64 *)nova_blocknr_to_addr(
			sb, count_blocknr + 1) - 1;
		nova_unlock_write_flush(sbi, new_tail, 0, true);
		nova_unlock_write_flush(sbi,
			allocator->last_counter_block_tail,
			cpu_to_le64(nova_get_blocknr_off(count_blocknr)),
			false);
		allocator->last_counter_block_tail = new_tail;
		allocator->max_region_num +=
			VALID_ENTRY_COUNTER_PER_BLOCK;
		// printk("New valid count block: %lu\n", count_blocknr);
	}
	nova_unlock_write_flush(sbi, allocator->last_region_tail,
		cpu_to_le64(nova_get_blocknr_off(region_blocknr)), true);
	allocator->last_region_tail =
		(__le64 *)nova_blocknr_to_addr(sb, region_blocknr + 1) - 1;
	// printk("%s: regionnr = %u, region_blocknr = %lu\n",
	// 	__func__, allocator->region_num, region_blocknr);
	++allocator->region_num;
	return 0;
err_out3:
	xa_erase_bh(&allocator->valid_entry, region_blocknr);
err_out2:
	if (count_blocknr)
		nova_free_log_block(sb, count_blocknr);
err_out1:
	nova_free_log_block(sb, region_blocknr);
err_out0:
	return ret;
}
// TODO: A more efficient way?
static int16_t add_valid_count(struct xarray *counts, unsigned long blocknr,
	int16_t delta)
{
	int16_t count;
	void *entry;
	INIT_TIMING(add_valid_count_time);

	// printk("%s: blocknr = %lu, delta = %d\n", __func__, blocknr, delta);
	NOVA_START_TIMING(add_valid_count_t, add_valid_count_time);
	entry = xa_load(counts, blocknr);
	do {
		count = (int16_t)xa_to_value(entry);
		// printk("count = %d\n", count);
		entry = xa_cmpxchg_bh(counts, blocknr,
			xa_mk_value((uint16_t)count),
			xa_mk_value((uint16_t)(count + delta)),
			GFP_ATOMIC);
		// Actually won't allocate
		BUG_ON(xa_is_err(entry)); // TODO: Is this safe?
	} while ((int16_t)xa_to_value(entry) != count);
	NOVA_END_TIMING(add_valid_count_t, add_valid_count_time);
	return count + delta;
}
static int
new_region(struct entry_allocator *allocator,
	struct entry_allocator_cpu *allocator_cpu,
	unsigned long *new_region_blocknr)
{
	struct nova_meta_table *meta_table = container_of(
		allocator, struct nova_meta_table, entry_allocator);
	struct nova_sb_info *sbi = container_of(
		meta_table, struct nova_sb_info, meta_table);
	unsigned long blocknr;
	int16_t count;
	int ret;
	INIT_TIMING(new_region_time);
	INIT_TIMING(alloc_region_time);

	NOVA_START_TIMING(new_region_t, new_region_time);
	spin_lock_bh(&allocator->lock);
	if (nova_queue_is_empty(&allocator->free_regions))
	{
		NOVA_START_TIMING(alloc_region_t, alloc_region_time);
		ret = alloc_region(allocator);
		NOVA_END_TIMING(alloc_region_t, alloc_region_time);
		if (ret < 0) {
			spin_unlock_bh(&allocator->lock);
			NOVA_END_TIMING(new_region_t, new_region_time);
			return ret;
		}
	}
	*new_region_blocknr = nova_queue_pop_ul(&allocator->free_regions);
	spin_unlock_bh(&allocator->lock);
	if (allocator_cpu->top_entry != NULL_PENTRY) {
		blocknr = nova_get_addr_off(sbi, allocator_cpu->top_entry) /
			PAGE_SIZE;
		count = add_valid_count(&allocator->valid_entry, blocknr,
			allocator_cpu->allocated);
		allocator_cpu->allocated = 0;
		if (count <= FREE_THRESHOLD)
		{
			spin_lock_bh(&allocator->lock);
			BUG_ON(nova_queue_push_ul(&allocator->free_regions,
				blocknr, GFP_ATOMIC
			) < 0);
			spin_unlock_bh(&allocator->lock);
		}
		allocator_cpu->top_entry = NULL_PENTRY;
	}
	// printk("%s: new_region_blocknr = %lx\n", __func__, *new_region_blocknr);
	NOVA_END_TIMING(new_region_t, new_region_time);
	return 0;
}
// No need to free until write
struct nova_pmm_entry *
nova_alloc_entry(struct entry_allocator *allocator,
	struct entry_allocator_cpu *allocator_cpu)
{
	struct nova_meta_table *meta_table = container_of(
		allocator, struct nova_meta_table, entry_allocator);
	struct nova_sb_info *sbi = container_of(
		meta_table, struct nova_sb_info, meta_table);
	struct nova_pmm_entry *pentry = allocator_cpu->top_entry;
	unsigned long new_region_blocknr;
	int ret;
	INIT_TIMING(alloc_entry_time);
	NOVA_START_TIMING(alloc_entry_t, alloc_entry_time);
	do {
		++pentry;
		if ((u64)pentry % PAGE_SIZE ==
			REAL_ENTRY_PER_REGION * sizeof(struct nova_pmm_entry))
		{
			ret = new_region(allocator, allocator_cpu, &new_region_blocknr);
			if (ret < 0) {
				NOVA_END_TIMING(alloc_entry_t, alloc_entry_time);
				return ERR_PTR(ret);
			}
			pentry = nova_sbi_blocknr_to_addr(
				sbi, new_region_blocknr);
		}
	} while (pentry->blocknr != 0);
	allocator_cpu->top_entry = pentry;
	NOVA_END_TIMING(alloc_entry_t, alloc_entry_time);
	return pentry;
}
void nova_write_entry(struct entry_allocator *allocator,
	struct entry_allocator_cpu *allocator_cpu,
	struct nova_pmm_entry *pentry, struct nova_fp fp, unsigned long blocknr)
{
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long irq_flags = 0;
	INIT_TIMING(write_new_entry_time);

	nova_memunlock(sbi, &irq_flags);
	NOVA_START_TIMING(write_new_entry_t, write_new_entry_time);
	pentry->fp = fp;
	atomic64_set(&pentry->refcount, 1);
	atomic64_set(&pentry->next_hint, 0);
	wmb();
	BUG_ON(pentry->blocknr != 0);
	pentry->blocknr = cpu_to_le64(blocknr);
	if (!in_the_same_cacheline(allocator_cpu->last_entry, pentry))
		flush_last_entry(allocator_cpu);
	allocator_cpu->last_entry = pentry;
	++allocator_cpu->allocated; // Commit the allocation
	NOVA_END_TIMING(write_new_entry_t, write_new_entry_time);
	nova_memlock(sbi, &irq_flags);
}

// Can be called in softirq context
void nova_free_entry(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry)
{
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct nova_sb_info *sbi = container_of(
		meta_table, struct nova_sb_info, meta_table);
	unsigned long blocknr = nova_get_addr_off(sbi, pentry) / PAGE_SIZE;
	int16_t count = add_valid_count(&allocator->valid_entry, blocknr, -1);

	if (count == FREE_THRESHOLD) {
		/*
		 * This region does not belong to an allocator_cpu. Because the
		 * valid counts of such regions decrease monotonously.
		 */
		spin_lock_bh(&allocator->lock);
		// TODO: Handle it
		BUG_ON(nova_queue_push_ul(
			&allocator->free_regions,
			blocknr,
			GFP_ATOMIC
		) < 0);
		spin_unlock_bh(&allocator->lock);
	}
	BUG_ON(pentry->blocknr == 0);
	nova_unlock_write_flush(sbi, &pentry->blocknr, 0, true);
}

static inline void
__save_valid_entry_counts(struct super_block *sb, __le16 *dst, __le64 *blocknrs,
	struct xarray *blocknr_count, size_t len)
{
	__le16 *end = dst + len;
	__le16 *d = dst;
	int16_t count;
	unsigned long irq_flags = 0;
	if (len == 0)
		return;
	nova_memunlock_range(sb, dst, len * sizeof(__le16), &irq_flags);
	while (d != end) {
		count = xa_to_value(xa_load(blocknr_count, *blocknrs++));
		*d++ = cpu_to_le16(count);
	}
	nova_memlock_range(sb, dst, len * sizeof(__le16), &irq_flags);
	nova_flush_buffer(dst, len * sizeof(__le16), false);
}
static inline void
save_valid_entry_counts(struct super_block *sb, __le16 *dst, __le64 *blocknrs,
	struct xarray *blocknr_count, size_t len)
{
	u64 offset;
	while (len >= VALID_ENTRY_COUNTER_PER_BLOCK) {
		__save_valid_entry_counts(sb, dst, blocknrs, blocknr_count,
			VALID_ENTRY_COUNTER_PER_BLOCK);
		blocknrs += VALID_ENTRY_COUNTER_PER_BLOCK;
		offset = le64_to_cpu(
			*(__le64 *)((u64)dst + PAGE_SIZE - sizeof(__le64))
		);
		dst = (__le16 *)nova_get_block(sb, offset);
		len -= VALID_ENTRY_COUNTER_PER_BLOCK;
	}
	__save_valid_entry_counts(sb, dst, blocknrs, blocknr_count, len);
}
void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	int cpu;
	struct entry_allocator_cpu *allocator_cpu;
	INIT_TIMING(save_entry_allocator_time);

	NOVA_START_TIMING(save_entry_allocator_t, save_entry_allocator_time);
	for_each_possible_cpu(cpu) {
		allocator_cpu = &per_cpu(entry_allocator_per_cpu, cpu);
		flush_last_entry(allocator_cpu);
		if (allocator_cpu->top_entry != NULL_PENTRY) {
			add_valid_count(&allocator->valid_entry,
				nova_get_addr_off(
					sbi,
					allocator_cpu->top_entry
				) / PAGE_SIZE,
				allocator_cpu->allocated);
			allocator_cpu->allocated = 0;
		}
	}
	nova_unlock_write_flush(sbi, &recover_meta->region_num,
		cpu_to_le64(allocator->region_num), false);
	nova_unlock_write_flush(sbi, &recover_meta->last_region_tail,
		cpu_to_le64(nova_get_addr_off(
			sbi, allocator->last_region_tail)),
		false);
	save_valid_entry_counts(sb,
		nova_sbi_blocknr_to_addr(sbi,
			sbi->first_counter_block_start),
		nova_sbi_blocknr_to_addr(sbi,
			sbi->region_blocknr_start),
		&allocator->valid_entry,
		allocator->region_num
	);
	nova_unlock_write_flush(sbi, &recover_meta->max_region_num,
		cpu_to_le64(allocator->max_region_num), false);
	nova_unlock_write_flush(sbi,
		&recover_meta->last_counter_block_tail_offset,
		nova_get_addr_off(sbi,
			allocator->last_counter_block_tail),
		false
	);
	NOVA_END_TIMING(save_entry_allocator_t, save_entry_allocator_time);

	nova_free_entry_allocator(allocator);
}

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
#if 0
	size_t i;
	unsigned long *count = vzalloc((ENTRY_PER_REGION + 1) * sizeof(unsigned long));
	if (count == NULL)
		return -ENOMEM;
	for (i = 0; i < allocator->region_num; ++i) {
		BUG_ON(allocator->valid_entry[i] > ENTRY_PER_REGION);
		++count[allocator->valid_entry[i]];
	}
	printk("Valid entry count of the regions:");
	for (i = 0; i <= ENTRY_PER_REGION; ++i)
		if (count[i])
			printk(KERN_CONT " (%d)%lu", (int)i, count[i]);
	printk(KERN_CONT "\n");
	vfree(count);
#endif
	printk("Number of regions: %u\n", allocator->region_num);
	return 0;
}
