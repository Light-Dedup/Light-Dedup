#include "nova.h"
#include "multithread.h"
#include "arithmetic.h"

// #define static _Static_assert(1, "2333");

#define ENTRY_PER_CACHELINE (CACHELINE_SIZE / sizeof(struct nova_pmm_entry))
// If the number of free entries in a region is greater or equal to FREE_THRESHOLD, then the region is regarded as free.
#define FREE_THRESHOLD (REAL_ENTRY_PER_REGION / 2)

#define NULL_PENTRY ((struct nova_pmm_entry *)( \
	(REAL_ENTRY_PER_REGION - 1) * sizeof(struct nova_pmm_entry)))

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
	char *regions;
	int ret;
	allocator->region_num = 1;
	ret = entry_allocator_alloc(sbi, allocator);
	if (ret < 0)
		return ret;
	regions = (char *)get_zeroed_page(GFP_KERNEL);
	BUG_ON(regions == NULL);
	ret = xa_err(xa_store(&allocator->valid_entry, (unsigned long)regions,
		xa_mk_value(0), GFP_KERNEL));
	BUG_ON(ret < 0); // TODO: Handle it
	BUG_ON(nova_queue_push_ul(
		&allocator->free_regions,
		(unsigned long)regions,
		GFP_KERNEL
	) < 0);
	allocator->first_region = regions;
	allocator->last_region_tail = (__le64 *)(regions + PAGE_SIZE - sizeof(__le64));

	return 0;
}

#if 0
static void rebuild_free_regions(struct nova_sb_info *sbi,
	struct entry_allocator *allocator)
{
	unsigned long blocknr;
	void *entry;
	int16_t count;
	xa_for_each(&allocator->valid_entry, blocknr, entry) {
		count = xa_to_value(entry);
		if (count <= FREE_THRESHOLD) {
			BUG_ON(nova_queue_push_ul(
				&allocator->free_regions,
				blocknr,
				GFP_KERNEL
			) < 0);
		}
	}
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
#endif
int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
#if 0
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
#endif
	BUG();
}

void nova_free_entry_allocator(struct entry_allocator *allocator)
{
	char *region = allocator->first_region;
	char *next;
	xa_destroy(&allocator->valid_entry);
	nova_queue_destroy(&allocator->free_regions);
	while (region != NULL) {
		next = (char *)*(__le64 *)(region + PAGE_SIZE - sizeof(__le64));
		free_page((unsigned long)region);
		region = next;
	}
}

#if 0
struct scan_para {
	struct completion entered;
	struct nova_sb_info *sbi;
	struct xatable *xat;
	struct rhashtable *rht;
	struct rhashtable_params params;
	regionnr_t start;
	regionnr_t end;
};
int nova_rhashtable_insert_entry(struct rhashtable *rht,
	const struct rhashtable_params params, struct nova_fp fp,
	struct nova_pmm_entry *pentry);
static int scan_region(struct entry_allocator *allocator, struct xatable *xat,
	void *region_start)
{
	struct nova_pmm_entry *pentry = (struct nova_pmm_entry *)region_start;
	struct nova_pmm_entry *pentry_end = pentry + REAL_ENTRY_PER_REGION;
	int16_t count = 0;
	int ret;

	for (; pentry < pentry_end; ++pentry) {
		if (pentry->flag != NOVA_LEAF_ENTRY_MAGIC)
			continue;
		// Impossible to conflict
		++count;
		ret = xa_err(xatable_store(
			xat, le64_to_cpu(pentry->blocknr), pentry, GFP_KERNEL));
		if (ret < 0)
			return ret;
		atomic64_set(&pentry->refcount, 0);
	}
	nova_flush_buffer(region_start, REGION_SIZE, true);
	return count;
}
static int __scan_worker(struct scan_para *para)
{
	struct nova_sb_info *sbi = para->sbi;
	struct xatable *xat = para->xat;
	struct rhashtable *rht = para->rht;
	const struct rhashtable_params params = para->params;
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
		ret = scan_region(allocator, xat, rht, params,
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
	struct entry_allocator *allocator, struct xatable *xat,
	struct rhashtable *rht, const struct rhashtable_params params)
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
		para[i].rht = rht;
		para[i].params = params;
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
#endif
int nova_scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat,
	struct rhashtable *rht, const struct rhashtable_params params,
	unsigned long *bm)
{
#if 0
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	scan_region_tails(sbi, allocator, bm);
	scan_valid_entry_count_block_tails(sbi, allocator, bm);
	ret = entry_allocator_alloc(sbi, allocator);
	if (ret < 0)
		return ret;
	ret = scan_entry_table(sb, allocator, xat, rht, params);
	if (ret < 0)
		goto err_out;
	rebuild_free_regions(sbi, allocator);
	return 0;
err_out:
	nova_free_entry_allocator(allocator);
	nova_err(sb, "%s return with error code %d\n", __func__, ret);
	return ret;
#endif
	BUG();
}

static inline void flush_last_entry(struct entry_allocator_cpu *allocator_cpu)
{
	// TODO: Does flush need memunlock?
	if (allocator_cpu->last_entry != NULL_PENTRY)
		nova_flush_cacheline(allocator_cpu->last_entry, true);
}
static inline bool in_the_same_cacheline(
	struct nova_pmm_entry *a,
	struct nova_pmm_entry *b)
{
	return (unsigned long)a / CACHELINE_SIZE ==
		(unsigned long)b / CACHELINE_SIZE;
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
	char *new_region = (char *)get_zeroed_page(GFP_ATOMIC);
	int ret;
	BUG_ON(new_region == NULL);
	ret = xa_err(xa_store(&allocator->valid_entry, (unsigned long)new_region,
		xa_mk_value(0), GFP_ATOMIC));
	BUG_ON(ret < 0);
	ret = nova_queue_push_ul(
		&allocator->free_regions,
		(unsigned long)new_region,
		GFP_ATOMIC);
	BUG_ON(ret < 0);
	*allocator->last_region_tail = (__le64)new_region;
	allocator->last_region_tail = (__le64 *)(new_region + PAGE_SIZE - sizeof(__le64));
	++allocator->region_num;
	return 0;
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
		entry = xa_cmpxchg(counts, blocknr,
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
	struct nova_pmm_entry **new_region)
{
	void *region;
	int16_t count;
	int ret;
	INIT_TIMING(new_region_time);
	INIT_TIMING(alloc_region_time);

	NOVA_START_TIMING(new_region_t, new_region_time);
	spin_lock(&allocator->lock);
	if (nova_queue_is_empty(&allocator->free_regions))
	{
		NOVA_START_TIMING(alloc_region_t, alloc_region_time);
		ret = alloc_region(allocator);
		NOVA_END_TIMING(alloc_region_t, alloc_region_time);
		if (ret < 0) {
			spin_unlock(&allocator->lock);
			NOVA_END_TIMING(new_region_t, new_region_time);
			return ret;
		}
	}
	*new_region = (struct nova_pmm_entry *)nova_queue_pop_ul(&allocator->free_regions);
	spin_unlock(&allocator->lock);
	if (allocator_cpu->top_entry != NULL_PENTRY) {
		region = (void *)((unsigned long)allocator_cpu->top_entry & ~(PAGE_SIZE - 1));
		count = add_valid_count(&allocator->valid_entry, (unsigned long)region,
			allocator_cpu->allocated);
		allocator_cpu->allocated = 0;
		if (count <= FREE_THRESHOLD)
		{
			BUG_ON(nova_queue_push_ul(&allocator->free_regions,
				(unsigned long)region, GFP_ATOMIC
			) < 0);
		}
		// new_region at most once, so it is safe to not update top_entrynr here.
	}
	// printk("%s: new_region = %p\n", __func__, *new_region);
	NOVA_END_TIMING(new_region_t, new_region_time);
	return 0;
}
// No need to free until write
struct nova_pmm_entry *
nova_alloc_entry(struct entry_allocator *allocator,
	struct entry_allocator_cpu *allocator_cpu)
{
	struct nova_pmm_entry *pentry = allocator_cpu->top_entry;
	int ret;
	INIT_TIMING(alloc_entry_time);
	NOVA_START_TIMING(alloc_entry_t, alloc_entry_time);
	do {
		++pentry;
		if ((u64)pentry % PAGE_SIZE ==
			REAL_ENTRY_PER_REGION * sizeof(struct nova_pmm_entry))
		{
			ret = new_region(allocator, allocator_cpu, &pentry);
			if (ret < 0) {
				NOVA_END_TIMING(alloc_entry_t, alloc_entry_time);
				return ERR_PTR(ret);
			}
		}
	} while (pentry->flag == NOVA_LEAF_ENTRY_MAGIC);
	allocator_cpu->top_entry = pentry;
	NOVA_END_TIMING(alloc_entry_t, alloc_entry_time);
	return pentry;
}
void nova_write_entry(struct entry_allocator *allocator,
	struct entry_allocator_cpu *allocator_cpu,
	struct nova_pmm_entry *pentry, struct nova_fp fp, unsigned long blocknr,
	int64_t refcount)
{
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	unsigned long irq_flags = 0;
	INIT_TIMING(write_new_entry_time);

	nova_memunlock(sb, &irq_flags);
	NOVA_START_TIMING(write_new_entry_t, write_new_entry_time);
	pentry->fp = fp;
	pentry->blocknr = cpu_to_le64(blocknr);
	atomic64_set(&pentry->refcount, refcount);
	wmb();
	pentry->flag = NOVA_LEAF_ENTRY_MAGIC;
	if (!in_the_same_cacheline(allocator_cpu->last_entry, pentry))
		flush_last_entry(allocator_cpu);
	allocator_cpu->last_entry = pentry;
	++allocator_cpu->allocated; // Commit the allocation
	NOVA_END_TIMING(write_new_entry_t, write_new_entry_time);
	nova_memlock(sb, &irq_flags);
}

void nova_free_entry(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry)
{
#if 0
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct nova_sb_info *sbi = container_of(
		meta_table, struct nova_sb_info, meta_table);
	struct super_block *sb = meta_table->sblock;
	unsigned long blocknr = nova_get_addr_off(sbi, pentry) / PAGE_SIZE;
	int16_t count = add_valid_count(&allocator->valid_entry, blocknr, -1);

	if (count == FREE_THRESHOLD) {
		/*
		 * This region does not belong to an allocator_cpu. Because the
		 * valid counts of such regions decrease monotonously.
		 */
		spin_lock(&allocator->lock);
		// TODO: Handle it
		BUG_ON(nova_queue_push_ul(
			&allocator->free_regions,
			blocknr,
			GFP_ATOMIC
		) < 0);
		spin_unlock(&allocator->lock);
	}
	nova_unlock_write(sb, &pentry->flag, 0, true);
#endif
	BUG();
}

#if 0
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
#endif
void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator)
{
#if 0
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
	nova_unlock_write(sb, &recover_meta->region_num,
		cpu_to_le64(allocator->region_num), false);
	nova_unlock_write(sb, &recover_meta->last_region_tail,
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
	nova_unlock_write(sb, &recover_meta->max_region_num,
		cpu_to_le64(allocator->max_region_num), false);
	nova_unlock_write(sb,
		&recover_meta->last_counter_block_tail_offset,
		nova_get_addr_off(sbi,
			allocator->last_counter_block_tail),
		false
	);
	NOVA_END_TIMING(save_entry_allocator_t, save_entry_allocator_time);
#endif
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
	return 0;
}
