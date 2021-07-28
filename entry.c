#include "nova.h"
#include "multithread.h"
#include "arithmetic.h"

// #define static _Static_assert(1, "2333");

#define ENTRY_PER_CACHELINE (CACHELINE_SIZE / sizeof(struct nova_pmm_entry))
// If the number of free entries in a region is greater or equal to FREE_THRESHOLD, then the region is regarded as free.
#define FREE_THRESHOLD (REAL_ENTRY_PER_REGION / 2)

_Static_assert((1ULL << (sizeof(atomic_t) * 8)) > REAL_ENTRY_PER_REGION, "Type of counter of valid entries in a region is too small!");

static int entry_allocator_alloc(
	struct nova_sb_info *sbi,
	struct entry_allocator *allocator,
	bool zero_valid_entry)
{
	size_t region_num = allocator->region_num;
	int ret;
	allocator->region_array_cap = (regionnr_t)1 << ceil_log_2(region_num);
	if (zero_valid_entry)
		allocator->valid_entry = vzalloc(
			allocator->region_array_cap *
			sizeof(allocator->valid_entry[0]));
	else
		allocator->valid_entry = vmalloc(
			allocator->region_array_cap *
			sizeof(allocator->valid_entry[0]));
	if (allocator->valid_entry == NULL) {
		ret = -ENOMEM;
		goto err_out0;
	}
	allocator->region_blocknr = vmalloc(
		allocator->region_array_cap * sizeof(unsigned long)
	);
	if (allocator->region_blocknr == NULL) {
		ret = -ENOMEM;
		goto err_out1;
	}
	ret = nova_queue_init(&allocator->free_regions,
		allocator->region_array_cap * sizeof(regionnr_t));
	if (ret)
		goto err_out2;
	// The first allocation will trigger a new_region request.
	allocator->top_entrynr = allocator->last_entrynr = -1;
	spin_lock_init(&allocator->lock);
	return 0;
err_out2:
	vfree(allocator->region_blocknr);
err_out1:
	vfree(allocator->valid_entry);
err_out0:
	return ret;
}

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	regionnr_t i;
	unsigned long blocknr;
	int ret;
	allocator->region_num = VALID_ENTRY_COUNTER_PER_BLOCK;
	allocator->last_region_tail = (__le64 *)nova_sbi_blocknr_to_addr(sbi,
		sbi->region_start + VALID_ENTRY_COUNTER_PER_BLOCK) - 1;
	allocator->valid_entry_count_num = VALID_ENTRY_COUNTER_PER_BLOCK;
	allocator->last_valid_entry_count_block_tail =
		(__le64 *)nova_sbi_blocknr_to_addr(sbi,
			sbi->region_valid_count_start + 1)
		- 1;
	ret = entry_allocator_alloc(sbi, allocator, true);
	if (ret < 0)
		return ret;
	blocknr = sbi->region_start;
	for (i = 0; i < allocator->region_num; ++i, ++blocknr)
		allocator->region_blocknr[i] = blocknr;
	for (i = 0; i < allocator->region_num; ++i)
		BUG_ON(nova_queue_push(
			&allocator->free_regions, &i, sizeof(i)
		) < 0);
	return 0;
}

// TODO: Save the blocknrs of regions into NVM when umount
static void scan_region_blocknr(struct nova_sb_info *sbi,
	struct entry_allocator *allocator)
{
	u64 offset = nova_get_blocknr_off(sbi->region_start);
	regionnr_t i = 0;
	__le64 *next;
	do {
		allocator->region_blocknr[i++] =
			offset / PAGE_SIZE;
		next = (__le64 *)nova_sbi_get_block(sbi,
			offset + PAGE_SIZE - sizeof(__le64));
		offset = le64_to_cpu(*next);
	} while (offset);
	BUG_ON(i != allocator->region_num);
	allocator->last_region_tail = next;
}
static void rebuild_free_regions(struct nova_sb_info *sbi,
	struct entry_allocator *allocator)
{
	uint16_t *valid_entry = allocator->valid_entry;
	regionnr_t i;
	for (i = 0; i < allocator->region_num; ++i)
		if (valid_entry[i] <= FREE_THRESHOLD)
			BUG_ON(nova_queue_push(
				&allocator->free_regions, &i, sizeof(i)
			) < 0);
}
static inline void
cp_from_nvm_16(void *_dst, __le16 *src, size_t len)
{
	uint16_t *d = (uint16_t *)_dst;
	__le16 *end = src + len;
	while (src != end)
		*d++ = le16_to_cpu(*src++);
}
static inline void
cp_arr_from_nvm_list_16(struct nova_sb_info *sbi,
	void *_dst, __le16 *src, size_t len)
{
	uint16_t *dst = (uint16_t *)_dst;
	u64 offset;
	const size_t elem_per_page =
		(PAGE_SIZE - sizeof(__le64)) / sizeof(__le16);
	while (len >= elem_per_page) {
		cp_from_nvm_16(dst, src, elem_per_page);
		dst += elem_per_page;
		offset = le64_to_cpu(
			*(__le64 *)((u64)src + PAGE_SIZE - sizeof(__le64))
		);
		src = (__le16 *)nova_sbi_get_block(sbi, offset);
		len -= elem_per_page;
	}
	cp_from_nvm_16(dst, src, len);
}
int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	__le16 *valid_entry_count = nova_sbi_blocknr_to_addr(
		sbi, sbi->region_valid_count_start);
	int ret;
	INIT_TIMING(normal_recover_entry_allocator_time);

	NOVA_START_TIMING(normal_recover_entry_allocator_t,
		normal_recover_entry_allocator_time);
	allocator->region_num = le64_to_cpu(recover_meta->region_num);
	ret = entry_allocator_alloc(sbi, allocator, false);
	if (ret < 0)
		return ret;
	scan_region_blocknr(sbi, allocator);
	allocator->valid_entry_count_num =
		le64_to_cpu(recover_meta->valid_entry_count_num);
	allocator->last_valid_entry_count_block_tail = nova_sbi_get_block(sbi,
		le64_to_cpu(
			recover_meta->last_valid_entry_count_block_tail_offset
		)
	);
	cp_arr_from_nvm_list_16(sbi, allocator->valid_entry, valid_entry_count,
		allocator->region_num);
	rebuild_free_regions(sbi, allocator);
	NOVA_END_TIMING(normal_recover_entry_allocator_t, normal_recover_entry_allocator_time);
	return 0;
}

void nova_free_entry_allocator(struct entry_allocator *allocator)
{
	vfree(allocator->valid_entry);
	vfree(allocator->region_blocknr);
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
	regionnr_t regionnr)
{
	entrynr_t entrynr = regionnr * ENTRY_PER_REGION;
	struct nova_pmm_entry *pentry = entrynr_to_pentry(allocator, entrynr);
	struct nova_pmm_entry *pentry_end = pentry + REAL_ENTRY_PER_REGION;
	struct nova_mm_entry_info info;
	int ret;

	for (; pentry < pentry_end; ++pentry, ++entrynr) {
		info = entry_info_pmm_to_mm(pentry->info);
		if (info.flag != NOVA_LEAF_ENTRY_MAGIC)
			continue;
		// Impossible to conflict
		++allocator->valid_entry[regionnr];
		ret = xa_err(xatable_store(
			xat, info.blocknr, xa_mk_value(entrynr), GFP_KERNEL));
		if (ret < 0)
			return ret;
	}
	return 0;
}
static int __scan_worker(struct scan_para *para)
{
	struct nova_sb_info *sbi = para->sbi;
	struct xatable *xat = para->xat;
	struct nova_meta_table *meta_table = &sbi->meta_table;
	struct entry_allocator *allocator = &meta_table->entry_allocator;
	regionnr_t i = para->start;
	regionnr_t region_end = para->end;
	int ret;

	for (; i < region_end; ++i) {
		ret = scan_region(allocator, xat, i);
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
	ret2 = run_and_stop_kthreads(sb, tasks, para, thread_num, i);
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
}
static void scan_valid_entry_count_block_tails(struct nova_sb_info *sbi,
	struct entry_allocator *allocator, unsigned long *bm)
{
	unsigned long offset = nova_get_blocknr_off(
		sbi->region_valid_count_start);
	__le64 *next;
	allocator->valid_entry_count_num = 0;
	do {
		set_bit(offset / PAGE_SIZE, bm);
		allocator->valid_entry_count_num +=
			VALID_ENTRY_COUNTER_PER_BLOCK;
		next = (__le64 *)nova_sbi_get_block(sbi,
			offset + PAGE_SIZE - sizeof(__le64));
		offset = *next;
	} while (offset);
	allocator->last_valid_entry_count_block_tail = next;
}
int nova_scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat,
	unsigned long *bm)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	scan_region_tails(sbi, allocator, bm);
	scan_valid_entry_count_block_tails(sbi, allocator, bm);
	ret = entry_allocator_alloc(sbi, allocator, true);
	if (ret < 0)
		return ret;
	scan_region_blocknr(sbi, allocator);
	ret = scan_entry_table(sb, allocator, xat);
	if (ret < 0)
		goto err_out;
	rebuild_free_regions(sbi, allocator);
	return 0;
err_out:
	nova_free_entry_allocator(allocator);
	nova_err(sb, "%s return with error code %d\n", __func__, ret);
	return ret;
}

static inline void
__flush_entry(struct entry_allocator *allocator, entrynr_t entrynr)
{
	nova_flush_cacheline(entrynr_to_pentry(allocator, entrynr), true);
}
static inline void flush_last_entry(struct entry_allocator *allocator)
{
	if (allocator->last_entrynr == (entrynr_t)-1)
		return;
	__flush_entry(allocator, allocator->last_entrynr);
}
static inline bool in_the_same_cacheline(entrynr_t a, entrynr_t b)
{
	return b / ENTRY_PER_CACHELINE == a / ENTRY_PER_CACHELINE;
}
void nova_flush_entry(struct entry_allocator *allocator, entrynr_t entrynr)
{
	if (!in_the_same_cacheline(entrynr, allocator->last_entrynr))
		return;	// Not in the volatile cache line.
	flush_last_entry(allocator);
	allocator->last_entrynr = -1;
}

static int
alloc_region(struct entry_allocator *allocator)
{
	struct nova_meta_table *meta_table = container_of(
		allocator, struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	unsigned long region_blocknr = nova_new_log_block(sb, true, ANY_CPU);
	unsigned long count_blocknr = 0;
	uint16_t *new_valid_entry_arr = NULL;
	unsigned long *new_region_blocknr_arr = NULL;
	__le64 *new_tail;
	int ret;
	if (region_blocknr == 0) {
		ret = -ENOSPC;
		goto err_out0;
	}
	if (allocator->region_num == allocator->valid_entry_count_num) {
		count_blocknr = nova_new_log_block(sb, false, ANY_CPU);
		if (count_blocknr == 0) {
			ret = -ENOSPC;
			goto err_out1;
		}
	}
	if (allocator->region_num == allocator->region_array_cap) {
		new_valid_entry_arr = vmalloc(
			(allocator->region_array_cap << 1) *
			sizeof(new_valid_entry_arr[0])
		);
		if (new_valid_entry_arr == NULL) {
			ret = -ENOMEM;
			goto err_out2;
		}
		// What if there is vrealloc!
		new_region_blocknr_arr = vmalloc(
			(allocator->region_array_cap << 1) *
			sizeof(new_region_blocknr_arr[0])
		);
		if (new_region_blocknr_arr == NULL) {
			ret = -ENOMEM;
			goto err_out3;
		}
	}
	ret = nova_queue_push(&allocator->free_regions, &allocator->region_num,
		sizeof(regionnr_t));
	if (ret < 0)
		goto err_out4;
	if (allocator->region_num == allocator->region_array_cap) {
		memcpy(new_valid_entry_arr, allocator->valid_entry,
			allocator->region_array_cap *
				sizeof(new_valid_entry_arr[0]));
		vfree(allocator->valid_entry);
		allocator->valid_entry = new_valid_entry_arr;
		memcpy(new_region_blocknr_arr, allocator->region_blocknr,
			allocator->region_array_cap *
				sizeof(new_region_blocknr_arr[0]));
		vfree(allocator->region_blocknr);
		allocator->region_blocknr = new_region_blocknr_arr;
		allocator->region_array_cap <<= 1;
	}
	allocator->valid_entry[allocator->region_num] = 0;
	allocator->region_blocknr[allocator->region_num] = region_blocknr;
	if (allocator->region_num == allocator->valid_entry_count_num) {
		new_tail = (__le64 *)nova_blocknr_to_addr(
			sb, count_blocknr + 1) - 1;
		nova_unlock_write(sb, new_tail, 0, true);
		nova_unlock_write(sb,
			allocator->last_valid_entry_count_block_tail,
			cpu_to_le64(nova_get_blocknr_off(count_blocknr)),
			false);
		allocator->last_valid_entry_count_block_tail = new_tail;
		allocator->valid_entry_count_num +=
			VALID_ENTRY_COUNTER_PER_BLOCK;
		// printk("New valid count block: %lu\n", count_blocknr);
	}
	nova_unlock_write(sb, allocator->last_region_tail,
		cpu_to_le64(nova_get_blocknr_off(region_blocknr)), true);
	allocator->last_region_tail =
		(__le64 *)nova_blocknr_to_addr(sb, region_blocknr + 1) - 1;
	// printk("%s: regionnr = %u, region_blocknr = %lu\n",
	// 	__func__, allocator->region_num, region_blocknr);
	++allocator->region_num;
	return 0;
err_out4:
	if (new_region_blocknr_arr)
		vfree(new_region_blocknr_arr);
err_out3:
	if (new_valid_entry_arr)
		vfree(new_valid_entry_arr);
err_out2:
	if (count_blocknr)
		nova_free_log_block(sb, count_blocknr);
err_out1:
	nova_free_log_block(sb, region_blocknr);
err_out0:
	return ret;
}
static int
new_region(struct entry_allocator *allocator, regionnr_t *new_regionnr)
{
	regionnr_t regionnr;
	int ret;
	if (nova_queue_pop(&allocator->free_regions,
		new_regionnr, sizeof(regionnr_t)) == 0)
	{
		ret = alloc_region(allocator);
		if (ret < 0)
			return ret;
		BUG_ON(nova_queue_pop(&allocator->free_regions,
			new_regionnr, sizeof(regionnr_t)
		) != sizeof(regionnr_t));
	}
	if (allocator->top_entrynr != -1) {
		regionnr = allocator->top_entrynr / ENTRY_PER_REGION;
		if (allocator->valid_entry[regionnr] <= FREE_THRESHOLD)
			BUG_ON(nova_queue_push(&allocator->free_regions,
				&regionnr, sizeof(regionnr)
			) < 0);
		// new_region at most once, so it is safe to not update top_entrynr here.
	}
	// printk("%s: new_regionnr = %u\n", __func__, *new_regionnr);
	return 0;
}
// No need to free until write
int alloc_entry(struct entry_allocator *allocator, entrynr_t *new_entrynr)
{
	struct nova_meta_table *meta_table = container_of(
		allocator, struct nova_meta_table, entry_allocator);
	struct nova_sb_info *sbi = container_of(
		meta_table, struct nova_sb_info, meta_table);
	entrynr_t entrynr = allocator->top_entrynr;
	int16_t i = (int16_t)entrynr % ENTRY_PER_REGION; // -1 % 256 == -1
	regionnr_t regionnr = (entrynr + 1) / ENTRY_PER_REGION;
	struct nova_pmm_entry *region_pentries =
		(struct nova_pmm_entry *)nova_sbi_blocknr_to_addr(sbi,
			allocator->region_blocknr[regionnr]);
	int ret;
	do {
		++i;
		if (i == REAL_ENTRY_PER_REGION) {
			ret = new_region(allocator, &regionnr);
			if (ret < 0)
				return ret;
			i = 0;
			region_pentries = (struct nova_pmm_entry *)
				nova_sbi_blocknr_to_addr(sbi,
					allocator->region_blocknr[regionnr]);
		}
	} while (entry_info_pmm_to_mm(region_pentries[i].info).flag
		== NOVA_LEAF_ENTRY_MAGIC);
	entrynr = regionnr * ENTRY_PER_REGION + i;
	allocator->top_entrynr = entrynr;
	*new_entrynr = entrynr;
	// printk("alloc_entry: new_entrynr = %llu\n", entrynr);
	return 0;
}
void write_entry(struct entry_allocator *allocator, entrynr_t entrynr,
	struct nova_fp fp, __le64 info)
{
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	struct nova_pmm_entry *pentry = entrynr_to_pentry(allocator, entrynr);
	unsigned long irq_flags = 0;
	INIT_TIMING(write_new_entry_time);

	nova_memunlock(sb, &irq_flags);
	NOVA_START_TIMING(write_new_entry_t, write_new_entry_time);
	pentry->fp = fp;
	wmb();
	pentry->info = info;
	if (!in_the_same_cacheline(allocator->last_entrynr, entrynr))
		flush_last_entry(allocator); // TODO: Does flush need memunlock?
	allocator->last_entrynr = entrynr;
	++allocator->valid_entry[entrynr / ENTRY_PER_REGION]; // Commit alloc
	NOVA_END_TIMING(write_new_entry_t, write_new_entry_time);
	nova_memlock(sb, &irq_flags);
}

void nova_free_entry(struct entry_allocator *allocator, entrynr_t entrynr) {
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	struct nova_pmm_entry *pentry = entrynr_to_pentry(allocator, entrynr);
	regionnr_t regionnr = entrynr / ENTRY_PER_REGION;

	spin_lock(&allocator->lock);
	if ((--allocator->valid_entry[regionnr]) == FREE_THRESHOLD)
		// To avoid adding the current region into free region queue repeatedly.
		if (regionnr != allocator->top_entrynr / ENTRY_PER_REGION)
			// TODO: Handle it
			BUG_ON(nova_queue_push(&allocator->free_regions, &regionnr, sizeof(regionnr)) < 0);
	nova_unlock_write(sb, &pentry->info, 0, true);
	spin_unlock(&allocator->lock);
}

static inline void
cp_to_nvm_16(struct super_block *sb, __le16 *dst, void *_src, size_t len)
{
	uint16_t *src = (uint16_t *)_src;
	uint16_t *end = src + len;
	__le16 *d = dst;
	unsigned long irq_flags = 0;
	nova_memunlock_range(sb, dst, len * sizeof(__le16), &irq_flags);
	while (src != end)
		*d++ = cpu_to_le16(*src++);
	nova_memlock_range(sb, dst, len * sizeof(__le16), &irq_flags);
	nova_flush_buffer(dst, len * sizeof(__le16), false);
}
static inline void
cp_arr_to_nvm_list_16(struct super_block *sb,
	__le16 *dst, void *_src, size_t len)
{
	uint16_t *src = (uint16_t *)_src;
	u64 offset;
	const size_t elem_per_page =
		(PAGE_SIZE - sizeof(__le64)) / sizeof(__le16);
	while (len >= elem_per_page) {
		cp_to_nvm_16(sb, dst, src, elem_per_page);
		src += elem_per_page;
		offset = le64_to_cpu(
			*(__le64 *)((u64)dst + PAGE_SIZE - sizeof(__le64))
		);
		dst = (__le16 *)nova_get_block(sb, offset);
		len -= elem_per_page;
	}
	cp_to_nvm_16(sb, dst, src, len);
}
void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	INIT_TIMING(save_entry_allocator_time);

	NOVA_START_TIMING(save_entry_allocator_t, save_entry_allocator_time);
	flush_last_entry(allocator);
	nova_unlock_write(sb, &recover_meta->region_num,
		cpu_to_le64(allocator->region_num), false);
	cp_arr_to_nvm_list_16(sb,
		nova_sbi_blocknr_to_addr(sbi,
			sbi->region_valid_count_start),
		allocator->valid_entry,
		allocator->region_num
	);
	nova_unlock_write(sb, &recover_meta->valid_entry_count_num,
		cpu_to_le64(allocator->valid_entry_count_num), false);
	nova_unlock_write(sb,
		&recover_meta->last_valid_entry_count_block_tail_offset,
		nova_get_addr_off(sbi,
			allocator->last_valid_entry_count_block_tail),
		false
	);
	NOVA_END_TIMING(save_entry_allocator_t, save_entry_allocator_time);

	nova_free_entry_allocator(allocator);
}

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
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
	return 0;
}
