#include "entry.h"
#include "nova.h"
#include "multithread.h"
#include "arithmetic.h"

#define INDEX_BIT 32
#define INDEX_MASK ((1ULL << INDEX_BIT) - 1)

// If the number of free entries in a region is greater or equal to FREE_THRESHOLD, then the region is regarded as free.
#define FREE_THRESHOLD (ENTRY_PER_REGION / 2)

_Static_assert((1ULL << (sizeof(atomic_t) * 8)) > ENTRY_PER_REGION, "Type of counter of valid entries in a region is too small!");

static int entry_allocator_alloc(struct nova_sb_info *sbi, struct entry_allocator *allocator,
	bool zero_valid_entry)
{
	int ret;
	if (zero_valid_entry)
		allocator->valid_entry = vzalloc(sbi->nr_regions * sizeof(allocator->valid_entry[0]));
	else
		allocator->valid_entry = vmalloc(sbi->nr_regions * sizeof(allocator->valid_entry[0]));
	if (allocator->valid_entry == NULL) {
		nova_dbg("%s: Allocate valid_entry failed.\n", __func__);
		return -ENOMEM;
	}
	ret = kfifo_alloc(&allocator->free_regions, sbi->nr_regions * sizeof(regionnr_t), GFP_KERNEL);
	if (ret) {
		vfree(allocator->valid_entry);
		return -ENOMEM;
	}
	spin_lock_init(&allocator->lock);
	return 0;
}

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	regionnr_t i;
	int ret = entry_allocator_alloc(sbi, allocator, true);
	if (ret < 0)
		return ret;
	for (i = 1; i < sbi->nr_regions; ++i)
		BUG_ON(kfifo_in(&allocator->free_regions, &i, sizeof(i)) == 0);
	atomic64_set(&allocator->regionnr_index, -1);
	return 0;
}

int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	__le16 *valid_entry_count = nova_sbi_blocknr_to_addr(sbi, sbi->region_valid_entry_count_start);
	u16 value;
	regionnr_t i;
	int ret;
	INIT_TIMING(normal_recover_entry_allocator_time);

	BUG_ON(recover_meta->region_valid_entry_count_saved != NOVA_RECOVER_META_FLAG_COMPLETE);
	ret = entry_allocator_alloc(sbi, allocator, false);
	if (ret < 0)
		return ret;
	NOVA_START_TIMING(normal_recover_entry_allocator_t, normal_recover_entry_allocator_time);
	for (i = 0; i < sbi->nr_regions; ++i) {
		value = le16_to_cpu(valid_entry_count[i]);
		atomic_set(allocator->valid_entry + i, value);
		if (value <= FREE_THRESHOLD)
			BUG_ON(kfifo_in(&allocator->free_regions, &i, sizeof(i)) != sizeof(i));
	}
	NOVA_END_TIMING(normal_recover_entry_allocator_t, normal_recover_entry_allocator_time);
	// The first allocation will trigger a new_region request.
	atomic64_set(&allocator->regionnr_index, ENTRY_PER_REGION - 1);
	return 0;
}

void nova_free_entry_allocator(struct entry_allocator *allocator)
{
	vfree(allocator->valid_entry);
	kfifo_free(&allocator->free_regions);
}

void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	__le16 *valid_entry_count = nova_sbi_blocknr_to_addr(sbi, sbi->region_valid_entry_count_start);
	regionnr_t i;
	unsigned long irq_flags = 0;
	INIT_TIMING(save_entry_allocator_time);

	NOVA_START_TIMING(save_entry_allocator_t, save_entry_allocator_time);
	nova_memunlock_range(sb, valid_entry_count, sbi->nr_regions * sizeof(__le16), &irq_flags);
	for (i = 0; i < sbi->nr_regions; ++i)
		valid_entry_count[i] = cpu_to_le16(atomic_read(allocator->valid_entry + i));
	nova_memlock_range(sb, valid_entry_count, sbi->nr_regions * sizeof(__le16), &irq_flags);
	nova_flush_buffer(valid_entry_count, sbi->nr_regions * sizeof(valid_entry_count[0]), true);
	nova_unlock_write(sb, &recover_meta->region_valid_entry_count_saved, NOVA_RECOVER_META_FLAG_COMPLETE, true);
	NOVA_END_TIMING(save_entry_allocator_t, save_entry_allocator_time);

	nova_free_entry_allocator(allocator);
}

#define REGION_PER_SCAN (2 * 1024 * 1024 / REGION_SIZE)
#define ENTRY_PER_SCAN (REGION_PER_SCAN * ENTRY_PER_REGION)
struct scan_para {
	struct completion entered;
	struct nova_sb_info *sbi;
	struct xatable *xat;
	atomic64_t *cur_scan_region;
	uint64_t scan_region_end;
};
static inline int handle_entry(struct nova_pmm_entry *pentries, atomic_t *valid_entry,
	struct xatable *xat, entrynr_t entrynr)
{
	struct nova_mm_entry_info info = entry_info_pmm_to_mm(pentries[entrynr].info);
	if (info.flag != NOVA_LEAF_ENTRY_MAGIC)
		return 0;
	atomic_add_return(1, valid_entry + entrynr / ENTRY_PER_REGION);
	return xa_err(xatable_store(xat, info.blocknr, xa_mk_value(entrynr), GFP_KERNEL));
}
static int scan_region(struct nova_pmm_entry *pentries, atomic_t *valid_entry,
	struct xatable *xat, uint64_t scan_regionnr)
{
	entrynr_t entrynr;
	entrynr_t entry_start = scan_regionnr * ENTRY_PER_SCAN;
	entrynr_t entry_end = entry_start + ENTRY_PER_SCAN;
	int ret;

	for (entrynr = entry_start; entrynr < entry_end; ++entrynr) {
		ret = handle_entry(pentries, valid_entry, xat, entrynr);
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
	struct entry_allocator *entry_allocator = &meta_table->entry_allocator;
	struct nova_pmm_entry *pentries = meta_table->pentries;
	atomic_t *valid_entry = entry_allocator->valid_entry;
	atomic64_t *cur_scan_region = para->cur_scan_region;
	uint64_t scan_region_end = para->scan_region_end;
	uint64_t scan_regionnr;
	int ret;

	while (1) {
		scan_regionnr = atomic64_add_return(1, cur_scan_region);
		if (scan_regionnr >= scan_region_end)
			break;
		ret = scan_region(pentries, valid_entry, xat, scan_regionnr);
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
static int handle_tail_entry(struct nova_sb_info *sbi, struct xatable *xat,
	uint64_t scan_region_end)
{
	struct nova_meta_table *meta_table = &sbi->meta_table;
	struct entry_allocator *allocator = &meta_table->entry_allocator;
	entrynr_t entrynr_start = scan_region_end * ENTRY_PER_SCAN;
	struct nova_pmm_entry *pentries = meta_table->pentries;
	atomic_t *valid_entry = allocator->valid_entry;
	entrynr_t entrynr;
	int ret;
	for (entrynr = entrynr_start; entrynr < sbi->nr_entries; ++entrynr) {
		ret = handle_entry(pentries, valid_entry, xat, entrynr);
		if (ret < 0)
			return ret;
	}
	return 0;
}
static void rebuild_free_regions(struct nova_sb_info *sbi,
	struct entry_allocator *allocator)
{
	atomic_t *valid_entry = allocator->valid_entry;
	struct kfifo *free_regions = &allocator->free_regions;
	regionnr_t i;
	for (i = 0; i < sbi->nr_regions; ++i)
		if (atomic_read(valid_entry + i) <= FREE_THRESHOLD)
			BUG_ON(kfifo_in(free_regions, &i, sizeof(i)) != sizeof(i));
}
static int scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat,
	uint64_t scan_region_end)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long thread_num = min_ul(scan_region_end, sbi->cpus);
	struct scan_para *para = NULL;
	struct task_struct **tasks = NULL;
	unsigned long i;
	atomic64_t cur_scan_region;
	int ret = 0, ret2;

	nova_info("Scan fingerprint entry table using %lu thread(s)\n", thread_num);
	if (thread_num == 0)
		return 0;
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
	atomic64_set(&cur_scan_region, -1);
	for (i = 0; i < thread_num; ++i) {
		init_completion(&para[i].entered);
		para[i].sbi = sbi;
		para[i].xat = xat;
		para[i].cur_scan_region = &cur_scan_region;
		para[i].scan_region_end = scan_region_end;
		tasks[i] = kthread_create(scan_worker, para + i,
			"scan_worker_%lu", i);
		if (IS_ERR(tasks[i])) {
			ret = PTR_ERR(tasks[i]);
			tasks[i] = NULL;
			nova_err(sb, "kthread_create %lu return %d\n", i, ret);
			break;
		}
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
int nova_scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	uint64_t scan_region_end = sbi->nr_regions / REGION_PER_SCAN;
	int ret;
	printk("%s: nr_regions = %u, scan_region_end = %llu, nr_entries = %llu\n",
		__func__, sbi->nr_regions, scan_region_end, sbi->nr_entries);
	ret = entry_allocator_alloc(sbi, allocator, true);
	if (ret < 0)
		return ret;
	ret = scan_entry_table(sb, allocator, xat, scan_region_end);
	if (ret < 0)
		goto err_out;
	ret = handle_tail_entry(sbi, xat, scan_region_end);
	if (ret < 0)
		goto err_out;
	rebuild_free_regions(sbi, allocator);
	return 0;
err_out:
	nova_free_entry_allocator(allocator);
	nova_err(sb, "%s return with error code %d\n", __func__, ret);
	return ret;
}

static entrynr_t
new_region(struct entry_allocator *allocator) {
	regionnr_t regionnr;

	// Singer consumer, but multiple producer.
	spin_lock(&allocator->lock);
	BUG_ON(kfifo_out(&allocator->free_regions, &regionnr, sizeof(regionnr)) != sizeof(regionnr));
	spin_unlock(&allocator->lock);

	atomic64_set(&allocator->regionnr_index, (uint64_t)regionnr << INDEX_BIT); // Allocate 0 for itself.

	return (entrynr_t)regionnr * ENTRY_PER_REGION;
}

// Test and test and add.
static entrynr_t
TTAA(struct entry_allocator *allocator) {
	uint64_t regionnr_index, index;
	do {
		do {
			regionnr_index = atomic64_read(&allocator->regionnr_index);   // TODO: Read directly without atomic?
			index = regionnr_index & INDEX_MASK;
		} while (index > ENTRY_PER_REGION);
		regionnr_index = atomic64_add_return(1, &allocator->regionnr_index);
		index = regionnr_index & INDEX_MASK;
		BUG_ON(index == INDEX_MASK);
	} while (index > ENTRY_PER_REGION);
	if (index == ENTRY_PER_REGION)
		return new_region(allocator);
	return (regionnr_index >> INDEX_BIT) * ENTRY_PER_REGION + index;
}

static entrynr_t
handle_overflow(struct entry_allocator *allocator, uint64_t index) {
	BUG_ON(index == INDEX_MASK);
	if (index > ENTRY_PER_REGION) {
		return TTAA(allocator);
	} else {    // index == ENTRY_PER_REGION
		return new_region(allocator);
	}
}

entrynr_t nova_alloc_entry(struct entry_allocator *allocator) {
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct nova_pmm_entry *pentries = meta_table->pentries;
	uint64_t regionnr_index, index;
	entrynr_t entrynr;

	do {
		regionnr_index = atomic64_add_return(1, &allocator->regionnr_index);
		index = regionnr_index & INDEX_MASK;
		if (unlikely(index >= ENTRY_PER_REGION)) {
			entrynr = handle_overflow(allocator, index);
		} else {
			entrynr = (regionnr_index >> INDEX_BIT) * ENTRY_PER_REGION + index;
		}
	} while (entry_info_pmm_to_mm(pentries[entrynr].info).flag == NOVA_LEAF_ENTRY_MAGIC);
	atomic_add_return(1, allocator->valid_entry + (entrynr / ENTRY_PER_REGION));

	return entrynr;
}

void nova_free_entry(struct entry_allocator *allocator, entrynr_t entrynr) {
	// if (test_and_set_bit(allocator->free, regionnr))
	//     return;
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	struct nova_pmm_entry *pentry = meta_table->pentries + entrynr;
	regionnr_t regionnr = entrynr / ENTRY_PER_REGION;
	if (atomic_sub_return(1, allocator->valid_entry + regionnr) == FREE_THRESHOLD) {
		spin_lock(&allocator->lock);
		BUG_ON(kfifo_in(&allocator->free_regions, &regionnr, sizeof(regionnr)) != sizeof(regionnr));
		spin_unlock(&allocator->lock);
	}
	nova_unlock_write(sb, &pentry->info, 0, true);
}

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	size_t i;
	unsigned long *count = vzalloc((ENTRY_PER_REGION + 1) * sizeof(unsigned long));
	if (count == NULL)
		return -ENOMEM;
	for (i = 0; i < sbi->nr_regions; ++i)
		++count[atomic_read(allocator->valid_entry + i)];
	printk("Valid entry count of the regions:");
	for (i = 0; i < ENTRY_PER_REGION + 1; ++i)
		if (count[i])
			printk(KERN_CONT " (%d)%lu", (int)i, count[i]);
	printk(KERN_CONT "\n");
	vfree(count);
	return 0;
}
