#include "entry.h"
#include "nova.h"
#include "multithread.h"
#include "arithmetic.h"

// #define static _Static_assert(1, "2333");

#define ENTRY_PER_CACHELINE (CACHELINE_SIZE / sizeof(struct nova_pmm_entry))
// If the number of free entries in a region is greater or equal to FREE_THRESHOLD, then the region is regarded as free.
#define FREE_THRESHOLD (ENTRY_PER_REGION / 2)

_Static_assert((1ULL << (sizeof(atomic_t) * 8)) > ENTRY_PER_REGION, "Type of counter of valid entries in a region is too small!");

static int entry_allocator_alloc(struct nova_sb_info *sbi, struct entry_allocator *allocator,
	bool zero_valid_entry)
{
	size_t buf_sz;
	char *buf;
	int ret;
	if (zero_valid_entry)
		allocator->valid_entry = vzalloc(sbi->nr_regions * sizeof(allocator->valid_entry[0]));
	else
		allocator->valid_entry = vmalloc(sbi->nr_regions * sizeof(allocator->valid_entry[0]));
	if (allocator->valid_entry == NULL) {
		nova_dbg("%s: Allocate valid_entry failed.\n", __func__);
		return -ENOMEM;
	}
	buf_sz = sbi->nr_regions * sizeof(regionnr_t);
	buf = vmalloc(buf_sz);
	if (buf == NULL) {
		vfree(buf);
		return -ENOMEM;
	}
	ret = kfifo_init(&allocator->free_regions, buf, buf_sz);
	if (ret) {
		vfree(buf);
		return ret;
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
	for (i = 0; i < sbi->nr_regions; ++i)
		BUG_ON(kfifo_in(&allocator->free_regions, &i, sizeof(i)) == 0);
	// The first allocation will trigger a new_region request.
	allocator->top_entrynr = allocator->last_entrynr = -1;
	return 0;
}

static void rebuild_free_regions(struct nova_sb_info *sbi,
	struct entry_allocator *allocator)
{
	uint16_t *valid_entry = allocator->valid_entry;
	struct kfifo *free_regions = &allocator->free_regions;
	regionnr_t i;
	for (i = 0; i < sbi->nr_regions; ++i)
		if (valid_entry[i] <= FREE_THRESHOLD)
			BUG_ON(kfifo_in(free_regions, &i, sizeof(i)) != sizeof(i));
	// The first allocation will trigger a new_region request.
	allocator->top_entrynr = allocator->last_entrynr = -1;
}
int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	__le16 *valid_entry_count = nova_sbi_blocknr_to_addr(sbi, sbi->region_valid_entry_count_start);
	regionnr_t i;
	int ret;
	INIT_TIMING(normal_recover_entry_allocator_time);

	BUG_ON(recover_meta->region_valid_entry_count_saved != NOVA_RECOVER_META_FLAG_COMPLETE);
	ret = entry_allocator_alloc(sbi, allocator, false);
	if (ret < 0)
		return ret;
	NOVA_START_TIMING(normal_recover_entry_allocator_t, normal_recover_entry_allocator_time);
	for (i = 0; i < sbi->nr_regions; ++i)
		allocator->valid_entry[i] = le16_to_cpu(valid_entry_count[i]);
	rebuild_free_regions(sbi, allocator);
	NOVA_END_TIMING(normal_recover_entry_allocator_t, normal_recover_entry_allocator_time);
	return 0;
}

void nova_free_entry_allocator(struct entry_allocator *allocator)
{
	vfree(allocator->valid_entry);
	vfree(allocator->free_regions.kfifo.data);
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
static inline int handle_entry(struct nova_pmm_entry *pentries, uint16_t *valid_entry,
	struct xatable *xat, entrynr_t entrynr)
{
	struct nova_mm_entry_info info = entry_info_pmm_to_mm(pentries[entrynr].info);
	if (info.flag != NOVA_LEAF_ENTRY_MAGIC)
		return 0;
	// Impossible to conflict
	++valid_entry[entrynr / ENTRY_PER_REGION];
	return xa_err(xatable_store(xat, info.blocknr, xa_mk_value(entrynr), GFP_KERNEL));
}
static int scan_region(struct nova_pmm_entry *pentries, uint16_t *valid_entry,
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
	uint16_t *valid_entry = entry_allocator->valid_entry;
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
	uint16_t *valid_entry = allocator->valid_entry;
	entrynr_t entrynr;
	int ret;
	for (entrynr = entrynr_start; entrynr < sbi->nr_entries; ++entrynr) {
		ret = handle_entry(pentries, valid_entry, xat, entrynr);
		if (ret < 0)
			return ret;
	}
	return 0;
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
	printk("%s: nr_regions = %lu, scan_region_end = %llu, nr_entries = %llu\n",
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

static inline void
__flush_entry(struct entry_allocator *allocator, entrynr_t entrynr)
{
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct nova_pmm_entry *pentries = meta_table->pentries;
	nova_flush_cacheline(pentries + entrynr, true);
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

static regionnr_t
new_region(struct entry_allocator *allocator)
{
	regionnr_t regionnr;
	if (allocator->top_entrynr != -1) {
		regionnr = allocator->top_entrynr / ENTRY_PER_REGION;
		if (allocator->valid_entry[regionnr] <= FREE_THRESHOLD)
			BUG_ON(kfifo_in(&allocator->free_regions, &regionnr, sizeof(regionnr)) != sizeof(regionnr));
		// new_region at most once, so it is safe to not update top_entrynr here.
	}
	BUG_ON(kfifo_out(&allocator->free_regions,
			&regionnr, sizeof(regionnr_t)
		) != sizeof(regionnr_t));
	return regionnr;
}
static entrynr_t
alloc_entry(struct entry_allocator *allocator)
{
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct nova_pmm_entry *pentries = meta_table->pentries;
	entrynr_t entrynr = allocator->top_entrynr;
	do {
		++entrynr;
		if ((entrynr % ENTRY_PER_REGION) == 0)
			entrynr = (entrynr_t)new_region(allocator) * ENTRY_PER_REGION;
	} while (entry_info_pmm_to_mm(pentries[entrynr].info).flag == NOVA_LEAF_ENTRY_MAGIC);
	allocator->top_entrynr = entrynr;
	++allocator->valid_entry[entrynr / ENTRY_PER_REGION];
	return entrynr;
}
static void
write_entry(struct entry_allocator *allocator, entrynr_t entrynr,
	struct nova_fp fp, __le64 info)
{
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	struct nova_pmm_entry *pentries = meta_table->pentries;
	struct nova_pmm_entry *pentry = pentries + entrynr;
	unsigned long irq_flags = 0;
	INIT_TIMING(write_new_entry_time);

	if (nova_is_protected(sb))
		__nova_writable(1, &irq_flags);
	NOVA_START_TIMING(write_new_entry_t, write_new_entry_time);
	pentry->fp = fp;
	wmb();
	pentry->info = info;
	if (!in_the_same_cacheline(allocator->last_entrynr, entrynr))
		flush_last_entry(allocator);
	allocator->last_entrynr = entrynr;
	NOVA_END_TIMING(write_new_entry_t, write_new_entry_time);
	if (nova_is_protected(sb))
		__nova_writable(0, &irq_flags);
}
entrynr_t nova_alloc_and_write_entry(struct entry_allocator *allocator,
	struct nova_fp fp, __le64 info)
{
	entrynr_t entrynr;
	spin_lock(&allocator->lock);
	entrynr = alloc_entry(allocator);
	write_entry(allocator, entrynr, fp, info);
	spin_unlock(&allocator->lock);
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

	spin_lock(&allocator->lock);
	if ((--allocator->valid_entry[regionnr]) == FREE_THRESHOLD)
		// To avoid adding the current region into free region queue repeatedly.
		if (regionnr != allocator->top_entrynr / ENTRY_PER_REGION)
			BUG_ON(kfifo_in(&allocator->free_regions, &regionnr, sizeof(regionnr)) != sizeof(regionnr));
	nova_unlock_write(sb, &pentry->info, 0, true);
	spin_unlock(&allocator->lock);
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
	flush_last_entry(allocator);
	nova_memunlock_range(sb, valid_entry_count, sbi->nr_regions * sizeof(__le16), &irq_flags);
	for (i = 0; i < sbi->nr_regions; ++i)
		valid_entry_count[i] = cpu_to_le16(allocator->valid_entry[i]);
	nova_memlock_range(sb, valid_entry_count, sbi->nr_regions * sizeof(__le16), &irq_flags);
	nova_flush_buffer(valid_entry_count, sbi->nr_regions * sizeof(valid_entry_count[0]), true);
	nova_unlock_write(sb, &recover_meta->region_valid_entry_count_saved, NOVA_RECOVER_META_FLAG_COMPLETE, true);
	NOVA_END_TIMING(save_entry_allocator_t, save_entry_allocator_time);

	nova_free_entry_allocator(allocator);
}

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	size_t i;
	unsigned long *count = vzalloc((ENTRY_PER_REGION + 1) * sizeof(unsigned long));
	if (count == NULL)
		return -ENOMEM;
	for (i = 0; i < sbi->nr_regions; ++i) {
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
