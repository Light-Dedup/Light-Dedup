#include "entry.h"
#include "nova.h"
#include "multithread.h"
#include "arithmetic.h"

// #define static _Static_assert(1, "2333");

#define ENTRY_PER_CACHELINE (CACHELINE_SIZE / sizeof(struct nova_pmm_entry))
// If the number of free entries in a region is greater or equal to FREE_THRESHOLD, then the region is regarded as free.
#define FREE_THRESHOLD (ENTRY_PER_REGION / 2)

#define ENTRY_PER_REGION (REGION_SIZE / sizeof(struct nova_pmm_entry))

#define REGION_FULL ((entrynr_t)-1)

_Static_assert((1ULL << (sizeof(atomic_t) * 8)) > ENTRY_PER_REGION, "Type of counter of valid entries in a region is too small!");

static int entry_allocator_alloc(struct nova_sb_info *sbi, struct entry_allocator *allocator,
	bool zero_valid_entry)
{
	spin_lock_init(&allocator->lock);
	return 0;
}

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	int ret = entry_allocator_alloc(sbi, allocator, true);
	// The first allocation will trigger a new_region request.
	allocator->entry_collision = 0 ;
	allocator->top_entrynr = -1;
	allocator->num_entry = sbi->nr_entries;
	return ret;
}


int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	return 0;
}

void nova_free_entry_allocator(struct entry_allocator *allocator)
{
	return;
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

int nova_scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat)
{
	int ret = 0;
	return ret;
}

static entrynr_t
alloc_entry(struct entry_allocator *allocator, struct nova_fp fp)
{
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct nova_pmm_entry *pentries = meta_table->pentries;
	entrynr_t index = fp.value % (allocator->num_entry);
	entrynr_t base = index & ~(ENTRY_PER_REGION - 1);
	entrynr_t offset = index & (ENTRY_PER_REGION - 1);
	entrynr_t i = offset;
	do {
		index = base + i;
		if (pentries[index].blocknr == 0)
			return index;
		++i;
		i &= ENTRY_PER_REGION - 1;
	} while (i != offset);
	return REGION_FULL;
}
static void
write_entry(struct entry_allocator *allocator, entrynr_t entrynr,
	struct nova_fp fp, __le32 blocknr, __le32 refcount)
{
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	struct nova_pmm_entry *pentries = meta_table->pentries;
	struct nova_pmm_entry *pentry = pentries + entrynr;
	unsigned long irq_flags = 0;
	INIT_TIMING(write_new_entry_time);

	nova_memunlock_range(sb, pentry, sizeof(*pentry), &irq_flags);
	NOVA_START_TIMING(write_new_entry_t, write_new_entry_time);
	pentry->fp = fp;
	wmb();
	pentry->refcount = refcount;
	pentry->blocknr = blocknr;
	nova_flush_buffer(pentry, sizeof(*pentry), true);
	NOVA_END_TIMING(write_new_entry_t, write_new_entry_time);
	nova_memlock_range(sb, pentry, sizeof(*pentry), &irq_flags);
}
void nova_alloc_and_write_entry(struct entry_allocator *allocator,
	struct nova_fp fp, __le32 blocknr, __le32 refcount)
{
	entrynr_t entrynr;
	spin_lock(&allocator->lock);
	entrynr = alloc_entry(allocator, fp);
	if (entrynr != REGION_FULL)
		write_entry(allocator, entrynr, fp, blocknr,refcount);
	else
		++allocator->entry_collision;
	spin_unlock(&allocator->lock);
}

void nova_free_entry(struct entry_allocator *allocator, entrynr_t entrynr) {
	// if (test_and_set_bit(allocator->free, regionnr))
	//     return;
	struct nova_meta_table *meta_table =
		container_of(allocator, struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	struct nova_pmm_entry *pentry = meta_table->pentries + entrynr;

	spin_lock(&allocator->lock);
	nova_unlock_write(sb, &pentry->blocknr, 0, true);
	spin_unlock(&allocator->lock);
}

void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator)
{
	nova_free_entry_allocator(allocator);
}

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	printk("collision happens %lu\n",allocator->entry_collision);
	return 0;
}
