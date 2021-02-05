#include "entry.h"
#include "nova.h"

#define INDEX_BIT 32
#define INDEX_MASK ((1ULL << INDEX_BIT) - 1)

// If the number of free entries in a region is greater or equal to FREE_THRESHOLD, then the region is regarded as free.
#define FREE_THRESHOLD (ENTRY_PER_REGION / 2)

_Static_assert((1ULL << (sizeof(atomic_t) * 8)) > ENTRY_PER_REGION, "Type of counter of valid entries in a region is too small!");

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator)
{
	regionnr_t i;
	int ret;

	printk("nova_init_entry_allocator: nr_regions = %u\n", sbi->nr_regions);
	allocator->valid_entry = vzalloc(sbi->nr_regions * sizeof(allocator->valid_entry[0]));
	if (allocator->valid_entry == NULL) {
		ret = -ENOMEM;
		nova_dbg("%s: Allocate valid_entry failed.\n", __func__);
		goto err_out0;
	}
	ret = kfifo_alloc(&allocator->free_regions, sbi->nr_regions * sizeof(regionnr_t), GFP_KERNEL);
	if (ret)
		goto err_out1;
	for (i = 1; i < sbi->nr_regions; ++i)
		BUG_ON(kfifo_in(&allocator->free_regions, &i, sizeof(i)) == 0);
	allocator->pentries = nova_sbi_blocknr_to_addr(sbi, sbi->entry_table_start);
	atomic64_set(&allocator->regionnr_index, -1);
	// allocator->cur = pentries - 1;
	// allocator->region_end = pentries + ENTRY_PER_REGION;
	spin_lock_init(&allocator->lock);

	return 0;
err_out1:
	vfree(allocator->valid_entry);
err_out0:
	return ret;
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
	allocator->valid_entry = vmalloc(sbi->nr_regions * sizeof(allocator->valid_entry[0]));
	if (allocator->valid_entry == NULL) {
		ret = -ENOMEM;
		nova_dbg("%s: Allocate valid_entry failed.\n", __func__);
		goto err_out0;
	}
	ret = kfifo_alloc(&allocator->free_regions, sbi->nr_regions * sizeof(regionnr_t), GFP_KERNEL);
	if (ret)
		goto err_out1;
	NOVA_START_TIMING(normal_recover_entry_allocator_t, normal_recover_entry_allocator_time);
	for (i = 0; i < sbi->nr_regions; ++i) {
		value = le16_to_cpu(valid_entry_count[i]);
		atomic_set(allocator->valid_entry + i, value);
		if (value <= FREE_THRESHOLD)
			BUG_ON(kfifo_in(&allocator->free_regions, &i, sizeof(i)) != sizeof(i));
	}
	NOVA_END_TIMING(normal_recover_entry_allocator_t, normal_recover_entry_allocator_time);
	allocator->pentries = nova_sbi_blocknr_to_addr(sbi, sbi->entry_table_start);
	// The first allocation will trigger a new_region request.
	atomic64_set(&allocator->regionnr_index, ENTRY_PER_REGION - 1);
	spin_lock_init(&allocator->lock);
	return 0;
err_out1:
	vfree(allocator->valid_entry);
err_out0:
	return ret;
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
	} while (entry_info_pmm_to_mm(allocator->pentries[entrynr].info).flag == NOVA_LEAF_ENTRY_MAGIC);
	atomic_add_return(1, allocator->valid_entry + (entrynr / ENTRY_PER_REGION));

	return entrynr;
}

void nova_free_entry(struct entry_allocator *allocator, entrynr_t entrynr) {
	// if (test_and_set_bit(allocator->free, regionnr))
	//     return;
	regionnr_t regionnr = entrynr / ENTRY_PER_REGION;
	if (atomic_sub_return(1, allocator->valid_entry + regionnr) == FREE_THRESHOLD) {
		spin_lock(&allocator->lock);
		BUG_ON(kfifo_in(&allocator->free_regions, &regionnr, sizeof(regionnr)) != sizeof(regionnr));
		spin_unlock(&allocator->lock);
	}
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
