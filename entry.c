#include "entry.h"
#include "nova.h"

#define INDEX_BIT 32
#define INDEX_MASK ((1ULL << INDEX_BIT) - 1)

// If the number of free entries in a region is greater or equal to FREE_THRESHOLD, then the region is regarded as free.
#define FREE_THRESHOLD (ENTRY_PER_REGION / 2)

_Static_assert((1ULL << (sizeof(atomic_t) * 8)) > ENTRY_PER_REGION, "Type of counter of valid entries in a region is too small!");

int nova_init_entry_allocator(struct super_block *sb, struct entry_allocator *allocator, struct nova_pmm_entry *pentries, entrynr_t entrynr) {
    regionnr_t i, region_num;
    int ret;

    // printk("nova_init_entry_allocator: entrynr = %llu\n", entrynr);
    BUG_ON(entrynr % ENTRY_PER_REGION != 0);

    region_num = entrynr / ENTRY_PER_REGION;
    // allocator->free = bitmap_zalloc(region_num, GFP_KERNEL);
    allocator->valid_entry = vzalloc(region_num * sizeof(allocator->valid_entry[0]));
    if (allocator->valid_entry == NULL) {
        ret = -ENOMEM;
        nova_dbg("%s: Allocate valid_entry failed. entrynr = %llu, region_num = %u\n", __func__, entrynr, region_num);
        goto err_out0;
    }
    ret = kfifo_alloc(&allocator->free_regions, region_num * sizeof(regionnr_t), GFP_KERNEL);
    if (ret)
        goto err_out1;
    for (i = 1; i < region_num; ++i) {
        BUG_ON(kfifo_in(&allocator->free_regions, &i, sizeof(i)) == 0);
    }
    allocator->pentries = pentries;
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
