#ifndef __NOVA_ENTRY_H
#define __NOVA_ENTRY_H

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/bitmap.h>
#include "fingerprint.h"
#include "xatable.h"
#include "queue.h"

#define NOVA_LEAF_ENTRY_MAGIC (0x3f3f)

struct nova_sb_info;

typedef uint64_t entrynr_t;
typedef uint32_t regionnr_t;

struct nova_mm_entry_info {
	union {
		struct {
			uint16_t flag: 16;
			uint64_t blocknr: 48;
		};
		uint64_t value;
	};
};
struct nova_pmm_entry {
	__le64 info;
	struct nova_fp fp;	// TODO: cpu_to_le64?
};

#define REGION_SIZE PAGE_SIZE
#define ENTRY_PER_REGION (REGION_SIZE / sizeof(struct nova_pmm_entry))
#define REAL_ENTRY_PER_REGION \
	((REGION_SIZE - sizeof(__le64)) / sizeof(struct nova_pmm_entry))

static inline struct nova_mm_entry_info
entry_info_pmm_to_mm(__le64 info) {
	struct nova_mm_entry_info entry_info;
	entry_info.value = le64_to_cpu(info);
	return entry_info;
}

// typedef uint32_t region_entry_index_t;
struct entry_allocator {
	regionnr_t region_num;
	__le64 *last_region_tail;
	regionnr_t valid_entry_count_num;
	__le64 *last_valid_entry_count_block_tail;
	regionnr_t region_array_cap; // Cap of valid_entry and region_blocknr
	uint16_t *valid_entry;	// At most ENTRY_PER_REGION
	unsigned long *region_blocknr;
	// TODO: Place most free regions in the NVM in a list queue manner.
	struct nova_queue free_regions; // Region numbers
	entrynr_t top_entrynr;	// Last allocated entry.
	entrynr_t last_entrynr;	// Last not flushed entry. If none then -1.
	spinlock_t lock;
};
#define VALID_ENTRY_COUNTER_PER_BLOCK \
	((PAGE_SIZE - sizeof(__le64)) / sizeof(uint16_t))

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator);
int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator);
void nova_free_entry_allocator(struct entry_allocator *allocator);
int nova_scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat,
	unsigned long *bm);

void nova_flush_entry(struct entry_allocator *allocator, entrynr_t entrynr);
int alloc_entry(struct entry_allocator *allocator, entrynr_t *new_entrynr);
void write_entry(struct entry_allocator *allocator, entrynr_t entrynr,
	struct nova_fp fp, __le64 info);
void nova_free_entry(struct entry_allocator *allocator, entrynr_t entrynr);

void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator);

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator);

#endif // __NOVA_ENTRY_H