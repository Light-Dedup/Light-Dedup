#ifndef __NOVA_ENTRY_H
#define __NOVA_ENTRY_H

#include <linux/atomic.h>
#include <linux/kfifo.h>
#include <linux/spinlock.h>
#include <linux/bitmap.h>
#include "fingerprint.h"
#include "xatable.h"

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

#define REGION_SIZE 4096
#define ENTRY_PER_REGION (REGION_SIZE / sizeof(struct nova_pmm_entry))

static inline struct nova_mm_entry_info
entry_info_pmm_to_mm(__le64 info) {
	struct nova_mm_entry_info entry_info;
	entry_info.value = le64_to_cpu(info);
	return entry_info;
}

// typedef uint32_t region_entry_index_t;
struct entry_allocator {
	atomic_t *valid_entry;
	/* Hopefuly the 4B index won't overflow. */
	atomic64_t regionnr_index;	// The lower 4B is index, upper 4B is regionnr.
    struct kfifo free_regions;
    spinlock_t lock;	// For free_regions
};

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator);
int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator);
void nova_free_entry_allocator(struct entry_allocator *allocator);
void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator);
int nova_scan_entry_table(struct super_block *sb, struct entry_allocator *allocator,
	struct xatable *xat);

entrynr_t nova_alloc_and_write_entry(struct entry_allocator *allocator, struct nova_fp fp, __le64 info);
void nova_free_entry(struct entry_allocator *allocator, entrynr_t entrynr);

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator);

#endif // __NOVA_ENTRY_H