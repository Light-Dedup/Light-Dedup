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
	__le64 padding[3];
} ____cacheline_aligned_in_smp;

_Static_assert(sizeof(struct nova_pmm_entry) == 64, "Meta Data Entry not 64B!");

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

struct entry_allocator_cpu {
	struct nova_pmm_entry *top_entry; // Last allocated entry.
	struct nova_pmm_entry *last_entry; // Last not flushed entry.
	int16_t allocated;
};
DECLARE_PER_CPU(struct entry_allocator_cpu, entry_allocator_per_cpu);

struct entry_allocator {
	regionnr_t region_num;
	__le64 *last_region_tail;
	regionnr_t valid_entry_count_num;
	__le64 *last_valid_entry_count_block_tail;
	// TODO: Place most free regions in the NVM in a list queue manner.
	struct nova_queue free_regions; // Region numbers
	spinlock_t lock;
	struct xarray valid_entry; // Key is blocknr of region
};
#define VALID_ENTRY_COUNTER_PER_BLOCK \
	((PAGE_SIZE - sizeof(__le64)) / sizeof(uint16_t))

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator);
int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator);
void nova_free_entry_allocator(struct entry_allocator *allocator);
int nova_scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat,
	unsigned long *bm);

void nova_flush_entry(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry);
struct nova_pmm_entry *
nova_alloc_entry(struct entry_allocator *allocator,
	struct entry_allocator_cpu *allocator_cpu);
static inline void
nova_alloc_entry_abort(struct entry_allocator_cpu *allocator_cpu)
{
}
void nova_write_entry(struct entry_allocator *allocator,
	struct entry_allocator_cpu *allocator_cpu,
	struct nova_pmm_entry *pentry, const struct nova_fp *fp, __le64 info);
void nova_free_entry(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry);

void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator);

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator);

#endif // __NOVA_ENTRY_H