#ifndef __NOVA_ENTRY_H
#define __NOVA_ENTRY_H

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/bitmap.h>
#include "fingerprint.h"
#include "xatable.h"
#include "queue.h"

struct nova_sb_info;

typedef uint64_t entrynr_t;
typedef uint32_t regionnr_t;

struct nova_pmm_entry_info {
	union {
		struct {
			u64 blocknr: 63;
			u64 to_be_freed;
		};
		u64 value;
	};
};

struct nova_pmm_entry {
	struct nova_fp fp;	// TODO: cpu_to_le64?
	__le64 info;
	atomic64_t refcount;
	// Lowest 3 bits are unsigned trust degree (<= 7). Initially 4.
	// For each result matching the hint, the trust degree += 1
	// For each result mismatching the hint, the trust degree -= 2.
	// If the resulting trust degree < 0, then the offset is updated.
	// If the trust degree < 4, then the hint is not taken.
	atomic64_t next_hint;
};
_Static_assert(sizeof(atomic64_t) == 8, "atomic64_t not 8B!");
#define TRUST_DEGREE_BITS 3
#define HINT_TRUST_DEGREE_THRESHOLD (1 << (TRUST_DEGREE_BITS - 1))
#define TRUST_DEGREE_MASK ((1 << TRUST_DEGREE_BITS) - 1)
#define HINT_OFFSET_MASK (~TRUST_DEGREE_MASK)
#define TRUST_DEGREE_MAX ((1 << TRUST_DEGREE_BITS) - 1)
#define TRUST_DEGREE_MIN 0

#define REGION_SIZE PAGE_SIZE
#define ENTRY_PER_REGION (REGION_SIZE / sizeof(struct nova_pmm_entry))
#define REAL_ENTRY_PER_REGION \
	((REGION_SIZE - sizeof(__le64)) / sizeof(struct nova_pmm_entry))

#define NULL_PENTRY ((struct nova_pmm_entry *)( \
	(REAL_ENTRY_PER_REGION - 1) * sizeof(struct nova_pmm_entry)))

static inline struct nova_pmm_entry_info
nova_pmm_entry_get_info(const struct nova_pmm_entry *pentry)
{
	struct nova_pmm_entry_info ret;
	ret.value = le64_to_cpu(pentry->info);
	return ret;
}
static inline unsigned long
nova_pmm_entry_blocknr(const struct nova_pmm_entry *pentry)
{
	return nova_pmm_entry_get_info(pentry).blocknr;
}
static inline void
nova_pmm_entry_mark_to_be_freed(struct nova_pmm_entry *pentry)
{
	struct nova_pmm_entry_info info = nova_pmm_entry_get_info(pentry);
	BUG_ON(info.to_be_freed == true);
	info.to_be_freed = true;
	pentry->info = cpu_to_le64(info.value);
}
static inline bool
nova_pmm_entry_is_to_be_freed(const struct nova_pmm_entry *pentry)
{
	return nova_pmm_entry_get_info(pentry).to_be_freed;
}
static inline bool
nova_pmm_entry_is_free(const struct nova_pmm_entry *pentry)
{
	return nova_pmm_entry_blocknr(pentry) == 0;
}

struct entry_allocator_cpu {
	struct nova_pmm_entry *top_entry; // Last allocated entry.
	int16_t allocated;
};
DECLARE_PER_CPU(struct entry_allocator_cpu, entry_allocator_per_cpu);

struct entry_allocator {
	regionnr_t region_num;
	__le64 *last_region_tail;
	// TODO: Place most free regions in the NVM in a list queue manner.
	struct nova_queue free_regions; // Region numbers
	// Used in softirq context
	spinlock_t lock;
	// Used in softirq context
	// Key is blocknr of region
	struct xarray valid_entry;
	void *first_region; // To free regions.
};
#define VALID_ENTRY_COUNTER_PER_BLOCK \
	((PAGE_SIZE - sizeof(__le64)) / sizeof(uint16_t))

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator);
int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator);
void nova_free_entry_allocator(struct entry_allocator *allocator);
int nova_scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat,
	unsigned long *bm, size_t *tot);

static inline bool in_the_same_cacheline(
	struct nova_pmm_entry *a,
	struct nova_pmm_entry *b)
{
	return (unsigned long)a / CACHELINE_SIZE ==
		(unsigned long)b / CACHELINE_SIZE;
}

void nova_flush_entry(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry);

static inline void nova_flush_entry_if_not_null(struct nova_pmm_entry *pentry,
	bool fence)
{
	if (pentry != NULL_PENTRY)
		nova_flush_cacheline(pentry, fence);
		
}

struct nova_pmm_entry *
nova_alloc_entry(struct entry_allocator *allocator,
	struct entry_allocator_cpu *allocator_cpu);
static inline void
nova_alloc_entry_abort(struct entry_allocator_cpu *allocator_cpu)
{
}
void nova_write_entry(struct entry_allocator *allocator,
	struct entry_allocator_cpu *allocator_cpu,
	struct nova_pmm_entry *pentry, struct nova_fp fp,
	unsigned long blocknr);
void nova_free_entry(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry);

void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator);

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator);

#endif // __NOVA_ENTRY_H