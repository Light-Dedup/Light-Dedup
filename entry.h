#ifndef __NOVA_ENTRY_H
#define __NOVA_ENTRY_H

#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/bitmap.h>
#include "fingerprint.h"
#include "xatable.h"
#include "queue.h"

#define NOVA_LEAF_ENTRY_MAGIC (0x66ccff2020ffcc66)

struct nova_sb_info;

typedef uint64_t entrynr_t;
typedef uint32_t regionnr_t;

struct nova_pmm_entry {
	struct nova_fp fp;	// TODO: cpu_to_le64?
	__le64 blocknr;
	atomic64_t refcount;
	__le64 flag;
};

#define REGION_SIZE PAGE_SIZE
#define ENTRY_PER_REGION (REGION_SIZE / sizeof(struct nova_pmm_entry))
#define REAL_ENTRY_PER_REGION \
	((REGION_SIZE - sizeof(__le64)) / sizeof(struct nova_pmm_entry))

struct entry_allocator {
	regionnr_t region_num;
	__le64 *last_region_tail;
	// Keep this in case we make region blocknrs a list later.
	regionnr_t max_region_num; // Determined by the number of counter blocks.
	struct nova_queue free_entries; // Addresses
	struct nova_pmm_entry *last_entry; // Last not flushed entry.
	spinlock_t lock;
};
#define VALID_ENTRY_COUNTER_PER_BLOCK \
	((PAGE_SIZE - sizeof(__le64)) / sizeof(uint16_t))

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator);
int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator);
void nova_free_entry_allocator(struct entry_allocator *allocator);
int nova_scan_entry_table(struct super_block *sb,
	struct entry_allocator *allocator, struct xatable *xat,
	struct rhashtable *rht, const struct rhashtable_params params,
	unsigned long *bm);

void nova_flush_entry(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry);
struct nova_pmm_entry *
nova_alloc_entry(struct entry_allocator *allocator);
static inline void
nova_alloc_entry_abort(void)
{
}
void nova_write_entry(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry, struct nova_fp fp,
	unsigned long blocknr, int64_t refcount);
void nova_free_entry(struct entry_allocator *allocator,
	struct nova_pmm_entry *pentry);

void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator);

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator);

#endif // __NOVA_ENTRY_H