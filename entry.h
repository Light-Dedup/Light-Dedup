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

struct nova_pmm_entry {
	__le32 refcount;
	__le32 blocknr;
	struct nova_fp fp;	// TODO: cpu_to_le64?
};

#define REGION_SIZE 4096
#define ENTRY_PER_REGION (REGION_SIZE / sizeof(struct nova_pmm_entry))


// typedef uint32_t region_entry_index_t;
struct entry_allocator {
	unsigned long num_entry;
	entrynr_t top_entrynr;	// Last allocated entry.
	entrynr_t last_entrynr;	// Last not flushed entry. If none then -1.
  spinlock_t lock;
};

int nova_init_entry_allocator(struct nova_sb_info *sbi, struct entry_allocator *allocator);
int nova_entry_allocator_recover(struct nova_sb_info *sbi, struct entry_allocator *allocator);
void nova_free_entry_allocator(struct entry_allocator *allocator);
int nova_scan_entry_table(struct super_block *sb, struct entry_allocator *allocator,
	struct xatable *xat);

void nova_flush_entry(struct entry_allocator *allocator, entrynr_t entrynr);
entrynr_t nova_alloc_and_write_entry(struct entry_allocator *allocator, struct nova_fp fp, __le32 blocknr, __le32 refcount);
void nova_free_entry(struct entry_allocator *allocator, entrynr_t entrynr);

void nova_save_entry_allocator(struct super_block *sb, struct entry_allocator *allocator);

int __nova_entry_allocator_stats(struct nova_sb_info *sbi, struct entry_allocator *allocator);

#endif // __NOVA_ENTRY_H