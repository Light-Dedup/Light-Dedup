#ifndef __NOVA_TABLE_H
#define __NOVA_TABLE_H

#include <linux/mutex.h>
#include "nova_def.h"
#include "generic_cache.h"
#include "entry.h"

_Static_assert(sizeof(unsigned long) == sizeof(uint64_t), "You should make all blocknr 64 bit");

struct nova_entry_refcount_record {
	__le64 entry_offset;
};

_Static_assert(sizeof(unsigned long) == sizeof(void *), "sizeof unsigned long != sizeof void * !!!");

struct nova_write_para_base {
	struct nova_fp fp;
	int64_t refcount;
};
struct nova_write_para_normal {
	// Because C does not support inheritance.
	struct nova_write_para_base base;
	const void *addr;
	unsigned long blocknr;
	struct nova_pmm_entry *pentry;
	// Two last not flushed referenced entries.
	// 0 is the last. 1 is the second to last.
	// The two fpentries should be flushed before
	// committing the corresponding write entry to guarantee persistency,
	// so that the corresponding block will not be regarded as a block
	// without deduplication.
	struct nova_pmm_entry *last_ref_entries[2];
	// Two last not flushed newly allocated entries.
	// 0 is the last. 1 is the second to last.
	// Maintained here to make sure that the newly allocated entry is
	// flushed after its hint is written.
	struct nova_pmm_entry *last_new_entries[2];
	__le64 *dirty_map_blocknr_to_pentry;
	// Last accessed entry to provide hint for the next entry.
	struct nova_pmm_entry *last_accessed;
};
struct nova_write_para_rewrite {
	struct nova_write_para_normal normal;
	unsigned long offset, len;
};

struct nova_write_para_continuous {
	const char __user *ubuf;
	size_t len;
	unsigned long blocknr;
	unsigned long num;
	unsigned long blocknr_next;
	// To keep track of last_ref_entry
	struct nova_write_para_normal normal;
	// Used internally
	char *kbuf;
	const char *block_prefetching;
	// Depends on the results of previous hints.
	// For stats
	// [0] is the lastest prefetched blocknr.
	unsigned long prefetched_blocknr[2];
};

struct light_dedup_meta {
	struct super_block *sblock;
	struct generic_cache kbuf_cache;
	struct nova_fp_strong_ctx fp_ctx;
	struct entry_allocator entry_allocator;
	struct rhashtable rht;
	struct kmem_cache *rht_entry_cache;
	atomic64_t thread_num;
};

static inline struct light_dedup_meta *
entry_allocator_to_light_dedup_meta(struct entry_allocator *allocator)
{
	return container_of(
		allocator, struct light_dedup_meta, entry_allocator);
}

struct kbuf_obj {
	struct llist_node node;
	void *kbuf;
};

int light_dedup_incr_ref(struct light_dedup_meta *meta, const void* addr,
	struct nova_write_para_normal *wp);

void light_dedup_decr_ref(struct light_dedup_meta *meta, unsigned long blocknr,
	struct nova_pmm_entry **last_pentry);
long light_dedup_decr_ref_1(struct light_dedup_meta *meta, const void *addr,
	unsigned long blocknr);

int light_dedup_insert_rht_entry(struct light_dedup_meta *meta,
	struct nova_fp fp, struct nova_pmm_entry *pentry);

int light_dedup_incr_ref_continuous(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp);

int light_dedup_meta_alloc(struct light_dedup_meta *meta,
	struct super_block *sb, size_t nelem_hint);
void light_dedup_meta_free(struct light_dedup_meta *meta);
int light_dedup_meta_init(struct light_dedup_meta *meta,
	struct super_block* sblock);
int light_dedup_meta_restore(struct light_dedup_meta *meta,
	struct super_block *sb);
void light_dedup_meta_save(struct light_dedup_meta *meta);

#endif
