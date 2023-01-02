#ifndef __NOVA_TABLE_H
#define __NOVA_TABLE_H

#include <linux/mutex.h>
#include "nova_def.h"
#include "entry.h"

_Static_assert(sizeof(unsigned long) == sizeof(uint64_t), "You should make all blocknr 64 bit");

struct nova_entry_refcount_record {
	__le64 entry_offset;
};

_Static_assert(sizeof(unsigned long) == sizeof(void *), "sizeof unsigned long != sizeof void * !!!");

static inline bool nova_is_inner_node(unsigned long node_p)
{
	return node_p & 1;
}

static inline bool nova_is_leaf_node(unsigned long node_p)
{
	return (node_p & 1) == 0;
}

// static inline void *
// nova_node_p_to_pointer(unsigned long node_p)
// {
// 	return (void *)(node_p & ~1);
// }

static inline struct nova_bucket *
nova_node_p_to_bucket(unsigned long node_p)
{
	return (struct nova_bucket *)node_p;
}

static inline struct nova_inner *
nova_node_p_to_inner(unsigned long node_p)
{
	return (struct nova_inner *)(node_p - 1);
}

static inline unsigned long
nova_bucket_to_node_p(struct nova_bucket *bucket) {
	return (unsigned long)bucket;
}

static inline unsigned long
nova_inner_to_node_p(struct nova_inner *inner) {
	return (unsigned long)inner | 1;
}

struct nova_mm_table {
	struct super_block    *sblock;
	struct entry_allocator *entry_allocator;
	struct rhashtable	rht;
	struct kmem_cache *rht_entry_cache;
};

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
	// [-4, 3]
	uint8_t stream_trust_degree;
	// For stats
	// [0] is the lastest prefetched blocknr.
	unsigned long prefetched_blocknr[2];
};

void nova_table_deref_block(struct nova_mm_table *table,
	struct nova_pmm_entry *pentry, struct nova_pmm_entry **last_pentry);
int nova_table_upsert_normal(struct nova_mm_table *table, struct nova_write_para_normal *wp);
int nova_table_upsert_rewrite(struct nova_mm_table *table, struct nova_write_para_rewrite *wp);
// refcount-- only if refcount == 1
int nova_table_upsert_decr1(struct nova_mm_table *table, struct nova_write_para_normal *wp);
int nova_table_insert_entry(struct nova_mm_table *rht, struct nova_fp fp,
	struct nova_pmm_entry *pentry);

int nova_fp_table_incr(struct nova_mm_table *table, const void* addr,
	struct nova_write_para_normal *wp);

int nova_fp_table_incr_continuous_kbuf(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp);
int nova_fp_table_incr_continuous(struct nova_sb_info *sbi,
	struct nova_write_para_continuous *wp);

int nova_table_init(struct super_block *sb, struct nova_mm_table *table,
	size_t nelem_hint);
int nova_table_recover(struct nova_mm_table *table);

void nova_table_free(struct nova_mm_table *table);
void nova_table_save(struct nova_mm_table* table);

#endif
