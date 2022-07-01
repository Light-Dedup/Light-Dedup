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
};
struct nova_write_para_rewrite {
	struct nova_write_para_normal normal;
	unsigned long offset, len;
};

int nova_table_deref_block(struct nova_mm_table *table,
	struct nova_write_para_normal *wp);
int nova_table_upsert_normal(struct nova_mm_table *table, struct nova_write_para_normal *wp);
int nova_table_upsert_rewrite(struct nova_mm_table *table, struct nova_write_para_rewrite *wp);
// refcount-- only if refcount == 1
int nova_table_upsert_decr1(struct nova_mm_table *table, struct nova_write_para_normal *wp);
int nova_table_insert_entry(struct nova_mm_table *rht, struct nova_fp fp,
	struct nova_pmm_entry *pentry);

int nova_fp_table_incr(struct nova_mm_table *table, const void* addr,
	struct nova_write_para_normal *wp);
int nova_fp_table_rewrite_on_insert(struct nova_mm_table *table,
	const void *addr, struct nova_write_para_rewrite *wp,
	unsigned long blocknr, size_t offset, size_t bytes);

int nova_table_init(struct super_block *sb, struct nova_mm_table *table,
	size_t nelem_hint);
int nova_table_recover(struct nova_mm_table *table);

void nova_table_free(struct nova_mm_table *table);
void nova_table_save(struct nova_mm_table* table);

#endif
