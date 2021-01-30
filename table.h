#ifndef __NOVA_TABLE_H
#define __NOVA_TABLE_H

#include <linux/mutex.h>
#include "nova_def.h"
#include "entry.h"

#define NOVA_TABLE_NODE_LEAF_TYPE (0)
#define NOVA_TABLE_NODE_INNER_TYPE (1)

struct nova_mm_entry {
	uint64_t                blocknr;
	int64_t                 refcount;
	struct nova_fp   fp;
	uint32_t                __reserved;
	uint32_t                flags;
};
_Static_assert(sizeof(unsigned long) == sizeof(uint64_t), "You should make all blocknr 64 bit");
_Static_assert(sizeof(struct nova_mm_entry) == CACHELINE_SIZE / 2, "nova_pmm_leaf not aligned!");

// 4096 / 8 = 512 = 2^9
#define NOVA_TABLE_INNER_BITS (9)
#define NOVA_TABLE_INNER_MASK (0x1ff)
#define NOVA_TABLE_INNER_SIZE (1 << NOVA_TABLE_INNER_BITS)
_Static_assert(INDEX_BIT_NUM % NOVA_TABLE_INNER_BITS == 0, "INDEX_BIT_NUM % NOVA_TABLE_INNER_BITS != 0 !!!");
#define NOVA_TABLE_MAX_DEPTH (INDEX_BIT_NUM / NOVA_TABLE_INNER_BITS)

#define NOVA_TABLE_LEAF_SIZE (1 << INDICATOR_BIT_NUM)
// If the sum of the sizes of two buckets <= NOVA_TABLE_MERGE_THRESHOLD, then we say that the two buckets are mergable.
#define NOVA_TABLE_MERGE_THRESHOLD (NOVA_TABLE_LEAF_SIZE / 2)

struct nova_mm_entry_p {
	// entrynr_t entrynr: 48;
	// uint16_t refcount: 16;
	entrynr_t entrynr: 32;
	uint32_t refcount: 32;
};
_Static_assert(sizeof(struct nova_mm_entry_p) == 8, "size of mm_entry_p is not 8!");
struct nova_entry_refcount_record {
	__le32 entrynr;
	__le32 refcount;
};

struct nova_bucket {
	struct {
		uint16_t mask: 4;	// The number of bits the bucket used. At most 9
		uint16_t size: 7;	// At most 64. Need recalculate when recovering.
	};
	uint8_t tags[NOVA_TABLE_LEAF_SIZE];
	struct nova_mm_entry_p entry_p[NOVA_TABLE_LEAF_SIZE];
};
_Static_assert((1 << INDICATOR_BIT_NUM) == NOVA_TABLE_LEAF_SIZE, "(1 << INDICATOR_BIT_NUM) != NOVA_TABLE_LEAF_SIZE!");

struct nova_inner {
	struct {
		uint16_t bits: 4;	// At most 9. Only inners need it. Need recalculate when recovering.
		uint16_t merged: 9;	// At most 256.	If merged == 1 << (bits - 1), then shrink, and --bits.
	};
	unsigned long node_p[0];	// If (node_p[i] & 1) != 0, then it is an inner node, else it is a bucket.
};
// If we set .align argument to 2, then the size of the inner_cache2 will be doubled. WHY???
// #define NOVA_INNER_ALIGN 2
#define NOVA_INNER_ALIGN 0

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
	return (void *)node_p;
}

static inline struct nova_inner *
nova_node_p_to_inner(unsigned long node_p)
{
	return (void *)(node_p - 1);
}

static inline unsigned long
nova_bucket_to_node_p(struct nova_bucket *bucket) {
	return (unsigned long)bucket;
}

static inline unsigned long
nova_inner_to_node_p(struct nova_inner *inner) {
	return (unsigned long)inner | 1;
}

struct nova_mm_tablet {
	struct mutex           mtx;
	unsigned long   node_p;
} ____cacheline_aligned_in_smp;

struct nova_mm_table {
	struct super_block    *sblock;
	struct kmem_cache *inner_cache[3], *bucket_cache;
	struct entry_allocator entry_allocator;
	struct nova_pmm_entry *pentries;
	uint64_t               nr_tablets;
	struct nova_mm_tablet  tablets[0];
};

static inline bool nova_fp_strong_equal(
	const struct nova_fp* left, 
	const struct nova_fp* right) 
{
	return left->value == right->value;
}

extern int nova_table_save(struct nova_mm_table* table);

struct nova_write_para_base {
	struct nova_fp fp;
	long refcount;
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

int nova_table_upsert_normal(struct nova_mm_table *table, struct nova_write_para_normal *wp);
int nova_table_upsert_rewrite(struct nova_mm_table *table, struct nova_write_para_rewrite *wp);
// refcount-- only if refcount == 1
int nova_table_upsert_decr1(struct nova_mm_table *table, struct nova_write_para_normal *wp);

struct nova_mm_table *nova_table_init(struct super_block *sb);
struct nova_mm_table *nova_table_recover(struct super_block *sb);

#endif
