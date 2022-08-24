
#ifndef __NOVA_META_H
#define __NOVA_META_H

#include "nova_def.h"
#include "table.h"
#include "linux/kfifo.h"

struct nova_meta_table {
    struct super_block   		*sblock;
	struct kmem_cache *kbuf_cache;
	struct nova_fp_strong_ctx fp_ctx;

    struct nova_mm_table      metas;
	struct entry_allocator entry_allocator;
	atomic64_t thread_num;
	struct task_struct **decrer_threads;
	wait_queue_head_t *decrer_waitqs;
};

#define MAX_DECRER_WQ_SIZE		32
#define MAX_DECRER_DQ_SIZE		8

struct nova_meta_table_decr_param {
	struct nova_meta_table *table; 
	unsigned long blocknr;
};

struct nova_meta_table_decrer_per_cpu {
	spinlock_t wqlock;
	DECLARE_KFIFO(workqueue, struct nova_meta_table_decr_param, 
				  MAX_DECRER_WQ_SIZE);
};
DECLARE_PER_CPU(struct nova_meta_table_decrer_per_cpu, nova_meta_table_decrer_per_cpu);

int nova_meta_table_decrers_init(struct super_block* sb);
int nova_meta_table_decrers_destroy(struct super_block* sb);
int nova_meta_table_alloc(struct nova_meta_table *table, struct super_block *sb,
	size_t nelem_hint);
void nova_meta_table_free(struct nova_meta_table *table);
int nova_meta_table_init(struct nova_meta_table *table, struct super_block* sblock);
int nova_meta_table_restore(struct nova_meta_table *table, struct super_block *sb);
void nova_meta_table_save(struct nova_meta_table *table);

long nova_meta_table_decr_refcount(struct nova_meta_table *table,
	const void *addr, unsigned long blocknr);
extern long nova_meta_table_decr(struct nova_meta_table *table, unsigned long blocknr);
extern long nova_meta_table_decr_async(struct nova_meta_table *table, unsigned long blocknr);
long nova_meta_table_decr1(struct nova_meta_table *table, const void *addr, unsigned long blocknr);
// extern long nova_meta_table_find_weak(struct nova_meta_table *table, struct nova_meta_entry *entry, const struct nova_fp_mem *fp, const void* addr);

#endif