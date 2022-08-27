
#ifndef __NOVA_META_H
#define __NOVA_META_H

#include "nova_def.h"
#include "table.h"
#include "linux/kfifo.h"

struct table_decr_item {
	unsigned long blocknr;
};

#define DECR_ITEM_SIZE					(sizeof(struct table_decr_item))
#define MAX_DECRER						8		/* consumers */
#define MAX_DECRER_LWB_NUM				32
#define MAX_DECRER_LWB_SIZE				(MAX_DECRER_LWB_NUM * DECR_ITEM_SIZE)	/* local write buffer */
#define MAX_DECRER_GWQ_SIZE(sbi)		(sbi->cpus * MAX_DECRER_LWB_SIZE) /* global write queue */ 
#define MAX_DECRER_PROCESS_BATCH		32
#define MAX_DECRER_PROCESS_BSIZE 		(MAX_DECRER_PROCESS_BATCH * DECR_ITEM_SIZE) 		/* process batch size */
#define WAKE_UP_THRESHOLD(sbi)			(MAX_DECRER_GWQ_SIZE(sbi) / 4)	/* wake up threshold */


struct nova_meta_table {
    struct super_block   		*sblock;
	struct kmem_cache *kbuf_cache;
	struct nova_fp_strong_ctx fp_ctx;

    struct nova_mm_table      metas;
	struct entry_allocator entry_allocator;
	atomic64_t thread_num;
	spinlock_t gwq_lock;
	struct kfifo global_wq;
	spinlock_t gwq_lock_nvm;
	struct kfifo global_wq_nvm;
	struct task_struct **decrer_threads;
	wait_queue_head_t *decrer_waitqs;
};

struct table_decrer_local_wb_per_cpu {
	struct table_decr_item items[MAX_DECRER_LWB_NUM];
	int capacity;
};
DECLARE_PER_CPU(struct table_decrer_local_wb_per_cpu, table_decrer_local_wb_per_cpu);

int nova_meta_table_decrers_init(struct super_block* sb, bool recovery);
int nova_meta_table_decrers_destroy(struct super_block* sb);
int nova_meta_table_alloc(struct nova_meta_table *table, struct super_block *sb,
	size_t nelem_hint);
void nova_meta_table_free(struct nova_meta_table *table);
int nova_meta_table_init(struct nova_meta_table *table, struct super_block* sblock);
int nova_meta_table_restore(struct nova_meta_table *table, struct super_block *sb);
void nova_meta_table_save(struct nova_meta_table *table);

extern long nova_meta_table_decr(struct nova_meta_table *table, unsigned long blocknr);
extern long nova_meta_table_decr_try_async(struct nova_meta_table *table, unsigned long blocknr);
long nova_meta_table_decr1(struct nova_meta_table *table, const void *addr, unsigned long blocknr);
// extern long nova_meta_table_find_weak(struct nova_meta_table *table, struct nova_meta_entry *entry, const struct nova_fp_mem *fp, const void* addr);

#endif