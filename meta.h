
#ifndef __NOVA_META_H
#define __NOVA_META_H

#include "arithmetic.h"
#include "nova_def.h"
#include "table.h"
#include "generic_cache.h"

struct nova_meta_table {
    struct super_block   		*sblock;
	struct generic_cache kbuf_cache;
	struct nova_fp_strong_ctx fp_ctx;

    struct nova_mm_table      metas;
	struct entry_allocator entry_allocator;
	atomic64_t thread_num;
};

int nova_meta_table_alloc(struct nova_meta_table *table, struct super_block *sb,
	size_t nelem_hint);
void nova_meta_table_free(struct nova_meta_table *table);
int nova_meta_table_init(struct nova_meta_table *table, struct super_block* sblock);
int nova_meta_table_restore(struct nova_meta_table *table, struct super_block *sb);
void nova_meta_table_save(struct nova_meta_table *table);

void nova_meta_table_decr(struct nova_meta_table *table, unsigned long blocknr);
long nova_meta_table_decr1(struct nova_meta_table *table, const void *addr, unsigned long blocknr);

// extern long nova_meta_table_find_weak(struct nova_meta_table *table, struct nova_meta_entry *entry, const struct nova_fp_mem *fp, const void* addr);

#endif