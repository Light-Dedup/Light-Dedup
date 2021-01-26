
#ifndef __NOVA_META_H
#define __NOVA_META_H

#include "nova_def.h"
#include "table.h"

struct nova_meta_table {
    struct nova_mm_table      *metas;
    struct super_block   		*sblock;
	struct kmem_cache *kbuf_cache;
};

int nova_meta_table_init(struct nova_meta_table *table, struct super_block* sblock);

static inline void nova_meta_table_destroy(struct nova_meta_table *table)
{
	kmem_cache_destroy(table->kbuf_cache);
	nova_table_free(table->metas);
	table->sblock = NULL;
}

int nova_meta_table_incr(struct nova_meta_table *table, const void* addr,
	struct nova_write_para *wp);
long nova_meta_table_decr_refcount(struct nova_meta_table *table,
	const void *addr, unsigned long blocknr);
extern long nova_meta_table_decr(struct nova_meta_table *table, unsigned long blocknr);

// extern long nova_meta_table_find_weak(struct nova_meta_table *table, struct nova_meta_entry *entry, const struct nova_fp_mem *fp, const void* addr);

#endif