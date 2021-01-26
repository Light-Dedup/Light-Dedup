#include "nova.h"
#include "meta.h"
#include "config.h"

int nova_meta_table_init(struct nova_meta_table *table, struct super_block* sblock)
{
	int retval;
	table->kbuf_cache = kmem_cache_create_usercopy("nova_kbuf_cache", PAGE_SIZE, 8, TABLE_KMEM_CACHE_FLAGS, 0, PAGE_SIZE, NULL);
	if (table->kbuf_cache == NULL) {
		retval = -ENOMEM;
		goto err_out;
	}
	table->metas = nova_table_alloc(sblock);
	if (IS_ERR(table->metas)) {
		retval = PTR_ERR(table->metas);
		goto err_out;
	}
	table->sblock = sblock;
	return 0;
err_out:
	if (table->kbuf_cache)
		kmem_cache_destroy(table->kbuf_cache);
	return retval;
}

int nova_meta_table_incr(struct nova_meta_table *table, const void* addr,
	struct nova_write_para *wp)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	INIT_TIMING(incr_ref_time);

	BUG_ON(nova_fp_calc(&sbi->fp_ctx, addr, &wp->fp));
	wp->addr = addr;
	wp->delta = 1;
	NOVA_START_TIMING(incr_ref_t, incr_ref_time);
	ret = nova_table_upsert(table->metas, wp);
	NOVA_END_TIMING(incr_ref_t, incr_ref_time);
	return ret;
}

long nova_meta_table_decr_refcount(struct nova_meta_table *table,
	const void *addr, unsigned long blocknr)
{
	struct super_block *sb = table->sblock;
	struct nova_write_para wp;
	int    retval;
	INIT_TIMING(decr_ref_time);

	BUG_ON(blocknr == 0);
	BUG_ON(nova_fp_calc(&NOVA_SB(sb)->fp_ctx, addr, &wp.fp));

	wp.addr = addr;
	wp.delta = -1;
	wp.blocknr = blocknr;
	NOVA_START_TIMING(decr_ref_t, decr_ref_time);
	retval = nova_table_upsert(table->metas, &wp);
	NOVA_END_TIMING(decr_ref_t, decr_ref_time);
	return retval < 0 ? retval : wp.refcount;
}

long nova_meta_table_decr(struct nova_meta_table *table, unsigned long blocknr) 
{
	struct super_block *sb = table->sblock;
	long    retval;

	retval = nova_meta_table_decr_refcount(table, nova_blocknr_to_addr(sb, blocknr), blocknr);
	if (retval == 0)
		nova_free_data_block(sb, blocknr);
	if (retval < 0)
		BUG_ON(retval != -EIO);
	return retval;
}
