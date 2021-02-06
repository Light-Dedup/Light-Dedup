#include "nova.h"
#include "meta.h"
#include "config.h"

int nova_meta_table_alloc(struct nova_meta_table *table, struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	table->sblock = sb;
	table->pentries = nova_sbi_blocknr_to_addr(sbi, sbi->entry_table_start);
	table->kbuf_cache = kmem_cache_create_usercopy(
		"nova_kbuf_cache", PAGE_SIZE, 8, TABLE_KMEM_CACHE_FLAGS, 0, PAGE_SIZE, NULL);
	if (table->kbuf_cache == NULL)
		return -ENOMEM;
	ret = nova_table_init(sb, &table->metas);
	if (ret < 0) {
		kmem_cache_destroy(table->kbuf_cache);
		return ret;
	}
	return 0;
}
void nova_meta_table_free(struct nova_meta_table *table)
{
	kmem_cache_destroy(table->kbuf_cache);
	nova_table_free(&table->metas);
}
int nova_meta_table_init(struct nova_meta_table *table, struct super_block* sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	ret = nova_meta_table_alloc(table, sb);
	if (ret < 0)
		return ret;
	ret = nova_init_entry_allocator(sbi, &table->entry_allocator);
	if (ret < 0) {
		nova_meta_table_free(table);
		return ret;
	}
	return 0;
}
int nova_meta_table_restore(struct nova_meta_table *table, struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	INIT_TIMING(normal_recover_fp_table_time);

	ret = nova_meta_table_alloc(table, sb);
	if (ret < 0)
		goto err_out0;
	NOVA_START_TIMING(normal_recover_fp_table_t, normal_recover_fp_table_time);
	ret = nova_table_recover(&table->metas);
	NOVA_END_TIMING(normal_recover_fp_table_t, normal_recover_fp_table_time);
	if (ret < 0)
		goto err_out1;
	ret = nova_entry_allocator_recover(sbi, &table->entry_allocator);
	if (ret < 0)
		goto err_out1;
	return 0;
err_out1:
	nova_meta_table_free(table);
err_out0:
	return ret;
}
void nova_meta_table_save(struct nova_meta_table *table)
{
	struct super_block *sb = table->sblock;
	table->sblock = NULL;
	kmem_cache_destroy(table->kbuf_cache);
	nova_table_save(&table->metas);
	nova_save_entry_allocator(sb, &table->entry_allocator);
}

long nova_meta_table_decr_refcount(struct nova_meta_table *table,
	const void *addr, unsigned long blocknr)
{
	struct super_block *sb = table->sblock;
	struct nova_write_para_normal wp;
	int    retval;
	INIT_TIMING(decr_ref_time);

	BUG_ON(blocknr == 0);
	BUG_ON(nova_fp_calc(&NOVA_SB(sb)->fp_ctx, addr, &wp.base.fp));

	wp.addr = addr;
	wp.base.refcount = -1;
	wp.blocknr = blocknr;
	NOVA_START_TIMING(decr_ref_t, decr_ref_time);
	retval = nova_table_upsert_normal(&table->metas, &wp);
	NOVA_END_TIMING(decr_ref_t, decr_ref_time);
	return retval < 0 ? retval : wp.base.refcount;
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

long nova_meta_table_decr1(struct nova_meta_table *table, const void *addr, unsigned long blocknr)
{
	struct super_block *sb = table->sblock;
	struct nova_write_para_normal wp;
	int    retval;
	INIT_TIMING(decr_ref_time);

	BUG_ON(blocknr == 0);
	BUG_ON(nova_fp_calc(&NOVA_SB(sb)->fp_ctx, addr, &wp.base.fp));

	wp.addr = addr;
	wp.blocknr = blocknr;
	NOVA_START_TIMING(decr_ref_t, decr_ref_time);
	retval = nova_table_upsert_decr1(&table->metas, &wp);
	NOVA_END_TIMING(decr_ref_t, decr_ref_time);
	return retval < 0 ? retval : wp.base.refcount;
}
