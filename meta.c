#include "nova.h"
#include "meta.h"
#include "config.h"

int nova_meta_table_alloc(struct nova_meta_table *table, struct super_block *sb,
	size_t nelem_hint)
{
	int ret;
	table->sblock = sb;
	ret = nova_fp_strong_ctx_init(&table->fp_ctx);
	if (ret < 0)
		goto err_out0;
	atomic64_set(&table->thread_num, 0);
	ret = nova_table_init(sb, &table->metas, nelem_hint);
	if (ret < 0)
		goto err_out1;
	return 0;
err_out1:
	nova_fp_strong_ctx_free(&table->fp_ctx);
err_out0:
	return ret;
}
void nova_meta_table_free(struct nova_meta_table *table)
{
	nova_fp_strong_ctx_free(&table->fp_ctx);
	nova_table_free(&table->metas);
}
int nova_meta_table_init(struct nova_meta_table *table, struct super_block* sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	ret = nova_meta_table_alloc(table, sb, 0);
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
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	int ret;
	INIT_TIMING(normal_recover_fp_table_time);

	ret = nova_meta_table_alloc(table, sb,
		le64_to_cpu(recover_meta->refcount_record_num));
	if (ret < 0)
		goto err_out0;
	ret = nova_entry_allocator_recover(sbi, &table->entry_allocator);
	if (ret < 0)
		goto err_out1;
	NOVA_START_TIMING(normal_recover_fp_table_t, normal_recover_fp_table_time);
	ret = nova_table_recover(&table->metas);
	NOVA_END_TIMING(normal_recover_fp_table_t, normal_recover_fp_table_time);
	if (ret < 0)
		goto err_out2;
	return 0;
err_out2:
	nova_free_entry_allocator(&table->entry_allocator);
err_out1:
	nova_meta_table_free(table);
err_out0:
	return ret;
}
void nova_meta_table_save(struct nova_meta_table *table)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	table->sblock = NULL;
	nova_fp_strong_ctx_free(&table->fp_ctx);
	nova_table_save(&table->metas);
	nova_save_entry_allocator(sb, &table->entry_allocator);
	nova_unlock_write_flush(sbi, &recover_meta->saved,
		NOVA_RECOVER_META_FLAG_COMPLETE, true);
}

long nova_meta_table_decr(struct nova_meta_table *table, unsigned long blocknr) 
{
	struct super_block *sb = table->sblock;
	const void *addr = nova_blocknr_to_addr(sb, blocknr);
	size_t i;
	struct nova_write_para_normal wp;
	long    retval;
	INIT_TIMING(decr_ref_time);

	BUG_ON(blocknr == 0);
	for (i = 0; i < 64; ++i)
		prefetcht0(addr + i * 64);
	BUG_ON(nova_fp_calc(&table->fp_ctx, addr, &wp.base.fp));

	wp.addr = addr;
	wp.blocknr = blocknr;
	NOVA_START_TIMING(decr_ref_t, decr_ref_time);
	retval = nova_table_deref_block(&table->metas, &wp);
	NOVA_END_TIMING(decr_ref_t, decr_ref_time);
	if (retval < 0) {
		BUG_ON(retval != -EIO);
		return retval;
	} else {
		BUG_ON(retval != 0);
		return wp.base.refcount;
	}
}

long nova_meta_table_decr1(struct nova_meta_table *table, const void *addr, unsigned long blocknr)
{
	struct nova_write_para_normal wp;
	int    retval;
	INIT_TIMING(decr_ref_time);

	BUG_ON(blocknr == 0);
	retval = nova_fp_calc(&table->fp_ctx, addr, &wp.base.fp);
	if (retval < 0)
		return retval;

	wp.addr = addr;
	wp.blocknr = blocknr;
	NOVA_START_TIMING(decr_ref_t, decr_ref_time);
	retval = nova_table_upsert_decr1(&table->metas, &wp);
	NOVA_END_TIMING(decr_ref_t, decr_ref_time);
	return retval < 0 ? retval : wp.base.refcount;
}
