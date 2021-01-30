#include "nova.h"
#include "meta.h"
#include "config.h"

static int meta_table_alloc(struct nova_meta_table *table, struct super_block *sb)
{
	table->sblock = sb;
	table->kbuf_cache = kmem_cache_create_usercopy(
		"nova_kbuf_cache", PAGE_SIZE, 8, TABLE_KMEM_CACHE_FLAGS, 0, PAGE_SIZE, NULL);
	if (table->kbuf_cache == NULL)
		return -ENOMEM;
	return 0;
}
int nova_meta_table_init(struct nova_meta_table *table, struct super_block* sb)
{
	int ret;
	ret = meta_table_alloc(table, sb);
	if (ret < 0)
		return ret;
	table->metas = nova_table_init(sb);
	if (IS_ERR(table->metas)) {
		kmem_cache_destroy(table->kbuf_cache);
		return PTR_ERR(table->metas);
	}
	return 0;
}
int nova_meta_table_restore(struct nova_meta_table *table, struct super_block *sb)
{
	int ret;
	ret = meta_table_alloc(table, sb);
	if (ret < 0)
		return ret;
	table->metas = nova_table_recover(sb);
	if (IS_ERR(table->metas)) {
		kmem_cache_destroy(table->kbuf_cache);
		return PTR_ERR(table->metas);
	}
	return 0;
}

static void init_normal_wp_incr(struct nova_sb_info *sbi,
	struct nova_write_para_normal *wp, const void *addr)
{
	BUG_ON(nova_fp_calc(&sbi->fp_ctx, addr, &wp->base.fp));
	wp->addr = addr;
	wp->base.refcount = 1;
}
int nova_meta_table_incr(struct nova_meta_table *table, const void* addr,
	struct nova_write_para_normal *wp)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	INIT_TIMING(incr_ref_time);

	init_normal_wp_incr(sbi, wp, addr);
	NOVA_START_TIMING(incr_ref_t, incr_ref_time);
	ret = nova_table_upsert_normal(table->metas, wp);
	NOVA_END_TIMING(incr_ref_t, incr_ref_time);
	return ret;
}
int nova_meta_table_rewrite_on_insert(struct nova_meta_table *table,
	const void *addr, struct nova_write_para_rewrite *wp,
	unsigned long blocknr, size_t offset, size_t bytes)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	INIT_TIMING(incr_ref_time);

	init_normal_wp_incr(sbi, &wp->normal, addr);
	wp->normal.blocknr = blocknr;
	wp->offset = offset;
	wp->len = bytes;
	NOVA_START_TIMING(incr_ref_t, incr_ref_time);
	ret = nova_table_upsert_rewrite(table->metas, wp);
	NOVA_END_TIMING(incr_ref_t, incr_ref_time);
	return ret;
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
	retval = nova_table_upsert_normal(table->metas, &wp);
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
	retval = nova_table_upsert_decr1(table->metas, &wp);
	NOVA_END_TIMING(decr_ref_t, decr_ref_time);
	return retval < 0 ? retval : wp.base.refcount;
}
