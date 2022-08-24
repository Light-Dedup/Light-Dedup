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
	table->kbuf_cache = kmem_cache_create_usercopy(
		"nova_kbuf_cache", PAGE_SIZE, 8, TABLE_KMEM_CACHE_FLAGS, 0, PAGE_SIZE, NULL);
	if (table->kbuf_cache == NULL) {
		ret = -ENOMEM;
		goto err_out1;
	}
	atomic64_set(&table->thread_num, 0);
	ret = nova_table_init(sb, &table->metas, nelem_hint);
	if (ret < 0)
		goto err_out2;
	return 0;
err_out2:
	kmem_cache_destroy(table->kbuf_cache);
err_out1:
	nova_fp_strong_ctx_free(&table->fp_ctx);
err_out0:
	return ret;
}
void nova_meta_table_free(struct nova_meta_table *table)
{
	nova_fp_strong_ctx_free(&table->fp_ctx);
	kmem_cache_destroy(table->kbuf_cache);
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
	nova_meta_table_decrers_init(sb);
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
	/* sync rcu to make sure all the rcu recycles are done */
	nova_meta_table_decrers_destroy(sb);
	synchronize_rcu();
	table->sblock = NULL;
	nova_fp_strong_ctx_free(&table->fp_ctx);
	kmem_cache_destroy(table->kbuf_cache);
	nova_table_save(&table->metas);
	nova_save_entry_allocator(sb, &table->entry_allocator);
	nova_unlock_write_flush(sbi, &recover_meta->saved,
		NOVA_RECOVER_META_FLAG_COMPLETE, true);
}

long nova_meta_table_decr_refcount(struct nova_meta_table *table,
	const void *addr, unsigned long blocknr)
{
	struct nova_write_para_normal wp;
	int    retval;
	INIT_TIMING(decr_ref_time);

	BUG_ON(blocknr == 0);
	BUG_ON(nova_fp_calc(&table->fp_ctx, addr, &wp.base.fp));

	wp.addr = addr;
	wp.blocknr = blocknr;
	NOVA_START_TIMING(decr_ref_t, decr_ref_time);
	retval = nova_table_deref_block(&table->metas, &wp);
	NOVA_END_TIMING(decr_ref_t, decr_ref_time);
	return retval < 0 ? retval : wp.base.refcount;
}

DEFINE_PER_CPU(struct nova_meta_table_decrer_per_cpu, meta_table_decrer_per_cpu);

static void wakeup_table_decrer(struct nova_meta_table *table, int cpu)
{
	wait_queue_head_t *waitq = &table->decrer_waitqs[cpu];

	if (!waitqueue_active(waitq))
		return;
	
	// nova_dbg("Wakeup meta table {dec-ref}er thread\n");
	wake_up_interruptible(waitq);
}

static void table_decrer_try_sleeping(struct nova_meta_table *table, int cpu)
{
	wait_queue_head_t *waitq = &table->decrer_waitqs[cpu];
	DEFINE_WAIT(wait);
	
	prepare_to_wait(waitq, &wait, TASK_INTERRUPTIBLE);
	schedule();
	finish_wait(waitq, &wait);
}

/* return errorno or number of decref has processed */
static int table_decrer_execute_cpu(int cpu) {
	int ret;
	int i;
	struct nova_meta_table_decrer_per_cpu *decrer_cpu;
	struct nova_meta_table_decr_param params[MAX_DECRER_DQ_SIZE];
	struct nova_meta_table_decr_param *param;

	decrer_cpu = &per_cpu(meta_table_decrer_per_cpu, cpu);
	ret = kfifo_out(&decrer_cpu->workqueue, params, 
				    MAX_DECRER_DQ_SIZE);
	if (ret < 0) {
		nova_dbg("%s: kfifo_out failed %d", __func__, ret);
		goto out;	
	}

	for (i = 0; i < ret; i++) {
		param = &params[i];
		nova_meta_table_decr(param->table, param->blocknr);
	}

out:
	return ret;
}
struct table_decrer_param {
	int cpu;
	struct super_block *sb;
};

static int table_decrer_thread(void *arg)
{
	struct table_decrer_param *param = arg;
	struct super_block *sb = param->sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_meta_table *table = &sbi->meta_table;
	int cpu = param->cpu;
	

	nova_dbg("Running {decr}er thread %d\n", cpu);
	for (;;) {
		table_decrer_try_sleeping(table, cpu);

		if (kthread_should_stop())
			break;

		table_decrer_execute_cpu(cpu);
	}
	nova_dbg("{Decr}er thread %d exit\n", cpu);
	kfree(param);

	return 0;
}

int nova_meta_table_decrers_init(struct super_block* sb) {
	int ret = 0, i;
	int cpu;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_meta_table *table = &sbi->meta_table;
	struct nova_meta_table_decrer_per_cpu *decrer_cpu;
	struct table_decrer_param *param;

	table->decrer_threads = kmalloc(sizeof(struct task_struct *) * sbi->cpus, GFP_KERNEL);
	if (!table->decrer_threads) {
		ret = -ENOMEM;
		goto err_out0;
	}

	table->decrer_waitqs = kmalloc(sizeof(wait_queue_head_t) * sbi->cpus, GFP_KERNEL);
	if (!table->decrer_waitqs) {
		ret = -ENOMEM;
		goto err_out1;
	}

	for (i = 0; i < sbi->cpus; i++) {
		init_waitqueue_head(&table->decrer_waitqs[i]);
	}
	
	for_each_possible_cpu(cpu) {
		decrer_cpu = &per_cpu(meta_table_decrer_per_cpu, cpu);
		spin_lock_init(&decrer_cpu->wqlock);
		INIT_KFIFO(decrer_cpu->workqueue);
		param = kmalloc(sizeof(struct table_decrer_param), GFP_KERNEL);
		if (!param) {
			ret = -ENOMEM;
			goto err_out2;
		}
		param->cpu = cpu;
		param->sb = sb;

		/* bind thread to specific cpu */
		table->decrer_threads[cpu] = kthread_create(table_decrer_thread, 
													param,  
													"table_decrer_thread_%d", 
													cpu);
		if (!table->decrer_threads[cpu]) {
			nova_err(sb, "Can't create decrer_threads");
			BUG_ON(1);
		}
		kthread_bind(table->decrer_threads[cpu], cpu);

		wake_up_process(table->decrer_threads[cpu]);
	}

	return ret;

err_out2:
	kfree(table->decrer_waitqs);
	table->decrer_waitqs = NULL;
err_out1:
	kfree(table->decrer_threads);
	table->decrer_threads = NULL;
err_out0:
	return ret;
}

int nova_meta_table_decrers_destroy(struct super_block* sb) {
	int cpu;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_meta_table *table = &sbi->meta_table;
	struct nova_meta_table_decrer_per_cpu *decrer_cpu;

	nova_info("Destroy Decrers");
	for_each_possible_cpu(cpu) {
		decrer_cpu = &per_cpu(meta_table_decrer_per_cpu, cpu);
		if (table->decrer_threads[cpu])
			kthread_stop(table->decrer_threads[cpu]);
		nova_info("Commit %d decr job in for id: %d", kfifo_len(&decrer_cpu->workqueue), cpu);
		while (kfifo_len(&decrer_cpu->workqueue) != 0) {
			table_decrer_execute_cpu(cpu);
		}
	}

	if (table->decrer_threads)
		kfree(table->decrer_threads);
	if (table->decrer_waitqs)
		kfree(table->decrer_waitqs);
	return 0;
}

/* return the decrer id */
long nova_meta_table_decr_async(struct nova_meta_table *table, unsigned long blocknr) 
{
	int cpu;
	struct nova_meta_table_decr_param param;
	struct nova_meta_table_decrer_per_cpu *decrer_cpu;
	int ret = 0, tries = 0;
	int fifo_len = 0;
	INIT_TIMING(request_decr_time);
	NOVA_START_TIMING(table_decr_async_t, request_decr_time);
	/* do not need disable preempt */
	cpu = nova_get_cpuid(table->sblock);
	decrer_cpu = &per_cpu(meta_table_decrer_per_cpu, cpu);
	param.table = table;
	param.blocknr = blocknr;

try:
	ret = kfifo_in_spinlocked(&decrer_cpu->workqueue, 
							  &param, 
							  1, 
							  &decrer_cpu->wqlock);
	if (unlikely(ret == 0)) {
		wakeup_table_decrer(table, cpu);
		tries++;
		schedule();
		goto try;
	}

	/* we do not need lock here */
	fifo_len = kfifo_len(&decrer_cpu->workqueue);
	if (fifo_len != 0 && fifo_len % MAX_DECRER_DQ_SIZE == 0);
		wakeup_table_decrer(table, cpu);
	NOVA_END_TIMING(table_decr_async_t, request_decr_time);
	return cpu;
}

long nova_meta_table_decr(struct nova_meta_table *table, unsigned long blocknr) 
{
	struct super_block *sb = table->sblock;
	long    retval;

	retval = nova_meta_table_decr_refcount(table, nova_blocknr_to_addr(sb, blocknr), blocknr);
	if (retval < 0)
		BUG_ON(retval != -EIO);
	return retval;
}

long nova_meta_table_decr1(struct nova_meta_table *table, const void *addr, unsigned long blocknr)
{
	struct nova_write_para_normal wp;
	int    retval;
	INIT_TIMING(decr_ref_time);

	BUG_ON(blocknr == 0);
	BUG_ON(nova_fp_calc(&table->fp_ctx, addr, &wp.base.fp));

	wp.addr = addr;
	wp.blocknr = blocknr;
	NOVA_START_TIMING(decr_ref_t, decr_ref_time);
	retval = nova_table_upsert_decr1(&table->metas, &wp);
	NOVA_END_TIMING(decr_ref_t, decr_ref_time);
	return retval < 0 ? retval : wp.base.refcount;
}
