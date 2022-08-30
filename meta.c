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
	nova_meta_table_decrers_init(sb, false);
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
	/* rcu_barrier_tasks to make sure all the rht recycles are done */
	nova_meta_table_decrers_destroy(sb);
	rcu_barrier();
	table->sblock = NULL;
	nova_fp_strong_ctx_free(&table->fp_ctx);
	kmem_cache_destroy(table->kbuf_cache);
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

DEFINE_PER_CPU(struct table_decrer_local_wb_per_cpu, table_decrer_local_wb_per_cpu);

static void wakeup_table_decrer(struct nova_meta_table *table, int id)
{
	wait_queue_head_t *waitq = &table->decrer_waitqs[id];

	if (!waitqueue_active(waitq))
		return;
	
	// nova_dbg("Wakeup meta table {dec-ref}er thread\n");
	wake_up_interruptible(waitq);
}

static void wakeup_table_decrers(struct nova_meta_table *table) {
	int i;
	for (i = 0; i < MAX_DECRER; i++)
		wakeup_table_decrer(table, i);
}

static void table_decrer_try_sleeping(struct nova_meta_table *table, int id)
{
	wait_queue_head_t *waitq = &table->decrer_waitqs[id];
	DEFINE_WAIT(wait);
	
	prepare_to_wait(waitq, &wait, TASK_INTERRUPTIBLE);
	schedule();
	finish_wait(waitq, &wait);
}

/* return errorno or number of decref has processed */
static int table_decrer_execute_global(struct nova_meta_table *table, bool nvm) {
	int ret, i;
	struct table_decr_item items[MAX_DECRER_PROCESS_BATCH];
	struct table_decr_item *item;
	int out_num;

	if (nvm) {
		ret = kfifo_out_spinlocked(&table->global_wq_nvm, 
								   items, 
								   MAX_DECRER_PROCESS_BSIZE, 
								   &table->gwq_lock_nvm);
	}
	else {
		ret = kfifo_out_spinlocked(&table->global_wq, 
								   items, 
								   MAX_DECRER_PROCESS_BSIZE, 
								   &table->gwq_lock);
	}
	if (ret < 0) {
		nova_dbg("%s: kfifo_out_spinlocked failed %d", __func__, ret);
		goto out;	
	}

	out_num = ret / DECR_ITEM_SIZE;

	for (i = 0; i < out_num; i++) {
		item = &items[i];
		// if (nvm) {
		// 	nova_dbg("%s: retrieve from nvm %ld", __func__, item->blocknr);		
		// }
		nova_meta_table_decr(table, item->blocknr);
	}

out:
	return ret;
}

struct table_decrer_param {
	int id;
	struct super_block *sb;
};

static int table_decrer_thread(void *arg)
{
	struct table_decrer_param *param = arg;
	struct super_block *sb = param->sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_meta_table *table = &sbi->meta_table;
	int id = param->id;

	nova_dbg("Running {decr}er thread %d\n", id);
	for (;;) {
		table_decrer_try_sleeping(table, id);

		if (kthread_should_stop())
			break;

		table_decrer_execute_global(table, false);

		/* digest NVM write queue when dram write queue is empty */
		if (kfifo_len(&table->global_wq) == 0) 
			table_decrer_execute_global(table, true);
	}
	nova_dbg("{Decr}er thread %d exit\n", id);
	kfree(param);

	return 0;
}

int nova_meta_table_decrers_init(struct super_block* sb, bool recovery) {
	int ret = 0, i;
	int cpu;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_meta_table *table = &sbi->meta_table;
	struct table_decrer_local_wb_per_cpu *decrer_lwb_cpu;
	struct table_decrer_param *param;
	
	/* init global structures, in-dram and in-nvm queue: gwq and gwq_nvm */
	spin_lock_init(&table->gwq_lock);
	ret = kfifo_alloc(&table->global_wq, 
					  MAX_DECRER_GWQ_SIZE(sbi), 
					  GFP_KERNEL);
	if (ret) {
		goto err_out0;
	}
	
	spin_lock_init(&table->gwq_lock_nvm);
	if (recovery) {	
		/* restore nvm write queue state */
		memcpy(&table->global_wq_nvm, 
			   nova_sbi_blocknr_to_addr(sbi, sbi->global_wq_head_start),
			   sizeof(struct kfifo));
		table->global_wq_nvm.kfifo.data = nova_sbi_blocknr_to_addr(sbi, sbi->global_wq_nvm_start);
		nova_info("Recovery %ld decr job in global nvm buffer", kfifo_len(&table->global_wq_nvm) / DECR_ITEM_SIZE);
	}
	else {	
		/* init */
		ret = kfifo_init(&table->global_wq_nvm, 
						 nova_sbi_blocknr_to_addr(sbi, sbi->global_wq_nvm_start), 
						 sbi->global_wq_nvm_size);
	}
	if (ret) {
		goto err_out0;
	}

	table->decrer_threads = kmalloc(sizeof(struct task_struct *) * MAX_DECRER, GFP_KERNEL);
	if (!table->decrer_threads) {
		ret = -ENOMEM;
		goto err_out0;
	}

	table->decrer_waitqs = kmalloc(sizeof(wait_queue_head_t) * MAX_DECRER, GFP_KERNEL);
	if (!table->decrer_waitqs) {
		ret = -ENOMEM;
		goto err_out1;
	}

	for (i = 0; i < MAX_DECRER; i++) {
		init_waitqueue_head(&table->decrer_waitqs[i]);
	}
	
	/* init consumers */
	for (i = 0; i < MAX_DECRER; i++) {
		param = kmalloc(sizeof(struct table_decrer_param), GFP_KERNEL);
		if (!param) {
			ret = -ENOMEM;
			goto err_out2;
		}
		param->id = i;
		param->sb = sb;

		table->decrer_threads[i] = kthread_create(table_decrer_thread, 
												  param,  
												  "table_decrer_thread_%d", 
												  i);
		if (!table->decrer_threads[i]) {
			nova_err(sb, "Can't create decrer_threads");
			BUG_ON(1);
		}

		/* NOTE: do not bind this */
		/* bind thread to specific cpu */
		// kthread_bind(table->decrer_threads[cpu], cpu);

		wake_up_process(table->decrer_threads[i]);
	}

	/* init local structures */
	for_each_possible_cpu(cpu) {
		decrer_lwb_cpu = &per_cpu(table_decrer_local_wb_per_cpu, cpu);
		decrer_lwb_cpu->capacity = 0;
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
	int i, cpu;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_meta_table *table = &sbi->meta_table;
	struct table_decrer_local_wb_per_cpu *decrer_lwb_cpu;
	struct table_decr_item *item;
	unsigned long flags = 0;

	nova_info("Destroy Decrers");
	for (i = 0; i < MAX_DECRER; i++) {
		if (table->decrer_threads[i]) {
			kthread_stop(table->decrer_threads[i]);
		}
	}

	/* flush local write queue */
	for_each_possible_cpu(cpu) {
		decrer_lwb_cpu = &per_cpu(table_decrer_local_wb_per_cpu, cpu);
		nova_info("Commit %d decr job in local buffer %d", decrer_lwb_cpu->capacity, cpu);
		for (i = 0; i < decrer_lwb_cpu->capacity; i++) {
			item = &decrer_lwb_cpu->items[i];
			nova_meta_table_decr(table, item->blocknr);
		}
	}
	
	nova_info("Commit %ld decr job in global buffer", kfifo_len(&table->global_wq) / DECR_ITEM_SIZE);
	/* flush global queue */
	while(kfifo_len(&table->global_wq) != 0) {
		table_decrer_execute_global(table, false);
	}

	nova_info("Detect %ld decr job in global nvm buffer", kfifo_len(&table->global_wq_nvm) / DECR_ITEM_SIZE);
	nova_memunlock_gwq_nvm(sb, &flags);
	/* dump the state of global nvm queue */
	memcpy_to_pmem_nocache((struct kfifo *)nova_sbi_blocknr_to_addr(sbi, sbi->global_wq_head_start),
						   &table->global_wq_nvm, 
						   sizeof(struct kfifo));
	nova_memlock_gwq_nvm(sb, &flags);

	kfifo_free(&table->global_wq);
	if (table->decrer_threads)
		kfree(table->decrer_threads);
	if (table->decrer_waitqs)
		kfree(table->decrer_waitqs);
	return 0;
}

static __always_inline int local_wb_num(struct table_decrer_local_wb_per_cpu *decrer_lwb_cpu) {
	return decrer_lwb_cpu->capacity;
}

/* return the number of elements added */
static int in_local_wb(struct table_decrer_local_wb_per_cpu *decrer_lwb_cpu, 
					   struct nova_meta_table *table, unsigned long blocknr) {
	int ret = 1;
	struct table_decr_item *item;

	if (local_wb_num(decrer_lwb_cpu) == MAX_DECRER_LWB_NUM) {
		ret = 0;
		return ret;
	}

	item = &decrer_lwb_cpu->items[decrer_lwb_cpu->capacity++];
	item->blocknr = blocknr;

	return ret;
}

static int commit_local_wb(struct nova_meta_table *table, 
						   struct table_decrer_local_wb_per_cpu *decrer_lwb_cpu) {
	int ret, i;
	struct table_decr_item *item;
	struct super_block *sb = table->sblock;
	int in_num;
	unsigned long __flags = 0, flags = 0;

	INIT_TIMING(enqueue_time);
	INIT_TIMING(ennvmqueue_time);

	/* batch commit */
	NOVA_START_TIMING(request_enqueue_t, enqueue_time);
	ret = kfifo_in_spinlocked(&table->global_wq, 
							  decrer_lwb_cpu->items, 
							  decrer_lwb_cpu->capacity * DECR_ITEM_SIZE, 
							  &table->gwq_lock);
	NOVA_END_TIMING(request_enqueue_t, enqueue_time);
	
	in_num = ret / DECR_ITEM_SIZE;

	/* commit to global write queue in NVM */
	if (unlikely(in_num != decrer_lwb_cpu->capacity)) {
		NOVA_START_TIMING(request_ennvmqueue_t, ennvmqueue_time);
		nova_memunlock_gwq_nvm(sb, &flags);
		spin_lock_irqsave(&table->gwq_lock_nvm, __flags); 
		for (i = in_num; i < decrer_lwb_cpu->capacity; i++) {
			item = &decrer_lwb_cpu->items[i];
			ret = kfifo_in(&table->global_wq_nvm, 
						   item, 
						   DECR_ITEM_SIZE); 
			/* since we've allocated enough entry */
			BUG_ON(ret == 0);
		}
		spin_unlock_irqrestore(&table->gwq_lock_nvm, __flags); 
		nova_memlock_gwq_nvm(sb, &flags);
		NOVA_END_TIMING(request_ennvmqueue_t, ennvmqueue_time);
	}

	decrer_lwb_cpu->capacity = 0;
	return 0;
}

/* return the decrer id */
long nova_meta_table_decr_try_async(struct nova_meta_table *table, unsigned long blocknr) 
{
	int cpu;
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct table_decrer_local_wb_per_cpu *decrer_lwb_cpu;
	int ret = 0, retries = 0; 
	int global_wq_len = 0; 
	INIT_TIMING(request_decr_time);

	NOVA_START_TIMING(table_decr_async_t, request_decr_time);
	/* disable preempt */
	cpu = get_cpu();
	decrer_lwb_cpu = &per_cpu(table_decrer_local_wb_per_cpu, cpu);
try:
	ret = in_local_wb(decrer_lwb_cpu, table, blocknr);
	if (ret == 0) {
		commit_local_wb(table, decrer_lwb_cpu);
		retries++;
		goto try;		
	}

	/* do not need spinlock. half buffer is occupied */
	global_wq_len = kfifo_len(&table->global_wq);
	if (global_wq_len >= WAKE_UP_THRESHOLD(sbi)) {
		wakeup_table_decrers(table);
	}
	put_cpu();
	NOVA_END_TIMING(table_decr_async_t, request_decr_time);
	return cpu;
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
