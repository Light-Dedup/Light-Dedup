#include <linux/atomic.h>
#include <linux/string.h>

#include "nova.h"
#include "faststr.h"
#include "arithmetic.h"
#include "multithread.h"
#include "rhashtable-ext.h"

// #define static _Static_assert(1, "2333");

struct nova_rht_entry {
	struct rhash_head node;
	struct nova_fp fp;
	struct nova_pmm_entry *pentry;
};

static u32 nova_rht_entry_key_hashfn(const void *data, u32 len, u32 seed)
{
	struct nova_fp *fp = (struct nova_fp *)data;
	return fp->index;
}

static u32 nova_rht_entry_hashfn(const void *data, u32 len, u32 seed)
{
	struct nova_rht_entry *entry = (struct nova_rht_entry *)data;
	return entry->fp.index;
}

static int nova_rht_key_entry_cmp(
	struct rhashtable_compare_arg *arg,
	const void *obj)
{
	const struct nova_fp *fp = (const struct nova_fp *)arg->key;
	struct nova_rht_entry *entry = (struct nova_rht_entry *)obj;
	// printk("%s: %llx, %llx", __func__, fp->value, entry->fp.value);
	return fp->value != entry->fp.value;
}

const struct rhashtable_params nova_rht_params = {
	.key_len = sizeof(struct nova_fp),
	.head_offset = offsetof(struct nova_rht_entry, node),
	.automatic_shrinking = true,
	.hashfn = nova_rht_entry_key_hashfn,
	.obj_hashfn = nova_rht_entry_hashfn,
	.obj_cmpfn = nova_rht_key_entry_cmp,
};

static inline struct nova_rht_entry* nova_rht_entry_alloc(
	struct nova_mm_table *table)
{
	return kmem_cache_alloc(table->rht_entry_cache, GFP_KERNEL);
}

static void nova_rht_entry_free(void *entry, void *arg)
{
	struct kmem_cache *c = (struct kmem_cache *)arg;
	kmem_cache_free(c, entry);
}

struct rht_entry_free_task {
	struct rcu_head head;
	struct entry_allocator *allocator;
	struct nova_rht_entry *entry;
};

static void rht_entry_free(struct rcu_head *head)
{
	struct rht_entry_free_task *task =
		container_of(head, struct rht_entry_free_task, head);
	struct nova_meta_table *meta_table = container_of(task->allocator,
		struct nova_meta_table, entry_allocator);
	struct super_block *sb = meta_table->sblock;
	struct nova_mm_table *table = &meta_table->metas;
	struct kmem_cache *rht_entry_cache = table->rht_entry_cache;
	struct nova_rht_entry *entry = task->entry;
	struct nova_pmm_entry *pentry = entry->pentry;
	unsigned long blocknr = pentry->blocknr;
	nova_free_data_block(sb, blocknr);
	nova_free_entry(task->allocator, pentry);
	nova_rht_entry_free(entry, rht_entry_cache);
	kfree(task);
}

static void nova_table_leaf_delete(
	struct nova_mm_table *table,
	struct rhashtable *rht,
	struct nova_rht_entry *entry)
{
	struct rht_entry_free_task *task;
	// Remove the entry first to make it invisible to other threads.
	int ret = rhashtable_remove_fast(rht, &entry->node, nova_rht_params);
	BUG_ON(ret < 0);
	task = kmalloc(sizeof(struct rht_entry_free_task), GFP_KERNEL);
	if (task) {
		task->allocator = table->entry_allocator;
		task->entry = entry;
		call_rcu(&task->head, rht_entry_free);
	} else {
		// printk(KERN_ERR "%s: Fail to allocate task\n", __func__);
		synchronize_rcu();
		nova_free_entry(table->entry_allocator, entry->pentry);
		nova_rht_entry_free(entry, table->rht_entry_cache);
	}
}

static void print(const char *addr) {
	int i;
	for (i = 0; i < 4096; ++i) {
		printk(KERN_CONT "%02x ", addr[i] & 0xff);
	}
	printk("\n");
}
static int alloc_and_fill_block(
	struct super_block *sb,
	struct nova_write_para_normal *wp)
{
	void *xmem;
	unsigned long irq_flags = 0;
	INIT_TIMING(memcpy_time);

	wp->blocknr = nova_new_data_block(sb, false, ANY_CPU);
	if (wp->blocknr == 0)
		return -ENOSPC;
	// printk("%s: Block %ld allocated", __func__, wp->blocknr);
	xmem = nova_blocknr_to_addr(sb, wp->blocknr);
	nova_memunlock_block(sb, xmem, &irq_flags);
	NOVA_START_TIMING(memcpy_data_block_t, memcpy_time);
	memcpy_flushcache((char *)xmem, (const char *)wp->addr, 4096);
	NOVA_END_TIMING(memcpy_data_block_t, memcpy_time);
	nova_memlock_block(sb, xmem, &irq_flags);
	// wp->refcount = wp->base.delta;
	// printk("xmem = %pK", xmem);
	return 0;
}
static int rewrite_block(
	struct super_block *sb,
	struct nova_write_para_normal *__wp)
{
	struct nova_write_para_rewrite *wp = (struct nova_write_para_rewrite *)__wp;
	void *xmem;
	unsigned long irq_flags = 0;
	INIT_TIMING(memcpy_time);

	xmem = nova_blocknr_to_addr(sb, wp->normal.blocknr);
	NOVA_START_TIMING(memcpy_data_block_t, memcpy_time);
	nova_memunlock_range(sb, xmem + wp->offset, wp->len, &irq_flags);
	memcpy_flushcache((char *)xmem + wp->offset, (const char *)wp->normal.addr + wp->offset, wp->len);
	nova_memlock_range(sb, xmem + wp->offset, wp->len, &irq_flags);
	// wp->refcount = wp->base.delta;
	NOVA_END_TIMING(memcpy_data_block_t, memcpy_time);
	return 0;
}
static void assign_entry(
	struct nova_rht_entry *entry,
	struct nova_pmm_entry *pentry,
	struct nova_fp fp)
{
	entry->fp = fp;
	entry->pentry = pentry;
}
static int nova_table_leaf_insert(
	struct nova_mm_table *table,
	struct rhashtable *rht,
	struct nova_write_para_normal *wp,
	int get_new_block(struct super_block *, struct nova_write_para_normal *))
{
	struct super_block *sb = table->sblock;
	struct nova_rht_entry *entry;
	struct nova_fp fp = wp->base.fp;
	struct nova_pmm_entry *pentry;
	int ret;
	INIT_TIMING(index_insert_new_entry_time);

	entry = nova_rht_entry_alloc(table);
	if (entry == NULL) {
		ret = -ENOMEM;
		goto fail0;
	}
	pentry = nova_alloc_entry(table->entry_allocator);
	if (IS_ERR(pentry)) {
		put_cpu();
		ret = PTR_ERR(pentry);
		goto fail1;
	}
	ret = get_new_block(sb, wp);
	if (ret < 0) {
		nova_alloc_entry_abort();
		goto fail1;
	}
	nova_write_entry(table->entry_allocator, pentry, fp,
		wp->blocknr, wp->base.refcount);
	assign_entry(entry, pentry, fp);
	NOVA_START_TIMING(index_insert_new_entry_t,
		index_insert_new_entry_time);
	ret = rhashtable_lookup_insert_key(rht, &fp, &entry->node,
		nova_rht_params);
	NOVA_END_TIMING(index_insert_new_entry_t, index_insert_new_entry_time);
	if (ret < 0) {
		// printk("Block %lu with fp %llx fail to insert into rhashtable "
		// 	"with error code %d\n", wp->blocknr, fp.value, ret);
		goto fail2;
	}
	// printk("Block %lu with fp %llx inserted into rhashtable %p\n",
	// 	wp->blocknr, fp.value, rht);
	return 0;
fail2:
	nova_free_data_block(sb, pentry->blocknr);
	nova_free_entry(table->entry_allocator, pentry);
fail1:
	nova_rht_entry_free(entry, table->rht_entry_cache);
fail0:
	return ret;
}
// True: Not equal. False: Equal
static bool cmp_content(struct super_block *sb, unsigned long blocknr, const void *addr) {
	INIT_TIMING(memcmp_time);
	const void *content;
	bool res;
	NOVA_START_TIMING(memcmp_t, memcmp_time);
	content = nova_blocknr_to_addr(sb, blocknr);
	res = cmp64(content, addr);
	NOVA_END_TIMING(memcmp_t, memcmp_time);
	if (res) {
		print(content);
		printk("\n");
		print(addr);
	}
	return res;
}
static int bucket_upsert_base(
	struct nova_mm_table *table,
	struct nova_write_para_normal *wp,
	int (*get_new_block)(struct super_block *, struct nova_write_para_normal *))
{
	struct super_block *sb = table->sblock;
	struct rhashtable *rht = &table->rht;
	struct nova_rht_entry *entry;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	long delta = wp->base.refcount;
	unsigned long irq_flags = 0;
	int ret;
	INIT_TIMING(mem_bucket_find_time);

	BUG_ON(delta == 0);
retry:
	rcu_read_lock();
	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	entry = rhashtable_lookup(rht, &wp->base.fp, nova_rht_params);
	NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	// We have to hold the read lock because if it is a hash collision,
	// then the entry, pentry, and blocknr could be freed by another thread.
	if (entry) {
		pentry = entry->pentry;
		BUG_ON(pentry->flag != NOVA_LEAF_ENTRY_MAGIC);
		blocknr = le64_to_cpu(pentry->blocknr);
		if (delta > 0) {
			if (cmp_content(sb, blocknr, wp->addr)) {
				rcu_read_unlock();
				nova_dbg("fp:%llx rentry.fp:%llx",wp->base.fp.value, entry->pentry->fp.value);
				printk("Collision, just write it.");
				return get_new_block(sb, wp);
				// const void *content = nova_get_block(sb, nova_sb_blocknr_to_addr(sb, le64_to_cpu(leaf->blocknr), NOVA_BLOCK_TYPE_4K));
				// printk("First 8 bytes of existed_entry: %llx, chunk_id = %llx, fingerprint = %llx %llx %llx %llx\nFirst 8 bytes of incoming block: %llx, fingerprint = %llx %llx %llx %llx\n",
				// 	*(uint64_t *)content, leaf->blocknr, leaf->fp_strong.u64s[0], leaf->fp_strong.u64s[1], leaf->fp_strong.u64s[2], leaf->fp_strong.u64s[3],
				// 	*(uint64_t *)addr, entry->fp_strong.u64s[0], entry->fp_strong.u64s[1], entry->fp_strong.u64s[2], entry->fp_strong.u64s[3]);
			}
			wp->blocknr = blocknr;// retrieval block info
			BUG_ON(wp->base.refcount < 0);
			nova_memunlock_range(sb, &pentry->refcount,
				sizeof(pentry->refcount), &irq_flags);
			ret = atomic64_add_unless(&pentry->refcount, delta, 0);
			nova_memlock_range(sb, &pentry->refcount,
				sizeof(pentry->refcount), &irq_flags);
			rcu_read_unlock();
			if (ret == false) {
				schedule();
				goto retry;
			}
		} else {
			if (blocknr != wp->blocknr) {
				// Collision happened. Just free it.
				rcu_read_unlock();
				printk("%s: Blocknr mismatch: blocknr = %ld, expected %ld\n", __func__, blocknr, wp->blocknr);
				wp->base.refcount = 0;
				return 0;
			}
			rcu_read_unlock();
			nova_memunlock_range(sb, &pentry->refcount,
				sizeof(pentry->refcount), &irq_flags);
			wp->base.refcount = atomic64_add_return(
				delta, &entry->pentry->refcount);
			nova_memlock_range(sb, &pentry->refcount,
				sizeof(pentry->refcount), &irq_flags);
			BUG_ON(wp->base.refcount < 0);
			if (wp->base.refcount == 0) {
				// Now only we can free the entry,
				// because there are no any other deleter.
				nova_table_leaf_delete(table, rht, entry);
				return 0;
			}
		}
		nova_flush_entry(table->entry_allocator, pentry);
		// printk("Block %lu has refcount %lld now\n",
		// 	wp->blocknr, wp->base.refcount);
		return 0;
	}
	rcu_read_unlock();
	// printk("Block with fp %llx not found in rhashtable %p\n",
	// 	wp->base.fp.value, rht);
	if (delta < 0) {
		// Collision happened. Just free it.
		printk("Block %ld can not be found in the hash table.", wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	ret = nova_table_leaf_insert(table, rht, wp, get_new_block);
	if (ret == -EEXIST)
		goto retry;
	return ret;
}

// Upsert : update or insert
int nova_table_upsert_normal(struct nova_mm_table *table, struct nova_write_para_normal *wp)
{
	return bucket_upsert_base(table, wp, alloc_and_fill_block);
}
// Inplace 
int nova_table_upsert_rewrite(struct nova_mm_table *table, struct nova_write_para_rewrite *wp)
{
	return bucket_upsert_base(table, (struct nova_write_para_normal *)wp,
		rewrite_block);
}

// refcount-- only if refcount == 1
int nova_table_upsert_decr1(
	struct nova_mm_table *table,
	struct nova_write_para_normal *wp)
{
	struct rhashtable *rht = &table->rht;
	struct nova_rht_entry *entry;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	int64_t refcount;
	INIT_TIMING(mem_bucket_find_time);

	rcu_read_lock();
	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	entry = rhashtable_lookup(rht, &wp->base.fp, nova_rht_params);
	NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	// We have to hold the read lock because if it is a hash collision,
	// then the entry could be freed by another thread.
	if (!entry) {
		rcu_read_unlock();
		// Collision happened. Just free it.
		printk("Block %ld can not be found in the hash table.", wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	pentry = entry->pentry;
	BUG_ON(pentry->flag != NOVA_LEAF_ENTRY_MAGIC);
	blocknr = le64_to_cpu(pentry->blocknr);
	if (blocknr != wp->blocknr) {
		rcu_read_unlock();
		// Collision happened. Just free it.
		printk("%s: Blocknr mismatch: blocknr = %ld, expected %ld\n",
			__func__, blocknr, wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	// The entry won't be freed by others
	// because we are referencing it.
	rcu_read_unlock();
	refcount = atomic64_cmpxchg(&pentry->refcount, 1, 0);
	BUG_ON(refcount == 0);
	if (refcount == 1) {
		nova_table_leaf_delete(table, rht, entry);
		wp->base.refcount = 0;
		return 0;
	}
	// refcount >= 2. So we do not decrease refcount.
	wp->base.refcount = refcount;
	// printk(KERN_WARNING " found at %d, ref %llu\n", leaf_index, refcount);
	return 0;
}

int nova_table_insert_entry(struct nova_mm_table *table, struct nova_fp fp,
	struct nova_pmm_entry *pentry)
{
	struct nova_rht_entry *entry = nova_rht_entry_alloc(table);
	int ret;

	if (entry == NULL)
		return -ENOMEM;
	assign_entry(entry, pentry, fp);
	while (1) {
		ret = rhashtable_insert_fast(&table->rht, &entry->node,
			nova_rht_params);
		if (ret != -EBUSY)
			break;
		schedule();
	};
	if (ret < 0) {
		printk("%s: rhashtable_insert_fast returns %d\n",
			__func__, ret);
		nova_rht_entry_free(entry, table->rht_entry_cache);
	}
	return ret;
}

static inline void init_normal_wp_incr(struct nova_sb_info *sbi,
	struct nova_write_para_normal *wp, const void *addr)
{
	BUG_ON(nova_fp_calc(&sbi->meta_table.fp_ctx, addr, &wp->base.fp));
	wp->addr = addr;
	wp->base.refcount = 1;
}
int nova_fp_table_incr(struct nova_mm_table *table, const void* addr,
	struct nova_write_para_normal *wp)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	INIT_TIMING(incr_ref_time);

	NOVA_START_TIMING(incr_ref_t, incr_ref_time);
	init_normal_wp_incr(sbi, wp, addr);
	ret = nova_table_upsert_normal(table, wp);
	NOVA_END_TIMING(incr_ref_t, incr_ref_time);
	return ret;
}
int nova_fp_table_rewrite_on_insert(struct nova_mm_table *table,
	const void *addr, struct nova_write_para_rewrite *wp,
	unsigned long blocknr, size_t offset, size_t bytes)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	INIT_TIMING(incr_ref_time);

	NOVA_START_TIMING(incr_ref_t, incr_ref_time);
	init_normal_wp_incr(sbi, &wp->normal, addr);
	wp->normal.blocknr = blocknr;
	wp->offset = offset;
	wp->len = bytes;
	ret = nova_table_upsert_rewrite(table, wp);
	NOVA_END_TIMING(incr_ref_t, incr_ref_time);
	return ret;
}

struct table_save_local_arg {
	size_t cur, end;
	struct nova_entry_refcount_record *rec;
	atomic64_t *saved;
	struct nova_sb_info *sbi;
};
struct table_save_factory_arg {
	struct nova_mm_table *table;
	atomic64_t saved;
};
static void *table_save_local_arg_factory(void *factory_arg) {
	struct table_save_factory_arg *arg =
		(struct table_save_factory_arg *)factory_arg;
	struct nova_mm_table *table = arg->table;
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct table_save_local_arg *local_arg = kmalloc(
		sizeof(struct table_save_local_arg), GFP_KERNEL);
	local_arg->cur = 0;
	local_arg->end = 0;
	local_arg->rec = nova_sbi_blocknr_to_addr(
		sbi, sbi->entry_refcount_record_start);
	local_arg->saved = &arg->saved;
	local_arg->sbi = sbi;
	return local_arg;
}
static void table_save_local_arg_recycler(void *local_arg)
{
	struct table_save_local_arg *arg =
		(struct table_save_local_arg *)local_arg;
	memset_nt(arg->rec + arg->cur,
		(arg->end - arg->cur) *
			sizeof(struct nova_entry_refcount_record),
		0);
	kfree(arg);
}
static void table_save_func(void *ptr, void *local_arg)
{
	struct nova_rht_entry *entry = (struct nova_rht_entry *)ptr;
	struct table_save_local_arg *arg =
		(struct table_save_local_arg *)local_arg;
	// printk("%s: entry = %p, rec = %p, cur = %lu\n", __func__, entry, arg->rec, arg->cur);
	// TODO: Make it a list
	if (arg->cur == arg->end) {
		arg->end = atomic64_add_return(ENTRY_PER_REGION, arg->saved);
		arg->cur = arg->end - ENTRY_PER_REGION;
		// printk("New region to save, start = %lu, end = %lu\n", arg->cur, arg->end);
	}
	arg->rec[arg->cur].entry_offset = cpu_to_le64(
		nova_get_addr_off(arg->sbi, entry->pentry));
	nova_flush_buffer(arg->rec + arg->cur,
		sizeof(struct nova_entry_refcount_record), false);
	++arg->cur;
}
static void table_save(struct nova_mm_table *table)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	struct table_save_factory_arg factory_arg;
	uint64_t saved;
	unsigned long irq_flags = 0;

	atomic64_set(&factory_arg.saved, 0);
	factory_arg.table = table;
	nova_memunlock(sb, &irq_flags);
	if (rhashtable_traverse_multithread(
		&table->rht, sbi->cpus, table_save_func,
		table_save_local_arg_factory, table_save_local_arg_recycler,
		&factory_arg) < 0)
	{
		nova_warn("%s: Fail to save the fingerprint table with multithread. Fall back to single thread.", __func__);
		BUG(); // TODO
	}
	nova_memlock(sb, &irq_flags);
	PERSISTENT_BARRIER();
	saved = atomic64_read(&factory_arg.saved);
	nova_unlock_write(sb, &recover_meta->refcount_record_num,
		cpu_to_le64(saved), true);
	printk("About %llu entries in hash table saved in NVM.", saved);
}

void nova_table_free(struct nova_mm_table *table)
{
	rhashtable_free_and_destroy(&table->rht, nova_rht_entry_free,
		table->rht_entry_cache);
	kmem_cache_destroy(table->rht_entry_cache);
}
void nova_table_save(struct nova_mm_table* table)
{
	INIT_TIMING(save_refcount_time);

	NOVA_START_TIMING(save_refcount_t, save_refcount_time);
	table_save(table);
	nova_table_free(table);
	NOVA_END_TIMING(save_refcount_t, save_refcount_time);
}

// nelem_hint: If 0 then use default
int nova_table_init(struct super_block *sb, struct nova_mm_table *table,
	size_t nelem_hint)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *psb = (struct nova_super_block *)sbi->virt_addr;
	int ret;
	INIT_TIMING(table_init_time);

	NOVA_START_TIMING(table_init_t, table_init_time);
	printk("psb = %p\n", psb);

	table->sblock = sb;
	table->entry_allocator = &sbi->meta_table.entry_allocator;

	ret = rhashtable_init_large(&table->rht, nelem_hint,
		&nova_rht_params);
	if (ret < 0)
		goto err_out0;

	table->rht_entry_cache = kmem_cache_create("rht_entry_cache",
		sizeof(struct nova_rht_entry), 0, TABLE_KMEM_CACHE_FLAGS, NULL);
	if (table->rht_entry_cache == NULL) {
		ret = -ENOMEM;
		goto err_out1;
	}
	NOVA_END_TIMING(table_init_t, table_init_time);
	return 0;
err_out1:
	rhashtable_free_and_destroy(&table->rht, nova_rht_entry_free,
		table->rht_entry_cache);
err_out0:
	NOVA_END_TIMING(table_init_t, table_init_time);
	return ret;
}

struct table_recover_para {
	struct completion entered;
	struct nova_mm_table *table;
	entrynr_t entry_start, entry_end;
};
static int __table_recover_func(struct nova_mm_table *table,
	entrynr_t entry_start, entrynr_t entry_end)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_entry_refcount_record *rec = nova_sbi_blocknr_to_addr(
		sbi, sbi->entry_refcount_record_start);
	struct nova_pmm_entry *pentry;
	entrynr_t i;
	int ret = 0;
	// printk("entry_start = %lu, entry_end = %lu\n", (unsigned long)entry_start, (unsigned long)entry_end);
	for (i = entry_start; i < entry_end; ++i) {
		if (rec[i].entry_offset == 0)
			continue;
		pentry = (struct nova_pmm_entry *)nova_sbi_get_block(sbi,
			le64_to_cpu(rec[i].entry_offset));
		BUG_ON(pentry->flag != NOVA_LEAF_ENTRY_MAGIC);
		ret = nova_table_insert_entry(table, pentry->fp,
			pentry);
		if (ret < 0)
			break;
	}
	return ret;
}
static int table_recover_func(void *__para)
{
	struct table_recover_para *para = (struct table_recover_para *)__para;
	int ret;
	// printk("%s\n", __func__);
	complete(&para->entered);
	ret = __table_recover_func(para->table, para->entry_start, para->entry_end);
	// printk("%s waiting for kthread_stop\n", __func__);
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	return ret;
}
int nova_table_recover(struct nova_mm_table *table)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	entrynr_t n = le64_to_cpu(recover_meta->refcount_record_num);
	unsigned long entry_per_thread_bit = max_ul(20, ceil_log_2(n / sbi->cpus));
	unsigned long entry_per_thread = 1UL << entry_per_thread_bit;
	unsigned long i, thread_num = ((n - 1) >> entry_per_thread_bit) + 1;
	unsigned long base;
	struct table_recover_para *para = NULL;
	struct task_struct **tasks = NULL;
	int ret = 0, ret2;

	nova_info("About %lu hash table entries found.\n", (unsigned long)n);
	if (n == 0)
		return 0;
	nova_info("Recover fingerprint table using %lu thread(s)\n", thread_num);
	if (thread_num == 1)
		return __table_recover_func(table, 0, n);
	para = kmalloc(thread_num * sizeof(para[0]), GFP_KERNEL);
	if (para == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	tasks = kmalloc(thread_num * sizeof(struct task_struct *), GFP_KERNEL);
	if (tasks == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	base = 0;
	for (i = 0; i < thread_num; ++i) {
		init_completion(&para[i].entered);
		para[i].table = table;
		para[i].entry_start = base;
		base += entry_per_thread;
		para[i].entry_end = base < n ? base : n;
		tasks[i] = kthread_create(table_recover_func, para + i,
			"%s_%lu", __func__, i);
		if (IS_ERR(tasks[i])) {
			ret = PTR_ERR(tasks[i]);
			nova_err(sb, "%lu: kthread_create %lu return %d\n",
				__func__, i, ret);
			break;
		}
	}
	ret2 = run_and_stop_kthreads(tasks, para, thread_num, i);
	if (ret2 < 0)
		ret = ret2;
out:
	if (para)
		kfree(para);
	if (tasks)
		kfree(tasks);
	return ret;
}

int nova_table_stats(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_meta_table *meta_table = &sbi->meta_table;
	struct nova_mm_table *table = &meta_table->metas;
	return __nova_entry_allocator_stats(sbi, table->entry_allocator);
}
