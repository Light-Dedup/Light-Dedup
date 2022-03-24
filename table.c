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

static struct nova_rht_entry* nova_rht_entry_alloc(void)
{
	return (struct nova_rht_entry *)kzalloc(
		sizeof(struct nova_rht_entry), GFP_ATOMIC);
}

static void nova_rht_entry_free(void *entry, void *arg)
{
	kfree(entry);
}

struct nova_write_para_entry {
	struct nova_write_para_base base;
	struct nova_pmm_entry *pentry;
};

static int nova_table_leaf_delete(
	struct nova_mm_table *table,
	struct rhashtable *rht,
	struct nova_rht_entry *entry)
{
	int ret;
	nova_free_entry(table->entry_allocator, entry->pentry);
	ret = rhashtable_remove_fast(rht, &entry->node, table->rht_param);
	BUG_ON(ret < 0);
	nova_rht_entry_free(entry, NULL);
	return 0;
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

	entry = nova_rht_entry_alloc();
	BUG_ON(entry == NULL); // TODO
	pentry = nova_alloc_entry(table->entry_allocator);
	if (IS_ERR(pentry))
		return PTR_ERR(pentry);
	ret = get_new_block(sb, wp);
	if (ret < 0) {
		nova_alloc_entry_abort();
		return ret;
	}
	nova_write_entry(table->entry_allocator, pentry, fp,
		wp->blocknr, wp->base.refcount);
	assign_entry(entry, pentry, fp);
	ret = rhashtable_insert_fast(rht, &entry->node, table->rht_param);
	if (ret < 0)
		nova_free_entry(table->entry_allocator, pentry);
	// if (ret == 0)
	// 	printk("Block %lu with fp %llx inserted into rhashtable %p\n",
	// 		wp->blocknr, fp.value, rht);
	// else
	// 	printk("rhashtable_insert_fast returns %d\n", ret);
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
	struct rhashtable *rht,
	struct nova_write_para_normal *wp,
	int (*get_new_block)(struct super_block *, struct nova_write_para_normal *))
{
	struct super_block *sb = table->sblock;
	struct nova_rht_entry *entry;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	long delta = wp->base.refcount;
	unsigned long irq_flags = 0;
	INIT_TIMING(mem_bucket_find_time);

	BUG_ON(delta == 0);
	rcu_read_lock();
	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	entry = rhashtable_lookup(rht, &wp->base.fp, table->rht_param);
	NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	// We have to hold the read lock because if it is a hash collision,
	// then the entry could be freed by another thread.
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
		} else {
			if (blocknr != wp->blocknr) {
				// Collision happened. Just free it.
				rcu_read_unlock();
				printk("Blocknr mismatch: blocknr = %ld, expected %ld\n", blocknr, wp->blocknr);
				wp->base.refcount = 0;
				return 0;
			}
		}
		// The entry won't be freed by others
		// because we are referencing it.
		rcu_read_unlock();
		nova_memunlock_range(sb, &pentry->refcount,
			sizeof(pentry->refcount), &irq_flags);
		wp->base.refcount = atomic64_add_return(
			delta, &entry->pentry->refcount);
		nova_memlock_range(sb, &pentry->refcount,
			sizeof(pentry->refcount), &irq_flags);
		BUG_ON(wp->base.refcount < 0);
		if (wp->base.refcount == 0) {
			nova_table_leaf_delete(table, rht, entry);
			return 0;
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
	return nova_table_leaf_insert(table, rht, wp, get_new_block);
}
static int bucket_upsert_normal(
	struct nova_mm_table *table,
	struct rhashtable *rht,
	struct nova_write_para_base *wp)
{
	return bucket_upsert_base(table, rht, (struct nova_write_para_normal *)wp, alloc_and_fill_block);
}
static int bucket_upsert_rewrite(
	struct nova_mm_table *table,
	struct rhashtable *rht,
	struct nova_write_para_base *wp)
{
	return bucket_upsert_base(table, rht, (struct nova_write_para_normal *)wp, rewrite_block);
}

// refcount-- only if refcount == 1
static int bucket_upsert_decr1(
	struct nova_mm_table *table,
	struct rhashtable *rht,
	struct nova_write_para_base *__wp)
{
	struct nova_rht_entry *entry;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	int64_t refcount;
	struct nova_write_para_normal *wp = (struct nova_write_para_normal *)__wp;
	INIT_TIMING(mem_bucket_find_time);

	rcu_read_lock();
	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	entry = rhashtable_lookup(rht, &wp->base.fp, table->rht_param);
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
		printk("Blocknr mismatch: blocknr = %ld, expected %ld\n", blocknr, wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	// The entry won't be freed by others
	// because we are referencing it.
	rcu_read_unlock();
	refcount = atomic64_read(&pentry->refcount);
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

// Used in entry.c
int nova_rhashtable_insert_entry(struct rhashtable *rht,
	const struct rhashtable_params params, struct nova_fp fp,
	struct nova_pmm_entry *pentry)
{
	struct nova_rht_entry *entry = nova_rht_entry_alloc();
	int ret;

	if (entry == NULL)
		return -ENOMEM;
	assign_entry(entry, pentry, fp);
	while(1) {
		ret = rhashtable_insert_fast(rht, &entry->node, params);
		if (ret != -EBUSY)
			break;
		schedule();
	};
	if (ret < 0) {
		printk("%s: rhashtable_insert_fast returns %d\n",
			__func__, ret);
		nova_rht_entry_free(entry, NULL);
	}
	return ret;
}
static int bucket_insert_entry(
	struct nova_mm_table *table,
	struct rhashtable *rht,
	struct nova_write_para_base *__wp)
{
	struct nova_write_para_entry *wp = (struct nova_write_para_entry *)__wp;
	return nova_rhashtable_insert_entry(&table->rht, table->rht_param,
		wp->base.fp, wp->pentry);
}

typedef int (*bucket_upsert_func)(struct nova_mm_table *,
	struct rhashtable *rht, struct nova_write_para_base *);

static int nova_table_upsert(
	struct nova_mm_table* table, 
	struct nova_write_para_base *wp,
	bucket_upsert_func bucket_upsert)
{
	return bucket_upsert(table, &table->rht, wp);
}
// Upsert : update or insert
int nova_table_upsert_normal(struct nova_mm_table *table, struct nova_write_para_normal *wp)
{
	return nova_table_upsert(table, (struct nova_write_para_base *)wp, bucket_upsert_normal);
}
// Inplace 
int nova_table_upsert_rewrite(struct nova_mm_table *table, struct nova_write_para_rewrite *wp)
{
	return nova_table_upsert(table, (struct nova_write_para_base *)wp, bucket_upsert_rewrite);
}
// Handle edge case when inplace
int nova_table_upsert_decr1(struct nova_mm_table *table, struct nova_write_para_normal *wp)
{
	return nova_table_upsert(table, (struct nova_write_para_base *)wp, bucket_upsert_decr1);
}
// Insert entry to rebuild the hash table during normal recovery
static int nova_table_insert_entry(struct nova_mm_table *table, struct nova_write_para_entry *wp)
{
	return nova_table_upsert(table, (struct nova_write_para_base *)wp, bucket_insert_entry);
}

static void init_normal_wp_incr(struct nova_sb_info *sbi,
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
	rhashtable_free_and_destroy(&table->rht, nova_rht_entry_free, NULL);
}
void nova_table_save(struct nova_mm_table* table)
{
	INIT_TIMING(save_refcount_time);

	NOVA_START_TIMING(save_refcount_t, save_refcount_time);
	table_save(table);
	nova_table_free(table);
	NOVA_END_TIMING(save_refcount_t, save_refcount_time);
}

int nova_table_init(struct super_block *sb, struct nova_mm_table *table) 
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *psb = (struct nova_super_block *)sbi->virt_addr;
	int retval;
	struct rhashtable_params param = {
		.key_len = sizeof(struct nova_fp),
		.head_offset = offsetof(struct nova_rht_entry, node),
		.automatic_shrinking = true,
		.hashfn = nova_rht_entry_key_hashfn,
		.obj_hashfn = nova_rht_entry_hashfn,
		.obj_cmpfn = nova_rht_key_entry_cmp,
	};
	INIT_TIMING(table_init_time);

	NOVA_START_TIMING(table_init_t, table_init_time);
	printk("psb = %p\n", psb);

	table->sblock = sb;
	table->entry_allocator = &sbi->meta_table.entry_allocator;
	table->rht_param = param; // TODO: A smarter way?

	retval = rhashtable_init(
		&table->rht, &table->rht_param);
	BUG_ON(retval < 0); // TODO

	NOVA_END_TIMING(table_init_t, table_init_time);
	return 0;
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
	struct nova_write_para_entry wp;
	entrynr_t i;
	int ret = 0;
	// printk("entry_start = %lu, entry_end = %lu\n", (unsigned long)entry_start, (unsigned long)entry_end);
	for (i = entry_start; i < entry_end; ++i) {
		if (rec[i].entry_offset == 0)
			continue;
		wp.pentry = (struct nova_pmm_entry *)nova_sbi_get_block(sbi,
			le64_to_cpu(rec[i].entry_offset));
		BUG_ON(wp.pentry->flag != NOVA_LEAF_ENTRY_MAGIC);
		wp.base.fp = wp.pentry->fp;
		ret = nova_table_insert_entry(table, &wp);
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
