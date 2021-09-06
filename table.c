#include <linux/atomic.h>
#include <linux/string.h>

#include "nova.h"
#include "faststr.h"
#include "arithmetic.h"
#include "multithread.h"

#define NOVA_FULL  (1)
// #define NOVA_INSERT_ENTRY (2)
#define NOVA_DELETE_ENTRY (2)
// #define NOVA_INNER_TO_BUCKET (3)

// #define static _Static_assert(1, "2333");

static inline struct nova_inner *
alloc_inner(size_t bits)
{
	return (struct nova_inner *)kmalloc(sizeof(struct nova_inner) +
		((size_t)1 << bits) * sizeof(unsigned long), GFP_ATOMIC);
}
static inline void
nova_table_free_inner(struct nova_mm_table *table, struct nova_inner *inner)
{
	(void)table;
	kfree(inner);
}
static inline struct nova_inner *
inner_realloc(struct nova_mm_table *table,
	struct nova_inner *inner, size_t new_bits)
{
	(void)table;
	return (struct nova_inner *)krealloc(inner,
		sizeof(struct nova_inner) +
		((size_t)1 << new_bits) * sizeof(unsigned long), GFP_ATOMIC);
}
static struct nova_inner *
inner_shrink(struct nova_mm_table *table, struct nova_inner *inner)
{
	struct nova_inner *new_inner = inner_realloc(table, inner, inner->bits - 1);
	if (new_inner != NULL)
		inner = new_inner;
	--inner->bits;
	return inner;
}
static struct nova_inner *
inner_expand(struct nova_mm_table *table, struct nova_inner *inner)
{
	size_t n = (size_t)1 << inner->bits;
	inner = inner_realloc(table, inner, inner->bits + 1);
	if (inner == NULL)
		return NULL;
	++inner->bits;
	memcpy(inner->node_p + n, inner->node_p, n * sizeof(unsigned long));
	inner->merged = n;
	return inner;
}

static struct nova_bucket *
alloc_empty_bucket(struct nova_mm_table *table)
{
	return kmem_cache_zalloc(table->bucket_cache, GFP_ATOMIC);
	// struct nova_bucket *bucket = kmem_cache_alloc(table->bucket_cache, GFP_KERNEL);
	// if (bucket == NULL)
	// 	return NULL;
	// bucket->size = 0;
	// memset(bucket->tags, 0, sizeof(bucket->tags));
	// return bucket;
}
static void
free_bucket(struct nova_mm_table *table, struct nova_bucket *bucket)
{
	kmem_cache_free(table->bucket_cache, bucket);
}

struct nova_write_para_entry {
	struct nova_write_para_base base;
	struct nova_pmm_entry *pentry;
};

static inline bool
fp_matches(struct entry_allocator *allocator,
	const struct nova_bucket *bucket,
	size_t i,
	const struct nova_fp *fp)
{
	return nova_fp_equal(fp, &bucket->entry_p[i].pentry->fp);
}
static size_t nova_table_leaf_find(
	struct entry_allocator *allocator,
	const struct nova_bucket *bucket,
	const struct nova_fp *fp)
{
	size_t i;
	uint64_t index = fp->indicator;
	uint8_t tag = (uint8_t)(fp->tag % 0xff + 1);
	for (i = index; i < NOVA_TABLE_LEAF_SIZE; i++) {
		if (bucket->tags[i] == tag && bucket->indicators[i] == fp->indicator &&
			fp_matches(allocator, bucket, i, fp)) {
			return i;
		}
	}
	for (i = 0; i < index; i++) {
		if (bucket->tags[i] == tag && bucket->indicators[i] == fp->indicator &&
			fp_matches(allocator, bucket, i, fp)) {
			return i;
		}
	}
	return NOVA_TABLE_LEAF_SIZE;
}

static int nova_table_leaf_delete(
	struct nova_mm_table *table,
	struct nova_bucket *bucket,
	size_t entry_index)
{
	struct nova_pmm_entry *pentry = bucket->entry_p[entry_index].pentry;
	nova_free_entry(table->entry_allocator, pentry);
	bucket->tags[entry_index] = 0;
	BUG_ON(bucket->size == 0);
	--bucket->size;
	return 0;

	// retval = nova_table_free_blocks(table->sblock, inner->inner.blocknr, 1);
	// // kfree(inner);
	// memset(inner, 0, sizeof *inner);
	// if (retval == 0)
	// 	retval = NOVA_LEAF_ALL_DELETED;
	// return retval;
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
static size_t
find_free_slot_in_bucket(
	struct nova_bucket *bucket,
	size_t indicator)
{
	size_t i;
	for (i = indicator; i < NOVA_TABLE_LEAF_SIZE; i++)
		if (bucket->tags[i] == 0)
			return i;
	for (i = 0; i < indicator; i++)
		if (bucket->tags[i] == 0)
			return i;
	return NOVA_TABLE_LEAF_SIZE;
}
static void assign_entry(
	struct nova_bucket *bucket,
	size_t i,
	struct nova_mm_entry_p entry_p,
	const struct nova_fp *fp,
	size_t used_hash_bit)
{
	size_t disbase;
	bucket->tags[i] = (uint8_t)((fp->tag % 0xff) + 1); // non zero
	bucket->indicators[i] = fp->indicator;
	if (used_hash_bit == 0) {
		// The bucket is the root of tablet, disbyte will not be used.
		bucket->disbyte[i] = 0;
	} else {
		BUG_ON(used_hash_bit < NOVA_TABLE_INNER_BITS);
		disbase = used_hash_bit - NOVA_TABLE_INNER_BITS;
		bucket->disbyte[i] = fp->index >> (disbase + 1);
	}
	bucket->entry_p[i] = entry_p;
	++bucket->size;
}
static int nova_table_leaf_insert(
	struct nova_mm_table *table,
	struct nova_bucket *bucket,
	size_t used_hash_bit,
	struct nova_write_para_normal *wp,
	int get_new_block(struct super_block *, struct nova_write_para_normal *))
{
	struct super_block *sb = table->sblock;
	const struct nova_fp *fp = &wp->base.fp;
	size_t i;
	int cpu;
	struct entry_allocator_cpu *allocator_cpu;
	struct nova_pmm_entry *pentry;
	struct nova_mm_entry_p entry_p;
	int ret;

	i = find_free_slot_in_bucket(bucket, fp->indicator);
	if (i == NOVA_TABLE_LEAF_SIZE)
		return NOVA_FULL;
	cpu = get_cpu();
	allocator_cpu = &per_cpu(entry_allocator_per_cpu, cpu);
	pentry = nova_alloc_entry(table->entry_allocator, allocator_cpu);
	if (IS_ERR(pentry)) {
		put_cpu();
		return PTR_ERR(pentry);
	}
	ret = get_new_block(sb, wp);
	if (ret < 0) {
		nova_alloc_entry_abort(allocator_cpu);
		put_cpu();
		return ret;
	}
	nova_write_entry(table->entry_allocator, allocator_cpu, pentry, fp,
		wp->blocknr, wp->base.refcount);
	put_cpu();
	entry_p.pentry = pentry;
	assign_entry(bucket, i, entry_p, fp, used_hash_bit);
	return 0;
}
#if 0
static void print_bucket_entry(
	struct nova_mm_table *table,
	const struct nova_bucket *bucket,
	size_t index)
{
	struct nova_pmm_entry *pentry =
		table->pentries + bucket->entry_p[index].entrynr;
	struct nova_mm_entry_info entry_info = entry_info_pmm_to_mm(pentry->info);
	BUG_ON(entry_info.flag != NOVA_LEAF_ENTRY_MAGIC);
	printk("index = %lu, tag = %d, indicator = %d, blocknr = %lu, fp = %llx\n",
		index, bucket->tags[index], bucket->indicators[index],
		(unsigned long)entry_info.blocknr,
		pentry->fp.value);
}
#endif
static int nova_table_leaf_mm_insert(
	struct nova_mm_table *table,
	struct nova_bucket *bucket,
	const struct nova_bucket *src,
	size_t index,
	uint8_t disbyte)
{
	size_t i;
	// print_bucket_entry(table, src, index);
	i = find_free_slot_in_bucket(bucket, src->indicators[index]);
	if (i == NOVA_TABLE_LEAF_SIZE)
		return NOVA_FULL;
	bucket->tags[i] = src->tags[index];
	bucket->indicators[i] = src->indicators[index];
	bucket->disbyte[i] = disbyte;
	bucket->entry_p[i] = src->entry_p[index];
	++bucket->size;
	return 0;
}
static int bucket_upsert_base(
	struct nova_mm_table *table,
	struct nova_bucket *bucket,
	size_t used_hash_bit,
	struct nova_write_para_normal *wp,
	int (*get_new_block)(struct super_block *, struct nova_write_para_normal *))
{
	struct super_block *sb = table->sblock;
	struct entry_allocator *allocator = table->entry_allocator;
	size_t leaf_index;
	// struct nova_pmm_node *pnode;
	struct nova_mm_entry_p *entry_p;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	int64_t refcount;
	long delta = wp->base.refcount;
	unsigned long irq_flags = 0;
	INIT_TIMING(mem_bucket_find_time);

	BUG_ON(delta == 0);
	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	leaf_index = nova_table_leaf_find(allocator, bucket, &wp->base.fp);
	NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	if (leaf_index != NOVA_TABLE_LEAF_SIZE) {
		entry_p = bucket->entry_p + leaf_index;
		pentry = entry_p->pentry;
		BUG_ON(pentry->flag != NOVA_LEAF_ENTRY_MAGIC);
		blocknr = le64_to_cpu(pentry->blocknr);
		refcount = le64_to_cpu(pentry->refcount);
		if (delta > 0) {
			wp->blocknr = blocknr;// retrieval block info
		} else {
			if (blocknr != wp->blocknr) {
				// Collision happened. Just free it.
				printk("Blocknr mismatch: blocknr = %ld, expected %ld\n", blocknr, wp->blocknr);
				wp->base.refcount = 0;
				return 0;
			}
			BUG_ON(refcount < -delta);
			if (refcount == -delta) {
				// printk("Before nova_table_leaf_delete");
				nova_table_leaf_delete(table, bucket, leaf_index);
				// printk("nova_table_leaf_delete return");
				wp->base.refcount = 0;
				return NOVA_DELETE_ENTRY;
			}
		}
		refcount += delta;
		wp->base.refcount = refcount;
		nova_memunlock_range(sb, &pentry->refcount,
			sizeof(pentry->refcount), &irq_flags);
		pentry->refcount = cpu_to_le64(refcount);
		nova_memlock_range(sb, &pentry->refcount,
			sizeof(pentry->refcount), &irq_flags);
		nova_flush_entry(table->entry_allocator, pentry);
		// printk(KERN_WARNING " found at %d, ref %llu\n", leaf_index, refcount);
		return 0;
	}
	if (delta < 0) {
		// Collision happened. Just free it.
		printk("Block %ld can not be found in the hash table.", wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	return nova_table_leaf_insert(table, bucket, used_hash_bit, wp, get_new_block);
}
static int bucket_upsert_normal(
	struct nova_mm_table *table,
	struct nova_bucket *bucket,
	size_t used_hash_bit,
	struct nova_write_para_base *wp)
{
	return bucket_upsert_base(table, bucket, used_hash_bit, (struct nova_write_para_normal *)wp, alloc_and_fill_block);
}
static int bucket_upsert_rewrite(
	struct nova_mm_table *table,
	struct nova_bucket *bucket,
	size_t used_hash_bit,
	struct nova_write_para_base *wp)
{
	return bucket_upsert_base(table, bucket, used_hash_bit, (struct nova_write_para_normal *)wp, rewrite_block);
}

// refcount-- only if refcount == 1
static int bucket_upsert_decr1(
	struct nova_mm_table *table,
	struct nova_bucket *bucket,
	size_t used_hash_bit,
	struct nova_write_para_base *__wp)
{
	struct entry_allocator *allocator = table->entry_allocator;
	size_t leaf_index;
	struct nova_mm_entry_p *entry_p;
	struct nova_pmm_entry *pentry;
	unsigned long blocknr;
	int64_t refcount;
	struct nova_write_para_normal *wp = (struct nova_write_para_normal *)__wp;
	INIT_TIMING(mem_bucket_find_time);

	NOVA_START_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	leaf_index = nova_table_leaf_find(allocator, bucket, &wp->base.fp);
	NOVA_END_TIMING(mem_bucket_find_t, mem_bucket_find_time);
	if (leaf_index == NOVA_TABLE_LEAF_SIZE) {
		// Collision happened. Just free it.
		printk("Block %ld can not be found in the hash table.", wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	entry_p = bucket->entry_p + leaf_index;
	pentry = entry_p->pentry;
	BUG_ON(pentry->flag != NOVA_LEAF_ENTRY_MAGIC);
	blocknr = le64_to_cpu(pentry->blocknr);
	if (blocknr != wp->blocknr) {
		// Collision happened. Just free it.
		printk("Blocknr mismatch: blocknr = %ld, expected %ld\n", blocknr, wp->blocknr);
		wp->base.refcount = 0;
		return 0;
	}
	refcount = le64_to_cpu(pentry->refcount);
	BUG_ON(refcount == 0);
	if (refcount == 1) {
		// printk("Before nova_table_leaf_delete");
		nova_table_leaf_delete(table, bucket, leaf_index);
		// printk("nova_table_leaf_delete return");
		wp->base.refcount = 0;
		return NOVA_DELETE_ENTRY;
	}
	// refcount >= 2. So we do not decrease refcount.
	wp->base.refcount = refcount;
	// printk(KERN_WARNING " found at %d, ref %llu\n", leaf_index, refcount);
	return 0;
}

static int bucket_insert_entry(
	struct nova_mm_table *table,
	struct nova_bucket *bucket,
	size_t used_hash_bit,
	struct nova_write_para_base *__wp)
{
	struct nova_write_para_entry *wp = (struct nova_write_para_entry *)__wp;
	size_t i;
	struct nova_mm_entry_p entry_p;

	i = find_free_slot_in_bucket(bucket, wp->base.fp.indicator);
	if (i == NOVA_TABLE_LEAF_SIZE)
		return NOVA_FULL;
	entry_p.pentry = wp->pentry;
	assign_entry(bucket, i, entry_p, &wp->base.fp, used_hash_bit);
	return 0;
}

static int bucket_upsert_entry(
	struct nova_mm_table *table,
	struct nova_bucket *bucket,
	size_t used_hash_bit,
	struct nova_write_para_base *__wp)
{
	struct super_block *sb = table->sblock;
	struct nova_write_para_entry *wp = (struct nova_write_para_entry *)__wp;
	size_t i;
	struct nova_mm_entry_p *entry_p;
	struct nova_pmm_entry *pentry;
	unsigned long irq_flags = 0;

	i = nova_table_leaf_find(table->entry_allocator, bucket, &wp->base.fp);
	if (i == NOVA_TABLE_LEAF_SIZE)
		return bucket_insert_entry(table, bucket, used_hash_bit, __wp);
	entry_p = bucket->entry_p + i;
	pentry = entry_p->pentry;
	// There should not be two entries which have the same fingerprint.
	BUG_ON(pentry != wp->pentry);
	nova_memunlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
		&irq_flags);
	le64_add_cpu(&pentry->refcount, 1);
	nova_memlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
		&irq_flags);
	nova_flush_entry(table->entry_allocator, pentry);
	return 0;
}

typedef int (*bucket_upsert_func)(struct nova_mm_table *, struct nova_bucket *,
	size_t used_hash_bit, struct nova_write_para_base *);

static void __bucket_rehash_new_inner(
	struct nova_mm_table *table,
	const struct nova_bucket *old_bucket,
	struct nova_bucket *bucket[2],
	size_t disbase)
{
	struct nova_pmm_entry *pentry;
	uint64_t cur_layer_fp;
	size_t which;
	size_t i;
	for (i = 0; i < NOVA_TABLE_LEAF_SIZE; i++) {
		pentry = old_bucket->entry_p[i].pentry;
		cur_layer_fp = pentry->fp.index >> disbase;
		which =  cur_layer_fp & 1;
		BUG_ON(nova_table_leaf_mm_insert(table, 
					bucket[which], old_bucket, i,
					(uint8_t)(cur_layer_fp >> 1)));
	}
}
static void __bucket_rehash(
	struct nova_mm_table *table,
	const struct nova_bucket *old_bucket,
	struct nova_bucket *bucket[2],
	size_t disoff)
{
	size_t which;
	size_t i;
	for (i = 0; i < NOVA_TABLE_LEAF_SIZE; i++) {
		which = (old_bucket->disbyte[i] >> (disoff - 1)) & 1;
		BUG_ON(nova_table_leaf_mm_insert(table, 
					bucket[which],
					old_bucket, i,
					old_bucket->disbyte[i]));
	}
}
static int bucket_rehash(
	struct nova_mm_table *table,
	const struct nova_bucket *old_bucket,
	struct nova_bucket *bucket[2],
	// (disbase + disoff) is the index of discriminative bit
	// disbase is the number of bits used before the target inner layer
	size_t disbase,
	// disoff is the offset of the new disbit in the target inner layer
	size_t disoff)
{
	bucket[0] = alloc_empty_bucket(table);
	if (bucket[0] == NULL)
		return -ENOMEM;
	bucket[1] = alloc_empty_bucket(table);
	if (bucket[1] == NULL) {
		free_bucket(table, bucket[0]);
		return -ENOMEM;
	}
	if (disoff == 0)
		__bucket_rehash_new_inner(table, old_bucket, bucket, disbase);
	else
		__bucket_rehash(table, old_bucket, bucket, disoff);
	return 0;
}
// Split vertically
static int __nova_table_split_leaf(
	struct nova_mm_table *table,
	unsigned long *node_p,	// A full bucket, will becomes a new inner.
	int used_hash_bit)
{
	struct nova_bucket *old_bucket = nova_node_p_to_bucket(*node_p);
	struct nova_bucket *bucket[2];
	struct nova_inner *new_inner = NULL;
	int i, retval;
	INIT_TIMING(split_leaf_time);

	// printk("__nova_table_split_leaf");
	NOVA_START_TIMING(split_leaf_t, split_leaf_time);

	new_inner = alloc_inner(1);
	if (!new_inner) {
		retval = -ENOMEM;
		goto err_out;
	}
	new_inner->bits = 1;
	new_inner->merged = 0;

	retval = bucket_rehash(table, old_bucket, bucket, used_hash_bit, 0);
	if (retval < 0)
		goto err_out;
	free_bucket(table, old_bucket);
	for (i = 0; i < 2; ++i) {
		bucket[i]->disbits = 1;
		new_inner->node_p[i] = nova_bucket_to_node_p(bucket[i]);
	}
	*node_p = nova_inner_to_node_p(new_inner);

	NOVA_END_TIMING(split_leaf_t, split_leaf_time);
	return 0;

err_out:
	if (new_inner)
		nova_table_free_inner(table, new_inner);
	NOVA_END_TIMING(split_leaf_t, split_leaf_time);
	// printk("__nova_table_split_leaf: err_out");
	return retval;
}

static int __nova_table_split(
	struct nova_mm_table *table,
	unsigned long * __restrict__ inner_p,
	uint64_t index,
	int used_hash_bit)
{
	struct nova_inner *inner = nova_node_p_to_inner(*inner_p);
	struct nova_bucket *old_bucket = nova_node_p_to_bucket(inner->node_p[index]);
	struct nova_bucket *bucket[2];
	int retval;
	size_t i;
	uint64_t new_bit;

	if (old_bucket->disbits == inner->bits) {
		if (inner->bits == NOVA_TABLE_INNER_BITS) {
			// printk(KERN_WARNING " split fulled depth %d, index %llu\n", depth, index);
			return __nova_table_split_leaf(table,
				inner->node_p + index, used_hash_bit + NOVA_TABLE_INNER_BITS);
		}
		inner = inner_expand(table, inner);
		if (inner == NULL)
			return -ENOMEM;	// Nothing to free, just return.
		*inner_p = nova_inner_to_node_p(inner);
	}

	retval = bucket_rehash(table, old_bucket, bucket, used_hash_bit, old_bucket->disbits);
	if (retval < 0)
		return retval;	// No need to revert expanded inner.
	if (old_bucket->disbits + 1 == inner->bits)
		--inner->merged;
	bucket[0]->disbits = bucket[1]->disbits = old_bucket->disbits + 1;
	new_bit = 1 << old_bucket->disbits;
	free_bucket(table, old_bucket);

	for (i = (index & (new_bit - 1)); i < (1 << inner->bits); i += (new_bit << 1)) {
		inner->node_p[i] = nova_bucket_to_node_p(bucket[0]);
		inner->node_p[i | new_bit] = nova_bucket_to_node_p(bucket[1]);
	}
	return 0;
}

static void merge_bucket(struct nova_mm_table *table, struct nova_bucket *dst, struct nova_bucket *src) {
	int i;
	for (i = 0; i < NOVA_TABLE_LEAF_SIZE; ++i)
		if (src->tags[i] != 0)
			nova_table_leaf_mm_insert(table, dst, src, i, src->disbyte[i]);
}
static inline bool
merged_bucket(struct nova_inner *inner, int i) {
	struct nova_bucket *bucket;
	if (nova_is_inner_node(inner->node_p[i]))
		return false;
	bucket = nova_node_p_to_bucket(inner->node_p[i]);
	return bucket->disbits < inner->bits;
}
static void
update_bucket_info(
	struct nova_mm_table *table,
	struct nova_bucket *bucket,
	int used_hash_bit)
{
	struct nova_pmm_entry *pentry;
	size_t shift = used_hash_bit - NOVA_TABLE_INNER_BITS + 1;
	int i;
	if (used_hash_bit == 0) // bucket is the root of a tablet.
		return;
	bucket->disbits = NOVA_TABLE_INNER_BITS;
	for (i = 0; i < NOVA_TABLE_LEAF_SIZE; ++i) {
		pentry = bucket->entry_p[i].pentry;
		bucket->disbyte[i] = (uint8_t)(pentry->fp.index >> shift);
	}
}
static void
handle_bucket_size_decrease(
	struct nova_mm_table *table,
	unsigned long * __restrict__ node_p,
	uint64_t index, int used_hash_bit)
{
	struct nova_inner *inner = nova_node_p_to_inner(*node_p);
	struct nova_bucket *bucket = nova_node_p_to_bucket(inner->node_p[index]);
	struct nova_bucket *sibling;
	int i;

	// printk("handle_bucket_size_decrease\n");
	index ^= (1 << (bucket->disbits - 1));
	if (nova_is_inner_node(inner->node_p[index]))	// inner node can not be merged.
		return;
	// printk("Sibling(%llu) is a bucket\n", index);
	sibling = nova_node_p_to_bucket(inner->node_p[index]);
	if (sibling->disbits != bucket->disbits)	// The sibling has been splitted more times.
		return;
	if (sibling->size + bucket->size > NOVA_TABLE_MERGE_THRESHOLD)
		return;
	// printk("Sibling mergable.\n");
	merge_bucket(table, bucket, sibling);
	for (i = index & ((1 << bucket->disbits) - 1);
		i < (1 << inner->bits);
		i += (1 << bucket->disbits)
	) {
		inner->node_p[i] = nova_bucket_to_node_p(bucket);
	}
	free_bucket(table, sibling);
	if (bucket->disbits == inner->bits)
		++inner->merged;
	--bucket->disbits;
	if (inner->merged != 1 << (inner->bits - 1))
		return;
	if (inner->bits == 1) {
		// printk("Delete the inner node.\n");
		update_bucket_info(table, bucket, used_hash_bit);
		*node_p = nova_bucket_to_node_p(bucket);
		nova_table_free_inner(table, inner);
		// Even if the new bucket has a sibling bucket whose size is 0,
		// the size of the new bucket is not 0,
		// so the next deletion in the new bucket will result in a mergence.
		return;
	}
	inner = inner_shrink(table, inner);
	*node_p = nova_inner_to_node_p(inner);
	inner->merged = 0;
	for (i = 0; i < (1 << (inner->bits - 1)); ++i) {
		if (merged_bucket(inner, i))
			++inner->merged;
	}
}

static int nova_table_recursive_upsert(
	struct nova_mm_table *table,
	unsigned long * __restrict__ node_p,
	struct nova_write_para_base *wp,
	int used_hash_bit,
	bucket_upsert_func bucket_upsert)
{
	int retval;
	uint64_t hash, index;
	struct nova_inner *inner;
	INIT_TIMING(split_time);

	if (nova_is_leaf_node(*node_p))
		return bucket_upsert(table, nova_node_p_to_bucket(*node_p), used_hash_bit, wp);
	if (unlikely(used_hash_bit == INDEX_BIT_NUM))
		return -EOVERFLOW;
	hash = wp->fp.index >> used_hash_bit;
retry:
	inner = nova_node_p_to_inner(*node_p);
	index = ((1 << inner->bits) - 1) & hash;
	retval = nova_table_recursive_upsert(table, inner->node_p + index,
		wp, used_hash_bit + NOVA_TABLE_INNER_BITS, bucket_upsert);

	if (likely(retval <= 0)) {
		return retval;
	} else if (retval == NOVA_DELETE_ENTRY) {
		handle_bucket_size_decrease(table, node_p, index, used_hash_bit);
		return 0;
	}
	BUG_ON(retval != NOVA_FULL);
	// printk(KERN_WARNING " fulled depth %d\n", depth);
	NOVA_START_TIMING(split_t, split_time);
	retval = __nova_table_split(table, node_p, index, used_hash_bit);
	NOVA_END_TIMING(split_t, split_time);
	if (retval)
		return retval;
	// printk(KERN_WARNING "retry\n");
	goto retry;
}

static int nova_table_upsert(
	struct nova_mm_table* table, 
	struct nova_write_para_base *wp,
	bucket_upsert_func bucket_upsert)
{
	int retval;
	unsigned long* node_p;
	uint64_t tablet = wp->fp.which_tablet;

	//printk(KERN_WARNING "tablet %llu, %llu\n", tablet, entry->fp_strong.u64s[0]);
	spin_lock(&table->tablets[tablet].lock);
retry:
	// printk("Step into tablet %lld", tablet);
	node_p = &table->tablets[tablet].node_p;
	retval = nova_table_recursive_upsert(table, node_p, wp, 0, bucket_upsert);
	if (retval == NOVA_FULL) {
		INIT_TIMING(split_time);
		// printk(KERN_WARNING " FULL tablets %llu, entry %llu\n",
		// 	tablet, entry->fp_strong.u64s[0]);

		NOVA_START_TIMING(split_t, split_time);
		retval = __nova_table_split_leaf(table, node_p, 0);
		NOVA_END_TIMING(split_t, split_time);
		if (0 == retval)
			goto  retry;
	}
	spin_unlock(&table->tablets[tablet].lock);
	return retval;
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
// Rebuild the hash table during failure recovery
static int nova_table_upsert_entry(struct nova_mm_table *table, struct nova_write_para_entry *wp)
{
	return nova_table_upsert(table, (struct nova_write_para_base *)wp, bucket_upsert_entry);
}

static int init_normal_wp_incr(struct nova_sb_info *sbi,
	struct nova_write_para_normal *wp, const void *addr)
{
	int ret = nova_fp_calc(&sbi->meta_table.fp_ctx, addr, &wp->base.fp);
	if (ret < 0)
		return ret;
	wp->addr = addr;
	wp->base.refcount = 1;
	return 0;
}
int nova_fp_table_incr(struct nova_mm_table *table, const void* addr,
	struct nova_write_para_normal *wp)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	INIT_TIMING(incr_ref_time);

	NOVA_START_TIMING(incr_ref_t, incr_ref_time);
	ret = init_normal_wp_incr(sbi, wp, addr);
	if (!(ret < 0))
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
	ret = init_normal_wp_incr(sbi, &wp->normal, addr);
	if (!(ret < 0)) {
		wp->normal.blocknr = blocknr;
		wp->offset = offset;
		wp->len = bytes;
		ret = nova_table_upsert_rewrite(table, wp);
	}
	NOVA_END_TIMING(incr_ref_t, incr_ref_time);
	return ret;
}

int nova_fp_table_upsert_entry(struct nova_mm_table *table,
	struct nova_pmm_entry *pentry)
{
	struct nova_write_para_entry wp;
	INIT_TIMING(upsert_fp_entry_time);
	int ret;

	NOVA_START_TIMING(upsert_fp_entry_t, upsert_fp_entry_time);
	wp.base.fp = pentry->fp;
	wp.base.refcount = 1;
	wp.pentry = pentry;
	ret = nova_table_upsert_entry(table, &wp);
	NOVA_END_TIMING(upsert_fp_entry_t, upsert_fp_entry_time);
	return ret;
}

static void __save_bucket(struct nova_mm_table *table,
	struct nova_bucket *bucket, atomic64_t *saved)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_entry_refcount_record *rec = nova_sbi_blocknr_to_addr(
		sbi, sbi->entry_refcount_record_start);
	unsigned long j;
	size_t head, top, len;
	struct nova_mm_entry_p *entry_p;
	unsigned long irq_flags = 0;

	// printk("%s: bucket->size = %hu\n", __func__, bucket->size);
	top = head = atomic64_add_return(bucket->size, saved) - bucket->size;
	len = bucket->size * sizeof(struct nova_entry_refcount_record);
	nova_memunlock_range(sb, rec + head, len, &irq_flags);
	for (j = 0; j < NOVA_TABLE_LEAF_SIZE; ++j) {
		if (bucket->tags[j]) {
			entry_p = bucket->entry_p + j;
			rec[top].entry_offset = cpu_to_le64(
				nova_get_addr_off(sbi, entry_p->pentry));
			++top;
		}
	}
	nova_memlock_range(sb, rec + head, len, &irq_flags);
	nova_flush_buffer(rec + head, len, false);
	BUG_ON(top != head + bucket->size);
}
static void save_bucket(struct nova_mm_table *table,
	struct nova_bucket *bucket, atomic64_t *saved)
{
	if (saved)
		__save_bucket(table, bucket, saved);
	free_bucket(table, bucket);
}
static void __nova_table_rescursive_save(
	struct nova_mm_table* table,
	struct nova_inner* inner,
	atomic64_t *saved,
	int depth/* for debug */)
{
	int i, j, n;
	unsigned long next;
	struct nova_bucket *bucket;

	// printk("__nova_table_rescursive_free: table = %pK, inner = %pK, depth = %d\n", table, inner, depth);
	n = (1 << inner->bits);
	for (i = 0; i < n; i++) {
		next = inner->node_p[i];
		if (nova_is_inner_node(next)) {
			__nova_table_rescursive_save(table, nova_node_p_to_inner(next), saved, depth+1);
			continue;
		}
		// next is a bucket
		if (next == 0) // Already handled
			continue;
		bucket = nova_node_p_to_bucket(next);
		j = i;
		while ((j += (1 << bucket->disbits)) < n) {
			BUG_ON(inner->node_p[j] == 0 || nova_is_inner_node(inner->node_p[j]));
			inner->node_p[j] = 0;
		}
		save_bucket(table, bucket, saved);
	}
	// printk("Going to free inners %pK", inner->inners);
	nova_table_free_inner(table, inner);
	// printk("return");
}

struct table_free_para {
	struct completion entered;
	struct nova_mm_table *table;
	atomic64_t *saved;
	size_t tablet_start, tablet_end;
};
static void __table_save_func(struct nova_mm_table *table,
	size_t tablet_start, size_t tablet_end, atomic64_t *saved)
{
	unsigned long next;
	size_t i;
	for (i = tablet_start; i < tablet_end; ++i) {
		next = table->tablets[i].node_p;
		if (nova_is_leaf_node(next))
			save_bucket(table, nova_node_p_to_bucket(next), saved);
		else
			__nova_table_rescursive_save(table, nova_node_p_to_inner(next), saved, 0);
	}
	PERSISTENT_BARRIER();
}
static int table_save_func(void *__para)
{
	struct table_free_para *para = (struct table_free_para *)__para;
	complete(&para->entered);
	__table_save_func(para->table, para->tablet_start, para->tablet_end,
		para->saved);
	// printk("%s waiting for kthread_stop\n", __func__);
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	return 0;
}
static int table_save_multithread(struct nova_mm_table *table, atomic64_t *saved)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long thread_num;
	unsigned long tablet_per_thread;
	struct table_free_para *para = NULL;
	struct task_struct **tasks = NULL;
	unsigned long i, base;
	int ret = 0, ret2;

	thread_num = sbi->cpus < table->nr_tablets ? sbi->cpus : table->nr_tablets;
	// if (thread_num > 8)
	// 	thread_num = 8;
	tablet_per_thread = (table->nr_tablets - 1) / thread_num + 1;
	thread_num = (table->nr_tablets - 1) / tablet_per_thread + 1;
	nova_info("Free fingerprint table using %lu threads\n", thread_num);
	para = kmalloc(thread_num * sizeof(struct table_free_para), GFP_KERNEL);
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
		para[i].saved = saved;
		para[i].tablet_start = base;
		base += tablet_per_thread;
		para[i].tablet_end = base < table->nr_tablets ? base : table->nr_tablets;
		tasks[i] = kthread_create(table_save_func, para + i,
			"nova_table_free_%lu", i);
		if (IS_ERR(tasks[i])) {
			ret = PTR_ERR(tasks[i]);
			nova_err(sb, "%lu: kthread_create %lu return %d\n",
				__func__, i, ret);
			break;
		}
	}
	ret2 = run_and_stop_kthreads(sb, tasks, para, thread_num, i);
	if (ret2 < 0)
		ret = ret2;
out:
	if (para)
		kfree(para);
	if (tasks)
		kfree(tasks);
	return ret;
}
static void table_save(struct nova_mm_table *table, atomic64_t *saved)
{
	if (table_save_multithread(table, saved) < 0) {
		nova_warn("%s: Fail to save the fingerprint table with multithread. Fall back to single thread.", __func__);
		__table_save_func(table, 0, table->nr_tablets, saved);
	}
}

static void __nova_table_save(struct nova_mm_table *table, atomic64_t *saved)
{
	table_save(table, saved);
	kmem_cache_destroy(table->bucket_cache);
	vfree(table->tablets);
}

void nova_table_free(struct nova_mm_table *table)
{
	__nova_table_save(table, NULL);
}
void nova_table_save(struct nova_mm_table* table)
{
	struct super_block *sb = table->sblock;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	atomic64_t __saved;
	uint64_t saved;
	INIT_TIMING(save_refcount_time);

	atomic64_set(&__saved, 0);
	NOVA_START_TIMING(save_refcount_t, save_refcount_time);
	__nova_table_save(table, &__saved);
	saved = atomic64_read(&__saved);
	nova_unlock_write(sb, &recover_meta->refcount_record_num, cpu_to_le64(saved), true);
	NOVA_END_TIMING(save_refcount_t, save_refcount_time);
	nova_info("Refcount of %llu entries saved.", saved);
}

int nova_table_init(struct super_block *sb, struct nova_mm_table *table) 
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *psb = (struct nova_super_block *)sbi->virt_addr;
	unsigned long nr_tablets = sbi->nr_tablets;
	int retval;
	unsigned long i = 0, j;
	struct nova_bucket *bucket;
	INIT_TIMING(table_init_time);

	NOVA_START_TIMING(table_init_t, table_init_time);
	printk("psb = %p, nr_tablets = %lu\n", psb, nr_tablets);

	table->tablets = vzalloc(sizeof(struct nova_mm_tablet) * nr_tablets);
	if (table->tablets == NULL) {
		retval = -ENOMEM;
		goto err_out;
	}
	printk("Static DRAM usage: %ld bytes\n",
		sizeof(struct nova_mm_tablet) * nr_tablets);

	table->sblock = sb;
	table->nr_tablets = nr_tablets;
	table->entry_allocator = &sbi->meta_table.entry_allocator;

	table->bucket_cache = kmem_cache_create("nova_bucket_cache", sizeof(struct nova_bucket), 0, TABLE_KMEM_CACHE_FLAGS, NULL);
	if (table->bucket_cache == NULL) {
		retval = -ENOMEM;
		goto err_out;
	}

	for (; i < nr_tablets; i++) {
		spin_lock_init(&table->tablets[i].lock);
		bucket = alloc_empty_bucket(table);
		if (bucket == NULL) {
			printk("OOM when allocating bucket!\n");
			retval = -ENOMEM;
			goto err_out;
		}
		bucket->disbits = 0;
		table->tablets[i].node_p = nova_bucket_to_node_p(bucket);
	}

	NOVA_END_TIMING(table_init_t, table_init_time);
	return 0;

err_out:
#ifdef FORBID_ERROR
	BUG_ON(1);
#endif
	for (j = 0; j < i; j++) {
		if (table->tablets[i].node_p) {
			bucket = nova_node_p_to_bucket(table->tablets[i].node_p);
			free_bucket(table, bucket);
		}
	}
	if (table->bucket_cache)
		kmem_cache_destroy(table->bucket_cache);

	vfree(table->tablets);
	NOVA_END_TIMING(table_init_t, table_init_time);
	return retval;
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
		wp.pentry = (struct nova_pmm_entry *)nova_sbi_get_block(sbi,
			le64_to_cpu(rec[i].entry_offset));
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

	nova_info("%lu refcount record found.\n", (unsigned long)n);
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
	ret2 = run_and_stop_kthreads(sb, tasks, para, thread_num, i);
	if (ret2 < 0)
		ret = ret2;
out:
	if (para)
		kfree(para);
	if (tasks)
		kfree(tasks);
	return ret;
}


static size_t node_height(unsigned long node_p) {
	size_t height, mx = 0;
	struct nova_inner *inner;
	int i;
	if (nova_is_leaf_node(node_p))
		return 1;
	inner = nova_node_p_to_inner(node_p);
	for (i = 0; i < (1 << inner->bits); ++i) {
		height = node_height(inner->node_p[i]);
		mx = mx < height ? height : mx;
	}
	return mx + 1;
}
static size_t nova_table_height(struct nova_mm_table *table) {
	size_t height, mx = 0;
	int i;
	for (i = 0; i < table->nr_tablets; ++i) {
		height = node_height(table->tablets[i].node_p);
		mx = mx < height ? height : mx;
	}
	return mx;
}
#define MERGED_CNT_MAX (NOVA_TABLE_INNER_SIZE / 2)
struct nova_inner_stat_info {
	uint64_t cnt;
	uint64_t bits_cnt[NOVA_TABLE_INNER_BITS + 1];
	uint64_t merged_cnt[MERGED_CNT_MAX + 1];
};
struct nova_bucket_stat_info {
	uint64_t cnt;
	uint64_t entry_cnt[NOVA_TABLE_LEAF_SIZE + 1];
	// uint64_t mask_cnt[NOVA_TABLE_INNER_BITS + 1];
	uint64_t delta_cnt[NOVA_TABLE_INNER_BITS + 1];
};
struct nova_stat_info {
	struct nova_inner_stat_info inner;
	struct nova_bucket_stat_info bucket;
};
static void update_inner_stat(const struct nova_inner *inner, struct nova_inner_stat_info *stat) {
	++stat->cnt;
	++stat->bits_cnt[inner->bits];
	++stat->merged_cnt[inner->merged];
}
static void update_bucket_stat(const struct nova_bucket *bucket, uint64_t bits, struct nova_bucket_stat_info *stat) {
	++stat->cnt;
	// ++stat->mask_cnt[maskbits];
	++stat->delta_cnt[bits - bucket->disbits];
	++stat->entry_cnt[bucket->size];
}
static void __nova_table_recursive_stat(unsigned long node_p, uint64_t bits, struct nova_stat_info *stats, size_t height)
{
	int i;
	if (nova_is_leaf_node(node_p)) {
		update_bucket_stat(nova_node_p_to_bucket(node_p), bits, &stats[height].bucket);
	} else {
		struct nova_inner *inner = nova_node_p_to_inner(node_p);
		update_inner_stat(inner, &stats[height].inner);
		for (i = 0; i < (1 << inner->bits); ++i) {
			__nova_table_recursive_stat(inner->node_p[i], inner->bits, stats, height + 1);
		}
	}
}
static inline void print_stat(struct nova_stat_info *stat) {
	int i;
	printk("(inner) cnt = %lld\nbits_cnt:", stat->inner.cnt);
	for (i = 0; i <= NOVA_TABLE_INNER_BITS; ++i)
		if (stat->inner.bits_cnt[i])
			printk(KERN_CONT " (%d)%lld", i, stat->inner.bits_cnt[i]);
	printk(KERN_CONT "\n");
	printk("merged_cnt:");
	for (i = 0; i <= MERGED_CNT_MAX; ++i)
		if (stat->inner.merged_cnt[i])
			printk(KERN_CONT " (%d)%lld", i, stat->inner.merged_cnt[i]);
	printk(KERN_CONT "\n");
	printk("(bucket) cnt = %lld\nentry_cnt:", stat->bucket.cnt);
	for (i = 0; i <= NOVA_TABLE_LEAF_SIZE; ++i)
		if (stat->bucket.entry_cnt[i])
			printk(KERN_CONT " (%d)%lld", i, stat->bucket.entry_cnt[i]);
	printk(KERN_CONT "\n");
	// printk("mask_cnt:");
	// for (i = 0; i <= NOVA_TABLE_INNER_BITS; ++i) {
	// 	printk(KERN_CONT " (%d)%lld", i, stat->bucket.mask_cnt[i]);
	// }
	// printk(KERN_CONT "\n");
	printk("delta_cnt(uniqued):");
	for (i = 0; i <= NOVA_TABLE_INNER_BITS; ++i) {
		BUG_ON(stat->bucket.delta_cnt[i] % (1 << i) != 0);
		printk(KERN_CONT " (%d)%lld", i, stat->bucket.delta_cnt[i] >> i);
	}
	printk(KERN_CONT "\n");
}
static int __nova_table_stats(struct nova_mm_table *table)
{
	uint64_t height = nova_table_height(table);
	struct nova_stat_info *stats;
	int i;
	printk("Height = %lld\n", height);
	stats = vzalloc(height * sizeof(struct nova_stat_info));
	if (stats == NULL) {
		printk("OOM in __nova_table_stats\n");
		return -ENOMEM;
	}
	for (i = 0; i < table->nr_tablets; ++i) {
		__nova_table_recursive_stat(table->tablets[i].node_p, 0, stats, 0);
	}
	for (i = 0; i < height; ++i) {
		printk("height = %d\n", i);
		print_stat(stats + i);
	}
	vfree(stats);
	return 0;
}
int nova_table_stats(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_meta_table *meta_table = &sbi->meta_table;
	struct nova_mm_table *table = &meta_table->metas;
	int ret = __nova_table_stats(table);
	if (ret < 0)
		return ret;
	return __nova_entry_allocator_stats(sbi, table->entry_allocator);
}
