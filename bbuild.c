/*
 * NOVA Recovery routines.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/fs.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/xarray.h>
#include "nova.h"
#include "journal.h"
#include "super.h"
#include "inode.h"
#include "log.h"
#include "multithread.h"
#include "xatable.h"
#include "arithmetic.h"

// #define static _Static_assert(1, "2333");

struct scan_bitmap {
	unsigned long bitmap_size;
	unsigned long *bitmap;
};

void nova_init_header(struct super_block *sb,
	struct nova_inode_info_header *sih, u16 i_mode)
{
	sih->log_pages = 0;
	sih->i_size = 0;
	sih->ino = 0;
	sih->i_blocks = 0;
	sih->pi_addr = 0;
	sih->alter_pi_addr = 0;
	INIT_RADIX_TREE(&sih->tree, GFP_ATOMIC);
	sih->rb_tree = RB_ROOT;
	sih->vma_tree = RB_ROOT;
	sih->num_vmas = 0;
	INIT_LIST_HEAD(&sih->list);
	sih->i_mode = i_mode;
	sih->i_flags = 0;
	sih->valid_entries = 0;
	sih->num_entries = 0;
	sih->last_setattr = 0;
	sih->last_link_change = 0;
	sih->last_dentry = 0;
	sih->trans_id = 0;
	sih->log_head = 0;
	sih->log_tail = 0;
	sih->alter_log_head = 0;
	sih->alter_log_tail = 0;
	sih->i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;
}

static inline int get_block_cpuid(struct nova_sb_info *sbi,
	unsigned long blocknr)
{
	return blocknr / sbi->per_list_blocks;
}

#if 0
static int nova_failure_insert_inodetree(struct super_block *sb,
	unsigned long ino_low, unsigned long ino_high)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	struct nova_range_node *prev = NULL, *next = NULL;
	struct nova_range_node *new_node;
	unsigned long internal_low, internal_high;
	int cpu;
	struct rb_root *tree;
	int ret;

	if (ino_low > ino_high) {
		nova_err(sb, "%s: ino low %lu, ino high %lu\n",
				__func__, ino_low, ino_high);
		BUG();
	}

	cpu = ino_low % sbi->cpus;
	if (ino_high % sbi->cpus != cpu) {
		nova_err(sb, "%s: ino low %lu, ino high %lu\n",
				__func__, ino_low, ino_high);
		BUG();
	}

	internal_low = ino_low / sbi->cpus;
	internal_high = ino_high / sbi->cpus;
	inode_map = &sbi->inode_maps[cpu];
	tree = &inode_map->inode_inuse_tree;
	mutex_lock(&inode_map->inode_table_mutex);

	ret = nova_find_free_slot(tree, internal_low, internal_high,
					&prev, &next);
	if (ret) {
		nova_dbg("%s: ino %lu - %lu already exists!: %d\n",
					__func__, ino_low, ino_high, ret);
		mutex_unlock(&inode_map->inode_table_mutex);
		return ret;
	}

	if (prev && next && (internal_low == prev->range_high + 1) &&
			(internal_high + 1 == next->range_low)) {
		/* fits the hole */
		rb_erase(&next->node, tree);
		inode_map->num_range_node_inode--;
		prev->range_high = next->range_high;
		nova_update_range_node_checksum(prev);
		nova_free_inode_node(next);
		goto finish;
	}
	if (prev && (internal_low == prev->range_high + 1)) {
		/* Aligns left */
		prev->range_high += internal_high - internal_low + 1;
		nova_update_range_node_checksum(prev);
		goto finish;
	}
	if (next && (internal_high + 1 == next->range_low)) {
		/* Aligns right */
		next->range_low -= internal_high - internal_low + 1;
		nova_update_range_node_checksum(next);
		goto finish;
	}

	/* Aligns somewhere in the middle */
	new_node = nova_alloc_inode_node(sb);
	NOVA_ASSERT(new_node);
	new_node->range_low = internal_low;
	new_node->range_high = internal_high;
	nova_update_range_node_checksum(new_node);
	ret = nova_insert_inodetree(sbi, new_node, cpu);
	if (ret) {
		nova_err(sb, "%s failed\n", __func__);
		nova_free_inode_node(new_node);
		goto finish;
	}
	inode_map->num_range_node_inode++;

finish:
	mutex_unlock(&inode_map->inode_table_mutex);
	return ret;
}

static void nova_destroy_blocknode_tree(struct super_block *sb, int cpu)
{
	struct free_list *free_list;

	free_list = nova_get_free_list(sb, cpu);
	nova_destroy_range_node_tree(sb, &free_list->block_free_tree);
}

static void nova_destroy_blocknode_trees(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int i;

	for (i = 0; i < sbi->cpus; i++)
		nova_destroy_blocknode_tree(sb, i);

}

static int nova_init_blockmap_from_inode(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	struct nova_inode_info_header sih;
	struct free_list *free_list;
	struct nova_range_node_lowhigh *entry;
	struct nova_range_node *blknode;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	u64 curr_p;
	u64 cpuid;
	int ret = 0;

	/* FIXME: Backup inode for BLOCKNODE */
	ret = nova_get_head_tail(sb, pi, &sih);
	if (ret)
		goto out;

	sih.ino = NOVA_BLOCKNODE_INO;
	curr_p = sih.log_head;
	if (curr_p == 0) {
		nova_dbg("%s: pi head is 0!\n", __func__);
		return -EINVAL;
	}

	while (curr_p != sih.log_tail) {
		if (is_last_entry(curr_p, size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_dbg("%s: curr_p is NULL!\n", __func__);
			NOVA_ASSERT(0);
			ret = -EINVAL;
			break;
		}

		entry = (struct nova_range_node_lowhigh *)nova_get_block(sb,
							curr_p);
		blknode = nova_alloc_blocknode(sb);
		if (blknode == NULL)
			NOVA_ASSERT(0);
		blknode->range_low = le64_to_cpu(entry->range_low);
		blknode->range_high = le64_to_cpu(entry->range_high);
		nova_update_range_node_checksum(blknode);
		cpuid = get_block_cpuid(sbi, blknode->range_low);

		/* FIXME: Assume NR_CPUS not change */
		free_list = nova_get_free_list(sb, cpuid);
		ret = nova_insert_blocktree(&free_list->block_free_tree,
						blknode);
		if (ret) {
			nova_err(sb, "%s failed\n", __func__);
			nova_free_blocknode(blknode);
			NOVA_ASSERT(0);
			nova_destroy_blocknode_trees(sb);
			goto out;
		}
		free_list->num_blocknode++;
		if (free_list->num_blocknode == 1)
			free_list->first_node = blknode;
		free_list->last_node = blknode;
		free_list->num_free_blocks +=
			blknode->range_high - blknode->range_low + 1;
		curr_p += sizeof(struct nova_range_node_lowhigh);
	}
out:
	nova_free_inode_log(sb, pi, &sih);
	return ret;
}

static void nova_destroy_inode_trees(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		nova_destroy_range_node_tree(sb,
					&inode_map->inode_inuse_tree);
	}
}

#define CPUID_MASK 0xff00000000000000

static int nova_init_inode_list_from_inode(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_INODELIST_INO);
	struct nova_inode_info_header sih;
	struct nova_range_node_lowhigh *entry;
	struct nova_range_node *range_node;
	struct inode_map *inode_map;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	unsigned long num_inode_node = 0;
	u64 curr_p;
	unsigned long cpuid;
	int ret;

	/* FIXME: Backup inode for INODELIST */
	ret = nova_get_head_tail(sb, pi, &sih);
	if (ret)
		goto out;

	sih.ino = NOVA_INODELIST_INO;
	sbi->s_inodes_used_count = 0;
	curr_p = sih.log_head;
	if (curr_p == 0) {
		nova_dbg("%s: pi head is 0!\n", __func__);
		return -EINVAL;
	}

	while (curr_p != sih.log_tail) {
		if (is_last_entry(curr_p, size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_dbg("%s: curr_p is NULL!\n", __func__);
			NOVA_ASSERT(0);
		}

		entry = (struct nova_range_node_lowhigh *)nova_get_block(sb,
							curr_p);
		range_node = nova_alloc_inode_node(sb);
		if (range_node == NULL)
			NOVA_ASSERT(0);

		cpuid = (entry->range_low & CPUID_MASK) >> 56;
		if (cpuid >= sbi->cpus) {
			nova_err(sb, "Invalid cpuid %lu\n", cpuid);
			nova_free_inode_node(range_node);
			NOVA_ASSERT(0);
			nova_destroy_inode_trees(sb);
			goto out;
		}

		range_node->range_low = entry->range_low & ~CPUID_MASK;
		range_node->range_high = entry->range_high;
		nova_update_range_node_checksum(range_node);
		ret = nova_insert_inodetree(sbi, range_node, cpuid);
		if (ret) {
			nova_err(sb, "%s failed, %d\n", __func__, cpuid);
			nova_free_inode_node(range_node);
			NOVA_ASSERT(0);
			nova_destroy_inode_trees(sb);
			goto out;
		}

		sbi->s_inodes_used_count +=
			range_node->range_high - range_node->range_low + 1;
		num_inode_node++;

		inode_map = &sbi->inode_maps[cpuid];
		inode_map->num_range_node_inode++;
		if (!inode_map->first_inode_range)
			inode_map->first_inode_range = range_node;

		curr_p += sizeof(struct nova_range_node_lowhigh);
	}

	nova_dbg("%s: %lu inode nodes\n", __func__, num_inode_node);
out:
	nova_free_inode_log(sb, pi, &sih);
	return ret;
}
#endif

static u64 nova_append_range_node_entry(struct super_block *sb,
	struct nova_range_node *curr, u64 tail, unsigned long cpuid)
{
	u64 curr_p;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	struct nova_range_node_lowhigh *entry;
	unsigned long irq_flags = 0;

	curr_p = tail;

	if (!nova_range_node_checksum_ok(curr)) {
		nova_dbg("%s: range node checksum failure\n", __func__);
		goto out;
	}

	if (curr_p == 0 || (is_last_entry(curr_p, size) &&
				next_log_page(sb, curr_p) == 0)) {
		nova_dbg("%s: inode log reaches end?\n", __func__);
		goto out;
	}

	if (is_last_entry(curr_p, size))
		curr_p = next_log_page(sb, curr_p);

	entry = (struct nova_range_node_lowhigh *)nova_get_block(sb, curr_p);
	nova_memunlock_range(sb, entry, size, &irq_flags);
	entry->range_low = cpu_to_le64(curr->range_low);
	if (cpuid)
		entry->range_low |= cpu_to_le64(cpuid << 56);
	entry->range_high = cpu_to_le64(curr->range_high);
	nova_memlock_range(sb, entry, size, &irq_flags);
	nova_dbgv("append entry block low 0x%lx, high 0x%lx\n",
			curr->range_low, curr->range_high);

	nova_flush_buffer(entry, sizeof(struct nova_range_node_lowhigh), 0);
out:
	return curr_p;
}

static u64 nova_save_range_nodes_to_log(struct super_block *sb,
	struct rb_root *tree, u64 temp_tail, unsigned long cpuid)
{
	struct nova_range_node *curr;
	struct rb_node *temp;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	u64 curr_entry = 0;

	/* Save in increasing order */
	temp = rb_first(tree);
	while (temp) {
		curr = container_of(temp, struct nova_range_node, node);
		curr_entry = nova_append_range_node_entry(sb, curr,
						temp_tail, cpuid);
		temp_tail = curr_entry + size;
		temp = rb_next(temp);
		rb_erase(&curr->node, tree);
		nova_free_range_node(curr);
	}

	return temp_tail;
}

static u64 nova_save_free_list_blocknodes(struct super_block *sb, int cpu,
	u64 temp_tail)
{
	struct free_list *free_list;

	free_list = nova_get_free_list(sb, cpu);
	temp_tail = nova_save_range_nodes_to_log(sb,
				&free_list->block_free_tree, temp_tail, 0);
	return temp_tail;
}

void nova_save_inode_list_to_log(struct super_block *sb)
{
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_INODELIST_INO);
	struct nova_inode_info_header sih;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long num_blocks;
	unsigned long num_nodes = 0;
	struct inode_map *inode_map;
	unsigned long i;
	u64 temp_tail;
	u64 new_block;
	int allocated;
	unsigned long irq_flags = 0;

	sih.ino = NOVA_INODELIST_INO;
	sih.i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;
	sih.i_blocks = 0;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		num_nodes += inode_map->num_range_node_inode;
	}

	num_blocks = num_nodes / RANGENODE_PER_PAGE;
	if (num_nodes % RANGENODE_PER_PAGE)
		num_blocks++;

	allocated = nova_allocate_inode_log_pages(sb, &sih, num_blocks,
						&new_block, ANY_CPU, 0);
	if (allocated != num_blocks) {
		nova_dbg("Error saving inode list: %d\n", allocated);
		return;
	}

	temp_tail = new_block;
	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		temp_tail = nova_save_range_nodes_to_log(sb,
				&inode_map->inode_inuse_tree, temp_tail, i);
	}

	nova_memunlock_inode(sb, pi, &irq_flags);
	pi->alter_log_head = pi->alter_log_tail = 0;
	pi->log_head = new_block;
	nova_update_tail(pi, temp_tail);
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);
	nova_memlock_inode(sb, pi, &irq_flags);

	nova_dbg("%s: %lu inode nodes, pi head 0x%llx, tail 0x%llx\n",
		__func__, num_nodes, pi->log_head, pi->log_tail);
}

void nova_save_blocknode_mappings_to_log(struct super_block *sb)
{
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	struct nova_inode_info_header sih;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long num_blocknode = 0;
	unsigned long num_pages;
	int allocated;
	u64 new_block = 0;
	u64 temp_tail;
	int i;
	unsigned long irq_flags = 0;

	sih.ino = NOVA_BLOCKNODE_INO;
	sih.i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;

	/* Allocate log pages before save blocknode mappings */
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		num_blocknode += free_list->num_blocknode;
		nova_dbgv("%s: free list %d: %lu nodes\n", __func__,
				i, free_list->num_blocknode);
	}

	num_pages = num_blocknode / RANGENODE_PER_PAGE;
	if (num_blocknode % RANGENODE_PER_PAGE)
		num_pages++;

	allocated = nova_allocate_inode_log_pages(sb, &sih, num_pages,
						&new_block, ANY_CPU, 0);
	if (allocated != num_pages) {
		nova_dbg("Error saving blocknode mappings: %d\n", allocated);
		return;
	}

	temp_tail = new_block;
	for (i = 0; i < sbi->cpus; i++)
		temp_tail = nova_save_free_list_blocknodes(sb, i, temp_tail);

	/* Finally update log head and tail */
	nova_memunlock_inode(sb, pi, &irq_flags);
	pi->alter_log_head = pi->alter_log_tail = 0;
	pi->log_head = new_block;
	nova_update_tail(pi, temp_tail);
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);
	nova_memlock_inode(sb, pi, &irq_flags);

	nova_dbg("%s: %lu blocknodes, %lu log pages, pi head 0x%llx, tail 0x%llx\n",
		  __func__, num_blocknode, num_pages,
		  pi->log_head, pi->log_tail);
}

#if 0
static int nova_insert_blocknode_map(struct super_block *sb,
	int cpuid, unsigned long low, unsigned long high)
{
	struct free_list *free_list;
	struct rb_root *tree;
	struct nova_range_node *blknode = NULL;
	unsigned long num_blocks = 0;
	int ret;

	num_blocks = high - low + 1;
	nova_dbgv("%s: cpu %d, low %lu, high %lu, num %lu\n",
		__func__, cpuid, low, high, num_blocks);
	free_list = nova_get_free_list(sb, cpuid);
	tree = &(free_list->block_free_tree);

	blknode = nova_alloc_blocknode(sb);
	if (blknode == NULL)
		return -ENOMEM;
	blknode->range_low = low;
	blknode->range_high = high;
	nova_update_range_node_checksum(blknode);
	ret = nova_insert_blocktree(tree, blknode);
	if (ret) {
		nova_err(sb, "%s failed\n", __func__);
		nova_free_blocknode(blknode);
		goto out;
	}
	if (!free_list->first_node)
		free_list->first_node = blknode;
	free_list->last_node = blknode;
	free_list->num_blocknode++;
	free_list->num_free_blocks += num_blocks;
out:
	return ret;
}

static int __nova_build_blocknode_map(struct super_block *sb,
	unsigned long *bitmap, unsigned long bsize, unsigned long scale)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long next = 0;
	unsigned long low = 0;
	unsigned long start, end;
	int cpuid = 0;

	free_list = nova_get_free_list(sb, cpuid);
	start = free_list->block_start;
	end = free_list->block_end + 1;
	while (1) {
		next = find_next_zero_bit(bitmap, end, start);
		if (next == bsize)
			break;
		if (next == end) {
			if (cpuid == sbi->cpus - 1)
				break;

			cpuid++;
			free_list = nova_get_free_list(sb, cpuid);
			start = free_list->block_start;
			end = free_list->block_end + 1;
			continue;
		}

		low = next;
		next = find_next_bit(bitmap, end, next);
		if (nova_insert_blocknode_map(sb, cpuid,
				low << scale, (next << scale) - 1)) {
			nova_dbg("Error: could not insert %lu - %lu\n",
				low << scale, ((next << scale) - 1));
		}
		start = next;
		if (next == bsize)
			break;
		if (next == end) {
			if (cpuid == sbi->cpus - 1)
				break;

			cpuid++;
			free_list = nova_get_free_list(sb, cpuid);
			start = free_list->block_start;
			end = free_list->block_end + 1;
		}
	}
	return 0;
}

struct failure_recovery_info {
	struct scan_bitmap *global_bm;
	struct nova_mm_table *fp_table;
	struct xatable map_blocknr_pentry;
};

struct invalidate_unused_fp_entry_para {
	struct completion entered;
	struct nova_sb_info *sbi;
	struct scan_bitmap *final_bm;
	struct xatable *map_blocknr_pentry;
	atomic64_t *cur_xa;
};
static void __invalidate_unused_fp_entry_xa(
	struct nova_sb_info *sbi,
	struct scan_bitmap *final_bm,
	struct xatable *map_blocknr_pentry,
	unsigned long i)
{
	struct entry_allocator *allocator = &sbi->meta_table.entry_allocator;
	unsigned long index, blocknr;
	struct nova_pmm_entry *pentry;

	xa_for_each(map_blocknr_pentry->xa + i, index, pentry) {
		blocknr = (index << map_blocknr_pentry->num_bit) + i;
		BUG_ON(blocknr >= sbi->num_blocks);
		if (test_bit(blocknr, final_bm->bitmap))
			continue;
		// Unused. Invalidate the fp_entry.
		// TODO: Actually no need to use spin_lock_bh inside
		nova_free_entry(allocator, pentry);
	}
}
static void __invalidate_unused_fp_entry_func(
	struct nova_sb_info *sbi,
	struct scan_bitmap *final_bm,
	struct xatable *map_blocknr_pentry,
	atomic64_t *cur_xa)
{
	u64 i;
	while (1) {
		i = atomic64_add_return(1, cur_xa);
		if (i >= (1UL << map_blocknr_pentry->num_bit))
			break;
		__invalidate_unused_fp_entry_xa(sbi, final_bm, map_blocknr_pentry, i);
	}
}
static int invalidate_unused_fp_entry_func(void *__para)
{
	struct invalidate_unused_fp_entry_para *para =
		(struct invalidate_unused_fp_entry_para *)__para;
	// printk("%s\n", __func__);
	complete(&para->entered);
	__invalidate_unused_fp_entry_func(para->sbi,
		para->final_bm, para->map_blocknr_pentry, para->cur_xa);
	// printk("%s waiting for kthread_stop\n", __func__);
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	return 0;
}
static int invalidate_unused_fp_entry(
	struct super_block *sb,
	struct xatable *map_blocknr_pentry,
	struct scan_bitmap *final_bm)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long i, thread_num = sbi->cpus;
	struct invalidate_unused_fp_entry_para *para = NULL;
	struct task_struct **tasks = NULL;
	atomic64_t cur_xa;
	int ret = 0, ret2;
	INIT_TIMING(time);

	NOVA_START_TIMING(invalidate_unused_fp_entry_t, time);
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
	atomic64_set(&cur_xa, -1);
	for (i = 0; i < thread_num; ++i) {
		init_completion(&para[i].entered);
		para[i].sbi = sbi;
		para[i].final_bm = final_bm;
		para[i].map_blocknr_pentry = map_blocknr_pentry;
		para[i].cur_xa = &cur_xa;
		tasks[i] = kthread_create(invalidate_unused_fp_entry_func, para + i,
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
	NOVA_END_TIMING(invalidate_unused_fp_entry_t, time);
	return ret;
}
static int nova_build_blocknode_map(struct super_block *sb,
	struct failure_recovery_info *info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *super = sbi->nova_sb;
	unsigned long initsize = le64_to_cpu(super->s_size);
	struct scan_bitmap *bm;
	struct scan_bitmap *final_bm;
	unsigned long *src, *dst;
	int i, j;
	int num;
	int ret;

	final_bm = kzalloc(sizeof(struct scan_bitmap), GFP_KERNEL);
	if (!final_bm)
		return -ENOMEM;

	final_bm->bitmap_size =
				(initsize >> (PAGE_SHIFT + 0x3));

	/* Alloc memory to hold the block alloc bitmap */
	final_bm->bitmap = kvzalloc(final_bm->bitmap_size, GFP_KERNEL);

	if (!final_bm->bitmap) {
		kfree(final_bm);
		return -ENOMEM;
	}

	/* Merge per-CPU bms to the final single bm */
	num = final_bm->bitmap_size / sizeof(unsigned long);
	if (final_bm->bitmap_size % sizeof(unsigned long))
		num++;

	for (i = 0; i < sbi->cpus; i++) {
		bm = info->global_bm + i;
		src = (unsigned long *)bm->bitmap;
		dst = (unsigned long *)final_bm->bitmap;

		for (j = 0; j < num; j++)
			dst[j] |= src[j];
	}

	ret = __nova_build_blocknode_map(sb, final_bm->bitmap,
			final_bm->bitmap_size * 8, PAGE_SHIFT - 12);
	if (ret < 0)
		goto out;
	ret = invalidate_unused_fp_entry(sb, &info->map_blocknr_pentry, final_bm);
out:
	kvfree(final_bm->bitmap);
	kfree(final_bm);

	return ret;
}

static struct scan_bitmap *
alloc_bm(struct nova_sb_info *sbi)
{
	struct nova_super_block *super = sbi->nova_sb;
	unsigned long initsize = le64_to_cpu(super->s_size);
	struct scan_bitmap *global_bm;
	struct scan_bitmap *bm;
	int i, j;

	global_bm = kmalloc(sbi->cpus * sizeof(struct scan_bitmap), GFP_KERNEL);
	if (global_bm == NULL)
		return ERR_PTR(-ENOMEM);
	for (i = 0; i < sbi->cpus; i++) {
		bm = global_bm + i;

		bm->bitmap_size =
				(initsize >> (PAGE_SHIFT + 0x3));

		/* Alloc memory to hold the block alloc bitmap */
		bm->bitmap = kvzalloc(bm->bitmap_size, GFP_KERNEL);

		if (!bm->bitmap)
			break;
	}
	if (i != sbi->cpus) {
		for (j = 0; j < i; ++j)
			vfree(global_bm[j].bitmap);
		kfree(global_bm);
		return ERR_PTR(-ENOMEM);
	}
	return global_bm;
}
static inline void free_bm(struct nova_sb_info *sbi,
	struct scan_bitmap *global_bm)
{
	int i;
	for (i = 0; i < sbi->cpus; i++)
		kvfree(global_bm[i].bitmap);
	kfree(global_bm);
}

static int alloc_failure_recovery_info(struct super_block *sb,
	struct failure_recovery_info *info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_meta_table *table = &sbi->meta_table;
	struct entry_allocator *allocator = &table->entry_allocator;
	struct xatable *xat = &info->map_blocknr_pentry;
	size_t tot;
	int ret;
	INIT_TIMING(scan_fp_entry_table_time);

	ret = xatable_init(xat, ceil_log_2(sbi->cpus) + 1);
	if (ret < 0)
		goto err_out0;

	info->global_bm = alloc_bm(sbi);
	if (IS_ERR(info->global_bm)) {
		ret = PTR_ERR(info->global_bm);
		goto err_out1;
	}

	NOVA_START_TIMING(scan_fp_entry_table_t, scan_fp_entry_table_time);
	ret = nova_scan_entry_table(sb, allocator, xat,
		info->global_bm[0].bitmap, &tot);
	NOVA_END_TIMING(scan_fp_entry_table_t, scan_fp_entry_table_time);
	if (ret < 0)
		goto err_out2;

	ret = nova_meta_table_alloc(table, sb, tot);
	if (ret < 0)
		goto err_out3;
	info->fp_table = &table->metas;
	return 0;
err_out3:
	nova_meta_table_free(table);
err_out2:
	free_bm(sbi, info->global_bm);
err_out1:
	xatable_destroy(xat);
err_out0:
	return ret;
}

static void free_failure_recovery_info(struct nova_sb_info *sbi, struct failure_recovery_info *info)
{
	xatable_destroy(&info->map_blocknr_pentry);
	free_bm(sbi, info->global_bm);
}
static void free_all_failure_recovery_info(struct nova_sb_info *sbi, struct failure_recovery_info *info)
{
	struct nova_meta_table *table = &sbi->meta_table;
	struct entry_allocator *allocator = &table->entry_allocator;
	free_failure_recovery_info(sbi, info);
	nova_meta_table_free(table);
	nova_free_entry_allocator(allocator);
}

static int upsert_blocknr(unsigned long blocknr, struct failure_recovery_info *info)
{
	struct xatable *xat = &info->map_blocknr_pentry;
	struct nova_mm_table *fp_table = info->fp_table;
	struct super_block *sb = fp_table->sblock;
	struct nova_pmm_entry *pentry;
	uint64_t refcount;
	unsigned long irq_flags = 0;
	int ret;

	pentry = (struct nova_pmm_entry *)xatable_load(xat, blocknr);
	if (pentry == NULL)
		return 0;
	nova_memunlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
		&irq_flags);
	refcount = atomic64_add_return(1, &pentry->refcount);
	nova_memlock_range(sb, &pentry->refcount, sizeof(pentry->refcount),
		&irq_flags);
	nova_flush_entry(fp_table->entry_allocator, pentry);
	if (refcount == 1) {
		ret = nova_table_insert_entry(fp_table, pentry->fp,
			pentry);
		if (ret < 0)
			return ret;
	}
	return 0;
}
static int
set_bm(unsigned long blocknr, struct failure_recovery_info *info, int cpuid)
{
	struct scan_bitmap *bm = info->global_bm + cpuid;
	set_bit(blocknr, bm->bitmap);
	return upsert_blocknr(blocknr, info);
}

/************************** NOVA recovery ****************************/

struct task_ring {
	u64 addr0[512];
	u64 addr1[512];		/* Second inode address */
	int num;
	int inodes_used_count;
	struct xarray entry_array;
};

static struct task_ring *task_rings;

static int nova_traverse_inode_log(struct super_block *sb,
	struct nova_inode *pi, u64 head,
	struct failure_recovery_info *info, int cpuid)
{
	u64 curr_p;
	u64 next;
	int ret;

	curr_p = head;

	if (curr_p == 0)
		return 0;

	BUG_ON(curr_p & (PAGE_SIZE - 1));
	ret = set_bm(curr_p >> PAGE_SHIFT, info, cpuid);
	if (ret < 0)
		return ret;

	next = next_log_page(sb, curr_p);
	while (next > 0) {
		curr_p = next;
		BUG_ON(curr_p & (PAGE_SIZE - 1));
		ret = set_bm(curr_p >> PAGE_SHIFT, info, cpuid);
		if (ret < 0)
			return ret;
		next = next_log_page(sb, curr_p);
	}

	return 0;
}

static int nova_traverse_dir_inode_log(struct super_block *sb,
	struct nova_inode *pi, struct failure_recovery_info *info, int cpuid)
{
	int ret = nova_traverse_inode_log(sb, pi, pi->log_head, info, cpuid);
	if (ret < 0)
		return ret;
	if (metadata_csum) {
		ret = nova_traverse_inode_log(sb, pi, pi->alter_log_head, info, cpuid);
		if (ret < 0)
			return ret;
	}
	return 0;
}

/*
 * retval > 0: Deletable?
 * retval == 0: Not deletable?
 * retval < 0: Error code.
 */
static int nova_check_old_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long pgoff,
	u64 epoch_id,
	struct failure_recovery_info *info, int cpuid)
{
	struct nova_file_write_entry *entryc, entry_copy;
	unsigned long old_nvmm;
	int ret;

	if (!entry)
		return 0;

	if (metadata_csum == 0)
		entryc = entry;
	else {
		entryc = &entry_copy;
		if (!nova_verify_entry_csum(sb, entry, entryc))
			return 0;
	}

	old_nvmm = get_nvmm(sb, sih, entryc, pgoff);

	ret = nova_append_data_to_snapshot(sb, entryc, old_nvmm,
				epoch_id);

	if (ret != 0)
		return ret;

	if (old_nvmm) {
		ret = set_bm(old_nvmm, info, cpuid);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int nova_set_ring_array(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	struct nova_file_write_entry *entryc, struct task_ring *ring,
	struct failure_recovery_info *info, int cpuid)
{
	unsigned long pgoff = entryc->pgoff;
	u64 epoch_id = entryc->epoch_id;
	void *xa_ret;
	int ret;

	xa_ret = xa_store(&ring->entry_array, pgoff, xa_tag_pointer(entry, 0), GFP_KERNEL);
	if (xa_is_err(xa_ret))
		return xa_err(xa_ret);
	entry = xa_untag_pointer(xa_ret);
	if (entry) {
		ret = nova_check_old_entry(sb, sih, entry, pgoff, epoch_id, info, cpuid);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int nova_set_file_bm(struct super_block *sb,
	struct nova_inode_info_header *sih, struct task_ring *ring,
	struct failure_recovery_info *info, int cpuid,
	unsigned long last_blocknr)
{
	struct nova_file_write_entry *entry;
	unsigned long nvmm, pgoff;
	int ret;

	for (pgoff = 0; pgoff <= last_blocknr; pgoff++) {
		entry = xa_untag_pointer(xa_erase(&ring->entry_array, pgoff));
		if (entry) {
			nvmm = get_nvmm(sb, sih, entry, pgoff);
			ret = set_bm(nvmm, info, cpuid);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

/* entry given to this function is a copy in dram */
static int nova_ring_setattr_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_setattr_logentry *entry, struct task_ring *ring,
	unsigned int data_bits, struct failure_recovery_info *info, int cpuid)
{
	unsigned long first_blocknr, last_blocknr;
	unsigned long pgoff;
	loff_t start, end;
	u64 epoch_id = entry->epoch_id;
	struct nova_file_write_entry *old_entry;
	int ret;

	if (sih->i_size <= entry->size)
		goto out;

	start = entry->size;
	end = sih->i_size;

	first_blocknr = (start + (1UL << data_bits) - 1) >> data_bits;

	if (end > 0)
		last_blocknr = (end - 1) >> data_bits;
	else
		last_blocknr = 0;

	if (first_blocknr > last_blocknr)
		goto out;

	for (pgoff = first_blocknr; pgoff <= last_blocknr; pgoff++) {
		old_entry = xa_untag_pointer(xa_erase(&ring->entry_array, pgoff));
		if (old_entry) {
			ret = nova_check_old_entry(sb, sih, old_entry,
					pgoff, epoch_id, info, cpuid);
			if (ret < 0)
				return ret;
		}
	}
out:
	sih->i_size = entry->size;
	return 0;
}

static long nova_traverse_file_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	struct nova_file_write_entry *entryc, struct task_ring *ring,
	struct failure_recovery_info *info, int cpuid)
{
	unsigned long max_blocknr = 0;
	int ret;
	sih->i_size = entryc->size;

	if (!entryc->invalid) {
		max_blocknr = entryc->pgoff;
		ret = nova_set_ring_array(sb, sih, entry, entryc,
					ring, info, cpuid);
		if (ret < 0)
			return ret;
	}

	return max_blocknr;
}

static int nova_traverse_file_inode_log(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	struct task_ring *ring, struct failure_recovery_info *info, int cpuid)
{
	char entry_copy[NOVA_MAX_ENTRY_LEN];
	unsigned long last_blocknr = 0;
	long curr_last;
	u64 ino = pi->nova_ino;
	void *entry, *entryc;
	unsigned int btype;
	unsigned int data_bits;
	u64 curr_p;
	u64 next;
	u8 type;
	int ret;

	btype = pi->i_blk_type;
	data_bits = blk_type_to_shift[btype];

	if (metadata_csum) {
		ret = nova_traverse_inode_log(sb, pi, pi->alter_log_head, info, cpuid);
		if (ret < 0)
			return ret;
	}

	entryc = (metadata_csum == 0) ? NULL : entry_copy;

	curr_p = pi->log_head;
	nova_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
				curr_p, pi->log_tail);
	if (curr_p == 0 || pi->log_tail == 0) {
		nova_warn("NULL log pointer(s) in file inode %llu\n", ino);
		pi->log_head = 0;
		pi->log_tail = 0;
		nova_flush_buffer(pi, sizeof(struct nova_inode), 1);
		return 0;
	}


	BUG_ON(curr_p & (PAGE_SIZE - 1));
	ret = set_bm(curr_p >> PAGE_SHIFT, info, cpuid);
	if (ret < 0)
		return ret;

	while (curr_p != pi->log_tail) {
		if (goto_next_page(sb, curr_p)) {
			curr_p = next_log_page(sb, curr_p);
			BUG_ON(curr_p & (PAGE_SIZE - 1));
			ret = set_bm(curr_p >> PAGE_SHIFT, info, cpuid);
			if (ret < 0)
				return ret;
		}

		if (curr_p == 0) {
			nova_err(sb, "File inode %llu log is NULL!\n", ino);
			BUG();
		}

		entry = (void *)nova_get_block(sb, curr_p);

		if (metadata_csum == 0)
			entryc = entry;
		else if (!nova_verify_entry_csum(sb, entry, entryc))
			return 0;

		type = nova_get_entry_type(entryc);
		switch (type) {
		case SET_ATTR:
			ret = nova_ring_setattr_entry(sb, sih, SENTRY(entryc),
						ring, data_bits,
						info, cpuid);
			if (ret < 0)
				return ret;
			curr_p += sizeof(struct nova_setattr_logentry);
			break;
		case LINK_CHANGE:
			curr_p += sizeof(struct nova_link_change_entry);
			break;
		case FILE_WRITE:
			curr_last = nova_traverse_file_write_entry(sb, sih, WENTRY(entry),
						WENTRY(entryc), ring, info, cpuid);
			if (curr_last < 0)
				return curr_last;
			curr_p += sizeof(struct nova_file_write_entry);
			if (last_blocknr < curr_last)
				last_blocknr = curr_last;
			break;
		case MMAP_WRITE:
			curr_p += sizeof(struct nova_mmap_entry);
			break;
		default:
			nova_dbg("%s: unknown type %d, 0x%llx\n",
						__func__, type, curr_p);
			NOVA_ASSERT(0);
			BUG();
		}

	}

	/* Keep traversing until log ends */
	curr_p &= PAGE_MASK;
	next = next_log_page(sb, curr_p);
	while (next > 0) {
		curr_p = next;
		BUG_ON(curr_p & (PAGE_SIZE - 1));
		ret = set_bm(curr_p >> PAGE_SHIFT, info, cpuid);
		if (ret < 0)
			return ret;
		next = next_log_page(sb, curr_p);
	}

	return nova_set_file_bm(sb, sih, ring, info, cpuid, last_blocknr);
}

/* Pi is DRAM fake version */
static int nova_recover_inode_pages(struct super_block *sb,
	struct nova_inode_info_header *sih, struct task_ring *ring,
	struct nova_inode *pi, struct failure_recovery_info *info, int cpuid)
{
	unsigned long nova_ino;
	int ret = 0;

	if (pi->deleted == 1)
		return 0;

	nova_ino = pi->nova_ino;
	ring->inodes_used_count++;

	sih->i_mode = __le16_to_cpu(pi->i_mode);
	sih->ino = nova_ino;

	nova_dbgv("%s: inode %lu, head 0x%llx, tail 0x%llx\n",
			__func__, nova_ino, pi->log_head, pi->log_tail);

	switch (__le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFDIR:
		ret = nova_traverse_dir_inode_log(sb, pi, info, cpuid);
		break;
	case S_IFLNK:
		/* Treat symlink files as normal files */
		/* Fall through */
	case S_IFREG:
		/* Fall through */
	default:
		/* In case of special inode, walk the log */
		ret = nova_traverse_file_inode_log(sb, pi, sih, ring, info, cpuid);
		break;
	}

	return ret;
}

static void free_resources(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct task_ring *ring;
	int i;

	if (task_rings) {
		for (i = 0; i < sbi->cpus; i++) {
			ring = &task_rings[i];
			xa_destroy(&ring->entry_array);
		}
	}

	kfree(task_rings);
}

static int failure_thread_func(void *data);

struct failure_recovery_thread_para {
	struct completion entered;
	struct super_block *sb;
	struct failure_recovery_info *info;
};
static int allocate_resources(struct super_block *sb, int cpus)
{
	struct task_ring *ring;
	int i;

	task_rings = kcalloc(cpus, sizeof(struct task_ring), GFP_KERNEL);
	if (!task_rings)
		goto fail;

	for (i = 0; i < cpus; i++) {
		ring = &task_rings[i];
		xa_init(&ring->entry_array);
	}

	return 0;

fail:
	free_resources(sb);
	return -ENOMEM;
}

/*********************** Failure recovery *************************/

static inline int nova_failure_update_inodetree(struct super_block *sb,
	struct nova_inode *pi, unsigned long *ino_low, unsigned long *ino_high)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (*ino_low == 0) {
		*ino_low = *ino_high = pi->nova_ino;
	} else {
		if (pi->nova_ino == *ino_high + sbi->cpus) {
			*ino_high = pi->nova_ino;
		} else {
			/* A new start */
			nova_failure_insert_inodetree(sb, *ino_low, *ino_high);
			*ino_low = *ino_high = pi->nova_ino;
		}
	}

	return 0;
}

static int __failure_thread_func(struct super_block *sb,
	struct failure_recovery_info *info)
{
	struct nova_inode_info_header sih;
	struct task_ring *ring;
	struct nova_inode *pi, fake_pi;
	unsigned long num_inodes_per_page;
	unsigned long ino_low, ino_high;
	unsigned long last_blocknr;
	unsigned int data_bits;
	u64 curr, curr1;
	int cpuid = nova_get_cpuid(sb);
	unsigned long i;
	unsigned long max_size = 0;
	u64 pi_addr = 0;
	int ret;
	int count;

	pi = nova_get_inode_by_ino(sb, NOVA_INODETABLE_INO);
	data_bits = blk_type_to_shift[pi->i_blk_type];
	num_inodes_per_page = 1 << (data_bits - NOVA_INODE_BITS);

	ring = &task_rings[cpuid];
	nova_init_header(sb, &sih, 0);

	for (count = 0; count < ring->num; count++) {
		curr = ring->addr0[count];
		curr1 = ring->addr1[count];
		ino_low = ino_high = 0;

		/*
		 * Note: The inode log page is allocated in 2MB
		 * granularity, but not aligned on 2MB boundary.
		 */
		for (i = 0; i < 512; i++) {
			ret = set_bm((curr >> PAGE_SHIFT) + i,
					info, cpuid);
			if (ret < 0)
				return ret;
		}

		if (metadata_csum) {
			for (i = 0; i < 512; i++) {
				ret = set_bm((curr1 >> PAGE_SHIFT) + i,
					info, cpuid);
				if (ret < 0)
					return ret;
			}
		}

		for (i = 0; i < num_inodes_per_page; i++) {
			pi_addr = curr + i * NOVA_INODE_SIZE;
			ret = nova_get_reference(sb, pi_addr, &fake_pi,
				(void **)&pi, sizeof(struct nova_inode));
			if (ret) {
				nova_dbg("Recover pi @ 0x%llx failed\n",
						pi_addr);
				continue;
			}
			/* FIXME: Check inode checksum */
			if (fake_pi.i_mode && fake_pi.deleted == 0) {
				if (fake_pi.valid == 0) {
					ret = nova_append_inode_to_snapshot(sb,
									pi);
					if (ret != 0) {
						/* Deleteable */
						pi->deleted = 1;
						fake_pi.deleted = 1;
						continue;
					}
				}

				ret = nova_recover_inode_pages(sb, &sih, ring,
						&fake_pi, info, cpuid);
				if (ret < 0)
					return ret;
				nova_failure_update_inodetree(sb, pi,
						&ino_low, &ino_high);
				if (sih.i_size > max_size)
					max_size = sih.i_size;
			}
		}

		if (ino_low && ino_high)
			nova_failure_insert_inodetree(sb, ino_low, ino_high);
	}

	/* Free radix tree */
	if (max_size) {
		last_blocknr = (max_size - 1) >> PAGE_SHIFT;
		nova_delete_file_tree(sb, &sih, 0, last_blocknr,
						false, false, 0);
	}
	return 0;
}
static int failure_thread_func(void *__data)
{
	struct failure_recovery_thread_para *para =
		(struct failure_recovery_thread_para *)__data;
	int ret;
	complete(&para->entered);
	ret = __failure_thread_func(para->sb, para->info);
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	return ret;
}

static int failure_recovery_multithread(
	struct super_block *sb,
	struct failure_recovery_info *info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct failure_recovery_thread_para *para = NULL;
	struct task_struct **tasks = NULL;
	unsigned long thread_num = sbi->cpus;
	unsigned long i;
	int ret = 0, ret2;

	para = kmalloc(thread_num * sizeof(para[0]), GFP_KERNEL);
	if (para == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	tasks = kmalloc(thread_num * sizeof(struct task_struct *), GFP_KERNEL);
	if (!tasks) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; i < thread_num; ++i) {
		init_completion(&para[i].entered);
		para[i].sb = sb;
		para[i].info = info;
		tasks[i] = kthread_create(failure_thread_func,
						para + i, "recovery_thread_%lu", i);
		if (IS_ERR(tasks[i])) {
			ret = PTR_ERR(tasks[i]);
			nova_err(sb, "%lu: kthread_create %lu return %d\n",
				__func__, i, ret);
			break;
		}
		kthread_bind(tasks[i], i);
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

static int nova_failure_recovery_crawl(struct super_block *sb,
	struct failure_recovery_info *info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info_header sih;
	struct inode_table *inode_table;
	struct task_ring *ring;
	struct nova_inode *pi, fake_pi;
	unsigned long curr_addr;
	u64 root_addr;
	u64 curr;
	int num_tables;
	int version;
	int ret = 0;
	int count;
	int cpuid;

	root_addr = nova_get_reserved_inode_addr(sb, NOVA_ROOT_INO);

	num_tables = 1;
	if (metadata_csum)
		num_tables = 2;

	for (cpuid = 0; cpuid < sbi->cpus; cpuid++) {
		ring = &task_rings[cpuid];
		for (version = 0; version < num_tables; version++) {
			inode_table = nova_get_inode_table(sb, version,
								cpuid);
			if (!inode_table)
				return -EINVAL;

			count = 0;
			curr = inode_table->log_head;
			while (curr) {
				if (ring->num >= 512) {
					nova_err(sb, "%s: ring size too small\n",
						 __func__);
					return -EINVAL;
				}

				if (version == 0)
					ring->addr0[count] = curr;
				else
					ring->addr1[count] = curr;

				count++;

				curr_addr = (unsigned long)nova_get_block(sb,
								curr);
				/* Next page resides at the last 8 bytes */
				curr_addr += 2097152 - 8;
				curr = *(u64 *)(curr_addr);
			}

			if (count > ring->num)
				ring->num = count;
		}
	}

	ret = failure_recovery_multithread(sb, info);
	if (ret < 0)
		return ret;

	nova_init_header(sb, &sih, 0);
	/* Recover the root inode */
	ret = nova_get_reference(sb, root_addr, &fake_pi,
			(void **)&pi, sizeof(struct nova_inode));
	if (ret) {
		nova_dbg("Recover root pi failed\n");
		return ret;
	}

	return nova_recover_inode_pages(sb, &sih, &task_rings[0],
					&fake_pi, info, 0);
}

static int nova_failure_recovery(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct task_ring *ring;
	struct nova_inode *pi;
	struct journal_ptr_pair *pair;
	struct failure_recovery_info info;
	int ret = 0;
	int i;
	INIT_TIMING(scan_inode_log_time);

	ret = alloc_failure_recovery_info(sb, &info);
	if (ret < 0)
		goto err_out0;
	sbi->s_inodes_used_count = 0;

	/* Initialize inuse inode list */
	if (nova_init_inode_inuse_list(sb) < 0) {
		ret = -EINVAL;
		goto err_out1;
	}

	/* Handle special inodes */
	pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	pi->log_head = pi->log_tail = 0;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	for (i = 0; i < sbi->cpus; i++) {
		pair = nova_get_journal_pointers(sb, i);

		ret = set_bm(pair->journal_head >> PAGE_SHIFT, &info, i);
		if (ret < 0)
			goto err_out1;
	}

	i = NOVA_SNAPSHOT_INO % sbi->cpus;
	pi = nova_get_inode_by_ino(sb, NOVA_SNAPSHOT_INO);
	/* Set snapshot info log pages */
	ret = nova_traverse_dir_inode_log(sb, pi, &info, i);
	if (ret < 0)
		goto err_out1;

	PERSISTENT_BARRIER();

	ret = allocate_resources(sb, sbi->cpus);
	if (ret)
		goto err_out1;

	NOVA_START_TIMING(scan_inode_log_t, scan_inode_log_time);
	ret = nova_failure_recovery_crawl(sb, &info);
	NOVA_END_TIMING(scan_inode_log_t, scan_inode_log_time);

	for (i = 0; i < sbi->cpus; i++) {
		ring = &task_rings[i];
		sbi->s_inodes_used_count += ring->inodes_used_count;
	}

	free_resources(sb);
	if (ret < 0)
		goto err_out1;
	ret = nova_build_blocknode_map(sb, &info);
	if (ret < 0)
		goto err_out1;

	nova_dbg("Failure recovery total recovered %lu\n",
			sbi->s_inodes_used_count - NOVA_NORMAL_INODE_START);
	free_failure_recovery_info(sbi, &info);
	return 0;
err_out1:
	free_all_failure_recovery_info(sbi, &info);
err_out0:
	return ret;
}

/*********************** Recovery entrance *************************/

/* Return TRUE if we can do a normal unmount recovery */
static bool nova_try_normal_recovery(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi =  nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	struct nova_recover_meta *recover_meta = nova_get_recover_meta(sbi);
	struct nova_meta_table *table = &sbi->meta_table;
	int ret;

	if (recover_meta->saved != NOVA_RECOVER_META_FLAG_COMPLETE)
		return false;
	if (pi->log_head == 0 || pi->log_tail == 0)
		return false;

	ret = nova_init_blockmap_from_inode(sb);
	if (ret) {
		nova_err(sb, "init blockmap failed, fall back to failure recovery\n");
		return false;
	}

	ret = nova_init_inode_list_from_inode(sb);
	if (ret) {
		nova_err(sb, "init inode list failed, fall back to failure recovery\n");
		nova_destroy_blocknode_trees(sb);
		return false;
	}

	if (sbi->mount_snapshot == 0) {
		ret = nova_restore_snapshot_table(sb, 0);
		if (ret) {
			nova_err(sb, "Restore snapshot table failed, fall back to failure recovery\n");
			nova_destroy_snapshot_infos(sb);
			return false;
		}
	}

	ret = nova_meta_table_restore(table, sb);
	if (ret < 0) {
		nova_err(sb, "Restore meta table failed with return code %d, fall back to failure recovery\n", ret);
		return false;
	}
	recover_meta->saved = 0;

	return true;
}
#endif

/*
 * Recovery routine has three tasks:
 * 1. Restore snapshot table;
 * 2. Restore inuse inode list;
 * 3. Restore the NVMM allocator.
 */
int nova_recovery(struct super_block *sb)
{
#if 0
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *super = sbi->nova_sb;
	bool value = false;
	int ret = 0;
	INIT_TIMING(start);
	INIT_TIMING(end);

	nova_dbgv("%s\n", __func__);

	/* Always check recovery time */
	if (measure_timing == 0)
		getrawmonotonic(&start);

	NOVA_START_TIMING(recovery_t, start);

	/* initialize free list info */
	nova_init_blockmap(sb, 1);

	value = nova_try_normal_recovery(sb);
	if (value) {
		nova_dbg("NOVA: Normal shutdown\n");
	} else {
		nova_dbg("NOVA: Failure recovery\n");
		if (sbi->mount_snapshot == 0) {
			/* Initialize the snapshot infos */
			ret = nova_restore_snapshot_table(sb, 1);
			if (ret) {
				nova_dbg("Initialize snapshot infos failed\n");
				nova_destroy_snapshot_infos(sb);
				goto out;
			}
		}

		sbi->s_inodes_used_count = 0;
		ret = nova_failure_recovery(sb);
		if (ret)
			goto out;
	}

out:
	NOVA_END_TIMING(recovery_t, start);
	if (measure_timing == 0) {
		getrawmonotonic(&end);
		Timingstats[recovery_t] +=
			(end.tv_sec - start.tv_sec) * 1000000000 +
			(end.tv_nsec - start.tv_nsec);
	}

	sbi->s_epoch_id = le64_to_cpu(super->s_epoch_id);
	return ret;
#endif
	BUG();
}
