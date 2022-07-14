/*
 * NOVA File System statistics
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
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

#ifndef __STATS_H
#define __STATS_H

#include "config.h"

/* ======================= Timing ========================= */
enum timing_category {
	/* Init */
	init_title_t,
	init_t,
	mount_t,
	ioremap_t,
	new_init_t,
	recovery_t,
	scan_inode_log_t,

	/* Namei operations */
	namei_title_t,
	create_t,
	lookup_t,
	link_t,
	unlink_t,
	symlink_t,
	mkdir_t,
	rmdir_t,
	mknod_t,
	rename_t,
	readdir_t,
	add_dentry_t,
	remove_dentry_t,
	setattr_t,
	setsize_t,

	/* I/O operations */
	io_title_t,
	dax_read_t,
	do_cow_write_t,
	cow_write_t,
	inplace_write_t,
	copy_to_nvmm_t,
	dax_get_block_t,
	read_iter_t,
	write_iter_t,
	wrap_iter_t,

	/* Memory operations */
	memory_title_t,
	memcpy_r_nvmm_t,
	memcpy_w_nvmm_t,
	memcpy_w_wb_t,
	partial_block_t,

	/* Memory management */
	mm_title_t,
	new_data_blocks_t,
	new_log_blocks_t,
	free_data_t,
	free_log_t,

	/* Transaction */
	trans_title_t,
	create_trans_t,
	link_trans_t,
	update_tail_t,

	/* Logging */
	logging_title_t,
	append_dir_entry_t,
	append_file_entry_t,
	append_mmap_entry_t,
	append_link_change_t,
	append_setattr_t,
	append_snapshot_info_t,
	update_entry_t,

	/* Tree */
	tree_title_t,
	check_entry_t,
	assign_t,

	/* GC */
	gc_title_t,
	fast_gc_t,
	thorough_gc_t,
	check_invalid_t,

	/* Integrity */
	integrity_title_t,
	block_csum_t,
	block_parity_t,
	block_csum_parity_t,
	protect_memcpy_t,
	protect_file_data_t,
	verify_entry_csum_t,
	verify_data_csum_t,
	calc_entry_csum_t,
	restore_data_t,
	reset_mapping_t,
	reset_vma_t,

	/* Others */
	others_title_t,
	find_cache_t,
	fsync_t,
	write_pages_t,
	fallocate_t,
	direct_IO_t,
	free_old_t,
	delete_file_tree_t,
	delete_dir_tree_t,
	new_vfs_inode_t,
	new_nova_inode_t,
	free_inode_t,
	free_inode_log_t,
	evict_inode_t,
	perf_t,
	wprotect_t,

	/* Mmap */
	mmap_title_t,
	mmap_fault_t,
	pmd_fault_t,
	pfn_mkwrite_t,
	insert_vma_t,
	remove_vma_t,
	set_vma_read_t,
	mmap_cow_t,
	update_mapping_t,
	update_pfn_t,
	mmap_handler_t,

	/* Rebuild */
	rebuild_title_t,
	rebuild_dir_t,
	rebuild_file_t,
	rebuild_snapshot_t,

	/* Snapshot */
	snapshot_title_t,
	create_snapshot_t,
	init_snapshot_info_t,
	delete_snapshot_t,
	append_snapshot_file_t,
	append_snapshot_inode_t,

	/* Fingerprint table */
	fingerprint_table_title_t,
	copy_from_user_t,
	fp_calc_t,
	incr_ref_t,
	decr_ref_t,
	memcpy_data_block_t,
	incr_continuous_t,
	cmp_user_t,
	update_hint_t,
	alloc_region_t,
	add_valid_count_t,
	new_region_t,
	alloc_entry_t,
	write_new_entry_t,
	mem_bucket_find_t,
	index_insert_new_entry_t,
	memcmp_t,
	prefetch_block_t,
	prefetch_cmp_t,
	table_init_t,
	save_refcount_t,
	save_entry_allocator_t,
	normal_recover_fp_table_t,
	normal_recover_entry_allocator_t,
	scan_fp_entry_table_t,
	upsert_fp_entry_t,
	invalidate_unused_fp_entry_t,

	/* xatable */
	xatable_title_t,
	xatable_store_t,
	xatable_load_t,

	/* Sentinel */
	TIMING_NUM,
};

enum stats_category {
	alloc_steps,
	cow_write_breaks,
	inplace_write_breaks,
	read_bytes,
	cow_write_bytes,
	inplace_write_bytes,
	fast_checked_pages,
	thorough_checked_pages,
	fast_gc_pages,
	thorough_gc_pages,
	dirty_pages,
	protect_head,
	protect_tail,
	block_csum_parity,
	dax_cow_during_snapshot,
	mapping_updated_pages,
	cow_overlap_mmap,
	dax_new_blocks,
	inplace_new_blocks,
	fdatasync,
	predict_hit,
	predict_miss,
	no_hint,
	hint_not_trusted_miss,
	hint_not_trusted_hit,
	prefetch_hit,

	/* Sentinel */
	STATS_NUM,
};

extern const char *Timingstring[TIMING_NUM];
extern u64 Timingstats[TIMING_NUM];
DECLARE_PER_CPU(u64[TIMING_NUM], Timingstats_percpu);
extern u64 Countstats[TIMING_NUM];
DECLARE_PER_CPU(u64[TIMING_NUM], Countstats_percpu);
extern u64 IOstats[STATS_NUM];
DECLARE_PER_CPU(u64[STATS_NUM], IOstats_percpu);

typedef struct timespec timing_t;

#define	INIT_TIMING(X)	timing_t X = {0}

#define NOVA_STRINGIFY(x) #x
#define __NOVA_TIMER_DISABLED(name_disabled) \
	(sizeof NOVA_STRINGIFY(name_disabled) == 2)
#define NOVA_TIMER_DISABLED(name) __NOVA_TIMER_DISABLED(name ## _disabled)

// For example
// #define mem_bucket_find_t_disabled 1
// _Static_assert(NOVA_TIMER_DISABLED(mem_bucket_find_t),
// 	"mem_bucket_find_t not disabled!");

#define NOVA_START_TIMING(name, start)	do { 			\
	if (measure_timing && !NOVA_TIMER_DISABLED(name))	\
		getrawmonotonic(&start);			\
} while (0)

#define NOVA_END_TIMING(name, start)	do { 				\
	if (measure_timing && !NOVA_TIMER_DISABLED(name)) { 		\
		INIT_TIMING(end); 					\
		getrawmonotonic(&end); 					\
		__this_cpu_add(Timingstats_percpu[name], 		\
			(end.tv_sec - start.tv_sec) * 1000000000 + 	\
			(end.tv_nsec - start.tv_nsec)); 		\
	} 								\
	__this_cpu_add(Countstats_percpu[name], 1); 			\
} while (0)

#define NOVA_STATS_ADD(name, value)	do {		\
	__this_cpu_add(IOstats_percpu[name], value);	\
} while (0)



#endif
