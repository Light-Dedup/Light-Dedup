/*
 * BRIEF DESCRIPTION
 *
 * Super block operations.
 *
 * Copyright 2020-2023 Jiansheng Qiu <jianshengqiu.cs@gmail.com>
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef __SUPER_H
#define __SUPER_H

#include "table.h"
/*
 * Structure of the NOVA super block in PMEM
 *
 * The fields are partitioned into static and dynamic fields. The static fields
 * never change after file system creation. This was primarily done because
 * nova_get_block() returns NULL if the block offset is 0 (helps in catching
 * bugs). So if we modify any field using journaling (for consistency), we
 * will have to modify s_sum which is at offset 0. So journaling code fails.
 * This (static+dynamic fields) is a temporary solution and can be avoided
 * once the file system becomes stable and nova_get_block() returns correct
 * pointers even for offset 0.
 */
struct nova_super_block {
	/* static fields. they never change after file system creation.
	 * checksum only validates up to s_start_dynamic field below
	 */
	__le32		s_sum;			/* checksum of this sb */
	__le32		s_magic;		/* magic signature */
	__le32		s_padding32;
	__le32		s_blocksize;		/* blocksize in bytes */
	__le64		s_size;			/* total size of fs in bytes */
	char		s_volume_name[16];	/* volume name */

	/* all the dynamic fields should go here */
	__le64		s_epoch_id;		/* Epoch ID */

	/* s_mtime and s_wtime should be together and their order should not be
	 * changed. we use an 8 byte write to update both of them atomically
	 */
	__le32		s_mtime;		/* mount time */
	__le32		s_wtime;		/* write time */

	/* Metadata and data protections */
	u8		s_padding8;
	u8		s_metadata_csum;
	u8		s_data_csum;
	u8		s_data_parity;
} __attribute((__packed__));

#define NOVA_SB_SIZE 512       /* must be power of two */

/* ======================= Reserved blocks ========================= */

/*
 * Block 0 contains super blocks;
 * Block 1 contains reserved inodes;
 * Block 2 - 15 are reserved.
 * Block 16 - 31 contain pointers to inode table.
 * Block 32 - 47 contain pointers to replica inode table.
 * Block 48 - 63 contain pointers to journal pages.
 *
 * If data protection is enabled, more blocks are reserverd for checksums and
 * parities and the number is derived according to the whole storage size.
 */
#define	HEAD_RESERVED_BLOCKS	64
#define	NUM_JOURNAL_PAGES	16

#define SUPER_BLOCK_START       0 // Superblock
#define	RESERVE_INODE_START	1 // Reserved inodes
#define RECOVER_META_START 15
#define	INODE_TABLE0_START	16 // inode table
#define	INODE_TABLE1_START	32 // replica inode table
#define	JOURNAL_START		48 // journal pointer table

/* ======================= Reserved inodes ========================= */

/* We have space for 31 reserved inodes */
#define NOVA_ROOT_INO		(1)
#define NOVA_INODETABLE_INO	(2)	/* Fake inode associated with inode
					 * stroage.  We need this because our
					 * allocator requires inode to be
					 * associated with each allocation.
					 * The data actually lives in linked
					 * lists in INODE_TABLE0_START. */
#define NOVA_BLOCKNODE_INO	(3)     /* Storage for allocator state */
#define NOVA_LITEJOURNAL_INO	(4)     /* Storage for lightweight journals */
#define NOVA_INODELIST_INO	(5)     /* Storage for Inode free list */
#define NOVA_SNAPSHOT_INO	(6)	/* Storage for snapshot state */
#define NOVA_TEST_PERF_INO	(7)


/* Normal inode starts at 32 */
#define NOVA_NORMAL_INODE_START      (32)

#define NOVA_RECOVER_META_FLAG_COMPLETE (0x3f)
struct nova_recover_meta {
	// u8 free_entrynr_saved;
	u8 saved;
	u8 __padding[7];
	// __le64 free_entrynr_list_head;
	// __le64 free_entrynr_list_tail;
	__le64 region_num;
	__le64 last_region_tail;
	__le64 max_region_num;
	__le64 last_counter_block_tail_offset;
	__le64 refcount_record_num;
};
_Static_assert(sizeof(struct nova_recover_meta) <= PAGE_SIZE, "struct nova_recover_meta too large!");


/*
 * NOVA super-block data in DRAM
 */
struct nova_sb_info {
	struct super_block *sb;			/* VFS super block */
	struct nova_super_block *nova_sb;	/* DRAM copy of SB */
	struct block_device *s_bdev;
	struct dax_device *s_dax_dev;

	/*
	 * base physical and virtual address of NOVA (which is also
	 * the pointer to the super block)
	 */
	phys_addr_t	phys_addr;
	void		*virt_addr;
	void		*replica_reserved_inodes_addr;
	void		*replica_sb_addr;

	unsigned long	num_blocks;

	/* TODO: Remove this, since it's unused */
	/*
	 * Backing store option:
	 * 1 = no load, 2 = no store,
	 * else do both
	 */
	unsigned int	nova_backing_option;

	/* Mount options */
	unsigned long	bpi;
	unsigned long	blocksize;
	unsigned long	initsize;
	unsigned long	s_mount_opt;
	kuid_t		uid;    /* Mount uid for root directory */
	kgid_t		gid;    /* Mount gid for root directory */
	umode_t		mode;   /* Mount mode for root directory */
	atomic_t	next_generation;
	/* inode tracking */
	unsigned long	s_inodes_used_count;

	struct mutex	s_lock;	/* protects the SB's buffer-head */

	int cpus;
	struct proc_dir_entry *s_proc;

	/* Snapshot related */
	struct nova_inode_info	*snapshot_si;
	struct radix_tree_root	snapshot_info_tree;
	int num_snapshots;
	/* Current epoch. volatile guarantees visibility */
	volatile u64 s_epoch_id;
	volatile int snapshot_taking;

	int mount_snapshot;
	u64 mount_snapshot_epoch_id;

	struct task_struct *snapshot_cleaner_thread;
	wait_queue_head_t snapshot_cleaner_wait;
	wait_queue_head_t snapshot_mmap_wait;
	void *curr_clean_snapshot_info;

	/* DAX-mmap snapshot structures */
	struct mutex vma_mutex;
	struct list_head mmap_sih_list;

	/* ZEROED page for cache page initialized */
	void *zeroed_page;

	/* Checksum and parity for zero block */
	u32 zero_csum[8];
	void *zero_parity;

	/* Per-CPU journal lock */
	spinlock_t *journal_locks;

	/* Per-CPU inode map */
	struct inode_map	*inode_maps;

	/* Decide new inode map id */
	unsigned long map_id;

	/* Per-CPU free block list */
	struct free_list *free_lists;
	unsigned long per_list_blocks;
	unsigned long	block_start;
	unsigned long	block_end;

	unsigned long region_start;
	unsigned long region_blocknr_start;
	unsigned long first_counter_block_start;
	unsigned long entry_refcount_record_start;
	unsigned long deref_table;

	struct light_dedup_meta light_dedup_meta;
};

static inline struct nova_sb_info *NOVA_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}
static inline struct nova_sb_info *
light_dedup_meta_to_sbi(struct light_dedup_meta *meta)
{
	return container_of(meta, struct nova_sb_info, light_dedup_meta);
}
static inline struct nova_sb_info *
entry_allocator_to_sbi(struct entry_allocator *allocator)
{
	return light_dedup_meta_to_sbi(
		entry_allocator_to_light_dedup_meta(allocator));
}

static inline void
nova_deref_blocks(struct super_block *sb, unsigned long blocknr,
	unsigned long num)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_pmm_entry *last_pentry = NULL;
	while (num) {
		light_dedup_decr_ref(&sbi->light_dedup_meta, blocknr,
			&last_pentry);
		num -= 1;
		blocknr += 1;
	}
	if (last_pentry) {
		nova_flush_cacheline(last_pentry, true);
	}
}

static inline struct nova_super_block
*nova_get_redund_super(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	return (struct nova_super_block *)(sbi->replica_sb_addr);
}


static inline struct nova_super_block *nova_sbi_get_super(struct nova_sb_info *sbi)
{
	return (struct nova_super_block *)sbi->virt_addr;
}
/* If this is part of a read-modify-write of the super block,
 * nova_memunlock_super() before calling!
 */
static inline struct nova_super_block *nova_get_super(struct super_block *sb)
{
	return nova_sbi_get_super(NOVA_SB(sb));
}

static inline u64
nova_get_blocknr_off(unsigned long blocknr)
{
	return (u64)blocknr << PAGE_SHIFT;
}
static inline void *nova_sbi_get_block(struct nova_sb_info *sbi, u64 block)
{
	struct nova_super_block *ps = nova_sbi_get_super(sbi);
	return block ? ((void *)ps + block) : NULL;
}
static inline void *
nova_sbi_blocknr_to_addr(struct nova_sb_info *sbi, unsigned long blocknr)
{
	return nova_sbi_get_block(sbi, nova_get_blocknr_off(blocknr));
}
static inline struct nova_recover_meta *
nova_get_recover_meta(struct nova_sb_info *sbi)
{
	return nova_sbi_blocknr_to_addr(sbi, RECOVER_META_START);
}

extern struct super_block *nova_read_super(struct super_block *sb, void *data,
	int silent);
extern int nova_statfs(struct dentry *d, struct kstatfs *buf);
extern int nova_remount(struct super_block *sb, int *flags, char *data);
void *nova_ioremap(struct super_block *sb, phys_addr_t phys_addr,
	ssize_t size);
extern struct nova_range_node *nova_alloc_range_node_atomic(struct super_block *sb);
extern struct nova_range_node *nova_alloc_range_node(struct super_block *sb);
extern void nova_free_range_node(struct nova_range_node *node);
extern void nova_update_super_crc(struct super_block *sb);
extern void nova_sync_super(struct super_block *sb);

struct snapshot_info *nova_alloc_snapshot_info(struct super_block *sb);
#endif
