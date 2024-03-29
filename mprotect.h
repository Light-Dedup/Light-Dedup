/*
 * BRIEF DESCRIPTION
 *
 * Memory protection definitions for the NOVA filesystem.
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

#ifndef __WPROTECT_H
#define __WPROTECT_H

#include <linux/fs.h>
#include "nova_def.h"
#include "super.h"

extern void nova_error_mng(struct super_block *sb, const char *fmt, ...);

static inline int nova_range_check(struct nova_sb_info *sbi, void *p,
	unsigned long len)
{
	if (p < sbi->virt_addr ||
			p + len > sbi->virt_addr + sbi->initsize) {
		printk("access pmem out of range: pmem range 0x%lx - 0x%lx, "
				"access range 0x%lx - 0x%lx\n",
				(unsigned long)sbi->virt_addr,
				(unsigned long)(sbi->virt_addr + sbi->initsize),
				(unsigned long)p, (unsigned long)(p + len));
		dump_stack();
		return -EINVAL;
	}

	return 0;
}

static inline void wprotect_disable(void)
{
	unsigned long cr0_val;

	cr0_val = read_cr0();
	cr0_val &= (~X86_CR0_WP);
	write_cr0(cr0_val);
}

static inline void wprotect_enable(void)
{
	unsigned long cr0_val;

	cr0_val = read_cr0();
	cr0_val |= X86_CR0_WP;
	write_cr0(cr0_val);
}

static inline void
__nova_writable(int rw, unsigned long *flags) {
	INIT_TIMING(wprotect_time);

	NOVA_START_TIMING(wprotect_t, wprotect_time);
	if (rw) {
		local_irq_save(*flags);
		wprotect_disable();
	} else {
		wprotect_enable();
		local_irq_restore(*flags);
	}
	NOVA_END_TIMING(wprotect_t, wprotect_time);
}

/* FIXME: Assumes that we are always called in the right order.
 * nova_writeable(vaddr, size, 1);
 * nova_writeable(vaddr, size, 0);
 */
static inline int
nova_writeable(void *vaddr, unsigned long size, int rw, unsigned long *flags)
{
	__nova_writable(rw, flags);
	return 0;
}

static inline int nova_is_protected(struct nova_sb_info *sbi)
{
	if (wprotect)
		return wprotect;

	return sbi->s_mount_opt & NOVA_MOUNT_PROTECT;
}

static inline int nova_is_wprotected(struct super_block *sb)
{
	return nova_is_protected(NOVA_SB(sb));
}

static inline void
nova_memunlock(struct nova_sb_info *sbi, unsigned long *flags)
{
	if (nova_is_protected(sbi))
		__nova_writable(1, flags);
}
static inline void
nova_memlock(struct nova_sb_info *sbi, unsigned long *flags)
{
	if (nova_is_protected(sbi))
		__nova_writable(0, flags);
}

static inline void
__nova_memunlock_range(void *p, unsigned long len, unsigned long *flags)
{
	/*
	 * NOTE: Ideally we should lock all the kernel to be memory safe
	 * and avoid to write in the protected memory,
	 * obviously it's not possible, so we only serialize
	 * the operations at fs level. We can't disable the interrupts
	 * because we could have a deadlock in this path.
	 */
	nova_writeable(p, len, 1, flags);
}

static inline void
__nova_memlock_range(void *p, unsigned long len, unsigned long *flags)
{
	nova_writeable(p, len, 0, flags);
}

static inline void nova_sbi_memunlock_range(struct nova_sb_info *sbi, void *p,
					 unsigned long len, unsigned long *flags)
{
	if (nova_range_check(sbi, p, len))
		return;

	if (nova_is_protected(sbi))
		__nova_memunlock_range(p, len, flags);
}

static inline void nova_sbi_memlock_range(struct nova_sb_info *sbi, void *p,
				       unsigned long len, unsigned long *flags)
{
	if (nova_is_protected(sbi))
		__nova_memlock_range(p, len, flags);
}

static inline void nova_memunlock_range(struct super_block *sb, void *p,
					 unsigned long len, unsigned long *flags)
{
	nova_sbi_memunlock_range(NOVA_SB(sb), p, len, flags);
}

static inline void nova_memlock_range(struct super_block *sb, void *p,
				       unsigned long len, unsigned long *flags)
{
	nova_sbi_memlock_range(NOVA_SB(sb), p, len, flags);
}

static inline void nova_memunlock_super(struct super_block *sb, unsigned long *flags)
{
	struct nova_super_block *ps = nova_get_super(sb);

	if (nova_is_protected(NOVA_SB(sb)))
		__nova_memunlock_range(ps, NOVA_SB_SIZE, flags);
}

static inline void nova_memlock_super(struct super_block *sb, unsigned long *flags)
{
	struct nova_super_block *ps = nova_get_super(sb);

	if (nova_is_protected(NOVA_SB(sb)))
		__nova_memlock_range(ps, NOVA_SB_SIZE, flags);
}

static inline void nova_memunlock_reserved(struct super_block *sb,
					 struct nova_super_block *ps, unsigned long *flags)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (nova_is_protected(NOVA_SB(sb)))
		__nova_memunlock_range(ps,
			sbi->block_start * NOVA_DEF_BLOCK_SIZE_4K, flags);
}

static inline void nova_memlock_reserved(struct super_block *sb,
				       struct nova_super_block *ps, unsigned long *flags)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (nova_is_protected(NOVA_SB(sb)))
		__nova_memlock_range(ps,
			sbi->block_start * NOVA_DEF_BLOCK_SIZE_4K, flags);
}

static inline void nova_memunlock_journal(struct super_block *sb, unsigned long *flags)
{
	void *addr = nova_get_block(sb, NOVA_DEF_BLOCK_SIZE_4K * JOURNAL_START);

	if (nova_range_check(NOVA_SB(sb), addr, NOVA_DEF_BLOCK_SIZE_4K))
		return;

	if (nova_is_protected(NOVA_SB(sb)))
		__nova_memunlock_range(addr, NOVA_DEF_BLOCK_SIZE_4K, flags);
}

static inline void nova_memlock_journal(struct super_block *sb, unsigned long *flags)
{
	void *addr = nova_get_block(sb, NOVA_DEF_BLOCK_SIZE_4K * JOURNAL_START);

	if (nova_is_protected(NOVA_SB(sb)))
		__nova_memlock_range(addr, NOVA_DEF_BLOCK_SIZE_4K, flags);
}

static inline void nova_memunlock_inode(struct super_block *sb,
					 struct nova_inode *pi, unsigned long *flags)
{
	if (nova_range_check(NOVA_SB(sb), pi, NOVA_INODE_SIZE))
		return;

	if (nova_is_protected(NOVA_SB(sb)))
		__nova_memunlock_range(pi, NOVA_INODE_SIZE, flags);
}

static inline void nova_memlock_inode(struct super_block *sb,
				       struct nova_inode *pi, unsigned long *flags)
{
	/* nova_sync_inode(pi); */
	if (nova_is_protected(NOVA_SB(sb)))
		__nova_memlock_range(pi, NOVA_INODE_SIZE, flags);
}

static inline void nova_memunlock_block(struct super_block *sb, void *bp, unsigned long *flags)
{
	if (nova_range_check(NOVA_SB(sb), bp, sb->s_blocksize))
		return;

	if (nova_is_protected(NOVA_SB(sb)))
		__nova_memunlock_range(bp, sb->s_blocksize, flags);
}

static inline void nova_memlock_block(struct super_block *sb, void *bp, unsigned long *flags)
{
	if (nova_is_protected(NOVA_SB(sb)))
		__nova_memlock_range(bp, sb->s_blocksize, flags);
}

#define nova_ntstore_val(addr, val)	\
	do {												\
		typeof(*addr) tmp = val;						\
		memcpy_flushcache(addr, &tmp, sizeof(*(addr)));	\
	} while (0)

#define nova_unlock_write(sbi, addr, val)				\
({									\
	unsigned long irq_flags = 0;					\
	nova_sbi_memunlock_range(sbi, addr, sizeof(*(addr)),		\
		&irq_flags);						\
	*(addr) = val;							\
	nova_sbi_memlock_range(sbi, addr, sizeof(*(addr)),		\
		&irq_flags);						\
})

#define nova_unlock_write_flush(sbi, addr, val, fence)			\
({									\
	nova_unlock_write(sbi, addr, val);				\
	nova_flush_buffer(addr, sizeof(*(addr)), fence);		\
})

#endif
