/*
 * Checksum related methods.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef __CHECKSUM_H_
#define __CHECKSUM_H_

#include <linux/types.h>
#include <linux/crc32c.h>

static inline u32 nova_crc32c(u32 crc, const u8 *data, size_t len)
{
	u8 *ptr = (u8 *) data;
	u64 acc = crc; /* accumulator, crc32c value in lower 32b */
	u32 csum;

	/* x86 instruction crc32 is part of SSE-4.2 */
	if (static_cpu_has(X86_FEATURE_XMM4_2)) {
		/* This inline assembly implementation should be equivalent
		 * to the kernel's crc32c_intel_le_hw() function used by
		 * crc32c(), but this performs better on test machines.
		 */
		while (len > 8) {
			asm volatile(/* 64b quad words */
				"crc32q (%1), %0"
				: "=r" (acc)
				: "r"  (ptr), "0" (acc)
			);
			ptr += 8;
			len -= 8;
		}

		while (len > 0) {
			asm volatile(/* trailing bytes */
				"crc32b (%1), %0"
				: "=r" (acc)
				: "r"  (ptr), "0" (acc)
			);
			ptr++;
			len--;
		}

		csum = (u32) acc;
	} else {
		/* The kernel's crc32c() function should also detect and use the
		 * crc32 instruction of SSE-4.2. But calling in to this function
		 * is about 3x to 5x slower than the inline assembly version on
		 * some test machines.
		 */
		csum = crc32c(crc, data, len);
	}

	return csum;
}

#endif // __CHECKSUM_H_